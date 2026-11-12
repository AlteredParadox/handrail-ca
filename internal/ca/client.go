// handrail-ca — a lightweight web UI for step-ca.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package ca is handrail-ca's client for the step-ca HTTP API. This file is
// the connection: the operator configures the SHA-256 fingerprint of the
// CA's root certificate, the root is fetched from the CA and accepted only
// if it has that fingerprint, and from then on it is the only trust anchor
// for every request. The response shapes were captured from step-ca 0.30.2
// (see docs/PLAN.md, section 3).
package ca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// maxJSON bounds every JSON answer. A page of 100 provisioners with
	// their encrypted keys is about 100 KiB.
	maxJSON = 1 << 20

	defaultTimeout = 10 * time.Second
)

// Config is what the client needs to know about the CA.
type Config struct {
	// URL is the CA's address, https://host[:port] with no path.
	URL string
	// Fingerprint is the SHA-256 of the CA's root certificate in hex, as
	// printed by `step certificate fingerprint root_ca.crt`.
	Fingerprint string
	// Timeout bounds each request, the fetch of the root included. Zero
	// means ten seconds.
	Timeout time.Duration
	// UserAgent is sent with every request, if set.
	UserAgent string
	// Provisioner is what handrail-ca acts on the CA through. Without one
	// the client only reads.
	Provisioner *ProvisionerConfig
	// Now is the clock tokens are dated with; nil means time.Now.
	Now func() time.Time
}

// Client talks to one step-ca. It is safe for concurrent use. Creating it
// makes no connection: the root is fetched and pinned on the first request,
// so handrail-ca can start, and say so, while the CA is down.
type Client struct {
	base        *url.URL
	fingerprint [sha256.Size]byte
	timeout     time.Duration
	userAgent   string
	now         func() time.Time
	// provisioner is nil in read-only mode.
	provisioner *provisioner

	mu     sync.Mutex
	root   *x509.Certificate
	pinned *http.Client
}

// New checks the configuration and returns a client for it.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("CA URL: %w", err)
	}
	switch {
	case base.Scheme != "https":
		return nil, errors.New("CA URL: must start with https://")
	case base.Host == "" || base.Hostname() == "":
		return nil, errors.New("CA URL: no host")
	case base.User != nil:
		return nil, errors.New("CA URL: must not carry a user or password")
	case strings.Trim(base.Path, "/") != "" || base.RawQuery != "" || base.Fragment != "":
		return nil, errors.New("CA URL: must be https://host[:port] with no path or query")
	}
	base.Path, base.RawPath = "", ""

	sum, err := hex.DecodeString(strings.TrimSpace(cfg.Fingerprint))
	if err != nil || len(sum) != sha256.Size {
		return nil, errors.New("CA root fingerprint: want 64 hexadecimal characters (step certificate fingerprint root_ca.crt)")
	}
	prov, err := newProvisioner(cfg.Provisioner)
	if err != nil {
		return nil, err
	}
	c := &Client{base: base, timeout: cfg.Timeout, userAgent: cfg.UserAgent, now: cfg.Now, provisioner: prov}
	copy(c.fingerprint[:], sum)
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// URL is the CA's address as configured.
func (c *Client) URL() string { return c.base.String() }

// RootFingerprint is the configured fingerprint of the CA's root, in
// lower-case hex: what the root must match, whether or not it has been
// fetched yet.
func (c *Client) RootFingerprint() string { return hex.EncodeToString(c.fingerprint[:]) }

// Root returns the CA's root certificate, fetching and pinning it if that
// has not happened yet.
func (c *Client) Root(ctx context.Context) (*x509.Certificate, error) {
	if _, err := c.client(ctx); err != nil {
		return nil, err
	}
	return c.root, nil
}

// Fingerprint is a certificate's SHA-256 in lower-case hex, as printed by
// `step certificate fingerprint`.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// StatusError is an answer from the CA outside the 2xx range.
type StatusError struct {
	// Status is the HTTP status code.
	Status int
	// Message is the CA's own explanation, when it gave one. It comes from
	// the network: shortened, and to be escaped like any other input.
	Message string
	// ClockDifference is how far the CA's clock is from this machine's,
	// going by the Date of its answer, when that is more than the CA
	// tolerates in a token; zero otherwise. Positive means the CA is ahead.
	ClockDifference time.Duration
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the CA answered %d", e.Status)
	}
	return fmt.Sprintf("the CA answered %d: %s", e.Status, e.Message)
}

// tokenLeeway is the clock difference step-ca accepts in a token.
const tokenLeeway = time.Minute

// clockDifference reads the Date of an answer. A token is dated by this
// machine and checked by the CA's clock, so a difference beyond the CA's
// leeway is the first thing to rule out when a token is refused. The Date
// header has whole seconds, and the answer took some time to arrive: only
// a difference that could matter is reported.
func (c *Client) clockDifference(resp *http.Response) time.Duration {
	theirs, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return 0
	}
	diff := theirs.Sub(c.now())
	if diff.Abs() < tokenLeeway-10*time.Second {
		return 0
	}
	return diff.Round(time.Second)
}

// client returns the HTTP client that trusts the pinned root and nothing
// else, pinning the root first if needed. A failed attempt is not
// remembered: the next request tries again.
func (c *Client) client(ctx context.Context) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pinned != nil {
		return c.pinned, nil
	}
	root, err := c.fetchRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("pinning the CA's root: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	c.root = root
	c.pinned = &http.Client{
		Timeout:       c.timeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   c.timeout,
			ResponseHeaderTimeout: c.timeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	return c.pinned, nil
}

// get fetches a path from the CA over the pinned connection. Any 2xx is a
// success: step-ca answers 201 for some plain reads.
func (c *Client) get(ctx context.Context, path string, query url.Values, limit int64) ([]byte, error) {
	hc, err := c.client(ctx)
	if err != nil {
		return nil, err
	}
	_, body, err := c.do(ctx, hc, path, query, limit)
	return body, err
}

// postJSON sends one JSON body to the CA over the pinned connection and
// returns the answer. It is sent once: nothing here retries, since a
// request that changes the CA must have its outcome checked first.
func (c *Client) postJSON(ctx context.Context, path string, body any, limit int64) ([]byte, error) {
	hc, err := c.client(ctx)
	if err != nil {
		return nil, err
	}
	sent, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	_, answer, err := c.send(ctx, hc, http.MethodPost, path, nil, sent, limit)
	return answer, err
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, into any) error {
	body, err := c.get(ctx, path, query, maxJSON)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s: answer is not the expected JSON: %w", path, err)
	}
	return nil
}

// do makes one GET and reads at most limit bytes of the answer; a longer
// answer is an error, not a truncated success.
func (c *Client) do(ctx context.Context, hc *http.Client, path string, query url.Values, limit int64) (*http.Response, []byte, error) {
	return c.send(ctx, hc, http.MethodGet, path, query, nil, limit)
}

// send makes one request, with a JSON body if there is one, and reads the
// answer as do describes.
func (c *Client) send(ctx context.Context, hc *http.Client, method, path string, query url.Values, body []byte, limit int64) (*http.Response, []byte, error) {
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	var sent io.Reader
	if body != nil {
		sent = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), sent)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The error text is optional: read a little of it and move on.
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, nil, &StatusError{Status: resp.StatusCode, Message: errorMessage(excerpt), ClockDifference: c.clockDifference(resp)}
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: reading the answer: %w", path, err)
	}
	if int64(len(answer)) > limit {
		return nil, nil, fmt.Errorf("%s: the answer is larger than %d bytes", path, limit)
	}
	return resp, answer, nil
}

// errorMessage is the "message" of a step-ca error body, shortened; empty
// when the body is something else.
func errorMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return clip(e.Message)
}

// noRedirect makes a redirect an answer in its own right. The CA's API does
// not redirect, so one is reported as the unexpected status it is.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// onePEMCertificate parses a string that must hold exactly one PEM
// certificate, which is how step-ca sends every certificate in JSON.
func onePEMCertificate(s string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("more than one PEM block where one certificate was expected")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate does not parse: %w", err)
	}
	return cert, nil
}
