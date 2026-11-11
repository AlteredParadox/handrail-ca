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
// the connection: the operator supplies the CA's root certificate, and that
// certificate is the only trust anchor for every request. Nothing is fetched
// before the CA has been verified. The response shapes were captured from
// step-ca 0.30.2 (see docs/PLAN.md, section 3).
package ca

import (
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
	"time"
)

const (
	// maxJSON bounds every JSON answer. A page of 100 provisioners with
	// their encrypted keys is about 100 KiB.
	maxJSON = 1 << 20
	// maxRoots bounds the configured trust anchors: one, or two while the
	// CA's root is being replaced.
	maxRoots = 4

	defaultTimeout = 10 * time.Second
)

// Config is what the client needs to know about the CA.
type Config struct {
	// URL is the CA's address, https://host[:port] with no path.
	URL string
	// RootPEM is the CA's root certificate in PEM, the content of
	// `$(step path)/certs/root_ca.crt` on the CA's host. More than one
	// certificate is accepted, for a CA that is replacing its root.
	RootPEM []byte
	// Timeout bounds each request. Zero means ten seconds.
	Timeout time.Duration
	// UserAgent is sent with every request, if set.
	UserAgent string
}

// Client talks to one step-ca. It is safe for concurrent use. Creating it
// makes no connection, so handrail-ca can start, and say so, while the CA is
// down.
type Client struct {
	base      *url.URL
	roots     []*x509.Certificate
	userAgent string
	http      *http.Client
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

	roots, err := parseRoots(cfg.RootPEM)
	if err != nil {
		return nil, fmt.Errorf("CA root certificate: %w", err)
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		base:      base,
		roots:     roots,
		userAgent: cfg.UserAgent,
		http: &http.Client{
			Timeout:       timeout,
			CheckRedirect: noRedirect,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
				MaxIdleConns:          4,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}, nil
}

// parseRoots reads the configured trust anchors: PEM certificates and
// nothing else, each of them a CA certificate. Handing over a server
// certificate or a key file by mistake is refused here, not discovered
// later as a failed connection.
func parseRoots(data []byte) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("found a PEM %q block; only certificates belong in this file", clip(block.Type))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d does not parse: %w", len(roots)+1, err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate %d (%s) is not a CA certificate", len(roots)+1, clip(cert.Subject.String()))
		}
		roots = append(roots, cert)
		if len(roots) > maxRoots {
			return nil, fmt.Errorf("more than %d certificates", maxRoots)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("no PEM certificate found (want the content of root_ca.crt)")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("unreadable data after the last certificate")
	}
	return roots, nil
}

// URL is the CA's address as configured.
func (c *Client) URL() string { return c.base.String() }

// TrustedRoots are the configured root certificates, the only ones the
// connection to the CA is verified against.
func (c *Client) TrustedRoots() []*x509.Certificate {
	return append([]*x509.Certificate(nil), c.roots...)
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
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the CA answered %d", e.Status)
	}
	return fmt.Sprintf("the CA answered %d: %s", e.Status, e.Message)
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

// get fetches a path from the CA and reads at most limit bytes of the
// answer; a longer answer is an error, not a truncated success. Any 2xx is
// a success: step-ca answers 201 for some plain reads.
func (c *Client) get(ctx context.Context, path string, query url.Values, limit int64) ([]byte, error) {
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The error text is optional: read a little of it and move on.
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, &StatusError{Status: resp.StatusCode, Message: errorMessage(excerpt)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: reading the answer: %w", path, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: the answer is larger than %d bytes", path, limit)
	}
	return body, nil
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
