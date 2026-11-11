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

package ca

// This file holds the one request in handrail-ca that is made before the
// server's certificate can be verified in the usual way, and nothing else.
// It is kept apart so that the exceptions it needs (AGENTS.md,
// sonar-project.properties) cover exactly this and no other code: a test
// (TestOnlyTheRootFetchSkipsVerification) fails if certificate verification
// is switched off anywhere else in the repository.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// fetchRoot asks the CA for the root with the configured fingerprint and
// accepts the answer only if its SHA-256 is that fingerprint.
//
// This is the one request in handrail-ca that cannot verify the server's
// certificate the usual way, because the root that would verify it is what
// is being fetched. It is the exchange `step ca bootstrap` makes, kept at
// the owner's decision (2026-11-11) so that the operator configures a
// fingerprint and not a certificate file. Nothing from it is trusted on
// the server's word:
//
//   - the certificate is authenticated by the operator's fingerprint;
//   - the request carries nothing secret, and its answer is public;
//   - before the root is accepted, the certificate the server presented on
//     this very connection must chain to it for the configured host name,
//     so a server that merely relays the CA's public root is refused.
//
// Every later request goes through a client that trusts that root alone.
// Do not add a second request of this kind (AGENTS.md).
func (c *Client) fetchRoot(ctx context.Context) (*x509.Certificate, error) {
	hc := &http.Client{
		Timeout:       c.timeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				// Verified below, against the fetched root: see above.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   c.timeout,
			ResponseHeaderTimeout: c.timeout,
		},
	}
	defer hc.CloseIdleConnections()

	resp, body, err := c.do(ctx, hc, "/root/"+c.RootFingerprint(), nil, maxJSON)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return nil, fmt.Errorf("the CA at %s has no root with fingerprint %s", c.base.Host, c.RootFingerprint())
		}
		return nil, err
	}
	var answer struct {
		CA string `json:"ca"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("root answer is not the expected JSON: %w", err)
	}
	root, err := onePEMCertificate(answer.CA)
	if err != nil {
		return nil, fmt.Errorf("root answer: %w", err)
	}
	sum := sha256.Sum256(root.Raw)
	if subtle.ConstantTimeCompare(sum[:], c.fingerprint[:]) != 1 {
		return nil, fmt.Errorf("the certificate the CA returned has fingerprint %s, not the configured %s",
			hex.EncodeToString(sum[:]), c.RootFingerprint())
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, errors.New("the connection to the CA presented no certificate")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, cert := range resp.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := resp.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       c.base.Hostname(),
	}); err != nil {
		return nil, fmt.Errorf("the server at %s returned the right root, but its own certificate does not check out against it: %w", c.base.Host, err)
	}
	return root, nil
}
