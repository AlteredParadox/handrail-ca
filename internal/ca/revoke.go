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

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
)

// revokePath is the endpoint, and with the CA's address the audience of a
// revocation token.
const revokePath = "/1.0/revoke"

// maxSerialDigits bounds a serial number. X.509 allows twenty bytes, which
// is 49 decimal digits; the CA's database holds whatever it was given.
const maxSerialDigits = 80

// Revocation is a request to mark a certificate as revoked.
type Revocation struct {
	// Serial is the certificate's serial number in decimal, the form the
	// CA stores it under.
	Serial string
	// ReasonCode is the RFC 5280 reason, 0 to 10.
	ReasonCode int
	// Reason is free text kept in the CA's record.
	Reason string
}

// NotSentError is returned for a request to change something on the CA
// that was never sent: the provisioner's key could not be opened, the CA
// could not be reached, or its certificate was not accepted. It is the one
// kind of failure after which it is certain that the CA did nothing. Any
// other error leaves that open.
type NotSentError struct {
	Err error
}

func (e *NotSentError) Error() string { return e.Err.Error() }
func (e *NotSentError) Unwrap() error { return e.Err }

// neverLeft reports whether a failed request can be said not to have
// reached the CA: no connection was made for it, or the server on the
// other end was not accepted as the CA. A request that failed on an open
// connection, or ran out of time, may have arrived.
func neverLeft(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	var unverified *tls.CertificateVerificationError
	return errors.As(err, &unverified)
}

// Revoke asks the CA to record a certificate as revoked. The CA calls this
// passive revocation: it stops renewing the certificate, and relying
// parties learn of it only from a revocation list, if the CA publishes one.
//
// The request is sent once. An error does not mean nothing happened,
// unless it is a NotSentError: the answer may have been lost on the way
// back, the CA may still be working on a request this client gave up
// waiting for, and a CA that publishes a revocation list can store the
// revocation and then fail to rebuild the list. After any other error the
// caller has to look at the CA's database to learn the outcome, and one
// look that finds nothing does not settle it. The CA does not check that
// the serial was ever issued, so the caller is also the one to know that
// it names a certificate.
func (c *Client) Revoke(ctx context.Context, r Revocation) error {
	request, err := c.revocationRequest(ctx, r)
	if err != nil {
		return &NotSentError{Err: err}
	}
	answer, err := c.postJSON(ctx, revokePath, request, maxJSON)
	if err != nil {
		return err
	}
	var said struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(answer, &said); err != nil || said.Status != "ok" {
		return errors.New("revoke: the CA answered with success, but not with the confirmation it sends for a revocation")
	}
	return nil
}

// revocationRequest checks a revocation and builds the body to send, with
// a token for it.
func (c *Client) revocationRequest(ctx context.Context, r Revocation) (any, error) {
	if c.provisioner == nil {
		return nil, ErrNoProvisioner
	}
	serial, err := decimalSerial(r.Serial)
	if err != nil {
		return nil, err
	}
	if r.ReasonCode < 0 || r.ReasonCode > 10 {
		return nil, fmt.Errorf("revoke: reason code %d is not one of RFC 5280's", r.ReasonCode)
	}
	// The token's subject is the serial, in exactly the form sent beside
	// it: the CA compares the two as strings.
	token, err := c.token(ctx, revokePath, serial, nil)
	if err != nil {
		return nil, err
	}
	return struct {
		Serial     string `json:"serial"`
		OTT        string `json:"ott"`
		ReasonCode int    `json:"reasonCode"`
		Reason     string `json:"reason"`
		Passive    bool   `json:"passive"`
	}{serial, token, r.ReasonCode, r.Reason, true}, nil
}

// decimalSerial checks a serial number and returns it as the CA will read
// it. step-ca parses the field with the base taken from its prefix, so
// "010" would be read as eight; only plain decimal is sent.
func decimalSerial(s string) (string, error) {
	if s == "" || len(s) > maxSerialDigits {
		return "", errors.New("revoke: not a serial number")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", errors.New("revoke: the serial number must be in decimal")
		}
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n.String(), nil
}
