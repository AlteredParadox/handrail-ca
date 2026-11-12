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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// signPath is the endpoint, and with the CA's address the audience of a
// signing token.
const signPath = "/1.0/sign"

const (
	// maxCSR bounds a certificate request in PEM. An RSA-4096 request with
	// a hundred names is under 8 KiB.
	maxCSR = 32 << 10
	// maxRequestNames bounds the names in one request, and maxRequestName
	// each of them: they all go into the token.
	maxRequestNames = 100
	maxRequestName  = 512
	// minRSABits is the smallest RSA key step-ca signs for.
	minRSABits = 2048
	// maxSigned bounds the answer to a signing request: a certificate and
	// its chain.
	maxSigned = 256 << 10
)

// Request is a certificate signing request that has been read and checked,
// together with what the CA will be asked to put in the certificate.
//
// The two are not the same thing. With step-ca's default template a JWK
// provisioner's certificate takes its common name and its names from the
// token, not from the request, and its subject is the common name alone
// (checked on step-ca 0.30.2; docs/PLAN.md, section 3). So the token
// handrail-ca signs decides what the certificate says, and this is the one
// place that works it out: the page shows these fields, and Sign sends
// them.
type Request struct {
	CSR *x509.CertificateRequest
	// PEM is the request as it will be sent.
	PEM string

	// CommonName is the common name the certificate will carry. It is the
	// request's own, or, for a request without one, its first name: the CA
	// wants a subject for the token, and puts it in the certificate.
	CommonName string
	// CommonNameFromName says CommonName was taken from the names because
	// the request has no common name.
	CommonNameFromName bool

	// The names the certificate will carry, as the CA will read them.
	DNSNames, IPAddresses, EmailAddresses, URIs []string
	// NameAdded says the request lists no names, and the certificate gets
	// its common name as its one name.
	NameAdded bool

	// SubjectNotCopied is the request's whole subject when it holds more
	// than a common name: the rest is not copied into the certificate.
	SubjectNotCopied string

	// sans is what goes into the token.
	sans []string
}

// ErrPrivateKey is returned by ReadRequest for a private key pasted where
// a request belongs. The caller should not show it back or keep it.
var ErrPrivateKey = errors.New("this is a private key, not a certificate signing request. It should never be pasted anywhere: treat it as exposed, and make a new one")

// ReadRequest reads one PEM certificate signing request and checks that it
// is one handrail-ca will ask the CA to sign. The errors are for the
// person who pasted it.
func ReadRequest(pemText string) (*Request, error) {
	if len(pemText) > maxCSR {
		return nil, fmt.Errorf("the request is larger than %d bytes", maxCSR)
	}
	// Before anything else, and whether or not it is well formed: a
	// private key is recognised by its label alone.
	if strings.Contains(pemText, "PRIVATE KEY-----") {
		return nil, ErrPrivateKey
	}
	// A paste often brings blank lines and indentation with it.
	block, rest := pem.Decode([]byte(strings.TrimSpace(pemText)))
	switch {
	case block == nil:
		return nil, errors.New("this is not a certificate signing request in PEM: it should begin with -----BEGIN CERTIFICATE REQUEST-----")
	case block.Type == "CERTIFICATE":
		return nil, errors.New("this is a certificate, not a certificate signing request")
	case block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST":
		return nil, fmt.Errorf("this is a PEM block of type %q, not a certificate signing request", clip(block.Type))
	case strings.TrimSpace(string(rest)) != "":
		return nil, errors.New("there is something after the request: paste one certificate signing request and nothing else")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the request does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("the request's signature does not verify: it was not signed with the key it carries, or it was changed afterwards")
	}
	if err := checkRequestKey(csr.PublicKey); err != nil {
		return nil, err
	}

	r := &Request{CSR: csr, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}))}
	names := requestNames(csr)
	if len(names) > maxRequestNames {
		return nil, fmt.Errorf("the request has %d names, more than the %d handrail-ca asks for in one certificate", len(names), maxRequestNames)
	}
	for _, n := range append([]string{csr.Subject.CommonName}, names...) {
		if len(n) > maxRequestName {
			return nil, fmt.Errorf("the request has a name longer than %d bytes", maxRequestName)
		}
	}
	switch {
	case csr.Subject.CommonName != "":
		r.CommonName = csr.Subject.CommonName
	case len(names) > 0:
		r.CommonName, r.CommonNameFromName = names[0], true
	default:
		return nil, errors.New("the request has no common name and no names: there is nothing to issue a certificate for")
	}
	r.sans = names
	if len(names) == 0 {
		r.sans, r.NameAdded = []string{r.CommonName}, true
	}
	// The CA sorts the token's names into kinds by what each looks like.
	// What it will make of them has to be the request's own names, or it
	// refuses; say so here, by name, when it would.
	r.DNSNames, r.IPAddresses, r.EmailAddresses, r.URIs = splitNames(r.sans)
	if !r.NameAdded {
		if err := sameNames(csr, r); err != nil {
			return nil, err
		}
	}
	if whole := csr.Subject.String(); whole != (nameOnly(csr.Subject.CommonName)) {
		r.SubjectNotCopied = clip(whole)
	}
	return r, nil
}

// NewRequest makes a certificate signing request for a key, with a common
// name and names typed by a person, and reads it back as ReadRequest
// would: what comes out is checked like any pasted request, and says what
// the certificate will carry. Each name is put in the request as the kind
// the CA will take it for (see splitNames), so the two agree. The common
// name may be empty if there are names.
func NewRequest(key crypto.Signer, commonName string, names []string) (*Request, error) {
	if len(names) > maxRequestNames {
		return nil, fmt.Errorf("%d names, more than the %d handrail-ca asks for in one certificate", len(names), maxRequestNames)
	}
	tmpl := &x509.CertificateRequest{}
	tmpl.Subject.CommonName = commonName
	dns, ips, emails, uris := splitNames(names)
	tmpl.DNSNames, tmpl.EmailAddresses = dns, emails
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("the name %q is not a URI", clip(u))
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("the request could not be made: %v", err)
	}
	return ReadRequest(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
}

// nameOnly is how a subject holding only this common name prints.
func nameOnly(cn string) string {
	if cn == "" {
		return ""
	}
	var csr x509.CertificateRequest
	csr.Subject.CommonName = cn
	return csr.Subject.String()
}

func checkRequestKey(key any) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return fmt.Errorf("the request's RSA key has %d bits: the CA signs for %d or more", k.N.BitLen(), minRSABits)
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errors.New("the request's key is of a kind the CA does not sign for: it takes RSA, ECDSA and Ed25519 keys")
	}
	return nil
}

// requestNames are a request's subject alternative names as strings, in
// the order a subject is taken from them: DNS names, IP addresses, email
// addresses, URIs.
func requestNames(csr *x509.CertificateRequest) []string {
	names := append([]string{}, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		names = append(names, u.String())
	}
	return names
}

// splitNames sorts names into kinds the way step-ca does with the names
// in a token (x509util.SplitSANs in go.step.sm/crypto): an IP address if
// it parses as one, a URI if it has a scheme, an email address if it has
// an @, and a DNS name otherwise.
func splitNames(names []string) (dns, ips, emails, uris []string) {
	for _, n := range names {
		if n == "" {
			continue
		}
		u, err := url.Parse(n)
		switch {
		case net.ParseIP(n) != nil:
			ips = append(ips, net.ParseIP(n).String())
		case err == nil && u.Scheme != "":
			uris = append(uris, u.String())
		case strings.Contains(n, "@"):
			emails = append(emails, n)
		default:
			dns = append(dns, n)
		}
	}
	return dns, ips, emails, uris
}

// sameNames checks that the CA will read the token's names as the names
// the request has, kind by kind.
func sameNames(csr *x509.CertificateRequest, r *Request) error {
	var wantIPs, wantURIs []string
	for _, ip := range csr.IPAddresses {
		wantIPs = append(wantIPs, ip.String())
	}
	for _, u := range csr.URIs {
		wantURIs = append(wantURIs, u.String())
	}
	for _, kind := range []struct {
		what      string
		want, got []string
	}{
		{"DNS name", csr.DNSNames, r.DNSNames},
		{"IP address", wantIPs, r.IPAddresses},
		{"email address", csr.EmailAddresses, r.EmailAddresses},
		{"URI", wantURIs, r.URIs},
	} {
		read := map[string]bool{}
		for _, n := range kind.got {
			read[n] = true
		}
		for _, n := range kind.want {
			if !read[n] {
				return fmt.Errorf("the request has the %s %q, which the CA would read as another kind of name and then refuse", kind.what, clip(n))
			}
		}
	}
	return nil
}

// Issued is a certificate the CA signed.
type Issued struct {
	Certificate *x509.Certificate
	// Intermediates are the certificates between it and the CA's root, as
	// the CA sent them.
	Intermediates []*x509.Certificate
}

// Sign asks the CA to sign a request. validity is how long the certificate
// is to be valid from now; zero leaves it to the provisioner's default.
//
// The token names exactly what Request says the certificate will carry,
// and is bound to this one request by its fingerprint, so it is of no use
// with another. The certificate that comes back is checked before it is
// returned: it must be for the request's key and chain to the CA's root.
//
// As with Revoke, the request is sent once, and an error other than a
// NotSentError does not mean no certificate was issued: the answer may
// have been lost, or the CA may still be at work. The caller looks at the
// CA's database before asking again.
func (c *Client) Sign(ctx context.Context, r *Request, validity time.Duration) (*Issued, error) {
	body, err := c.signRequest(ctx, r, validity)
	if err != nil {
		return nil, &NotSentError{Err: err}
	}
	answer, err := c.postJSON(ctx, signPath, body, maxSigned)
	if err != nil {
		return nil, err
	}
	issued, err := readSigned(answer)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(issued.Certificate.RawSubjectPublicKeyInfo, r.CSR.RawSubjectPublicKeyInfo) {
		return nil, errors.New("sign: the CA answered with a certificate for another key than the request's")
	}
	root, err := c.Root(ctx)
	if err != nil {
		return nil, err
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, cert := range issued.Intermediates {
		inters.AddCert(cert)
	}
	// Verified as of now, by our clock, moved into the certificate's own
	// validity if it lies outside: the CA dates a certificate by its
	// clock, which may be a little off ours, and it is the chain that is
	// being checked here, not the clocks.
	at := c.now()
	if at.Before(issued.Certificate.NotBefore) {
		at = issued.Certificate.NotBefore
	}
	if at.After(issued.Certificate.NotAfter) {
		at = issued.Certificate.NotAfter
	}
	if _, err := issued.Certificate.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("sign: the CA answered with a certificate that does not chain to its root: %w", err)
	}
	return issued, nil
}

// signRequest builds the body of a signing request, with a token for it.
func (c *Client) signRequest(ctx context.Context, r *Request, validity time.Duration) (any, error) {
	if c.provisioner == nil {
		return nil, ErrNoProvisioner
	}
	if r == nil || r.CSR == nil || r.CommonName == "" || len(r.sans) == 0 {
		return nil, errors.New("sign: not a request that was read by ReadRequest")
	}
	if validity < 0 {
		return nil, errors.New("sign: a validity cannot be negative")
	}
	fingerprint := sha256.Sum256(r.CSR.Raw)
	token, err := c.token(ctx, signPath, r.CommonName, map[string]any{
		"sans": r.sans,
		// Binds the token to this request: the CA refuses it for any other.
		"cnf": map[string]string{"x5rt#S256": base64.RawURLEncoding.EncodeToString(fingerprint[:])},
	})
	if err != nil {
		return nil, err
	}
	body := map[string]string{"csr": r.PEM, "ott": token}
	if validity > 0 {
		// A length, not a moment: the CA counts it from its own clock.
		body["notAfter"] = validity.String()
	}
	return body, nil
}

// readSigned reads the CA's answer to a signing request.
func readSigned(answer []byte) (*Issued, error) {
	var said struct {
		Certificate string   `json:"crt"`
		CA          string   `json:"ca"`
		Chain       []string `json:"certChain"`
	}
	if err := json.Unmarshal(answer, &said); err != nil {
		return nil, fmt.Errorf("sign: the CA's answer is not the expected JSON: %w", err)
	}
	chain := said.Chain
	if len(chain) == 0 {
		chain = []string{said.Certificate}
		if said.CA != "" {
			chain = append(chain, said.CA)
		}
	}
	if len(chain) > maxCertificates {
		return nil, fmt.Errorf("sign: the CA answered with %d certificates", len(chain))
	}
	var certs []*x509.Certificate
	for i, s := range chain {
		cert, err := onePEMCertificate(s)
		if err != nil {
			return nil, fmt.Errorf("sign: certificate %d of the CA's answer: %w", i+1, err)
		}
		certs = append(certs, cert)
	}
	return &Issued{Certificate: certs[0], Intermediates: certs[1:]}, nil
}
