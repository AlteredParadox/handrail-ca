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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// csrPEM makes a certificate signing request from a template, signed with
// a new key of the given kind.
func csrPEM(t *testing.T, kind string, tmpl *x509.CertificateRequest) (string, crypto.Signer) {
	t.Helper()
	key := newKey(t, kind)
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func mustRead(t *testing.T, tmpl *x509.CertificateRequest) *Request {
	t.Helper()
	text, _ := csrPEM(t, "P-256", tmpl)
	r, err := ReadRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReadRequest(t *testing.T) {
	uri, _ := url.Parse("spiffe://internal.example/app")
	tests := []struct {
		name string
		tmpl x509.CertificateRequest
		want Request
	}{
		{
			name: "a common name among its names",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example"}, DNSNames: []string{"git.internal.example", "git"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.14")}},
			want: Request{CommonName: "git.internal.example", DNSNames: []string{"git.internal.example", "git"}, IPAddresses: []string{"10.20.0.14"},
				sans: []string{"git.internal.example", "git", "10.20.0.14"}},
		},
		{
			name: "names and no common name: the first DNS name stands in",
			tmpl: x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.20.0.14")}, DNSNames: []string{"git.internal.example"}},
			want: Request{CommonName: "git.internal.example", CommonNameFromName: true, DNSNames: []string{"git.internal.example"}, IPAddresses: []string{"10.20.0.14"},
				sans: []string{"git.internal.example", "10.20.0.14"}},
		},
		{
			name: "only an address",
			tmpl: x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("2001:db8::1")}},
			want: Request{CommonName: "2001:db8::1", CommonNameFromName: true, IPAddresses: []string{"2001:db8::1"}, sans: []string{"2001:db8::1"}},
		},
		{
			name: "a common name that is not among the names",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "Build server"}, DNSNames: []string{"ci.internal.example"}},
			want: Request{CommonName: "Build server", DNSNames: []string{"ci.internal.example"}, sans: []string{"ci.internal.example"}},
		},
		{
			name: "a common name and no names: it becomes the one name",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example"}},
			want: Request{CommonName: "git.internal.example", NameAdded: true, DNSNames: []string{"git.internal.example"}, sans: []string{"git.internal.example"}},
		},
		{
			name: "a common name that is an address, and no names",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "10.20.0.14"}},
			want: Request{CommonName: "10.20.0.14", NameAdded: true, IPAddresses: []string{"10.20.0.14"}, sans: []string{"10.20.0.14"}},
		},
		{
			name: "more in the subject than a common name",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example", Organization: []string{"Example"}, Country: []string{"DE"}}, DNSNames: []string{"git.internal.example"}},
			want: Request{CommonName: "git.internal.example", DNSNames: []string{"git.internal.example"}, sans: []string{"git.internal.example"},
				SubjectNotCopied: "CN=git.internal.example,O=Example,C=DE"},
		},
		{
			name: "a subject without a common name",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"Example"}}, DNSNames: []string{"git.internal.example"}},
			want: Request{CommonName: "git.internal.example", CommonNameFromName: true, DNSNames: []string{"git.internal.example"}, sans: []string{"git.internal.example"},
				SubjectNotCopied: "O=Example"},
		},
		{
			name: "every kind of name",
			tmpl: x509.CertificateRequest{Subject: pkix.Name{CommonName: "app"}, DNSNames: []string{"app.internal.example"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.1")},
				EmailAddresses: []string{"ops@internal.example"}, URIs: []*url.URL{uri}},
			want: Request{CommonName: "app", DNSNames: []string{"app.internal.example"}, IPAddresses: []string{"10.20.0.1"}, EmailAddresses: []string{"ops@internal.example"},
				URIs: []string{"spiffe://internal.example/app"},
				sans: []string{"app.internal.example", "10.20.0.1", "ops@internal.example", "spiffe://internal.example/app"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, key := csrPEM(t, "P-256", &tt.tmpl)
			got, err := ReadRequest(text)
			if err != nil {
				t.Fatal(err)
			}
			if got.CSR == nil || !reflect.DeepEqual(got.CSR.PublicKey, key.Public()) || got.PEM != text {
				t.Error("the request that was read is not the one given")
			}
			got.CSR, got.PEM = nil, ""
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("read as\n%+v\nwant\n%+v", *got, tt.want)
			}
		})
	}
}

func TestReadRequestAcceptsWhatToolsWrite(t *testing.T) {
	text, _ := csrPEM(t, "P-256", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}})
	for name, form := range map[string]string{
		"space around it":      "\n\n  " + text + "\r\n\n",
		"the older PEM label":  strings.ReplaceAll(text, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"),
		"Windows line endings": strings.ReplaceAll(text, "\n", "\r\n"),
	} {
		got, err := ReadRequest(form)
		if err != nil || got.CommonName != "a.internal.example" {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// What is sent to the CA is the request re-encoded, not the paste.
		if got.PEM != text {
			t.Errorf("%s: sent as %q", name, got.PEM)
		}
	}
	for _, kind := range []string{"P-384", "P-521", "Ed25519", "RSA"} {
		text, _ := csrPEM(t, kind, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}})
		if _, err := ReadRequest(text); err != nil {
			t.Errorf("a request with a %s key: %v", kind, err)
		}
	}
}

func TestReadRequestRefusals(t *testing.T) {
	good, key := csrPEM(t, "P-256", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}})
	block, _ := pem.Decode([]byte(good))
	asPEM := func(kind string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
	}
	altered := append([]byte{}, block.Bytes...)
	altered[len(altered)-1] ^= 0xff

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}}, weakKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	request := func(tmpl x509.CertificateRequest) string {
		text, _ := csrPEM(t, "P-256", &tmpl)
		return text
	}
	var many []string
	for i := 0; i <= maxRequestNames; i++ {
		many = append(many, "h"+strings.Repeat("0", i%7)+string(rune('a'+i%26))+".internal.example")
	}

	tests := []struct {
		name, text, want string
	}{
		{"nothing", "", "not a certificate signing request in PEM"},
		{"not PEM", "git.internal.example", "not a certificate signing request in PEM"},
		{"a certificate", asPEM("CERTIFICATE", block.Bytes), "this is a certificate, not a certificate signing request"},
		{"a private key", asPEM("PRIVATE KEY", keyDER), "this is a private key"},
		{"an EC private key", asPEM("EC PRIVATE KEY", keyDER), "this is a private key"},
		{"another kind of block", asPEM("PUBLIC KEY", block.Bytes), `a PEM block of type "PUBLIC KEY"`},
		{"two requests", good + good, "something after the request"},
		{"a request and words", good + "please sign", "something after the request"},
		{"not a request inside", asPEM("CERTIFICATE REQUEST", []byte("hello")), "does not parse"},
		{"changed after signing", asPEM("CERTIFICATE REQUEST", altered), "signature does not verify"},
		{"a 1024-bit RSA key", asPEM("CERTIFICATE REQUEST", weakDER), "RSA key has 1024 bits"},
		{"no common name and no names", request(x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"Example"}}}), "no common name and no names"},
		{"too large", good + strings.Repeat(" ", maxCSR), "larger than"},
		{"too many names", request(x509.CertificateRequest{DNSNames: many}), "more than the 100"},
		{"a name too long", request(x509.CertificateRequest{DNSNames: []string{strings.Repeat("a", maxRequestName+1)}}), "a name longer than"},
		// Names the CA would sort into another kind than the request has
		// them under: it would refuse, so this says which and why.
		{"a DNS name that is an address", request(x509.CertificateRequest{DNSNames: []string{"10.20.0.14"}}), `the DNS name "10.20.0.14", which the CA would read as another kind of name`},
		{"a DNS name with an @", request(x509.CertificateRequest{DNSNames: []string{"ops@internal.example"}}), `the DNS name "ops@internal.example"`},
		{"an email address with a scheme", request(x509.CertificateRequest{EmailAddresses: []string{"mailto:ops@internal.example"}}), `the email address "mailto:ops@internal.example"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadRequest(tt.text)
			if err == nil || got != nil {
				t.Fatalf("read as %+v, want a refusal", got)
			}
			wantErr(t, err, tt.want)
		})
	}
}

// signings stands in for the CA's /1.0/sign: it checks the token as
// step-ca would, signs with the PKI's intermediate what the token names,
// and records what it was sent.
type signings struct {
	mu     sync.Mutex
	bodies []map[string]string
	claims []map[string]any
	// respond replaces the answer, if set.
	respond func(w http.ResponseWriter, cert *x509.Certificate)
}

func (f *fakeCA) signs(t *testing.T, p testProvisioner) *signings {
	rec := &signings{}
	f.mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": 400, "message": "error reading request body"})
			return
		}
		jws, err := jose.ParseSigned(body["ott"], []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": 401, "message": "no token"})
			return
		}
		payload, err := jws.Verify(p.public.Key)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": 401, "message": "bad token"})
			return
		}
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		rec.mu.Lock()
		rec.bodies, rec.claims = append(rec.bodies, body), append(rec.claims, claims)
		respond := rec.respond
		rec.mu.Unlock()

		block, _ := pem.Decode([]byte(body["csr"]))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": 400, "message": "invalid csr"})
			return
		}
		// The token decides the subject and the names, as on step-ca.
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: claims["sub"].(string)},
			NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		for _, n := range claims["sans"].([]any) {
			if ip := net.ParseIP(n.(string)); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, n.(string))
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.pki.inter, csr.PublicKey, f.pki.interKey)
		if err != nil {
			t.Error(err)
			return
		}
		cert, _ := x509.ParseCertificate(der)
		if respond != nil {
			respond(w, cert)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"crt": pemOf(cert), "ca": pemOf(f.pki.inter), "certChain": []string{pemOf(cert), pemOf(f.pki.inter)}})
	})
	return rec
}

func (rec *signings) sent(t *testing.T, n int) ([]map[string]string, []map[string]any) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.bodies) != n {
		t.Fatalf("the CA was sent %d signing requests, want %d", len(rec.bodies), n)
	}
	return rec.bodies, rec.claims
}

func TestSign(t *testing.T) {
	f := newFakeCA(t)
	p := newTestProvisioner(t, "P-256", "ES256")
	f.lists(p.entry())
	rec := f.signs(t, p)
	now := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	c := f.acting(t, testPassword, func() time.Time { return now })
	ctx := context.Background()

	req := mustRead(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example"}, DNSNames: []string{"git.internal.example", "git"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.14")}})
	issued, err := c.Sign(ctx, req, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert := issued.Certificate
	if cert.Subject.CommonName != "git.internal.example" || !reflect.DeepEqual(cert.DNSNames, []string{"git.internal.example", "git"}) || len(cert.IPAddresses) != 1 {
		t.Errorf("issued: %s %v %v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}
	if !reflect.DeepEqual(cert.PublicKey, req.CSR.PublicKey) || len(issued.Intermediates) != 1 || !issued.Intermediates[0].Equal(f.pki.inter) {
		t.Error("the certificate is not for the request's key, or the chain is not the CA's")
	}

	bodies, claims := rec.sent(t, 1)
	// With no validity asked for, none is sent: the provisioner's default
	// applies.
	if len(bodies[0]) != 2 || bodies[0]["csr"] != req.PEM {
		t.Errorf("request body: %v", bodies[0])
	}
	sum := sha256.Sum256(req.CSR.Raw)
	want := map[string]any{
		"iss": "handrail", "sub": "git.internal.example", "aud": f.srv.URL + "/1.0/sign",
		"sans": []any{"git.internal.example", "git", "10.20.0.14"},
		"cnf":  map[string]any{"x5rt#S256": base64.RawURLEncoding.EncodeToString(sum[:])},
		"iat":  float64(now.Unix()), "nbf": float64(now.Unix()), "exp": float64(now.Add(time.Minute).Unix()),
	}
	got := claims[0]
	id, _ := got["jti"].(string)
	delete(got, "jti")
	if len(id) != 64 || !reflect.DeepEqual(got, want) {
		t.Errorf("token claims:\n%v\nwant\n%v", got, want)
	}

	// A validity is sent as a length, for the CA to count from its clock.
	if _, err := c.Sign(ctx, req, 2160*time.Hour); err != nil {
		t.Fatal(err)
	}
	bodies, claims = rec.sent(t, 2)
	if bodies[1]["notAfter"] != "2160h0m0s" || len(bodies[1]) != 3 {
		t.Errorf("request body with a validity: %v", bodies[1])
	}
	if claims[1]["jti"] == id {
		t.Error("the token's ID was used twice")
	}
}

// What the certificate will carry is what the token says, for each shape
// of request: this is the working-out ReadRequest does, as it is sent.
func TestSignAsksForWhatTheRequestWasReadAs(t *testing.T) {
	for name, tt := range map[string]struct {
		tmpl x509.CertificateRequest
		sub  string
		sans []any
	}{
		"names and no common name":      {x509.CertificateRequest{DNSNames: []string{"a.internal.example"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.1")}}, "a.internal.example", []any{"a.internal.example", "10.20.0.1"}},
		"a common name not among names": {x509.CertificateRequest{Subject: pkix.Name{CommonName: "Build server"}, DNSNames: []string{"ci.internal.example"}}, "Build server", []any{"ci.internal.example"}},
		"a common name and no names":    {x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}}, "a.internal.example", []any{"a.internal.example"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCA(t)
			p := newTestProvisioner(t, "P-256", "")
			f.lists(p.entry())
			rec := f.signs(t, p)
			issued, err := f.acting(t, testPassword, nil).Sign(context.Background(), mustRead(t, &tt.tmpl), 0)
			if err != nil {
				t.Fatal(err)
			}
			_, claims := rec.sent(t, 1)
			if claims[0]["sub"] != tt.sub || !reflect.DeepEqual(claims[0]["sans"], tt.sans) {
				t.Errorf("token: sub %v, sans %v", claims[0]["sub"], claims[0]["sans"])
			}
			if issued.Certificate.Subject.CommonName != tt.sub {
				t.Errorf("issued for %s", issued.Certificate.Subject)
			}
		})
	}
}

// A certificate that comes back is checked before it is believed.
func TestSignChecksWhatComesBack(t *testing.T) {
	other := newTestPKI(t)
	strangerKey, strangerCert := newCert(t, "someone else", nil, nil, false)
	_ = strangerKey
	tests := []struct {
		name    string
		respond func(f *fakeCA) func(w http.ResponseWriter, cert *x509.Certificate)
		want    string
	}{
		{"a certificate for another key", func(f *fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, _ *x509.Certificate) {
				_, another := newCert(t, "git.internal.example", f.pki.inter, f.pki.interKey, false)
				writeJSON(w, http.StatusCreated, map[string]any{"crt": pemOf(another), "ca": pemOf(f.pki.inter), "certChain": []string{pemOf(another), pemOf(f.pki.inter)}})
			}
		}, "for another key than the request's"},
		{"a chain that is not the CA's", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, cert *x509.Certificate) {
				writeJSON(w, http.StatusCreated, map[string]any{"crt": pemOf(cert), "ca": pemOf(other.inter), "certChain": []string{pemOf(cert), pemOf(other.inter)}})
			}
		}, "does not chain to its root"},
		{"no intermediate", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, cert *x509.Certificate) {
				writeJSON(w, http.StatusCreated, map[string]any{"crt": pemOf(cert)})
			}
		}, "does not chain to its root"},
		{"a self-signed certificate", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, _ *x509.Certificate) {
				writeJSON(w, http.StatusCreated, map[string]any{"crt": pemOf(strangerCert), "certChain": []string{pemOf(strangerCert)}})
			}
		}, "for another key than the request's"},
		{"not certificates", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, _ *x509.Certificate) {
				writeJSON(w, http.StatusCreated, map[string]any{"crt": "hello", "certChain": []string{"hello"}})
			}
		}, "certificate 1 of the CA's answer"},
		{"no certificate at all", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, _ *x509.Certificate) { writeJSON(w, http.StatusCreated, map[string]any{}) }
		}, "certificate 1 of the CA's answer"},
		{"not JSON", func(*fakeCA) func(http.ResponseWriter, *x509.Certificate) {
			return func(w http.ResponseWriter, _ *x509.Certificate) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("<html>"))
			}
		}, "not the expected JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCA(t)
			p := newTestProvisioner(t, "P-256", "")
			f.lists(p.entry())
			rec := f.signs(t, p)
			rec.respond = tt.respond(f)
			issued, err := f.acting(t, testPassword, nil).Sign(context.Background(),
				mustRead(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example"}}), 0)
			if issued != nil {
				t.Error("a certificate was returned")
			}
			wantErr(t, err, tt.want)
			// The CA did sign something: this is not "never sent".
			var notSent *NotSentError
			if errors.As(err, &notSent) {
				t.Error("the error says nothing was sent")
			}
			rec.sent(t, 1)
		})
	}
}

func TestSignFailures(t *testing.T) {
	ctx := context.Background()
	req := mustRead(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "git.internal.example"}})
	notSent := func(err error) bool {
		var e *NotSentError
		return errors.As(err, &e)
	}

	t.Run("the CA refuses", func(t *testing.T) {
		f := newFakeCA(t)
		p := newTestProvisioner(t, "P-256", "")
		f.lists(p.entry())
		rec := f.signs(t, p)
		rec.respond = func(w http.ResponseWriter, _ *x509.Certificate) {
			writeJSON(w, http.StatusForbidden, map[string]any{"status": 403, "message": `The request was forbidden by the certificate authority: dns name "git.internal.example" not allowed`})
		}
		_, err := f.acting(t, testPassword, nil).Sign(ctx, req, 0)
		var refused *StatusError
		if !errors.As(err, &refused) || refused.Status != 403 || !strings.Contains(refused.Message, "not allowed") || notSent(err) {
			t.Errorf("err = %#v", err)
		}
		bodies, _ := rec.sent(t, 1)
		if strings.Contains(err.Error(), bodies[0]["ott"]) {
			t.Error("the error carries the token")
		}
	})
	t.Run("read-only", func(t *testing.T) {
		f := newFakeCA(t)
		if _, err := f.client(t).Sign(ctx, req, 0); !errors.Is(err, ErrNoProvisioner) || !notSent(err) {
			t.Errorf("err = %#v", err)
		}
	})
	t.Run("the key cannot be opened", func(t *testing.T) {
		f := newFakeCA(t)
		p := newTestProvisioner(t, "P-256", "")
		f.lists(p.entry())
		rec := f.signs(t, p)
		if _, err := f.acting(t, "not the password", nil).Sign(ctx, req, 0); !notSent(err) {
			t.Errorf("err = %#v", err)
		}
		rec.sent(t, 0)
	})
	t.Run("not something to send", func(t *testing.T) {
		f := newFakeCA(t)
		p := newTestProvisioner(t, "P-256", "")
		f.lists(p.entry())
		rec := f.signs(t, p)
		c := f.acting(t, testPassword, nil)
		for name, tt := range map[string]struct {
			r *Request
			d time.Duration
		}{
			"no request":                    {nil, 0},
			"a request that was never read": {&Request{CSR: req.CSR, CommonName: "git.internal.example"}, 0},
			"a negative validity":           {req, -time.Hour},
		} {
			if _, err := c.Sign(ctx, tt.r, tt.d); !notSent(err) {
				t.Errorf("%s: err = %#v", name, err)
			}
		}
		rec.sent(t, 0)
	})
}

// The request's own extensions are sent as they are; what the CA makes of
// them is the CA's business. This only pins that reading a request does
// not drop or rewrite it.
func TestReadRequestKeepsTheRequestWhole(t *testing.T) {
	text, _ := csrPEM(t, "P-256", &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "git.internal.example"}, DNSNames: []string{"git.internal.example"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}},
	})
	r, err := ReadRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(r.PEM))
	if string(block.Bytes) != string(r.CSR.Raw) || r.PEM != text {
		t.Error("the request to be sent is not the request that was read")
	}
}
