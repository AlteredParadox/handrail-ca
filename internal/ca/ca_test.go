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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testPKI is a root, an intermediate and a server certificate for
// 127.0.0.1, shaped like a step-ca deployment.
type testPKI struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
	serverCert  tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	rootKey, root := newCert(t, "Test Root CA", nil, nil, true)
	interKey, inter := newCert(t, "Test Intermediate CA", root, rootKey, true)
	leafKey, leaf := newCert(t, "ca.test", inter, interKey, false)
	return &testPKI{
		root: root, inter: inter, interKey: interKey,
		serverCert: tls.Certificate{Certificate: [][]byte{leaf.Raw, inter.Raw}, PrivateKey: leafKey},
	}
}

func newCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		tmpl.DNSNames = []string{"localhost"}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func pemOf(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// fakeCA is a TLS server with the PKI's server certificate, for a test to
// hang step-ca's routes on.
type fakeCA struct {
	pki  *testPKI
	mux  *http.ServeMux
	srv  *httptest.Server
	hits atomic.Int64
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	f := &fakeCA{pki: newTestPKI(t), mux: http.NewServeMux()}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mux.ServeHTTP(w, r)
	}))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.pki.serverCert}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCA) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{URL: f.srv.URL, RootPEM: []byte(pemOf(f.pki.root)), Timeout: 5 * time.Second, UserAgent: "handrail-ca/test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonRoute(status int, v any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, status, v) }
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one containing %q", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %q, want it to contain %q", err, contains)
	}
}

func TestNewRejectsABadURL(t *testing.T) {
	root := []byte(pemOf(newTestPKI(t).root))
	tests := []struct {
		name, url, want string
	}{
		{"plain http", "http://ca.test:9000", "https://"},
		{"no scheme", "ca.test:9000", "https://"},
		{"no host", "https://", "no host"},
		{"port only", "https://:9000", "no host"},
		{"credentials", "https://user:pw@ca.test", "user or password"},
		{"path", "https://ca.test/ca", "no path"},
		{"query", "https://ca.test/?x=1", "no path"},
		{"unparseable", "https://ca.test:port", "CA URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{URL: tt.url, RootPEM: root})
			wantErr(t, err, tt.want)
		})
	}
}

func TestNewRejectsABadRoot(t *testing.T) {
	pki := newTestPKI(t)
	root := pemOf(pki.root)
	leaf, err := x509.ParseCertificate(pki.serverCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, pem, want string
	}{
		{"empty", "", "no PEM certificate"},
		{"not PEM", "root_ca.crt", "no PEM certificate"},
		{"a key file", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", `"EC PRIVATE KEY" block`},
		{"garbage inside", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "certificate 1 does not parse"},
		{"the server's own certificate", pemOf(leaf), "is not a CA certificate"},
		{"junk after the certificate", root + "-----BEGIN CERTIFICATE-----\ntruncated", "unreadable data after"},
		{"too many", strings.Repeat(root, maxRoots+1), "more than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{URL: "https://ca.test", RootPEM: []byte(tt.pem)})
			wantErr(t, err, "CA root certificate: ")
			wantErr(t, err, tt.want)
		})
	}
}

func TestNewNormalizes(t *testing.T) {
	pki := newTestPKI(t)
	// Text before a certificate, as `openssl x509 -text` writes it, and two
	// roots, as during a root replacement.
	c, err := New(Config{URL: " https://ca.test:9000/ ", RootPEM: []byte("Certificate:\n    Data: ...\n" + pemOf(pki.root) + "\n" + pemOf(pki.inter))})
	if err != nil {
		t.Fatal(err)
	}
	if c.URL() != "https://ca.test:9000" {
		t.Errorf("URL = %q", c.URL())
	}
	if c.http.Timeout != defaultTimeout {
		t.Errorf("timeout = %v, want the default", c.http.Timeout)
	}
	roots := c.TrustedRoots()
	if len(roots) != 2 || !roots[0].Equal(pki.root) || !roots[1].Equal(pki.inter) {
		t.Fatalf("TrustedRoots = %d certificates", len(roots))
	}
	roots[0] = nil // a copy: the client's own list is unaffected
	if c.TrustedRoots()[0] == nil {
		t.Error("TrustedRoots hands out the client's own slice")
	}
	sum := sha256.Sum256(pki.root.Raw)
	if Fingerprint(pki.root) != hex.EncodeToString(sum[:]) {
		t.Errorf("Fingerprint = %q", Fingerprint(pki.root))
	}
}

func TestTrustsOnlyTheConfiguredRoot(t *testing.T) {
	f := newFakeCA(t)
	var agent atomic.Value
	f.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		agent.Store(r.UserAgent())
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	ctx := context.Background()

	c := f.client(t)
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if got := agent.Load(); got != "handrail-ca/test" {
		t.Errorf("User-Agent = %v", got)
	}
	tlsConfig := c.http.Transport.(*http.Transport).TLSClientConfig
	if tlsConfig.InsecureSkipVerify {
		t.Error("the client skips certificate verification")
	}
	want := x509.NewCertPool()
	want.AddCert(f.pki.root)
	if !tlsConfig.RootCAs.Equal(want) {
		t.Error("the client trusts something other than the configured root")
	}

	t.Run("a server of another CA is refused", func(t *testing.T) {
		before := f.hits.Load()
		other, err := New(Config{URL: f.srv.URL, RootPEM: []byte(pemOf(newTestPKI(t).root)), Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		var unknown x509.UnknownAuthorityError
		if err := other.Health(ctx); !errors.As(err, &unknown) {
			t.Fatalf("err = %v, want an unknown-authority error", err)
		}
		if f.hits.Load() != before {
			t.Error("a request reached a server that was not verified")
		}
	})

	t.Run("the right CA under another name is refused", func(t *testing.T) {
		before := f.hits.Load()
		// The same server, reached by an address its certificate does not carry.
		elsewhere, err := New(Config{URL: strings.Replace(f.srv.URL, "127.0.0.1", "127.0.0.2", 1), RootPEM: []byte(pemOf(f.pki.root)), Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if err := elsewhere.Health(ctx); err == nil {
			t.Fatal("accepted a server whose certificate is for another address")
		}
		if f.hits.Load() != before {
			t.Error("a request reached a server that was not verified")
		}
	})
}

func TestUnreachableCA(t *testing.T) {
	f := newFakeCA(t)
	c := f.client(t)
	f.srv.Close()
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("no error from a CA that is not listening")
	}
}

func TestCancelledContext(t *testing.T) {
	f := newFakeCA(t)
	c := f.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Health(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestStatusErrors(t *testing.T) {
	f := newFakeCA(t)
	f.mux.HandleFunc("GET /health", jsonRoute(http.StatusInternalServerError, map[string]any{"status": 500, "message": "database is down"}))
	f.mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	})
	f.mux.HandleFunc("GET /roots", jsonRoute(http.StatusForbidden, map[string]any{"message": strings.Repeat("x", 5000)}))
	f.mux.HandleFunc("GET /intermediates", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.test/intermediates", http.StatusFound)
	})
	c := f.client(t)
	ctx := context.Background()

	var se *StatusError
	err := c.Health(ctx)
	if !errors.As(err, &se) || se.Status != 500 || se.Message != "database is down" {
		t.Errorf("Health: %v", err)
	}
	wantErr(t, err, "the CA answered 500: database is down")

	_, err = c.Version(ctx)
	if !errors.As(err, &se) || se.Status != 502 || se.Message != "" {
		t.Errorf("Version: %v", err)
	}
	wantErr(t, err, "the CA answered 502")

	_, err = c.Roots(ctx)
	if !errors.As(err, &se) || len([]rune(se.Message)) > 300 {
		t.Errorf("Roots: message of %d runes kept", len([]rune(se.Message)))
	}

	// A redirect is not followed: it is an unexpected status.
	_, err = c.Intermediates(ctx)
	if !errors.As(err, &se) || se.Status != http.StatusFound {
		t.Errorf("Intermediates: %v, want a 302 StatusError", err)
	}
}

func TestHealthAndVersion(t *testing.T) {
	f := newFakeCA(t)
	status := "ok"
	version := any(map[string]string{"version": "0.30.2"})
	f.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	})
	f.mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, version)
	})
	c := f.client(t)
	ctx := context.Background()

	if err := c.Health(ctx); err != nil {
		t.Errorf("Health: %v", err)
	}
	if v, err := c.Version(ctx); err != nil || v != "0.30.2" {
		t.Errorf("Version = %q, %v", v, err)
	}

	status = "degraded"
	wantErr(t, c.Health(ctx), `status "degraded"`)
	version = map[string]string{}
	_, err := c.Version(ctx)
	wantErr(t, err, "no version")
	version = []int{1}
	_, err = c.Version(ctx)
	wantErr(t, err, "expected JSON")
}

func TestOversizedAnswer(t *testing.T) {
	f := newFakeCA(t)
	f.mux.HandleFunc("GET /version", jsonRoute(http.StatusOK, map[string]string{"version": strings.Repeat("9", maxJSON)}))
	_, err := f.client(t).Version(context.Background())
	wantErr(t, err, "larger than")
}

func TestRootsAndIntermediates(t *testing.T) {
	f := newFakeCA(t)
	// step-ca answers 201 for both.
	f.mux.HandleFunc("GET /roots", jsonRoute(http.StatusCreated, map[string][]string{"crts": {pemOf(f.pki.root)}}))
	f.mux.HandleFunc("GET /intermediates", jsonRoute(http.StatusCreated, map[string][]string{"crts": {pemOf(f.pki.inter)}}))
	c := f.client(t)
	ctx := context.Background()

	roots, err := c.Roots(ctx)
	if err != nil || len(roots) != 1 || !roots[0].Equal(f.pki.root) {
		t.Fatalf("Roots = %d certificates, %v", len(roots), err)
	}
	inters, err := c.Intermediates(ctx)
	if err != nil || len(inters) != 1 || !inters[0].Equal(f.pki.inter) {
		t.Fatalf("Intermediates = %d certificates, %v", len(inters), err)
	}
}

func TestCertificateListsFailVisibly(t *testing.T) {
	f := newFakeCA(t)
	many := make([]string, maxCertificates+1)
	for i := range many {
		many[i] = pemOf(f.pki.root)
	}
	f.mux.HandleFunc("GET /roots", jsonRoute(http.StatusCreated, map[string][]string{"crts": {pemOf(f.pki.root), "junk"}}))
	f.mux.HandleFunc("GET /intermediates", jsonRoute(http.StatusCreated, map[string][]string{"crts": many}))
	c := f.client(t)

	_, err := c.Roots(context.Background())
	wantErr(t, err, "/roots: entry 2: not a PEM certificate")
	_, err = c.Intermediates(context.Background())
	wantErr(t, err, "more than the")
}

// provisionersJSON is the list as step-ca 0.30.2 sends it for the
// development CA, with the encrypted keys shortened.
const provisionersJSON = `{"provisioners":[
 {"type":"JWK","name":"Admin JWK","key":{"use":"sig","kty":"EC","kid":"Oa1vCqYez46qTaSt1jOGD2oOXdFtqO9M354y43ifbks","crv":"P-256","alg":"ES256","x":"xLzu","y":"Ewo4"},"encryptedKey":"eyJhbGci",
  "claims":{"defaultTLSCertDuration":"5m0s","disableRenewal":false,"allowRenewalAfterExpiry":false,"disableSmallstepExtensions":false},"options":{"x509":{},"ssh":{}}},
 {"type":"JWK","name":"handrail","key":{"use":"sig","kty":"EC","kid":"bV0DLKeg_g9QxXGc3SsJY5LKafxDzsbJkSVKnh2OBWs","crv":"P-256","alg":"ES256","x":"WVlR","y":"xRNM"},"encryptedKey":"eyJhbGci",
  "claims":{"maxTLSCertDuration":"2160h0m0s","enableSSHCA":false,"disableRenewal":false,"allowRenewalAfterExpiry":false,"disableSmallstepExtensions":false},"options":{"x509":{},"ssh":{}}},
 {"type":"ACME","name":"acme","claims":{"enableSSHCA":true,"disableRenewal":true,"allowRenewalAfterExpiry":true,"disableSmallstepExtensions":false},"options":{"x509":{},"ssh":{}}},
 {"type":"OIDC","name":"sso"}
],"nextCursor":""}`

func rawRoute(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestProvisioners(t *testing.T) {
	f := newFakeCA(t)
	f.mux.HandleFunc("GET /provisioners", rawRoute(provisionersJSON))
	got, err := f.client(t).Provisioners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Provisioner{
		{Type: "JWK", Name: "Admin JWK", KeyID: "Oa1vCqYez46qTaSt1jOGD2oOXdFtqO9M354y43ifbks", Claims: Claims{DefaultTLSCertDuration: 5 * time.Minute}},
		{Type: "JWK", Name: "handrail", KeyID: "bV0DLKeg_g9QxXGc3SsJY5LKafxDzsbJkSVKnh2OBWs", Claims: Claims{MaxTLSCertDuration: 2160 * time.Hour}},
		{Type: "ACME", Name: "acme", Claims: Claims{DisableRenewal: true, AllowRenewalAfterExpiry: true}},
		{Type: "OIDC", Name: "sso"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d provisioners, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("provisioner %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestProvisionersFollowsPages(t *testing.T) {
	f := newFakeCA(t)
	pages := map[string]string{
		"":   `{"provisioners":[{"type":"JWK","name":"one"}],"nextCursor":"c1"}`,
		"c1": `{"provisioners":[{"type":"JWK","name":"two"}],"nextCursor":"c2"}`,
		"c2": `{"provisioners":[{"type":"ACME","name":"three"}],"nextCursor":""}`,
	}
	f.mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "100" {
			http.Error(w, "limit", http.StatusBadRequest)
			return
		}
		rawRoute(pages[r.URL.Query().Get("cursor")])(w, r)
	})
	got, err := f.client(t).Provisioners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "one,two,three" {
		t.Errorf("names = %v", names)
	}
}

func TestProvisionersFailVisibly(t *testing.T) {
	tests := []struct {
		name string
		body func(cursor string) string
		want string
	}{
		{"repeated cursor", func(string) string {
			return `{"provisioners":[{"type":"JWK","name":"p"}],"nextCursor":"same"}`
		}, "repeated a page cursor"},
		{"endless pages", func(cursor string) string {
			return `{"provisioners":[],"nextCursor":"` + cursor + `x"}`
		}, "more than"},
		{"bad duration", func(string) string {
			return `{"provisioners":[{"type":"JWK","name":"p","claims":{"maxTLSCertDuration":"a while"}}]}`
		}, `provisioner "p": maxTLSCertDuration "a while" is not a duration`},
		{"negative duration", func(string) string {
			return `{"provisioners":[{"type":"JWK","name":"p","claims":{"minTLSCertDuration":"-5m"}}]}`
		}, "minTLSCertDuration"},
		{"no name", func(string) string {
			return `{"provisioners":[{"type":"JWK"}]}`
		}, "no type or no name"},
		{"wrong shape", func(string) string {
			return `{"provisioners":["JWK"]}`
		}, "expected JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCA(t)
			f.mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, r *http.Request) {
				rawRoute(tt.body(r.URL.Query().Get("cursor")))(w, r)
			})
			_, err := f.client(t).Provisioners(context.Background())
			wantErr(t, err, tt.want)
		})
	}
}

func newCRL(t *testing.T, pki *testPKI, revoked int) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Date(2026, 11, 11, 17, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 11, 12, 17, 0, 0, 0, time.UTC),
	}
	for i := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(int64(1000 + i)),
			RevocationTime: tmpl.ThisUpdate,
			ReasonCode:     1,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, pki.inter, pki.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCRL(t *testing.T) {
	ctx := context.Background()

	t.Run("switched off", func(t *testing.T) {
		f := newFakeCA(t)
		// What step-ca 0.30.2 answers when crl.enabled is not set.
		f.mux.HandleFunc("GET /1.0/crl", jsonRoute(http.StatusNotFound, map[string]any{"status": 404, "message": "The certificate authority received an unexpected HTTP status code - '404'."}))
		crl, err := f.client(t).CRL(ctx)
		if err != nil || crl.Published {
			t.Fatalf("CRL = %+v, %v; want not published", crl, err)
		}
	})

	for _, form := range []string{"DER", "PEM"} {
		t.Run("published as "+form, func(t *testing.T) {
			f := newFakeCA(t)
			body := newCRL(t, f.pki, 2)
			if form == "PEM" {
				body = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: body})
			}
			f.mux.HandleFunc("GET /1.0/crl", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/pkix-crl")
				_, _ = w.Write(body)
			})
			crl, err := f.client(t).CRL(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !crl.Published || crl.Entries != 2 || crl.Issuer != "CN=Test Intermediate CA" {
				t.Errorf("CRL = %+v", crl)
			}
			if !crl.NextUpdate.Equal(time.Date(2026, 11, 12, 17, 0, 0, 0, time.UTC)) || !crl.ThisUpdate.Before(crl.NextUpdate) {
				t.Errorf("updates = %v, %v", crl.ThisUpdate, crl.NextUpdate)
			}
		})
	}

	t.Run("an answer that is not a list is not a yes", func(t *testing.T) {
		f := newFakeCA(t)
		f.mux.HandleFunc("GET /1.0/crl", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>welcome</html>"))
		})
		crl, err := f.client(t).CRL(ctx)
		wantErr(t, err, "not with a revocation list")
		if crl.Published {
			t.Error("Published set alongside an error")
		}
	})

	t.Run("a failure is not a no", func(t *testing.T) {
		f := newFakeCA(t)
		f.mux.HandleFunc("GET /1.0/crl", jsonRoute(http.StatusInternalServerError, map[string]any{"message": "boom"}))
		_, err := f.client(t).CRL(ctx)
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 500 {
			t.Fatalf("err = %v, want a 500 StatusError", err)
		}
	})
}

func TestOnePEMCertificate(t *testing.T) {
	pki := newTestPKI(t)
	if cert, err := onePEMCertificate(pemOf(pki.root)); err != nil || !cert.Equal(pki.root) {
		t.Fatalf("a single certificate: %v", err)
	}
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "not a PEM certificate"},
		{"a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "not a PEM certificate"},
		{"two certificates", pemOf(pki.root) + pemOf(pki.inter), "more than one PEM block"},
		{"garbage inside", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "does not parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := onePEMCertificate(tt.in)
			wantErr(t, err, tt.want)
		})
	}
}

func TestClip(t *testing.T) {
	if got := clip("short"); got != "short" {
		t.Errorf("clip = %q", got)
	}
	long := strings.Repeat("é", 300)
	if got := []rune(clip(long)); len(got) != 257 || got[256] != '…' {
		t.Errorf("clip kept %d runes", len(got))
	}
}
