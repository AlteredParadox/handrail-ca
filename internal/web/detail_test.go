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

package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/inventory"
)

// issuer is a CA certificate with its key, for signing test certificates.
type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIssuer(t *testing.T, cn string) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(3, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issuer{cert: cert, key: key}
}

// issue signs a certificate from a template and returns it as the CA
// would store it.
func (i issuer) issue(t *testing.T, tmpl *x509.Certificate, pub any) inventory.RawCertificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.cert, pub, i.key)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.RawCertificate{Serial: tmpl.SerialNumber.String(), DER: der, Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`)}
}

// addRows puts rows into the site's database and has the inventory read it.
func (s *site) addRows(rows ...inventory.RawCertificate) {
	s.t.Helper()
	s.rows.mu.Lock()
	s.rows.certs = append(s.rows.certs, rows...)
	s.rows.mu.Unlock()
	if err := s.inv.Refresh(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

// siteWithIssued is a site whose CA's intermediate issued one certificate
// that says a good deal about itself: serial 0x1a2b3c4d5e6f.
func siteWithIssued(t *testing.T, publicURL string) (*site, []byte) {
	t.Helper()
	s := newSite(t, publicURL)
	inter := newIssuer(t, "Example Intermediate CA")
	s.ca.inter = inter.cert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://internal.example/app")
	row := inter.issue(t, &x509.Certificate{
		SerialNumber:   big.NewInt(0x1a2b3c4d5e6f),
		Subject:        pkix.Name{CommonName: "app.internal.example", Organization: []string{"Example <Org>"}},
		DNSNames:       []string{"app.internal.example", "app"},
		IPAddresses:    []net.IP{net.ParseIP("10.20.0.7"), net.ParseIP("fd00::7")},
		EmailAddresses: []string{"ops@internal.example"},
		URIs:           []*url.URL{uri},
		NotBefore:      t0.Add(-3 * 24 * time.Hour), NotAfter: t0.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, &key.PublicKey)
	s.addRows(row)
	return s, row.DER
}

const issuedSerial = "28772997619311" // 0x1a2b3c4d5e6f

func TestDetailPage(t *testing.T) {
	s, der := siteWithIssued(t, "http://127.0.0.1:8080")
	sum := sha256.Sum256(der)

	// Not without a session.
	wantRedirect(t, s.browser().get("/certificates/"+issuedSerial), "/sign-in")

	// A viewer may look.
	b := s.browser()
	b.signIn("bob", bobPassword)
	page := b.get("/certificates/" + issuedSerial)
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"<h1>app.internal.example</h1>", `<span class="badge warn">Expiring</span>`,
		"Expires in 24 hours, on 2026-11-12 at 12:00 UTC. Issued by the handrail provisioner.",
		// The subject is the certificate's own text: escaped.
		`CN=app.internal.example,O=Example \&lt;Org\&gt;`,
		"DNS names", ">app<", "IP addresses", "10.20.0.7", "fd00::7", "Email addresses", "ops@internal.example", "URIs", "spiffe://internal.example/app",
		"2026-11-08 12:00 UTC", "2026-11-12 12:00 UTC", "4 days, 3 days used", `<progress max="345600" value="259200"`,
		"Example Intermediate CA", "1a2b 3c4d 5e6f", issuedSerial,
		"RSA 2048 bits", "ECDSA-SHA256", "Digital signature, Key encipherment", "Server authentication, Client authentication",
		"Subject alternative name", "2.5.29.17", "Authority key identifier",
		`<span class="badge ok">Not revoked</span>`, "The CA has no revocation record for this certificate, as of 0 seconds ago.",
		"-----BEGIN CERTIFICATE-----", grouped(hex.EncodeToString(sum[:])),
		`href="/certificates/`+issuedSerial+`/pem"`, `href="/certificates/`+issuedSerial+`/chain"`, `href="/certificates/`+issuedSerial+`/der"`,
	)
	if strings.Contains(page.Body.String(), "<Org>") {
		t.Error("the subject is on the page unescaped")
	}
	if strings.Contains(page.Body.String(), "<script") || strings.Contains(page.Body.String(), "style=") {
		t.Error("the page has inline script or style, which its own policy forbids")
	}

	// The list leads here.
	wantBody(t, b.get("/"), `<a class="strong" href="/certificates/`+issuedSerial+`">app.internal.example</a>`)
}

func TestDetailOfEachStatus(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)

	valid := b.get("/certificates/101")
	wantStatus(t, valid, http.StatusOK)
	wantBody(t, valid, `<span class="badge ok">Valid</span>`, "Expires in 3 months, on 2027-02-09 at 12:00 UTC.", "ECDSA P-256")

	expired := b.get("/certificates/102")
	wantBody(t, expired, `<span class="badge unknown">Expired</span>`, "Expired 24 hours ago, on 2026-11-10 at 12:00 UTC.", "all used")

	revoked := b.get("/certificates/103")
	wantBody(t, revoked, `<span class="badge bad">Revoked</span>`, "Revoked on 2026-11-11. It would have expired on 2027-02-09.",
		"2026-11-11 08:00 UTC", "Key compromise", "With a provisioner&#39;s token", "The CA will not renew a revoked certificate, but it will issue a new one for the same names")
	if strings.Contains(revoked.Body.String(), "Not revoked") {
		t.Error("a revoked certificate's page says it is not revoked")
	}

	// A row that is not a certificate has a page that says so, and nothing
	// to download.
	unreadable := b.get("/certificates/104")
	wantStatus(t, unreadable, http.StatusOK)
	wantBody(t, unreadable, "<h1>Serial 104</h1>", `<span class="badge bad">Unreadable</span>`, "This row is not a certificate")
	for _, absent := range []string{"Download", "BEGIN CERTIFICATE", "Subject and names"} {
		if strings.Contains(unreadable.Body.String(), absent) {
			t.Errorf("an unreadable row's page shows %q", absent)
		}
	}
	for _, form := range []string{"pem", "der", "chain"} {
		wantStatus(t, b.get("/certificates/104/"+form), http.StatusNotFound)
	}

	// No such certificate, and nothing that is not a serial's page.
	for _, path := range []string{"/certificates/999", "/certificates/", "/certificates", "/certificates/101/pem/extra", "/certificates/101/key", "/certificates/..%2f..%2fstatus"} {
		if got := b.get(path); got.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, got.Code)
		}
	}

	// A certificate not yet valid.
	s.addRows(leafRow(t, 105, "soon.internal.example", t0.Add(time.Hour), t0.Add(48*time.Hour)))
	wantBody(t, b.get("/certificates/105"), "Not valid until 2026-11-11 at 13:00 UTC.", "not started")
}

// A row that is not a certificate can have any key. Its page is found by
// that key, whatever is shown for it; a key that cannot be put in an
// address has no link, not a link that leads nowhere.
func TestUnreadableRowsWithOddKeysHaveTheirPages(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	junk := []byte("not a certificate")
	long := strings.Repeat("9", 65) // one digit too many for a serial
	odd := "odd/key ?#%\xff"
	s.addRows(
		inventory.RawCertificate{Serial: long, DER: junk},
		inventory.RawCertificate{Serial: odd, DER: junk},
		inventory.RawCertificate{Serial: "..", DER: junk},
		inventory.RawCertificate{Serial: strings.Repeat("7", maxKeyInAddress+1), DER: junk},
	)
	b := signedIn(t, s)
	list := b.get("/?view=unreadable")
	wantStatus(t, list, http.StatusOK)
	// Five rows that are not certificates: these four and the site's own.
	if got := strings.Count(list.Body.String(), "could not be read as a certificate"); got != 5 {
		t.Fatalf("%d unreadable rows in the list, want 5", got)
	}
	links := regexp.MustCompile(`<a href="([^"]+)">What is known of it</a>`).FindAllStringSubmatch(list.Body.String(), -1)
	if len(links) != 3 {
		t.Fatalf("%d of the rows have a link, want 3: the two keys that fit no address have none", len(links))
	}
	for _, link := range links {
		page := b.get(html.UnescapeString(link[1]))
		wantStatus(t, page, http.StatusOK)
		wantBody(t, page, "This row is not a certificate")
	}
	// The long key is shown shortened, and found whole.
	wantBody(t, list, `href="/certificates/`+long+`"`)
	wantBody(t, b.get("/certificates/"+long), "<dd class=\"mono small\">"+long[:64]+"…</dd>")
	// The shortened form is nobody's address.
	wantStatus(t, b.get("/certificates/"+url.PathEscape(long[:64]+"…")), http.StatusNotFound)
}

func TestDetailWhenTheRowHasChanged(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	paths := []string{"/certificates/101", "/certificates/101/pem", "/certificates/101/der", "/certificates/101/chain"}

	// Another certificate under the same serial since the list was read.
	s.rows.mu.Lock()
	kept := s.rows.certs[0]
	s.rows.certs[0].DER = s.rows.certs[1].DER
	s.rows.mu.Unlock()
	for _, path := range paths {
		got := b.get(path)
		wantStatus(t, got, http.StatusBadGateway)
		wantBody(t, got, "is not the certificate that was listed")
	}

	// The row gone.
	s.rows.mu.Lock()
	s.rows.certs = s.rows.certs[1:]
	s.rows.mu.Unlock()
	for _, path := range paths {
		wantStatus(t, b.get(path), http.StatusNotFound)
	}

	// The database not answering: an error, said plainly, with the cause
	// in the log and not on the page.
	s.rows.mu.Lock()
	s.rows.certs = append([]inventory.RawCertificate{kept}, s.rows.certs...)
	s.rows.mu.Unlock()
	s.rows.fail(errors.New("dial tcp 10.9.8.7:5432: connection refused"))
	for _, path := range paths {
		got := b.get(path)
		wantStatus(t, got, http.StatusBadGateway)
		wantBody(t, got, "could not be read from the CA&#39;s database just now")
		if strings.Contains(got.Body.String(), "10.9.8.7") {
			t.Errorf("GET %s shows the database's address", path)
		}
	}
	if !strings.Contains(s.log.String(), "10.9.8.7:5432: connection refused") {
		t.Error("the log does not say why the certificate could not be read")
	}
}

// When the last read of the CA's database failed, the page is an old
// picture and says so: a certificate that was not revoked then is not
// called "not revoked" now.
func TestDetailWhenTheInventoryIsStale(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	fresh := b.get("/certificates/101")
	wantBody(t, fresh, `<span class="badge ok">Not revoked</span>`)
	if strings.Contains(fresh.Body.String(), `class="stale"`) {
		t.Error("a page from a current picture carries the stale notice")
	}

	// A read fails, ten minutes on; the certificate itself can still be
	// fetched afterwards.
	s.clock.advance(10 * time.Minute)
	s.rows.fail(errors.New("reading revocations: connection reset by peer"))
	if err := s.inv.Refresh(context.Background()); err == nil {
		t.Fatal("the refresh succeeded against a failing source")
	}
	s.rows.fail(nil)

	page := b.get("/certificates/101")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `class="stale"`, "This page is as the CA's database was 10 minutes ago", "If this certificate has been revoked since then, that is not shown here.",
		"connection reset by peer", `<span class="badge warn">Not revoked 10 minutes ago</span>`, "a revocation after that would not show here")
	for _, absent := range []string{`<span class="badge ok">Not revoked</span>`, "The CA has no revocation record for this certificate"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("a page from an old picture says %q", absent)
		}
	}
	// A revoked certificate stays revoked, with the same notice; so does
	// the page of a row that is not a certificate.
	wantBody(t, b.get("/certificates/103"), `class="stale"`, `<span class="badge bad">Revoked</span>`, "Key compromise")
	wantBody(t, b.get("/certificates/104"), `class="stale"`, "This row is not a certificate")

	// The next read works: the notice goes.
	if err := s.inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again := b.get("/certificates/101"); strings.Contains(again.Body.String(), `class="stale"`) || !strings.Contains(again.Body.String(), `<span class="badge ok">Not revoked</span>`) {
		t.Error("the stale notice outlived the failure")
	}
}

func parsePEM(t *testing.T, data []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("something other than certificates in the file: %.80q", data)
	}
	return certs
}

func TestCertificateDownloads(t *testing.T) {
	s, der := siteWithIssued(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	base := "/certificates/" + issuedSerial

	// Not without a session.
	for _, form := range []string{"pem", "der", "chain"} {
		wantRedirect(t, s.browser().get(base+"/"+form), "/sign-in")
	}

	got := b.get(base + "/pem")
	wantStatus(t, got, http.StatusOK)
	if ct, cd := got.Header().Get("Content-Type"), got.Header().Get("Content-Disposition"); ct != "application/x-pem-file" || cd != `attachment; filename="app.internal.example.pem"` {
		t.Errorf("PEM headers: %q, %q", ct, cd)
	}
	if certs := parsePEM(t, got.Body.Bytes()); len(certs) != 1 || !bytes.Equal(certs[0].Raw, der) {
		t.Error("the PEM download is not the certificate")
	}

	got = b.get(base + "/der")
	wantStatus(t, got, http.StatusOK)
	if ct, cd := got.Header().Get("Content-Type"), got.Header().Get("Content-Disposition"); ct != "application/pkix-cert" || cd != `attachment; filename="app.internal.example.der"` {
		t.Errorf("DER headers: %q, %q", ct, cd)
	}
	if !bytes.Equal(got.Body.Bytes(), der) {
		t.Error("the DER download is not the certificate")
	}

	// The chain: the certificate, then the intermediate that signed it,
	// and together they verify up to that intermediate.
	got = b.get(base + "/chain")
	wantStatus(t, got, http.StatusOK)
	if cd := got.Header().Get("Content-Disposition"); cd != `attachment; filename="app.internal.example-chain.pem"` {
		t.Errorf("chain file name: %q", cd)
	}
	chain := parsePEM(t, got.Body.Bytes())
	if len(chain) != 2 || !bytes.Equal(chain[0].Raw, der) || !chain[1].Equal(s.ca.inter) {
		t.Fatalf("the chain has %d certificates, or not the leaf then the intermediate", len(chain))
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("the chain does not verify: %v", err)
	}

	// The CA lists two intermediates: the one that signed is the one sent.
	other := newIssuer(t, "Example Intermediate CA")
	signer := s.ca.inter
	s.ca.inters = []*x509.Certificate{other.cert, signer}
	if chain := parsePEM(t, b.get(base+"/chain").Body.Bytes()); len(chain) != 2 || !chain[1].Equal(signer) {
		t.Error("with two intermediates, the chain does not end in the one that signed")
	}

	// None of them signed it: no chain, and the reason. The fake rows of
	// the plain site are self-signed.
	got = b.get("/certificates/101/chain")
	wantStatus(t, got, http.StatusConflict)
	wantBody(t, got, "None of the CA&#39;s current intermediate certificates signed this certificate")
	// The certificate alone is still to be had.
	wantStatus(t, b.get("/certificates/101/pem"), http.StatusOK)

	// The CA not answering: no chain, the cause in the log only.
	s.ca.intersErr = errors.New("dial tcp 10.1.2.3:9000: i/o timeout")
	got = b.get(base + "/chain")
	wantStatus(t, got, http.StatusBadGateway)
	wantBody(t, got, "The certificate alone can still be downloaded")
	if strings.Contains(got.Body.String(), "10.1.2.3") || !strings.Contains(s.log.String(), "10.1.2.3:9000: i/o timeout") {
		t.Error("the CA's failure is on the page, or not in the log")
	}
	wantStatus(t, b.get(base+"/der"), http.StatusOK)
}

func TestDownloadFileNames(t *testing.T) {
	long := strings.Repeat("a", 80) + ".internal.example"
	for _, tc := range []struct{ subject, hex, want string }{
		{"web1.internal.example", "65", "web1.internal.example.pem"},
		{"Web1.Internal.Example", "65", "web1.internal.example.pem"},
		{"*.internal.example", "65", "internal.example.pem"},
		{`evil".pem; filename="x`, "65", "evil-.pem-filename-x.pem"},
		{"a\r\nSet-Cookie: x=y", "65", "a-set-cookie-x-y.pem"},
		{"../../etc/passwd", "65", "etc-passwd.pem"},
		{"CN=,O=Example Org", "65", "cn-o-example-org.pem"},
		{"名前", "1a2b", "certificate-1a2b.pem"},
		{"", "1a2b", "certificate-1a2b.pem"},
		{long, "65", strings.Repeat("a", 64) + ".pem"},
	} {
		got := fileName(&inventory.Certificate{Subject: tc.subject, SerialHex: tc.hex}, ".pem")
		if got != tc.want {
			t.Errorf("fileName(%q) = %q, want %q", tc.subject, got, tc.want)
		}
		if strings.ContainsAny(got, "\"\\/\r\n; ") {
			t.Errorf("fileName(%q) = %q is not safe in a header", tc.subject, got)
		}
	}
}

func TestDetailUnderABasePath(t *testing.T) {
	s, _ := siteWithIssued(t, "https://tools.internal.example/handrail")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/handrail/")
	page := b.get("/handrail/certificates/" + issuedSerial)
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `href="/handrail/"`, `href="/handrail/certificates/`+issuedSerial+`/pem"`, `href="/handrail/status"`)
	wantBody(t, b.get("/handrail/"), `href="/handrail/certificates/`+issuedSerial+`"`)
	wantStatus(t, b.get("/handrail/certificates/"+issuedSerial+"/der"), http.StatusOK)
}

func TestRevocationInWords(t *testing.T) {
	known := []inventory.ProvisionerCount{{Provisioner: inventory.Provisioner{ID: "p1", Name: "handrail", Type: "JWK"}}}
	at := time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		rev  inventory.Revocation
		want revocationView
	}{
		{"by token, provisioner known", inventory.Revocation{ReasonCode: 4, Reason: "replaced", RevokedAt: at, ProvisionerID: "p1"},
			revocationView{When: "2026-11-11 08:00 UTC", Reason: "Superseded", Detail: "replaced", How: "With a provisioner's token", By: "handrail"}},
		{"provisioner not among the certificates", inventory.Revocation{ProvisionerID: "p9"},
			revocationView{Reason: "Unspecified", How: "With a provisioner's token", By: "p9"}},
		{"acme", inventory.Revocation{ReasonCode: 1, ACME: true},
			revocationView{Reason: "Key compromise", How: "Through ACME"}},
		{"by the certificate itself", inventory.Revocation{ReasonCode: 5, MTLS: true},
			revocationView{Reason: "Cessation of operation", How: "By the certificate itself, over mutual TLS"}},
		{"a code RFC 5280 does not define", inventory.Revocation{ReasonCode: 7},
			revocationView{Reason: "Reason code 7", How: "With a provisioner's token"}},
		{"unreadable", inventory.Revocation{Problem: "not JSON"}, revocationView{Problem: "not JSON"}},
	} {
		if got := *newRevocationView(&tc.rev, known); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// What the template says when revocations are not known, or a revocation
// record could not be read: states the inventory does not produce for a
// listed certificate today, and which must not read as "not revoked" if it
// ever does.
func TestDetailTemplateNeverImpliesNotRevoked(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	render := func(data detailData) string {
		var buf bytes.Buffer
		if err := s.server.pages["detail.html"].Execute(&buf, view{Title: data.Title, Page: "detail.html", Data: data}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	unknown := render(detailData{Serial: "101", Title: "web1.internal.example", Badge: "unknown", StatusLabel: "Unknown", CommonName: "web1.internal.example", PEM: "x"})
	for _, want := range []string{"cannot say whether this certificate has been revoked", `<span class="badge unknown">Not known</span>`, "This certificate may have been revoked."} {
		if !strings.Contains(unknown, want) {
			t.Errorf("with revocations unknown, the page lacks %q", want)
		}
	}
	if strings.Contains(unknown, "Not revoked") || strings.Contains(unknown, "no revocation record") {
		t.Error("with revocations unknown, the page says the certificate is not revoked")
	}

	broken := render(detailData{Serial: "101", Title: "web1.internal.example", RevocationsKnown: true, Revocation: &revocationView{Problem: "not JSON"}, PEM: "x"})
	if !strings.Contains(broken, "it treats the certificate as revoked, but the record could not be read: not JSON") || strings.Contains(broken, "Not revoked") {
		t.Error("an unreadable revocation record is not shown as a revocation")
	}

	// Many names: the first are listed, the rest counted.
	var names []string
	for i := range maxShownNames + 5 {
		names = append(names, fmt.Sprintf("n%d.internal.example", i))
	}
	groups := nameGroups(&x509.Certificate{DNSNames: names})
	if len(groups) != 1 || len(groups[0].Values) != maxShownNames || groups[0].More != 5 {
		t.Fatalf("name groups: %d, want one of %d and 5 more", len(groups), maxShownNames)
	}
	if page := render(detailData{Serial: "1", Title: "x", RevocationsKnown: true, Names: groups, PEM: "x"}); !strings.Contains(page, "and 5 more, in the downloaded certificate") {
		t.Error("the page does not say that names were left out")
	}
}

func TestCertificateWords(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cert *x509.Certificate
		want string
	}{
		{&x509.Certificate{PublicKey: edKey.Public()}, "Ed25519"},
		{&x509.Certificate{PublicKey: "something newer", PublicKeyAlgorithm: x509.DSA}, "DSA"},
	} {
		if got := publicKeyWords(tc.cert); got != tc.want {
			t.Errorf("publicKeyWords = %q, want %q", got, tc.want)
		}
	}

	usages := extendedUsageWords(&x509.Certificate{
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}},
	})
	if got, want := strings.Join(usages, "; "), fmt.Sprintf("Code signing; Usage %d; 1.3.6.1.4.1.99999.1", int(x509.ExtKeyUsageMicrosoftKernelCodeSigning)); got != want {
		t.Errorf("extended usages = %q, want %q", got, want)
	}

	// A certificate in date whose revocation status is not known is not
	// called valid, in the sentence either.
	c := &inventory.Certificate{NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(48 * time.Hour)}
	if got := summarySentence(inventory.StatusUnknown, c, nil, t0); !strings.Contains(got, "whether it has been revoked is not known") || strings.Contains(got, "Expires in") {
		t.Errorf("the sentence for an unknown status: %q", got)
	}
	// Revoked, the time not recorded.
	if got := summarySentence(inventory.StatusRevoked, c, &inventory.Revocation{}, t0); got != "Revoked. It would have expired on 2026-11-13." {
		t.Errorf("the sentence for a revocation without a time: %q", got)
	}

	// An issuer without a common name is shown whole.
	var data detailData
	fillCertificate(&data, &x509.Certificate{
		SerialNumber: big.NewInt(1), Issuer: pkix.Name{Organization: []string{"Example Org"}},
		NotBefore: t0, NotAfter: t0.Add(time.Hour), IsCA: true,
	}, t0)
	if data.Issuer != "O=Example Org" || data.Authority != "Yes: this certificate can sign others" {
		t.Errorf("issuer %q, authority %q", data.Issuer, data.Authority)
	}
}

// N-19 of the security review: a certificate with thousands of names, as
// a client of the provisioner can have the CA issue, is more than 64 KiB
// of DER. Its page shows it and it can be revoked from there. The cap on
// what is read from the database is the query's, tested against the
// development CA (TestIntegrationReadsALargeCertificate); this is the
// pages, given such a certificate.
func TestALargeCertificateHasItsPageAndCanBeRevoked(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 3200)
	for i := range names {
		names[i] = fmt.Sprintf("n%d-large.internal.example", i)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "large.internal.example"}, DNSNames: names,
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) <= 64<<10 {
		t.Fatalf("the fixture is %d bytes, not over 64 KiB", len(der))
	}
	s.addRows(inventory.RawCertificate{Serial: "4242", DER: der, Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`)})
	b := signedIn(t, s)
	page := b.get("/certificates/4242")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "large.internal.example", `href="/certificates/4242/revoke"`)
	wantStatus(t, b.get("/certificates/4242/revoke"), http.StatusOK)
}
