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
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
)

// Runs against the development CA (deploy/dev), a real step-ca, and is
// skipped without it; `make dev-test` sets the variables. The site is the
// usual test site with the real CA client in place of the fake one.
func TestIntegrationPages(t *testing.T) {
	caURL, fingerprint := os.Getenv("HANDRAIL_DEV_CA_URL"), os.Getenv("HANDRAIL_DEV_CA_FINGERPRINT")
	if caURL == "" || fingerprint == "" {
		t.Skip("no development CA: run `make dev-up` and `make dev-test`")
	}
	client, err := ca.New(ca.Config{URL: caURL, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.opts.CA = client

	// The inventory too, read from the development CA's database with the
	// read-only role.
	conn, err := os.ReadFile(os.Getenv("HANDRAIL_DEV_DB_URL_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := inventory.OpenPostgres(string(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	inv := inventory.New(db)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.server.opts.Inventory = inv

	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	// What deploy/dev sets up: a reachable CA with no CRL and three
	// provisioners, one of them handrail-ca's with a 90-day cap.
	wantBody(t, page,
		">Reachable<", caURL,
		"Handrail Dev CA Root CA", grouped(fingerprint), "was fetched from the CA and matched",
		"Handrail Dev CA Intermediate CA",
		"No revocation list",
		"Admin JWK", "5 minutes", "handrail", "90 days", "acme",
		"Certificate inventory", "Up to date", "PostgreSQL database &#34;stepca&#34; at 127.0.0.1:15432, as &#34;handrail&#34;, read-only",
	)
	// The list, read from the same database: the seed's certificates, the
	// revoked one marked so, and the CA's admin certificates left out
	// until asked for.
	list := b.get("/?view=all")
	wantStatus(t, list, http.StatusOK)
	wantBody(t, list,
		"web1.handrail.test", "web2.handrail.test", "10.20.0.14", "acme1.handrail.test", "gone.handrail.test",
		`<span class="badge bad">Revoked</span>`, "acme <span class=\"sub\">ACME</span>",
		"the CA issued to its own admins",
	)
	if strings.Contains(list.Body.String(), "Admin JWK <span") {
		t.Error("the CA's admin certificates are in the list without being asked for")
	}
	wantBody(t, b.get("/?view=all&admin=1"), "Admin JWK <span")
	wantBody(t, b.get("/?q=10.20.0.20&view=all"), "git.handrail.test")

	// A certificate's own page, reached from the list, and its chain: the
	// certificate, then the CA's intermediate, verifying up to the root
	// the CA client pinned.
	link := regexp.MustCompile(`href="(/certificates/\d+)">web1\.handrail\.test<`).FindStringSubmatch(b.get("/?q=web1.handrail.test").Body.String())
	if link == nil {
		t.Fatal("the list does not link to web1.handrail.test's page")
	}
	detail := b.get(link[1])
	wantStatus(t, detail, http.StatusOK)
	wantBody(t, detail, "<h1>web1.handrail.test</h1>", "Issued by the handrail provisioner.", "Handrail Dev CA Intermediate CA",
		"step-ca provisioner", "Server authentication", ">Not revoked<", "-----BEGIN CERTIFICATE-----")
	chain := parsePEM(t, b.get(link[1]+"/chain").Body.Bytes())
	if len(chain) != 2 {
		t.Fatalf("the chain has %d certificates, want the leaf and the intermediate", len(chain))
	}
	root, err := client.Root(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "web1.handrail.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("the downloaded chain does not verify to the CA's root: %v", err)
	}
	if der := b.get(link[1] + "/der"); !bytes.Equal(der.Body.Bytes(), chain[0].Raw) {
		t.Error("the DER download is not the certificate in the chain")
	}
	// The revoked one says who revoked it and why.
	link = regexp.MustCompile(`href="(/certificates/\d+)">gone\.handrail\.test<`).FindStringSubmatch(b.get("/?q=gone.handrail.test&view=revoked").Body.String())
	if link == nil {
		t.Fatal("the list does not link to gone.handrail.test's page")
	}
	gone := b.get(link[1])
	wantBody(t, gone, `<span class="badge bad">Revoked</span>`, "<dt>Revoked</dt>", "<dt>Reason</dt>")
	t.Logf("the revoked certificate's record: %s", regexp.MustCompile(`(?s)<h2>Revocation</h2>.*?</dl>`).FindString(gone.Body.String()))

	// The names in use, from the same rows: the seed's names under their
	// domain and network. With every certificate counted, the CA's own
	// admin certificates bring their subject, a single-label name that a
	// policy has to allow (docs/ca-setup.md, section 2).
	names := b.get("/names")
	wantStatus(t, names, http.StatusOK)
	wantBody(t, names, `<span class="strong">handrail.test</span>`, "web1.handrail.test", "git.handrail.test", "10.20.0.0/24", "10.20.0.20")
	if strings.Contains(names.Body.String(), "gone.handrail.test") {
		t.Error("a revoked certificate's name is among the names of certificates that are not revoked")
	}
	wantBody(t, b.get("/names?view=all"), "gone.handrail.test", `<span class="strong">Single-label names</span>`, ">step</a>")

	if !regexp.MustCompile(`\d+ in all: .*[1-9]\d* revoked`).MatchString(page.Body.String()) {
		t.Error("no certificate counts on the page")
	}
	body := page.Body.String()
	if !regexp.MustCompile(`<dd>\d+\.\d+\.\d+`).MatchString(body) {
		t.Error("no step-ca version on the page")
	}
	for _, absent := range []string{"Not reachable", "Not known", "could not", "does not list"} {
		if strings.Contains(body, absent) {
			t.Errorf("the page for a healthy CA says %q", absent)
		}
	}
}

// Revoking through the pages, against the development CA: an operator
// opens a certificate's revoke page, confirms, and the CA's own database
// then holds the record, which the certificate's page shows. This is the
// whole path: the form, the provisioner's key, the token, step-ca, the
// re-read of its database, the history.
func TestIntegrationRevokeThroughThePages(t *testing.T) {
	caURL, fingerprint := os.Getenv("HANDRAIL_DEV_CA_URL"), os.Getenv("HANDRAIL_DEV_CA_FINGERPRINT")
	serial, pwFile := os.Getenv("HANDRAIL_DEV_REVOKE_SERIAL_PAGES"), os.Getenv("HANDRAIL_DEV_PROVISIONER_PASSWORD_FILE")
	if caURL == "" || fingerprint == "" || serial == "" || pwFile == "" {
		t.Skip("no development CA: run `make dev-up` and `make dev-test`")
	}
	pw, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.New(ca.Config{URL: caURL, Fingerprint: fingerprint, Provisioner: &ca.ProvisionerConfig{Name: "handrail", Password: strings.TrimSpace(string(pw))}})
	if err != nil {
		t.Fatal(err)
	}
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.opts.CA = client
	conn, err := os.ReadFile(os.Getenv("HANDRAIL_DEV_DB_URL_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := inventory.OpenPostgres(string(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	inv := inventory.New(db)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.server.opts.Inventory = inv

	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	wantBody(t, b.get("/status"), "Acting on the CA", ">Ready<", "held in memory only")

	wantBody(t, b.get("/certificates/"+serial), ">Not revoked<", `href="/certificates/`+serial+`/revoke">Revoke…</a>`)
	form := b.get("/certificates/" + serial + "/revoke")
	wantStatus(t, form, http.StatusOK)
	wantBody(t, form, "This CA does not publish a revocation list.")
	word := regexp.MustCompile(`<span class="mono ink">(revoke-\d+\.handrail\.test)</span>`).FindStringSubmatch(form.Body.String())
	if word == nil {
		t.Fatal("the form does not ask for the certificate's subject")
	}

	rec := b.do(http.MethodPost, "/certificates/"+serial+"/revoke", url.Values{
		"form_token": {tokenIn(t, form)}, "reason": {"4"}, "note": {"handrail-ca integration test, through the pages"}, "confirm": {word[1]},
	})
	wantRedirect(t, rec, "/certificates/"+serial+"?revoked=now#revocation")

	// The record is the CA's own, read back from its database.
	page := b.get("/certificates/" + serial + "?revoked=now")
	wantBody(t, page, `<span class="badge bad">Revoked</span>`, "Revoked. The CA confirmed it, and this is its record.",
		"Superseded", "handrail-ca integration test, through the pages", "With a provisioner&#39;s token", "<dt>Provisioner</dt><dd>handrail</dd>")
	if strings.Contains(page.Body.String(), "Revoke…") {
		t.Error("a revoked certificate's page offers revoking")
	}
	rev := inv.Snapshot().Revocation(serial)
	if rev == nil || rev.ReasonCode != 4 || time.Since(rev.RevokedAt) > 5*time.Minute {
		t.Errorf("the record in the CA's database: %+v", rev)
	}
	events := s.revokeEvents()
	if len(events) != 2 || events[1].Outcome != "ok" || !strings.HasSuffix(events[1].Detail, "confirmed by the CA and recorded in its database") {
		t.Errorf("history: %+v", events)
	}
}

// devSite is the test site with the real CA client, acting through the
// named provisioner of the development CA, and the real inventory.
func devSite(t *testing.T, provisioner string) (*site, *ca.Client, *inventory.Inventory) {
	t.Helper()
	caURL, fingerprint := os.Getenv("HANDRAIL_DEV_CA_URL"), os.Getenv("HANDRAIL_DEV_CA_FINGERPRINT")
	pwFile, dbFile := os.Getenv("HANDRAIL_DEV_PROVISIONER_PASSWORD_FILE"), os.Getenv("HANDRAIL_DEV_DB_URL_FILE")
	if caURL == "" || fingerprint == "" || pwFile == "" || dbFile == "" {
		t.Skip("no development CA: run `make dev-up` and `make dev-test`")
	}
	pw, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.New(ca.Config{URL: caURL, Fingerprint: fingerprint, Provisioner: &ca.ProvisionerConfig{Name: provisioner, Password: strings.TrimSpace(string(pw))}})
	if err != nil {
		t.Fatal(err)
	}
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.opts.CA = client
	// The site's clock is fixed in the past; what is issued here is dated
	// by the real CA, so the pages need the real time.
	s.server.opts.Now = time.Now
	conn, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatal(err)
	}
	db, err := inventory.OpenPostgres(string(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	inv := inventory.New(db)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.server.opts.Inventory = inv
	return s, client, inv
}

var issuedPage = regexp.MustCompile(`^/certificates/(\d+)\?issued=(\w+)$`)

// Issuing through the pages, against the development CA: a request is
// pasted, read, signed for a week, and the certificate that the CA's own
// database then holds is the one the page said it would be, with a chain
// that verifies to the root. The whole path: the form, the provisioner's
// key, the token, step-ca, the re-read of its database, the history.
func TestIntegrationIssueThroughThePages(t *testing.T) {
	s, client, inv := devSite(t, "handrail")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	first := b.get("/issue")
	wantStatus(t, first, http.StatusOK)
	// The limits are the development CA's: a longest of ninety days set
	// on the provisioner, the rest left to the CA.
	wantBody(t, first, "<dt>Longest</dt><dd>90 days</dd>", `<dt>Default</dt><dd><span class="muted">The CA's own</span></dd>`)

	name := fmt.Sprintf("pages-%d.handrail.test", time.Now().UnixNano()%1_000_000_000)
	csr := newCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name, Organization: []string{"Example Org"}}, DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("10.20.6.1")},
	})
	page, form := b.readCSR(csr)
	for _, want := range []string{"<dt>Common name</dt><dd>" + name + "</dd>", "10.20.6.1", "Only the common name of the subject is kept.",
		`<option value="2160h0m0s">90 days (the longest this provisioner allows)</option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "certificate template of its own") || strings.Contains(page, "365 days") {
		t.Error("the page speaks of a template the provisioner does not have, or offers more than its longest validity")
	}

	form.Set("validity", "168h0m0s")
	rec := b.do(http.MethodPost, "/issue", form)
	m := issuedPage.FindStringSubmatch(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || m == nil || m[2] != "now" {
		t.Fatalf("signing: %d to %q; body: %.400s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	serial := m[1]

	// The certificate's page, from the CA's database.
	cert := b.get("/certificates/" + serial + "?issued=now")
	wantStatus(t, cert, http.StatusOK)
	wantBody(t, cert, "<h1>"+name+"</h1>", "Issued. This is the certificate the CA signed for the request.", "10.20.6.1", ">Not revoked<",
		"7 days", `<span class="strong">alice</span> Issue <span class="badge ok">Done</span>`)
	if strings.Contains(cert.Body.String(), "Example Org") {
		t.Error("the certificate carries the organisation, which the default template drops")
	}
	if inv.Snapshot().Certificate(serial) == nil {
		t.Fatal("the certificate is not in the inventory after issuing")
	}
	chain := parsePEM(t, b.get("/certificates/"+serial+"/chain").Body.Bytes())
	if len(chain) != 2 {
		t.Fatalf("the chain has %d certificates", len(chain))
	}
	root, err := client.Root(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the issued certificate does not verify for its name: %v", err)
	}
	if d := chain[0].NotAfter.Sub(chain[0].NotBefore); d != 7*24*time.Hour+time.Minute {
		t.Errorf("validity = %s, want the week asked for and the CA's minute", d)
	}
	block, _ := pem.Decode([]byte(csr))
	request, _ := x509.ParseCertificateRequest(block.Bytes)
	if !bytes.Equal(chain[0].RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo) {
		t.Error("the certificate is not for the request's key")
	}

	events := s.issueEvents()
	if len(events) != 2 || events[1].Outcome != "ok" || events[1].Serial != serial || !strings.Contains(events[1].Detail, "validity: 7 days; issued, valid until ") {
		t.Errorf("history: %+v", events)
	}

	// The same form again: no second certificate.
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/"+serial+"?issued=before")

	// A name the CA's policy does not allow is refused in the CA's words,
	// and nothing is issued.
	_, outside := b.readCSR(newCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "outside.example.org"}, DNSNames: []string{"outside.example.org"}}))
	rec = b.do(http.MethodPost, "/issue", outside)
	wantStatus(t, rec, http.StatusBadGateway)
	wantBody(t, rec, "No certificate was issued", "The CA refused the request", "dns name &#34;outside.example.org&#34; not allowed")
	// Longer than the provisioner allows is refused here, before the CA
	// is asked.
	_, long := b.readCSR(newCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}))
	long.Set("validity", "custom")
	long.Set("custom_n", "91")
	long.Set("custom_unit", "days")
	rec = b.do(http.MethodPost, "/issue", long)
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "longest validity is 90 days")
}

// Through the development CA's provisioner that has the guide's template:
// the page says there is a template, shows it, and the certificate comes
// back with the request's whole subject, which is not reported as a
// difference.
func TestIntegrationIssueUnderATemplate(t *testing.T) {
	s, _, _ := devSite(t, "handrail-template")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	name := fmt.Sprintf("tpl-%d.handrail.test", time.Now().UnixNano()%1_000_000_000)
	page, form := b.readCSR(newCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name, Organization: []string{"Example Org"}, Country: []string{"DE"}}, DNSNames: []string{name},
	}))
	for _, want := range []string{"This provisioner has a certificate template of its own on the CA.", "{{ toJson .Insecure.CR.Subject }}",
		"<dt>Request's subject</dt><dd>CN=" + name + ",O=Example Org,C=DE</dd>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "Only the common name of the subject is kept") {
		t.Error("the page says the subject will be cut down, under a template that keeps it")
	}
	rec := b.do(http.MethodPost, "/issue", form)
	m := issuedPage.FindStringSubmatch(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || m == nil || m[2] != "now" {
		t.Fatalf("signing: %d to %q; body: %.400s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	cert := b.get("/certificates/" + m[1])
	wantBody(t, cert, "CN="+name+",O=Example Org,C=DE", "handrail-template <span")
}

// The other way of issuing, against the development CA: handrail-ca makes
// the key, and the page that answers carries the key, the certificate the
// real CA signed for it, and a chain that verifies to the root.
func TestIntegrationGenerateThroughThePages(t *testing.T) {
	s, client, inv := devSite(t, "handrail")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	name := fmt.Sprintf("gen-%d.handrail.test", time.Now().UnixNano()%1_000_000_000)

	form := b.generateForm(name, name+"\n10.20.7.1", "ed25519")
	form.Set("validity", "24h0m0s")
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "Save the private key now.", "<dt>Subject</dt><dd>CN="+name+"</dd>", "<dt>Key</dt><dd>Ed25519, not encrypted</dd>")
	blocks := pemBlocks(t, rec.Body.String())
	if len(blocks) != 4 || blocks[0].Type != "PRIVATE KEY" {
		t.Fatalf("%d PEM blocks on the page", len(blocks))
	}
	key, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(blocks[3].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok || !private.Public().(ed25519.PublicKey).Equal(cert.PublicKey) {
		t.Error("the key on the page is not the certificate's")
	}
	root, err := client.Root(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(inter)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the certificate does not verify for its name: %v", err)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.20.7.1" {
		t.Errorf("addresses: %v", cert.IPAddresses)
	}
	serial := cert.SerialNumber.String()
	if inv.Snapshot().Certificate(serial) == nil {
		t.Error("the certificate is not in the inventory")
	}
	wantBody(t, rec, `href="/certificates/`+serial+`"`)
	// The certificate's page does not have the key, and nor does the log.
	if strings.Contains(b.get("/certificates/"+serial).Body.String(), "PRIVATE KEY") {
		t.Error("the certificate's page carries a private key")
	}
	if strings.Contains(s.log.String(), string(pem.EncodeToMemory(blocks[0])[40:80])) {
		t.Error("the private key is in the log")
	}
	// Sent again, it makes nothing.
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", form), http.StatusConflict)

	// A name the CA's policy refuses: no certificate, and no key shown.
	refused := b.do(http.MethodPost, "/issue/generate", b.generateForm("outside.example.org", "", "p256"))
	wantStatus(t, refused, http.StatusBadGateway)
	wantBody(t, refused, "No certificate was issued", "not allowed", "The key handrail-ca made for this request has been discarded.")
	if strings.Contains(refused.Body.String(), "PRIVATE KEY") {
		t.Error("a key is on the page of a request that was refused")
	}
}
