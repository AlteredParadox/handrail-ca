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
	"crypto/x509"
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
