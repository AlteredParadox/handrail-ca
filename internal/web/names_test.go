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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestNamesPage(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	inter := newIssuer(t, "Example Intermediate CA")
	day := 24 * time.Hour
	s.addRows(
		inter.issue(t, &x509.Certificate{
			SerialNumber: big.NewInt(201), Subject: pkix.Name{CommonName: "Backup <Service>"},
			DNSNames:    []string{"backup.internal.example", "web1.internal.example", "*.apps.internal.example", "git"},
			IPAddresses: []net.IP{net.ParseIP("10.20.0.7")}, EmailAddresses: []string{"ops@internal.example"},
			NotBefore: t0.Add(-day), NotAfter: t0.Add(30 * day),
		}, &inter.key.PublicKey),
	)

	// Not without a session; a viewer may look.
	wantRedirect(t, s.browser().get("/names"), "/sign-in")
	b := s.browser()
	b.signIn("bob", bobPassword)
	page := b.get("/names")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"<h1>Names in use</h1>", `href="/names" aria-current="page"`,
		// The valid seed certificate and the new one; not the expired or
		// the revoked one, nor the row that is not a certificate.
		"the certificates that are in date and not revoked: 2 certificates.",
		"DNS names", `<span class="sub">4 names</span>`,
		`<span class="strong">internal.example</span>`, `<span class="strong">apps.internal.example</span>`, `<span class="strong">Single-label names</span>`,
		// web1 is in both certificates, and leads to them in the list.
		`<a class="mono small" href="/?admin=1&amp;q=web1.internal.example">web1.internal.example</a> <span class="sub">in 2 certificates</span>`,
		`href="/?admin=1&amp;q=%2A.apps.internal.example"`,
		"IP addresses", "10.20.0.0/24", "Email addresses", "ops@internal.example",
		"Common names that are not among the certificate&#39;s names", "Backup &lt;Service&gt;", `href="/?admin=1&amp;q=Backup&#43;%3CService%3E"`,
		"1 of the DNS names is a literal wildcard",
	)
	for _, absent := range []string{"old.internal.example", "gone.internal.example", "<Service>", "URIs", `class="stale"`} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the summary of active certificates shows %q", absent)
		}
	}

	// Every certificate: the expired and the revoked one's names too, and
	// each name's link searches all of them.
	all := b.get("/names?view=all")
	wantBody(t, all, "every certificate the CA has issued, ended or not: 4 certificates.", "old.internal.example",
		`href="/?admin=1&amp;q=gone.internal.example&amp;view=all"`, `<a href="/names?view=all" aria-current="true">`)
	// Any other view is the default.
	wantBody(t, b.get("/names?view=revoked"), "in date and not revoked: 2 certificates.")
}

func TestNamesPageBoundsWhatItShows(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	inter := newIssuer(t, "Example Intermediate CA")
	day := 24 * time.Hour
	var rows []inventory.RawCertificate
	// One certificate with more names in one domain than a group shows,
	// and one name in each of more domains than a kind shows.
	many := &x509.Certificate{SerialNumber: big.NewInt(500), NotBefore: t0.Add(-day), NotAfter: t0.Add(30 * day)}
	for i := range maxGroupNames + 7 {
		many.DNSNames = append(many.DNSNames, fmt.Sprintf("n%03d.big.example", i))
	}
	for i := range maxNameGroups + 3 {
		many.DNSNames = append(many.DNSNames, fmt.Sprintf("host.d%03d.example", i))
	}
	rows = append(rows, inter.issue(t, many, &inter.key.PublicKey))
	s.addRows(rows...)
	b := signedIn(t, s)
	page := b.get("/names")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, fmt.Sprintf(`<span class="sub">%d names</span>`, maxGroupNames+7+maxNameGroups+3+1),
		"and 7 more, not shown",
		// Every group has one certificate, so they are in order of name:
		// big.example, then the single-name domains. The last four of
		// those and internal.example do not fit.
		"5 more groups are not shown: these are the ones with the most certificates.", "n199.big.example", "host.d098.example")
	for _, absent := range []string{"n200.big.example", "host.d099.example", `<span class="strong">internal.example</span>`} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the page shows %q, past its bounds", absent)
		}
	}
}

func TestNamesPageWhenTheInventoryIsStaleOrUnread(t *testing.T) {
	ctx := context.Background()
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)

	// Read, then the database goes away: the summary as it was, and a
	// notice that says what that means.
	s.clock.advance(10 * time.Minute)
	s.rows.fail(errors.New("connection reset by peer"))
	_ = s.inv.Refresh(ctx)
	page := b.get("/names")
	wantBody(t, page, "web1.internal.example", `class="stale"`, "This summary is as the CA's database was 10 minutes ago", "Names in certificates issued since then are not counted.", "connection reset by peer")

	// Never read: no summary, only the reason. An empty summary would
	// read as "the CA has issued no names".
	never := inventory.New(&fakeRows{err: errors.New("connection refused")})
	never.SetClock(s.clock.Now)
	_ = never.Refresh(ctx)
	s.server.opts.Inventory = never
	page = b.get("/names")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "The certificates have not been read yet", "connection refused")
	for _, absent := range []string{"No names", "<table", "step-ca has no such list"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("an unread summary shows %q", absent)
		}
	}
	s.server.opts.Inventory = inventory.New(&fakeRows{})
	wantBody(t, b.get("/names"), "handrail-ca has only just started")

	// Read, and the CA has issued nothing.
	empty := inventory.New(&fakeRows{})
	if err := empty.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	s.server.opts.Inventory = empty
	wantBody(t, b.get("/names"), "0 certificates.", "No names: there are no such certificates.")
}

// A name's link shows the certificates the summary counted for it: the
// CA's own admin certificates too, which the list otherwise leaves out.
func TestNameLinksReachEveryCertificateCounted(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	inter := newIssuer(t, "Example Intermediate CA")
	admin := inter.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "step"}, DNSNames: []string{"step"},
		NotBefore: t0.Add(-time.Minute), NotAfter: t0.Add(4 * time.Minute),
	}, &inter.key.PublicKey)
	admin.Data = []byte(`{"provisioner":{"id":"a1","name":"Admin JWK","type":"JWK"}}`)
	s.addRows(admin)
	b := signedIn(t, s)

	page := b.get("/names")
	link := regexp.MustCompile(`href="([^"]+)">step</a>`).FindStringSubmatch(page.Body.String())
	if link == nil {
		t.Fatal("the admin certificate's name is not in the summary")
	}
	list := b.get(html.UnescapeString(link[1]))
	wantStatus(t, list, http.StatusOK)
	wantBody(t, list, `href="/certificates/301"`, "Admin JWK")
	if strings.Contains(list.Body.String(), "No certificates match") {
		t.Error("the name's link leads to an empty list")
	}
}

// A very long name is counted whole and shown shortened; its link
// searches for as much of it as a search takes.
func TestNamesPageShortensWhatItShowsOnly(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	inter := newIssuer(t, "Example Intermediate CA")
	long := "spiffe://internal.example/" + strings.Repeat("a", 300)
	one, _ := url.Parse(long + "/one")
	two, _ := url.Parse(long + "/two")
	s.addRows(inter.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(302), Subject: pkix.Name{CommonName: "long.internal.example"}, URIs: []*url.URL{one, two},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour),
	}, &inter.key.PublicKey))
	b := signedIn(t, s)
	page := b.get("/names")
	// Two names, though they are the same for their first 256 characters.
	wantBody(t, page, "URIs", `<span class="sub">2 names</span>`, long[:256]+"…</a>")
	if strings.Contains(page.Body.String(), long) {
		t.Error("the page shows a very long name whole")
	}
	link := regexp.MustCompile(`href="([^"]+)">spiffe`).FindStringSubmatch(page.Body.String())
	if link == nil {
		t.Fatal("no link for the long name")
	}
	wantBody(t, b.get(html.UnescapeString(link[1])), `href="/certificates/302"`)
}
