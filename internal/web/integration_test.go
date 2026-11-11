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
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"handrail-ca/internal/ca"
)

// Runs against the development CA (deploy/dev), a real step-ca, and is
// skipped without it; `make dev-test` sets the variables. The site is the
// usual test site with the real CA client in place of the fake one.
func TestIntegrationStatusPage(t *testing.T) {
	caURL, rootFile := os.Getenv("HANDRAIL_DEV_CA_URL"), os.Getenv("HANDRAIL_DEV_CA_ROOT")
	if caURL == "" || rootFile == "" {
		t.Skip("no development CA: run `make dev-up` and `make dev-test`")
	}
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.New(ca.Config{URL: caURL, RootPEM: rootPEM})
	if err != nil {
		t.Fatal(err)
	}
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.opts.CA = client

	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	// What deploy/dev sets up: a reachable CA with no CRL and three
	// provisioners, one of them handrail-ca's with a 90-day cap.
	wantBody(t, page,
		">Reachable<", caURL,
		"Handrail Dev CA Root CA", grouped(ca.Fingerprint(client.TrustedRoots()[0])),
		"Handrail Dev CA Intermediate CA",
		"No revocation list",
		"Admin JWK", "5 minutes", "handrail", "90 days", "acme",
	)
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
