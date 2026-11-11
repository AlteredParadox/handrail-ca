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

package inventory

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Runs against the development CA's PostgreSQL (deploy/dev), with the
// read-only role the setup guide describes, and is skipped without it.
// `make dev-test` writes the connection string to a file and names it here.
func devDatabase(t *testing.T) *Postgres {
	t.Helper()
	file := os.Getenv("HANDRAIL_DEV_DB_URL_FILE")
	if file == "" {
		t.Skip("no development database: run `make dev-up` and `make dev-test`")
	}
	conn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenPostgres(string(conn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestIntegrationReadsTheCAsDatabase(t *testing.T) {
	p := devDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inv := New(p)
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	if st := snap.State; st.Problem != "" || !st.RevocationsKnown || st.LoadedAt.IsZero() || !strings.Contains(st.Source, "PostgreSQL") {
		t.Errorf("state = %+v", st)
	}
	// What deploy/dev/seed.sh issues, by provisioner.
	subjects := map[string]int{}
	provisioners := map[string]int{}
	for _, c := range snap.Certificates {
		if c.Problem != "" {
			t.Errorf("%s is unreadable: %s", c.Serial, c.Problem)
		}
		subjects[c.Subject]++
		provisioners[c.Provisioner.Name+"/"+c.Provisioner.Type]++
	}
	for _, want := range []string{"web1.handrail.test", "web2.handrail.test", "git.handrail.test", "soon.handrail.test", "gone.handrail.test", "acme1.handrail.test", "acme2.handrail.test"} {
		if subjects[want] != 1 {
			t.Errorf("%d certificates for %s, want 1", subjects[want], want)
		}
	}
	if subjects["renewed.handrail.test"] != 2 {
		t.Errorf("%d certificates for the renewed name, want 2", subjects["renewed.handrail.test"])
	}
	if provisioners["handrail/JWK"] < 9 || provisioners["acme/ACME"] != 2 || provisioners["Admin JWK/JWK"] < 1 {
		t.Errorf("by provisioner: %v", provisioners)
	}
	// The one the seed revoked, and nothing else.
	revoked := 0
	for _, c := range snap.Certificates {
		if r := snap.Revocation(c.Serial); r != nil {
			revoked++
			if c.Subject != "gone.handrail.test" || r.ReasonCode != 1 || r.Reason != "development seed" || r.Problem != "" {
				t.Errorf("revoked: %s, %+v", c.Subject, r)
			}
		}
	}
	if revoked != 1 {
		t.Errorf("%d revoked certificates, want 1", revoked)
	}

	// A second read fetches nothing it already has and changes nothing.
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if again := inv.Snapshot(); len(again.Certificates) != len(snap.Certificates) {
		t.Errorf("%d certificates on the second read, %d on the first", len(again.Certificates), len(snap.Certificates))
	}
}

// The account is meant to be able to read three tables and nothing else,
// and the session to be read-only on top of that. Asked of the database
// itself, through the same connection the inventory uses.
func TestIntegrationCanOnlyRead(t *testing.T) {
	p := devDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var readOnly string
	if err := p.pool.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		t.Errorf("default_transaction_read_only = %q, %v", readOnly, err)
	}
	for _, stmt := range []string{
		`DELETE FROM x509_certs`,
		`UPDATE revoked_x509_certs SET nvalue = nvalue`,
		`INSERT INTO x509_certs (nkey, nvalue) VALUES ('1', '1')`,
		`CREATE TABLE handrail_was_here (id int)`,
		// Tables of the CA that are none of handrail-ca's business.
		`SELECT count(*) FROM used_ott`,
		`SELECT count(*) FROM provisioners`,
		`SELECT count(*) FROM admins`,
		`SELECT count(*) FROM acme_accounts`,
	} {
		if _, err := p.pool.Exec(ctx, stmt); err == nil {
			t.Errorf("%q was allowed", stmt)
		}
	}
}
