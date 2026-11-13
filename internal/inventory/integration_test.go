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
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"handrail-ca/internal/ca"
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
	p, err := OpenPostgres(string(conn), nil)
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
	if provisioners["handrail/JWK"] < 9 || provisioners["acme/ACME"] < 2 || provisioners["Admin JWK/JWK"] < 1 {
		t.Errorf("by provisioner: %v", provisioners)
	}
	// The one the seed revoked, as recorded; and the seed's other
	// certificates are not. (`make dev-verify`, which CI runs first,
	// revokes more of its own, so no total is asserted.)
	for _, c := range snap.Certificates {
		r := snap.Revocation(c.Serial)
		switch {
		case c.Subject == "gone.handrail.test":
			if r == nil || r.ReasonCode != 1 || r.Reason != "development seed" || r.Problem != "" || r.RevokedAt.IsZero() {
				t.Errorf("revocation of gone.handrail.test = %+v", r)
			}
		case c.Subject == "web1.handrail.test" || c.Subject == "acme1.handrail.test" || c.Subject == "soon.handrail.test":
			if r != nil {
				t.Errorf("%s is recorded as revoked: %+v", c.Subject, r)
			}
		case r != nil && r.Problem != "":
			t.Errorf("the revocation of %s could not be read: %s", c.Subject, r.Problem)
		}
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

// devTLSDatabase is the development database as another machine would
// reach it: by the name on its certificate (db.handrail.test), with
// sslmode=verify-full. Nothing here resolves that name, so the connection
// is pointed at the loopback port by hand; the TLS handshake and the
// certificate check are the real thing. asHost replaces the name asked
// for, to test a name the certificate does not carry.
func devTLSDatabase(t *testing.T, caRoot RootFunc, asHost string) *Postgres {
	t.Helper()
	file := os.Getenv("HANDRAIL_DEV_DB_TLS_URL_FILE")
	if file == "" {
		t.Skip("no development database with TLS: run `make dev-up` and `make dev-test`")
	}
	conn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	connString := string(conn)
	if asHost != "" {
		connString = strings.Replace(connString, "@db.handrail.test:", "@"+asHost+":", 1)
	}
	p, err := openPostgres(connString, caRoot, func(cfg *pgxpool.Config) {
		cfg.ConnConfig.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// devCARoot fetches the development CA's root the way handrail-ca does: by
// its fingerprint, from the CA.
func devCARoot(t *testing.T) RootFunc {
	t.Helper()
	client, err := ca.New(ca.Config{URL: os.Getenv("HANDRAIL_DEV_CA_URL"), Fingerprint: os.Getenv("HANDRAIL_DEV_CA_FINGERPRINT")})
	if err != nil {
		t.Skipf("no development CA: %v", err)
	}
	return client.Root
}

// The arrangement docs/ca-setup.md describes for a database on another
// machine: PostgreSQL holds a certificate from the CA, and handrail-ca
// checks it against the CA root it already has. No root file anywhere.
func TestIntegrationDatabaseOverVerifiedTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := devTLSDatabase(t, devCARoot(t), "")
	inv := New(p)
	if err := inv.Refresh(ctx); err != nil {
		t.Fatalf("reading over verified TLS: %v", err)
	}
	if n := len(inv.Snapshot().Certificates); n < 16 {
		t.Errorf("%d certificates read over TLS", n)
	}
	// The sign-in was SCRAM bound to the server's certificate: the reader
	// requires that of a database on another machine, so the read above
	// would have failed without it.
	if c := p.pool.Config().ConnConfig; c.ChannelBinding != "require" || c.RequireAuth != "scram-sha-256" {
		t.Errorf("channel_binding=%q require_auth=%q on a connection to another machine", c.ChannelBinding, c.RequireAuth)
	}
	// It really is TLS, and the session is still read-only.
	var ssl bool
	var readOnly string
	if err := p.pool.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&ssl); err != nil || !ssl {
		t.Errorf("the connection is not using TLS (%v, %v)", ssl, err)
	}
	if err := p.pool.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		t.Errorf("default_transaction_read_only = %q, %v", readOnly, err)
	}
}

func TestIntegrationDatabaseTLSIsReallyVerified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	realRoot := devCARoot(t)

	// Another CA's root: the database's certificate does not chain to it.
	other, err := x509.ParseCertificate(newDER(t, "8001", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Some Other Root"}
		c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign
	}))
	if err != nil {
		t.Fatal(err)
	}
	wrongRoot := func(context.Context) (*x509.Certificate, error) { return other, nil }
	if _, err := devTLSDatabase(t, wrongRoot, "").Serials(ctx); err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("with another CA's root: %v, want an unknown-authority failure", err)
	}

	// The right root, but a name the database's certificate does not carry.
	if _, err := devTLSDatabase(t, realRoot, "other.handrail.test").Serials(ctx); err == nil || !strings.Contains(err.Error(), "not other.handrail.test") {
		t.Errorf("under another name: %v, want a host-name failure", err)
	}

	// No CA root offered: the system's roots do not know a private CA.
	if _, err := devTLSDatabase(t, nil, "").Serials(ctx); err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("with the system's roots: %v, want an unknown-authority failure", err)
	}
}
