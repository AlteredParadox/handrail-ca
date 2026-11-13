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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The password must never come back out of this package: not in an error,
// not in the description shown on the status page.
const testPassword = "s3cret-db-pass"

func TestOpenPostgresAcceptsOnlySafeTransport(t *testing.T) {
	// pgx also reads the PG* environment variables; keep them out of this.
	for _, name := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT", "PGSERVICE"} {
		t.Setenv(name, "")
	}
	tests := []struct {
		name, conn string
		ok         bool
	}{
		// This machine: any mode.
		{"loopback, no TLS", "postgres://handrail:" + testPassword + "@127.0.0.1:5432/stepca?sslmode=disable", true},
		{"loopback, default mode", "postgres://handrail:" + testPassword + "@127.0.0.1:5432/stepca", true},
		{"localhost", "postgres://handrail:" + testPassword + "@localhost/stepca?sslmode=prefer", true},
		{"IPv6 loopback", "postgres://handrail:" + testPassword + "@[::1]:5432/stepca?sslmode=disable", true},
		{"socket directory", "host=/var/run/postgresql user=handrail password=" + testPassword + " dbname=stepca", true},
		{"keyword form, loopback", "host=127.0.0.1 port=5432 user=handrail password=" + testPassword + " dbname=stepca sslmode=disable", true},
		// Another machine: only TLS with the server's certificate checked.
		{"remote, verify-full", "postgres://handrail:" + testPassword + "@db.internal.example:5432/stepca?sslmode=verify-full", true},
		{"remote, no TLS", "postgres://handrail:" + testPassword + "@db.internal.example:5432/stepca?sslmode=disable", false},
		{"remote, default mode", "postgres://handrail:" + testPassword + "@db.internal.example:5432/stepca", false},
		{"remote, prefer", "postgres://handrail:" + testPassword + "@db.internal.example/stepca?sslmode=prefer", false},
		{"remote, allow", "postgres://handrail:" + testPassword + "@db.internal.example/stepca?sslmode=allow", false},
		// Encrypted, but to whoever answers.
		{"remote, require", "postgres://handrail:" + testPassword + "@db.internal.example/stepca?sslmode=require", false},
		{"remote, verify-ca", "postgres://handrail:" + testPassword + "@10.20.0.30/stepca?sslmode=verify-ca", false},
		{"private address, no TLS", "postgres://handrail:" + testPassword + "@10.20.0.30/stepca?sslmode=disable", false},
		// Every host the driver might try counts.
		{"a remote host behind a local one", "postgres://handrail:" + testPassword + "@127.0.0.1:5432,db.internal.example:5432/stepca?sslmode=disable", false},
		{"two local hosts", "postgres://handrail:" + testPassword + "@127.0.0.1:5432,localhost:5433/stepca?sslmode=disable", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := OpenPostgres(tt.conn, nil)
			if (err == nil) != tt.ok {
				t.Fatalf("OpenPostgres: %v, want ok=%v", err, tt.ok)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "sslmode=verify-full") || strings.Contains(err.Error(), testPassword) {
					t.Errorf("error = %q", err)
				}
				return
			}
			defer p.Close()
			if d := p.Describe(); strings.Contains(d, testPassword) || !strings.Contains(d, `"stepca"`) || !strings.Contains(d, `"handrail"`) || !strings.Contains(d, "read-only") {
				t.Errorf("Describe = %q", d)
			}
			// Sessions are read-only and bounded whatever the string says.
			params := p.pool.Config().ConnConfig.RuntimeParams
			if params["default_transaction_read_only"] != "on" || params["statement_timeout"] != "30000" || params["application_name"] != "handrail-ca" {
				t.Errorf("session parameters = %v", params)
			}
		})
	}
}

// A connection string that is written wrongly can still parse, with the
// password, or a part of it, where the host, the database or the user
// belongs. Those are shown on the status page and written to the log, so
// such a string is refused like one that does not parse, and nothing of
// it is repeated.
func TestOpenPostgresRefusesAStringThatParsesAsSomethingElse(t *testing.T) {
	clearPGEnv(t)
	const tail = "@db.internal.example:5432/stepca?sslmode=verify-full"
	for name, conn := range map[string]string{
		"a password that begins with a slash":          "postgres://handrail:/" + testPassword + tail,
		"a password of digits, a slash and more":       "postgres://handrail:2026/" + testPassword + tail,
		"a password with an at sign in it":             "postgres://handrail:Dummy@" + testPassword + tail,
		"no space before password=":                    "host=db.internal.examplepassword=" + testPassword + " user=handrail dbname=stepca sslmode=verify-full",
		"no space before password=, and no sslmode":    "host=db.internal.examplepassword=" + testPassword + " user=handrail dbname=stepca",
		"no space before password=, after a socket":    "host=/var/run/postgresqlpassword=" + testPassword + " user=handrail dbname=stepca",
		"no space before password=, after the user":    "host=127.0.0.1 user=handrailpassword=" + testPassword + " dbname=stepca",
		"no space before password=, after the dbname":  "host=127.0.0.1 user=handrail dbname=stepcapassword=" + testPassword,
		"a URL that names no user":                     "postgres://db.internal.example:5432/stepca?sslmode=verify-full",
		"a second host that is part of the password":   "postgres://handrail:x@127.0.0.1," + testPassword + "@db.internal.example/stepca?sslmode=verify-full",
		"the other spelling of the scheme, same fault": "postgresql://handrail:/" + testPassword + tail,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := OpenPostgres(conn, nil)
			if err == nil {
				defer p.Close()
				t.Fatalf("accepted, as %s", strings.ReplaceAll(p.Describe(), testPassword, "<THE PASSWORD>"))
			}
			if !errors.Is(err, errNotUnderstood) {
				t.Errorf("refused with %q, want the fixed message", strings.ReplaceAll(err.Error(), testPassword, "<THE PASSWORD>"))
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Error("the error repeats the password")
			}
		})
	}
	// What is written rightly is still taken, awkward passwords included.
	for name, conn := range map[string]string{
		"a password with a colon":          "postgres://handrail:Dummy:" + testPassword + tail,
		"an encoded slash and at sign":     "postgres://handrail:%2F" + testPassword + "%40x" + tail,
		"a quoted password with a space":   "host=db.internal.example user=handrail password='a b " + testPassword + "' dbname=stepca sslmode=verify-full",
		"an address and a socket":          "host=/var/run/postgresql user=handrail password=" + testPassword + " dbname=stepca",
		"IPv6":                             "postgres://handrail:" + testPassword + "@[::1]:5432/stepca?sslmode=disable",
		"a role and database with marks":   "postgres://handrail_ro:" + testPassword + "@127.0.0.1/step-ca.db?sslmode=disable",
		"two hosts":                        "postgres://handrail:" + testPassword + "@db1.internal.example,db2.internal.example/stepca?sslmode=verify-full",
		"the other spelling of the scheme": "postgresql://handrail:" + testPassword + tail,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := OpenPostgres(conn, nil)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			defer p.Close()
			if strings.Contains(p.Describe(), testPassword) {
				t.Errorf("Describe carries the password: %q", p.Describe())
			}
		})
	}
}

func TestOpenPostgresDoesNotEchoWhatItCannotParse(t *testing.T) {
	for _, conn := range []string{
		"postgres://handrail:" + testPassword + "@127.0.0.1:notaport/stepca",
		"host=127.0.0.1 password=" + testPassword + " sslmode=bogus",
		"postgres://handrail:" + testPassword + "@127.0.0.1/stepca?pool_max_conns=many",
		"password='" + testPassword,
	} {
		_, err := OpenPostgres(conn, nil)
		if err == nil {
			t.Errorf("accepted %q", strings.ReplaceAll(conn, testPassword, "…"))
			continue
		}
		if strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), "handrail:") {
			t.Errorf("the error repeats the connection string: %q", err)
		}
	}
	// The read-only setting cannot be turned off from the string.
	p, err := OpenPostgres("postgres://handrail:"+testPassword+"@127.0.0.1/stepca?sslmode=disable&default_transaction_read_only=off&statement_timeout=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if params := p.pool.Config().ConnConfig.RuntimeParams; params["default_transaction_read_only"] != "on" || params["statement_timeout"] == "0" {
		t.Errorf("the connection string overrode the session parameters: %v", params)
	}
}

func TestLocalHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.8.9.10": true, "::1": true, "localhost": true, "LOCALHOST": true,
		"/var/run/postgresql": true, "/tmp": true,
		"": false, "10.20.0.30": false, "192.168.1.5": false, "db": false, "localhost.example": false,
		"0.0.0.0": false, "::": false, "db.internal.example": false,
	} {
		if got := localHost(host); got != want {
			t.Errorf("localHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestPlainErrors(t *testing.T) {
	if plain(nil) != nil {
		t.Error("plain(nil) is not nil")
	}
	refused := plain(&pgconn.PgError{Code: "42501", Message: "permission denied for table used_ott", Detail: "internal detail"})
	if got := refused.Error(); got != "the database refused: permission denied for table used_ott (SQLSTATE 42501)" {
		t.Errorf("a refused query: %q", got)
	}
	if !errors.Is(plain(context.DeadlineExceeded), context.DeadlineExceeded) || !errors.Is(plain(context.Canceled), context.Canceled) {
		t.Error("context errors are not kept recognisable")
	}
	long := plain(errors.New(strings.Repeat("x", 5000)))
	if len([]rune(long.Error())) > maxText+1 {
		t.Errorf("an error of %d characters was kept whole", len(long.Error()))
	}
}

// With nothing listening, each read fails with an error that names where
// it tried and not the password; nothing hangs.
func TestUnreachableDatabase(t *testing.T) {
	p, err := OpenPostgres("postgres://handrail:"+testPassword+"@127.0.0.1:1/stepca?sslmode=disable&connect_timeout=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := context.Background()
	_, e1 := p.Serials(ctx)
	_, e2 := p.Certificates(ctx, []string{"1"})
	_, e3 := p.Revocations(ctx)
	for i, err := range []error{e1, e2, e3} {
		if err == nil {
			t.Fatalf("read %d succeeded against nothing", i+1)
		}
		if strings.Contains(err.Error(), testPassword) {
			t.Errorf("read %d: the error carries the password: %q", i+1, err)
		}
	}
	inv := New(p)
	if err := inv.Refresh(ctx); err == nil || !strings.Contains(inv.Snapshot().State.Problem, "listing certificates") {
		t.Errorf("Refresh = %v, state %+v", err, inv.Snapshot().State)
	}
}

func parsed(t *testing.T, conn string) *pgconn.Config {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(conn)
	if err != nil {
		t.Fatal(err)
	}
	return &cfg.ConnConfig.Config
}

// A verified connection that was given no roots of its own is checked
// against the CA's root and nothing else; every other kind is left alone.
func TestCARootIsTheTrustAnchorForTheDatabase(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT", "PGSERVICE", "PGPASSWORD"} {
		t.Setenv(name, "")
	}
	root, err := x509.ParseCertificate(newDER(t, "7001", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Test Root CA"}
		c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(root)

	// A root file of the operator's own choosing.
	rootFile := filepath.Join(t.TempDir(), "other-root.pem")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER(t, "7002", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Some Other Root"}
		c.IsCA, c.BasicConstraintsValid = true, true
	})}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, conn string
		wants      bool
	}{
		{"remote, verify-full", "postgres://u:p@db.internal.example/stepca?sslmode=verify-full", true},
		{"local, verify-full", "postgres://u:p@localhost/stepca?sslmode=verify-full", true},
		{"two hosts, verify-full", "postgres://u:p@db1.internal.example,db2.internal.example/stepca?sslmode=verify-full", true},
		{"verify-full with its own root file", "postgres://u:p@db.internal.example/stepca?sslmode=verify-full&sslrootcert=" + rootFile, false},
		{"local, no TLS", "postgres://u:p@127.0.0.1/stepca?sslmode=disable", false},
		{"local, unverified TLS", "postgres://u:p@127.0.0.1/stepca?sslmode=require", false},
		{"local, default mode", "postgres://u:p@127.0.0.1/stepca", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := parsed(t, tt.conn)
			if got := wantsCARoot(c); got != tt.wants {
				t.Fatalf("wantsCARoot = %v, want %v", got, tt.wants)
			}
			before := c.TLSConfig
			var beforeRoots *x509.CertPool
			if before != nil {
				beforeRoots = before.RootCAs
			}
			trustCARoot(c, root)
			all := []*tls.Config{c.TLSConfig}
			for _, f := range c.Fallbacks {
				all = append(all, f.TLSConfig)
			}
			for _, tc := range all {
				// verified: the driver checks this connection's certificate.
				verified := tc != nil && !tc.InsecureSkipVerify
				switch {
				case tc == nil:
				case tt.wants && verified:
					if !tc.RootCAs.Equal(want) {
						t.Error("a verified connection is not anchored to the CA's root alone")
					}
					if tc.ServerName == "" {
						t.Error("no server name to check the certificate for")
					}
				case !tt.wants && tc == before && tc.RootCAs != beforeRoots:
					t.Error("the roots of a connection that did not want the CA's were changed")
				}
			}
		})
	}
}

// The CA's root is asked for when a connection is made, not when the
// reader is set up, and a CA that cannot give it yet is a clear failure of
// that read, not a silent fall back to other roots.
func TestCARootIsFetchedOnConnect(t *testing.T) {
	asked := 0
	caDown := func(context.Context) (*x509.Certificate, error) {
		asked++
		return nil, errors.New("pinning the CA's root: connection refused")
	}
	p, err := OpenPostgres("postgres://handrail:"+testPassword+"@db.invalid:5432/stepca?sslmode=verify-full&connect_timeout=2", caDown)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if asked != 0 {
		t.Fatal("the CA's root was asked for before any connection was made")
	}
	_, err = p.Serials(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the CA's root, which is not known yet") || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Serials = %v", err)
	}
	if asked == 0 {
		t.Error("the CA's root was never asked for")
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Error("the error carries the password")
	}

	// A connection that is not verified does not need the CA at all.
	asked = 0
	local, err := OpenPostgres("postgres://handrail:"+testPassword+"@127.0.0.1:1/stepca?sslmode=disable&connect_timeout=2", caDown)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if _, err := local.Serials(context.Background()); err == nil || strings.Contains(err.Error(), "CA's root") {
		t.Errorf("Serials on a local database = %v", err)
	}
	if asked != 0 {
		t.Error("the CA's root was asked for on behalf of an unverified local connection")
	}
}
