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
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
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
			p, err := OpenPostgres(tt.conn)
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

func TestOpenPostgresDoesNotEchoWhatItCannotParse(t *testing.T) {
	for _, conn := range []string{
		"postgres://handrail:" + testPassword + "@127.0.0.1:notaport/stepca",
		"host=127.0.0.1 password=" + testPassword + " sslmode=bogus",
		"postgres://handrail:" + testPassword + "@127.0.0.1/stepca?pool_max_conns=many",
		"password='" + testPassword,
	} {
		_, err := OpenPostgres(conn)
		if err == nil {
			t.Errorf("accepted %q", strings.ReplaceAll(conn, testPassword, "…"))
			continue
		}
		if strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), "handrail:") {
			t.Errorf("the error repeats the connection string: %q", err)
		}
	}
	// The read-only setting cannot be turned off from the string.
	p, err := OpenPostgres("postgres://handrail:" + testPassword + "@127.0.0.1/stepca?sslmode=disable&default_transaction_read_only=off&statement_timeout=0")
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
	p, err := OpenPostgres("postgres://handrail:" + testPassword + "@127.0.0.1:1/stepca?sslmode=disable&connect_timeout=2")
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
