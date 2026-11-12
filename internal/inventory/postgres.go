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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits on what is taken from the database. step-ca stores a certificate's
// DER and two small JSON documents; anything far beyond that is not one.
const (
	maxDER    = 64 << 10
	maxJSON   = 16 << 10
	maxRows   = 5_000_000
	pgTimeout = 30 * time.Second
)

// Postgres reads the three tables step-ca keeps in PostgreSQL (docs/PLAN.md,
// section 3): x509_certs, x509_certs_data and revoked_x509_certs, each with a
// binary key column nkey and a binary value column nvalue. It only ever
// SELECTs, in sessions that are read-only, and expects an account that can
// do nothing else.
type Postgres struct {
	pool     *pgxpool.Pool
	describe string
}

// RootFunc returns the root certificate of the CA whose database this is.
type RootFunc func(ctx context.Context) (*x509.Certificate, error)

// OpenPostgres prepares a reader for the database a connection string
// names: a postgres:// URL or libpq's keyword=value form. No connection is
// made yet, so handrail-ca can start while the database is down.
//
// A database on another machine must be reached over TLS with the server's
// certificate verified (sslmode=verify-full): the password and every
// certificate cross that connection. On this machine (a loopback address,
// localhost, or a socket) any mode is accepted.
//
// What a verified connection is verified against: the CA's own root, from
// caRoot, unless the connection string names a file with sslrootcert. The
// operator already told handrail-ca which CA to trust, by its fingerprint,
// and that CA can issue the database's certificate, so nothing more has to
// be configured here. The root is asked for when a connection is made, not
// now. caRoot may be nil; then only sslrootcert, or failing that the
// system's roots, apply.
func OpenPostgres(connString string, caRoot RootFunc) (*Postgres, error) {
	return openPostgres(connString, caRoot, nil)
}

// openPostgres is OpenPostgres with a last word on the configuration, for
// the tests that have to reach a database under a name the machine they
// run on cannot resolve.
func openPostgres(connString string, caRoot RootFunc, adjust func(*pgxpool.Config)) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(strings.TrimSpace(connString))
	if err != nil {
		// Not wrapped: the text of a parse error can repeat the string it
		// could not parse, password included.
		return nil, errors.New("the database connection string could not be understood (want postgres://user:password@host:port/database?sslmode=verify-full, or libpq's keyword=value form)")
	}
	if err := checkTransport(&cfg.ConnConfig.Config); err != nil {
		return nil, err
	}
	// Every session is read-only whatever the account's own default is,
	// and no query runs for ever.
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(pgTimeout.Milliseconds())
	cfg.ConnConfig.RuntimeParams["application_name"] = "handrail-ca"
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	cfg.MaxConns, cfg.MinConns = 2, 0
	if caRoot != nil && wantsCARoot(&cfg.ConnConfig.Config) {
		cfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
			root, err := caRoot(ctx)
			if err != nil {
				return fmt.Errorf("the database's certificate is checked against the CA's root, which is not known yet: %w", err)
			}
			trustCARoot(&cc.Config, root)
			return nil
		}
	}

	if adjust != nil {
		adjust(cfg)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, errors.New("the database connection could not be set up")
	}
	c := cfg.ConnConfig
	return &Postgres{
		pool:     pool,
		describe: fmt.Sprintf("PostgreSQL database %q at %s, as %q, read-only", clip(c.Database), clip(net.JoinHostPort(c.Host, fmt.Sprint(c.Port))), clip(c.User)),
	}, nil
}

// checkTransport refuses a configuration that would talk to another
// machine without verified TLS. Every host the driver might try counts,
// the fallbacks included: sslmode=prefer, for one, means "TLS without
// verification, and failing that no TLS at all".
func checkTransport(c *pgconn.Config) error {
	type target struct {
		host     string
		verified bool
	}
	targets := []target{{c.Host, c.TLSConfig != nil && !c.TLSConfig.InsecureSkipVerify}}
	for _, f := range c.Fallbacks {
		targets = append(targets, target{f.Host, f.TLSConfig != nil && !f.TLSConfig.InsecureSkipVerify})
	}
	for _, t := range targets {
		if !t.verified && !localHost(t.host) {
			return fmt.Errorf("the database at %q is on another machine, so it must be reached with sslmode=verify-full (TLS, with the server's certificate checked against sslrootcert); "+
				"anything less sends the password and the certificates over a connection that is not known to be the database's", clip(t.host))
		}
	}
	return nil
}

// verifiedWithoutRoots reports whether a TLS configuration verifies the
// server's certificate in full but was given no roots to verify it
// against, which is the case for sslmode=verify-full without sslrootcert.
func verifiedWithoutRoots(c *tls.Config) bool {
	return c != nil && !c.InsecureSkipVerify && c.RootCAs == nil
}

// wantsCARoot reports whether any connection this configuration can make
// is to be verified against the CA's root.
func wantsCARoot(c *pgconn.Config) bool {
	if verifiedWithoutRoots(c.TLSConfig) {
		return true
	}
	for _, f := range c.Fallbacks {
		if verifiedWithoutRoots(f.TLSConfig) {
			return true
		}
	}
	return false
}

// trustCARoot makes the CA's root the only trust anchor of every verified
// connection in c that was not given roots of its own. Without it such a
// connection would be checked against the system's roots, which a
// database with a certificate from a private CA can never satisfy, and
// which would accept a certificate for the same name from any public CA.
func trustCARoot(c *pgconn.Config, root *x509.Certificate) {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if verifiedWithoutRoots(c.TLSConfig) {
		c.TLSConfig.RootCAs = pool
	}
	for _, f := range c.Fallbacks {
		if verifiedWithoutRoots(f.TLSConfig) {
			f.TLSConfig.RootCAs = pool
		}
	}
}

// localHost reports whether a database host can only mean this machine: a
// socket directory, localhost, or a loopback address.
func localHost(host string) bool {
	if strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close releases the connections.
func (p *Postgres) Close() { p.pool.Close() }

// Describe says where the rows come from, without the password.
func (p *Postgres) Describe() string { return p.describe }

// Serials lists the key of every issued certificate.
func (p *Postgres) Serials(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT nkey FROM x509_certs`)
	if err != nil {
		return nil, plain(err)
	}
	defer rows.Close()
	var serials []string
	for rows.Next() {
		var key []byte
		if err := rows.Scan(&key); err != nil {
			return nil, plain(err)
		}
		if len(serials) >= maxRows {
			return nil, fmt.Errorf("more than %d certificates in the database", maxRows)
		}
		serials = append(serials, string(key))
	}
	return serials, plain(rows.Err())
}

// Certificates returns the rows for the given keys, each with the issuance
// record stored under the same key. A value larger than a certificate can
// be is not transferred: the row comes back marked TooLarge.
func (p *Postgres) Certificates(ctx context.Context, serials []string) ([]RawCertificate, error) {
	keys := make([][]byte, len(serials))
	for i, s := range serials {
		keys[i] = []byte(s)
	}
	rows, err := p.pool.Query(ctx, `
		SELECT c.nkey,
		       CASE WHEN octet_length(c.nvalue) <= $2 THEN c.nvalue END,
		       COALESCE(octet_length(c.nvalue) > $2, false),
		       CASE WHEN octet_length(d.nvalue) <= $3 THEN d.nvalue END
		  FROM x509_certs c
		  LEFT JOIN x509_certs_data d ON d.nkey = c.nkey
		 WHERE c.nkey = ANY($1)`, keys, maxDER, maxJSON)
	if err != nil {
		return nil, plain(err)
	}
	defer rows.Close()
	var out []RawCertificate
	for rows.Next() {
		var (
			key, der, data []byte
			tooLarge       bool
		)
		if err := rows.Scan(&key, &der, &tooLarge, &data); err != nil {
			return nil, plain(err)
		}
		out = append(out, RawCertificate{Serial: string(key), DER: der, TooLarge: tooLarge, Data: data})
	}
	return out, plain(rows.Err())
}

// Revocations returns every revocation the CA has recorded.
func (p *Postgres) Revocations(ctx context.Context) ([]RawRevocation, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT nkey, CASE WHEN octet_length(nvalue) <= $1 THEN nvalue END
		  FROM revoked_x509_certs`, maxJSON)
	if err != nil {
		return nil, plain(err)
	}
	defer rows.Close()
	var out []RawRevocation
	for rows.Next() {
		var key, value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return nil, plain(err)
		}
		if len(out) >= maxRows {
			return nil, fmt.Errorf("more than %d revocations in the database", maxRows)
		}
		out = append(out, RawRevocation{Serial: string(key), JSON: value})
	}
	return out, plain(rows.Err())
}

// plain turns a driver error into one that is safe to show and to log. The
// driver's connection errors name the host, the database and the user, not
// the password; this keeps the server's own message for a refused query
// and otherwise the error as it is, bounded.
func plain(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return fmt.Errorf("the database refused: %s (SQLSTATE %s)", clip(pg.Message), pg.Code)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.New(clip(err.Error()))
}
