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
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits on what is taken from the database. step-ca stores a certificate's
// DER and two small JSON documents; anything far beyond that is not one.
const (
	maxDER  = 64 << 10
	maxJSON = 16 << 10
	maxRows = 5_000_000
	// maxMessage bounds one message from the server. The largest a
	// handrail-ca query asks for is one row of Certificates: a key, a DER
	// of at most maxDER and a document of at most maxJSON. Without it the
	// driver takes messages up to 1 GiB from whoever answers.
	maxMessage = 1 << 20
	pgTimeout  = 30 * time.Second
)

// queryTimeout bounds one call from this side as well, the pool's check of
// an idle connection included. statement_timeout is kept by the server,
// which is no help when the server, or the path to it, has stopped
// answering: a read that hangs would otherwise report nothing, and the
// picture read before it would go on looking current. A variable for the
// tests, which cannot wait that long.
var queryTimeout = pgTimeout + 10*time.Second

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
//
// A certificate from that CA for the database's name is not proof of being
// the database: the CA issues certificates, to handrail-ca's own operators
// among others. So a database on another machine must also sign in with
// SCRAM bound to the certificate this client saw (see requireBoundSCRAM).
func OpenPostgres(connString string, caRoot RootFunc) (*Postgres, error) {
	return openPostgres(connString, caRoot, nil)
}

// openPostgres is OpenPostgres with a last word on the configuration, for
// the tests that have to reach a database under a name the machine they
// run on cannot resolve.
func openPostgres(connString string, caRoot RootFunc, adjust func(*pgxpool.Config)) (*Postgres, error) {
	connString = strings.TrimSpace(connString)
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		// Not wrapped: the text of a parse error can repeat the string it
		// could not parse, password included.
		return nil, errNotUnderstood
	}
	if !plausible(&cfg.ConnConfig.Config, connString) {
		// As for a string that does not parse: nothing from it is repeated.
		// A string written wrongly can parse all the same, with the
		// password, or a part of it, as the host, the database or the user,
		// all of which are shown and logged.
		return nil, errNotUnderstood
	}
	if err := checkTransport(&cfg.ConnConfig.Config); err != nil {
		return nil, err
	}
	unbound := requireBoundSCRAM(&cfg.ConnConfig.Config)
	// Every session is read-only whatever the account's own default is,
	// and no query runs for ever.
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(pgTimeout.Milliseconds())
	cfg.ConnConfig.RuntimeParams["application_name"] = "handrail-ca"
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	cfg.MaxConns, cfg.MinConns = 2, 0
	cfg.ConnConfig.MaxProtocolMessageBodyLen = maxMessage
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
	describe := fmt.Sprintf("PostgreSQL database %q at %s, as %q, read-only", clip(c.Database), clip(net.JoinHostPort(c.Host, fmt.Sprint(c.Port))), clip(c.User))
	if unbound {
		describe += "; channel binding is switched off in the connection string, so any holder of a certificate from the CA for that name could stand in for the database"
	}
	return &Postgres{pool: pool, describe: describe}, nil
}

var errNotUnderstood = errors.New("the database connection string could not be understood (want postgres://user:password@host:port/database?sslmode=verify-full, or libpq's keyword=value form; " +
	"in a URL, percent-encode every character of the password that is not a letter, a digit, '-', '.', '_' or '~')")

var (
	plainHost   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	plainSocket = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,254}$`)
	plainName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}$`)
)

// plausible reports whether what the driver made of the connection string
// can be what was meant, and so can be shown and logged: every host an IP
// address, a host name or a socket directory, the database and the user
// plain names, and, in a URL, a user named in the URL itself.
//
// The driver is forgiving. A password that begins with a slash ends the
// part of a URL it looks for the user and password in, and the rest becomes
// the database's name; an unencoded "@" in a password moves its tail into
// the host; in the keyword form a missing space joins the next keyword to
// the host. Each of those parses.
func plausible(c *pgconn.Config, connString string) bool {
	hosts := []string{c.Host}
	for _, f := range c.Fallbacks {
		hosts = append(hosts, f.Host)
	}
	for _, h := range hosts {
		if net.ParseIP(h) == nil && !plainHost.MatchString(h) && !plainSocket.MatchString(h) {
			return false
		}
	}
	if !plainName.MatchString(c.Database) || !plainName.MatchString(c.User) {
		return false
	}
	// The driver, like libpq, takes what precedes an "@" as the user and
	// password only if no "/" comes first. A URL in which it found neither
	// would be used with the name of the account the process runs as, which
	// is never what was meant here.
	for _, scheme := range []string{"postgres://", "postgresql://"} {
		if rest, ok := strings.CutPrefix(connString, scheme); ok {
			if i := strings.IndexAny(rest, "@/"); i < 0 || rest[i] != '@' {
				return false
			}
		}
	}
	return true
}

// requireBoundSCRAM makes a database on another machine prove more than a
// certificate from the CA for its name, which the CA will issue to whoever
// may ask it for one. Unless the connection string says otherwise:
//
//   - the only way of signing in that is accepted is SCRAM-SHA-256
//     (require_auth), so a peer that asks for the password in clear, or
//     hashed the old way, is refused before anything is sent to it; and
//   - the exchange is bound to the server certificate this client saw
//     (channel_binding=require), so a peer holding another certificate can
//     neither complete it nor pass it on to the real server and back.
//
// PostgreSQL has both since version 11, and stores passwords this way by
// default since 14. channel_binding=disable in the connection string opts
// out, for a server or a pooler in front of it that cannot do it;
// unbound reports that, and the description of the source then says so.
// What this does not close: a peer that offers SCRAM is sent a proof made
// from the password before it has proved anything itself, enough to test
// guesses of the password against. The role's password should be long and
// random (docs/ca-setup.md).
func requireBoundSCRAM(c *pgconn.Config) (unbound bool) {
	if !anyRemote(c) {
		return false
	}
	if c.RequireAuth == "" {
		c.RequireAuth = "scram-sha-256"
	}
	if c.ChannelBinding == "disable" {
		return true
	}
	c.ChannelBinding = "require"
	return false
}

// anyRemote reports whether any host the driver might try is another
// machine.
func anyRemote(c *pgconn.Config) bool {
	if !localHost(c.Host) {
		return true
	}
	for _, f := range c.Fallbacks {
		if !localHost(f.Host) {
			return true
		}
	}
	return false
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
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	serials, err := p.serials(bounded)
	return serials, overdue(ctx, err)
}

// overdue says in plain words that a call ran into queryTimeout, which
// from the driver is the same "context deadline exceeded" as any other.
// A deadline of the caller's own is left as it is.
func overdue(caller context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && caller.Err() == nil {
		return fmt.Errorf("the database did not answer within %s", queryTimeout)
	}
	return err
}

func (p *Postgres) serials(ctx context.Context) ([]string, error) {
	// A key longer than maxKey is not transferred; the read fails, naming
	// the table, and the picture read before is kept.
	rows, err := p.pool.Query(ctx, `
		SELECT CASE WHEN octet_length(nkey) <= $1 THEN nkey END, octet_length(nkey) > $1
		  FROM x509_certs`, maxKey)
	if err != nil {
		return nil, plain(err)
	}
	defer rows.Close()
	var serials []string
	for rows.Next() {
		var key []byte
		var tooLong bool
		if err := rows.Scan(&key, &tooLong); err != nil {
			return nil, plain(err)
		}
		serial, err := keyFrom("x509_certs", key, tooLong)
		if err != nil {
			return nil, err
		}
		if len(serials) >= maxRows {
			return nil, fmt.Errorf("more than %d certificates in the database", maxRows)
		}
		serials = append(serials, serial)
	}
	return serials, plain(rows.Err())
}

// Certificates returns the rows for the given keys, each with the issuance
// record stored under the same key. A value larger than a certificate can
// be is not transferred: the row comes back marked TooLarge.
func (p *Postgres) Certificates(ctx context.Context, serials []string) ([]RawCertificate, error) {
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := p.certificates(bounded, serials)
	return out, overdue(ctx, err)
}

func (p *Postgres) certificates(ctx context.Context, serials []string) ([]RawCertificate, error) {
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
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := p.revocations(bounded)
	return out, overdue(ctx, err)
}

func (p *Postgres) revocations(ctx context.Context) ([]RawRevocation, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT CASE WHEN octet_length(nkey) <= $2 THEN nkey END, octet_length(nkey) > $2,
		       CASE WHEN octet_length(nvalue) <= $1 THEN nvalue END
		  FROM revoked_x509_certs`, maxJSON, maxKey)
	if err != nil {
		return nil, plain(err)
	}
	defer rows.Close()
	var out []RawRevocation
	for rows.Next() {
		var key, value []byte
		var tooLong bool
		if err := rows.Scan(&key, &tooLong, &value); err != nil {
			return nil, plain(err)
		}
		serial, err := keyFrom("revoked_x509_certs", key, tooLong)
		if err != nil {
			return nil, err
		}
		if len(out) >= maxRows {
			return nil, fmt.Errorf("more than %d revocations in the database", maxRows)
		}
		out = append(out, RawRevocation{Serial: serial, JSON: value})
	}
	return out, plain(rows.Err())
}

// keyFrom is the key of a row of table as the queries return it: the key,
// or nothing and tooLong for one longer than maxKey, which fails the read.
// The error does not repeat the key.
func keyFrom(table string, key []byte, tooLong bool) (string, error) {
	if tooLong || len(key) > maxKey {
		return "", fmt.Errorf("a row of %s has a key of more than %d bytes", table, maxKey)
	}
	return string(key), nil
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
