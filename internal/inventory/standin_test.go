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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// clearPGEnv keeps the PG* environment variables, which the driver reads
// too, out of a test.
func clearPGEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT", "PGSERVICE",
		"PGCHANNELBINDING", "PGREQUIREAUTH",
	} {
		t.Setenv(name, "")
	}
}

// What the first message of a server that is not the database asks for.
const (
	asksNothing   = 0  // AuthenticationOk: come in, no questions asked
	asksClearText = 3  // AuthenticationCleartextPassword
	asksMD5       = 5  // AuthenticationMD5Password
	asksSCRAM     = 10 // AuthenticationSASL
)

// standIn is something on the network that answers for the database and is
// not it: a listener on loopback that speaks enough of PostgreSQL's
// protocol to ask a client to sign in, and keeps what the client sends.
type standIn struct {
	addr string
	mu   sync.Mutex
	got  bytes.Buffer
	done chan struct{}
}

// sent is everything the client sent after the connection was set up, once
// the client has gone.
func (s *standIn) sent(t *testing.T) string {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stand-in is still waiting for the client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got.String()
}

// newStandIn starts one. With a certificate it speaks TLS, as a database on
// another machine must; ask is its first message. mechanisms are what it
// offers when it asks for SCRAM.
func newStandIn(t *testing.T, cert *tls.Certificate, ask uint32, mechanisms ...string) *standIn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{addr: ln.Addr().String(), done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var first sync.Once
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer first.Do(func() { close(s.done) })
				defer conn.Close()
				s.serve(conn, cert, ask, mechanisms)
			}()
		}
	}()
	return s
}

// cancelRequest is the code of the message with which the driver, giving
// up on a statement, asks on a connection of its own for it to be cancelled.
const cancelRequest = 80877102

func (s *standIn) serve(conn net.Conn, cert *tls.Certificate, ask uint32, mechanisms []string) {
	// One that lets the client in and then says nothing would otherwise
	// keep the client's pool from closing until this ran out.
	patience := 10 * time.Second
	if ask == asksNothing {
		patience = 2 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(patience))
	if cert != nil {
		// SSLRequest, answered "S", then the handshake.
		if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
			return
		}
		if _, err := conn.Write([]byte("S")); err != nil {
			return
		}
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			return
		}
		conn = secure
	}
	// The startup message: its length, then that much.
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	startup := make([]byte, binary.BigEndian.Uint32(size[:])-4)
	if _, err := io.ReadFull(conn, startup); err != nil {
		return
	}
	if len(startup) >= 4 && binary.BigEndian.Uint32(startup) == cancelRequest {
		return
	}
	body := binary.BigEndian.AppendUint32(nil, ask)
	switch ask {
	case asksMD5:
		body = append(body, 1, 2, 3, 4) // the salt
	case asksSCRAM:
		for _, m := range mechanisms {
			body = append(append(body, m...), 0)
		}
		body = append(body, 0)
	}
	msg := append([]byte{'R'}, binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))...)
	msg = append(msg, body...)
	if ask == asksNothing {
		msg = append(msg, 'Z', 0, 0, 0, 5, 'I') // ReadyForQuery
	}
	if _, err := conn.Write(msg); err != nil {
		return
	}
	// What the client says next is kept, and nothing more is answered. One
	// that was let in without a question is left waiting; any other is hung
	// up on once it has said something.
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		s.mu.Lock()
		s.got.Write(buf[:n])
		s.mu.Unlock()
		if err != nil || ask != asksNothing {
			return
		}
	}
}

// A root, and a certificate from it for the database's name: what the CA
// gives whoever may ask it for a certificate with that name.
func rootAndLeaf(t *testing.T, name string) (*x509.Certificate, *tls.Certificate) {
	t.Helper()
	rootDER := newDER(t, "7101", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Test Root CA"}
		c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign
		c.NotBefore, c.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	})
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(7102),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &testKey.PublicKey, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return root, &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: testKey}
}

// A certificate from the CA for the database's name is not the database:
// the CA issues certificates, to handrail-ca's own operators among others.
// A peer that holds one and is reached in the database's place passes the
// TLS check. It must not be given the role's password for that, nor taken
// for the database without having shown that it knows the password itself.
func TestAPeerWithTheCAsCertificateIsNotTakenForTheDatabase(t *testing.T) {
	clearPGEnv(t)
	const name = "db.internal.example"
	root, cert := rootAndLeaf(t, name)
	caRoot := func(context.Context) (*x509.Certificate, error) { return root, nil }
	read := func(t *testing.T, peer *standIn, extra string) (string, error) {
		t.Helper()
		_, port, _ := net.SplitHostPort(peer.addr)
		conn := "postgres://handrail:" + testPassword + "@" + name + ":" + port + "/stepca?sslmode=verify-full&connect_timeout=5" + extra
		p, err := openPostgres(conn, caRoot, func(cfg *pgxpool.Config) {
			cfg.ConnConfig.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
		})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = p.Serials(ctx)
		return peer.sent(t), err
	}

	for _, tt := range []struct {
		name       string
		ask        uint32
		mechanisms []string
	}{
		{"asks for the password in clear", asksClearText, nil},
		{"asks for the password hashed with MD5", asksMD5, nil},
		{"asks for nothing", asksNothing, nil},
		{"offers SCRAM that is not bound to the certificate", asksSCRAM, []string{"SCRAM-SHA-256"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := read(t, newStandIn(t, cert, tt.ask, tt.mechanisms...), "")
			if err == nil {
				t.Error("the peer was taken for the database")
			}
			if got != "" {
				t.Errorf("the peer was sent %d bytes after its first message: %q", len(got), got)
			}
			if err != nil && strings.Contains(err.Error(), testPassword) {
				t.Errorf("the error carries the password: %v", err)
			}
		})
	}

	// The check of this test itself: with both requirements switched off in
	// the connection string, the same peer is sent the password.
	t.Run("with the requirements switched off", func(t *testing.T) {
		got, _ := read(t, newStandIn(t, cert, asksClearText), "&channel_binding=disable&require_auth=password")
		if !strings.Contains(got, testPassword) {
			t.Errorf("the stand-in did not get the password it asked for (got %q): this test proves nothing", got)
		}
	})
}

func TestARemoteDatabaseMustSignInWithBoundSCRAM(t *testing.T) {
	clearPGEnv(t)
	const remote = "postgres://handrail:" + testPassword + "@db.internal.example/stepca?sslmode=verify-full"
	note := "channel binding is switched off"
	tests := []struct {
		name, conn    string
		env           [2]string
		binding, auth string
		unbound       bool
	}{
		{"another machine", remote, [2]string{}, "require", "scram-sha-256", false},
		{"another machine, prefer written out", remote + "&channel_binding=prefer", [2]string{}, "require", "scram-sha-256", false},
		{"another machine, switched off", remote + "&channel_binding=disable", [2]string{}, "disable", "scram-sha-256", true},
		{"another machine, switched off in the environment", remote, [2]string{"PGCHANNELBINDING", "disable"}, "disable", "scram-sha-256", true},
		{"another machine, its own require_auth", remote + "&require_auth=scram-sha-256,none", [2]string{}, "require", "scram-sha-256,none", false},
		{"another machine behind a local one", "postgres://handrail:" + testPassword + "@127.0.0.1:5432,db.internal.example:5432/stepca?sslmode=verify-full", [2]string{}, "require", "scram-sha-256", false},
		{"keyword form", "host=db.internal.example user=handrail password=" + testPassword + " dbname=stepca sslmode=verify-full", [2]string{}, "require", "scram-sha-256", false},
		// This machine: as the string has it.
		{"this machine", "postgres://handrail:" + testPassword + "@127.0.0.1/stepca?sslmode=disable", [2]string{}, "prefer", "", false},
		{"a socket", "host=/var/run/postgresql user=handrail password=" + testPassword + " dbname=stepca", [2]string{}, "prefer", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env[0] != "" {
				t.Setenv(tt.env[0], tt.env[1])
			}
			p, err := OpenPostgres(tt.conn, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			c := p.pool.Config().ConnConfig
			if c.ChannelBinding != tt.binding || c.RequireAuth != tt.auth {
				t.Errorf("channel_binding=%q require_auth=%q, want %q and %q", c.ChannelBinding, c.RequireAuth, tt.binding, tt.auth)
			}
			if got := strings.Contains(p.Describe(), note); got != tt.unbound {
				t.Errorf("Describe = %q", p.Describe())
			}
			if strings.Contains(p.Describe(), testPassword) {
				t.Errorf("Describe carries the password: %q", p.Describe())
			}
		})
	}
}

// A database that stops answering without closing the connection is a read
// that failed, in a time that is bounded on this side: not a read that
// never reports, behind which the picture read before goes on looking
// current.
func TestADatabaseThatStopsAnsweringIsAFailedRead(t *testing.T) {
	clearPGEnv(t)
	before := queryTimeout
	queryTimeout = 300 * time.Millisecond
	t.Cleanup(func() { queryTimeout = before })

	// It lets the client in and then says nothing more.
	silent := newStandIn(t, nil, asksNothing)
	p, err := OpenPostgres("postgres://handrail:"+testPassword+"@"+silent.addr+"/stepca?sslmode=disable", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for name, call := range map[string]func(context.Context) error{
		"Serials":      func(ctx context.Context) error { _, err := p.Serials(ctx); return err },
		"Certificates": func(ctx context.Context) error { _, err := p.Certificates(ctx, []string{"1"}); return err },
		"Revocations":  func(ctx context.Context) error { _, err := p.Revocations(ctx); return err },
	} {
		began := time.Now()
		err := call(context.Background())
		if err == nil || !strings.Contains(err.Error(), "the database did not answer within 300ms") {
			t.Errorf("%s = %v", name, err)
		}
		if took := time.Since(began); took > 5*time.Second {
			t.Errorf("%s gave up after %v", name, took)
		}
	}
	inv := New(p)
	if err := inv.Refresh(context.Background()); err == nil || !strings.Contains(inv.Snapshot().State.Problem, "did not answer") {
		t.Errorf("Refresh = %v, state %+v", err, inv.Snapshot().State)
	}

	// A caller who gives up first gets its own error, not this one.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.Serials(ctx); err == nil || strings.Contains(err.Error(), "did not answer") {
		t.Errorf("Serials under the caller's own deadline = %v", err)
	}
}
