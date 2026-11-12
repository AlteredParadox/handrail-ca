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

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"handrail-ca/internal/store"
)

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version"} {
		var out bytes.Buffer
		if code := run(context.Background(), []string{arg}, nil, &out, io.Discard); code != 0 {
			t.Errorf("run(%q) = %d, want 0", arg, code)
		}
		if got, want := out.String(), "handrail-ca "+version+"\n"; got != want {
			t.Errorf("run(%q) printed %q, want %q", arg, got, want)
		}
	}
}

func TestRunBadFlag(t *testing.T) {
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"-no-such-flag"}, nil, io.Discard, &errOut); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "no-such-flag") {
		t.Errorf("stderr %q does not name the flag", errOut.String())
	}
}

// testFingerprint is a well-formed root fingerprint that is no CA's.
var testFingerprint = strings.Repeat("ab", 32)

// dbURLFile writes a connection string for a database nothing listens on.
func dbURLFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db_url")
	if err := os.WriteFile(path, []byte("postgres://handrail:not-a-real-password@127.0.0.1:1/stepca?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// serverArgs is a complete configuration: a fresh data directory, a CA
// address nothing listens on, a root fingerprint, and a database nothing
// listens on.
func serverArgs(t *testing.T, listen string, more ...string) []string {
	t.Helper()
	clearEnv(t)
	return append([]string{"-listen", listen, "-data", t.TempDir(), "-ca-url", "https://ca.invalid:9000", "-ca-fingerprint", testFingerprint, "-db-url-file", dbURLFile(t)}, more...)
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HANDRAIL_LISTEN", "HANDRAIL_DATA", "HANDRAIL_CA_URL", "HANDRAIL_CA_FINGERPRINT", "HANDRAIL_DB_URL_FILE", "HANDRAIL_PUBLIC_URL", "HANDRAIL_TRUSTED_PROXIES"} {
		t.Setenv(name, "")
	}
}

func TestRunListenFailure(t *testing.T) {
	// The port is taken for the length of the test, so the listen must fail.
	ln := listenLoopback(t)
	defer ln.Close()
	var errOut bytes.Buffer
	code := run(context.Background(), serverArgs(t, ln.Addr().String()), nil, io.Discard, &errOut)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "listen") {
		t.Errorf("stderr %q does not report the listen error", errOut.String())
	}
}

// An empty store on loopback starts, and says what to do next. Cancelling
// the context is the SIGTERM path: run drains and exits 0.
func TestRunStartsWithoutAccountsOnLoopback(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errOut syncBuffer
	done := make(chan int, 1)
	args := serverArgs(t, addr)
	go func() { done <- run(ctx, args, nil, io.Discard, &errOut) }()
	waitForHealth(t, addr, &errOut)
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit code = %d, want 0: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "no accounts yet") {
		t.Errorf("no hint about adding an account: %s", errOut.String())
	}
}

// An https public URL means a proxy is in front. Without being told which,
// handrail-ca says at start what that costs; told, it does not.
func TestRunWarnsAboutAnUndeclaredProxy(t *testing.T) {
	const warning = "no -trusted-proxy"
	for name, tt := range map[string]struct {
		more []string
		want bool
	}{
		"undeclared": {[]string{"-public-url", "https://handrail.example"}, true},
		"declared":   {[]string{"-public-url", "https://handrail.example", "-trusted-proxy", "127.0.0.1, 10.20.0.0/16"}, false},
		"plain HTTP": {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			addr := freeAddr(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var errOut syncBuffer
			done := make(chan int, 1)
			args := serverArgs(t, addr, tt.more...)
			go func() { done <- run(ctx, args, nil, io.Discard, &errOut) }()
			waitForHealth(t, addr, &errOut)
			cancel()
			if code := <-done; code != 0 {
				t.Fatalf("exit code = %d: %s", code, errOut.String())
			}
			if got := strings.Contains(errOut.String(), warning); got != tt.want {
				t.Errorf("warning present = %v, want %v: %s", got, tt.want, errOut.String())
			}
		})
	}
}

// waitForHealth returns once the server at addr answers its health probe.
func waitForHealth(t *testing.T, addr string, log *syncBuffer) {
	t.Helper()
	var err error
	for range 200 {
		var resp *http.Response
		if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ok"`) {
				t.Fatalf("GET /healthz = %d %q", resp.StatusCode, body)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the server did not come up: %v\n%s", err, log.String())
}

func TestRunRefusesAnIncompleteConfiguration(t *testing.T) {
	root, db := testFingerprint, dbURLFile(t)
	remoteDB := filepath.Join(t.TempDir(), "remote")
	if err := os.WriteFile(remoteDB, []byte("postgres://handrail:hunter2hunter2@db.internal.example/stepca?sslmode=require"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyDB := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyDB, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataIsAFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(dataIsAFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	clearEnv(t)
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"nothing", nil, 2, "not configured: -data (HANDRAIL_DATA), -ca-url (HANDRAIL_CA_URL), -ca-fingerprint (HANDRAIL_CA_FINGERPRINT), -db-url-file (HANDRAIL_DB_URL_FILE)"},
		{"no CA", []string{"-data", data}, 2, "not configured: -ca-url (HANDRAIL_CA_URL), -ca-fingerprint"},
		{"trusted proxy by name", []string{"-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db, "-trusted-proxy", "proxy.internal.example"}, 2, "-trusted-proxy: invalid IP address or CIDR range: proxy.internal.example"},
		{"stray argument", []string{"-data", data, "serve"}, 2, `unexpected argument "serve"`},
		{"data directory is a file", []string{"-data", dataIsAFile, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db}, 1, "opening the store"},
		{"fingerprint is not one", []string{"-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", "root_ca.crt", "-db-url-file", db}, 1, "64 hexadecimal characters"},
		{"no database file", []string{"-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", filepath.Join(data, "none")}, 1, "reading the database connection file"},
		{"empty database file", []string{"-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", emptyDB}, 1, "is empty"},
		{"database on another machine without verified TLS", []string{"-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", remoteDB}, 1, "sslmode=verify-full"},
		{"CA over plain HTTP", []string{"-data", data, "-ca-url", "http://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db}, 1, "must start with https://"},
		{"bad public URL", []string{"-listen", "127.0.0.1:0", "-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db, "-public-url", "handrail.example"}, 1, "-public-url"},
		{"plain HTTP public URL beyond this machine", []string{"-listen", "127.0.0.1:0", "-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db, "-public-url", "http://handrail.example"}, 1, "only accepted for a loopback address"},
		{"beyond loopback without a public URL", []string{"-listen", "0.0.0.0:0", "-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db}, 1, "-public-url (HANDRAIL_PUBLIC_URL) is required"},
		{"beyond loopback without an account", []string{"-listen", "0.0.0.0:0", "-data", data, "-ca-url", "https://ca.invalid", "-ca-fingerprint", root, "-db-url-file", db, "-public-url", "https://handrail.example"}, 1, "no accounts yet"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errOut bytes.Buffer
			code := run(context.Background(), tt.args, nil, io.Discard, &errOut)
			if code != tt.code || !strings.Contains(errOut.String(), tt.want) {
				t.Errorf("exit %d, stderr %q; want %d and %q", code, errOut.String(), tt.code, tt.want)
			}
		})
	}
}

func TestResolvePublicURL(t *testing.T) {
	loopback := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	v6 := &net.TCPAddr{IP: net.IPv6loopback, Port: 8080}
	anywhere := &net.TCPAddr{IP: net.IPv4zero, Port: 8080}
	tests := []struct {
		name, configured string
		addr             net.Addr
		want             string
	}{
		{"loopback default", "", loopback, "http://127.0.0.1:8080"},
		{"IPv6 loopback default", "", v6, "http://[::1]:8080"},
		{"configured on loopback", "https://handrail.example/ca/", loopback, "https://handrail.example/ca/"},
		{"configured beyond loopback", "https://handrail.example", anywhere, "https://handrail.example"},
		{"required beyond loopback", "", anywhere, ""},
		{"no scheme", "handrail.example", anywhere, ""},
		{"with credentials", "https://u:p@handrail.example", anywhere, ""},
		{"with query", "https://handrail.example/?a=b", anywhere, ""},
		{"unparseable", "https://handrail.example:port", anywhere, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := config{publicURL: tt.configured}.resolvePublicURL(tt.addr)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("accepted, as %v", u)
				}
				return
			}
			if err != nil || u.String() != tt.want {
				t.Fatalf("got %v, %v; want %s", u, err, tt.want)
			}
		})
	}
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln := listenLoopback(t)
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// The whole program: configure, add an account, serve, probe, stop.
func TestRunServesAndHealthcheck(t *testing.T) {
	addr := freeAddr(t)
	args := serverArgs(t, addr)
	data := args[3]
	if code := run(context.Background(), []string{"user", "add", "-data", data, "alice"}, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("user add = %d", code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errOut syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, nil, io.Discard, &errOut) }()

	waitForHealth(t, addr, &errOut)
	// The pages are there, and want a sign-in.
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") || !strings.Contains(string(body), "ca.invalid") {
		t.Errorf("GET / ended at %d %q", resp.StatusCode, resp.Request.URL)
	}

	if code := healthcheck([]string{"-listen", addr}, io.Discard); code != 0 {
		t.Errorf("healthcheck against a live server = %d, want 0", code)
	}
	// The container binds the wildcard address, which cannot be dialled:
	// the probe goes to loopback on that port.
	_, port, _ := net.SplitHostPort(addr)
	if code := healthcheck([]string{"-listen", "0.0.0.0:" + port}, io.Discard); code != 0 {
		t.Errorf("healthcheck with a wildcard listen address = %d, want 0", code)
	}
	if strings.Contains(errOut.String(), "no accounts yet") {
		t.Error("warned about accounts although one exists")
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run returned %d after cancel, want 0", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after cancel")
	}

	var probeErr bytes.Buffer
	if code := healthcheck([]string{"-listen", addr}, &probeErr); code != 1 {
		t.Errorf("healthcheck against a stopped server = %d, want 1", code)
	}
	if !strings.Contains(probeErr.String(), "healthcheck:") {
		t.Errorf("stderr %q does not report the failure", probeErr.String())
	}
}

// syncBuffer is a buffer the server's log can write to while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// serve reports a listener that fails underneath it rather than hanging.
func TestServeListenerClosed(t *testing.T) {
	ln := listenLoopback(t)
	ln.Close()
	if code := serve(context.Background(), ln, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil))); code != 1 {
		t.Errorf("serve on a closed listener = %d, want 1", code)
	}
}

func TestSweepSessionsStopsWithTheContext(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sweepSessions(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep did not stop")
	}
}

func TestProbeHost(t *testing.T) {
	tests := []struct{ listen, want string }{
		{"", "127.0.0.1"},
		{"0.0.0.0", "127.0.0.1"},
		{"::", "::1"},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"192.0.2.10", "192.0.2.10"},
		{"2001:db8::10", "2001:db8::10"},
		{"localhost", "localhost"},
	}
	for _, tt := range tests {
		if got := probeHost(tt.listen); got != tt.want {
			t.Errorf("probeHost(%q) = %q, want %q", tt.listen, got, tt.want)
		}
	}
}

// A server bound to IPv6 loopback only does not answer on 127.0.0.1: the
// probe has to follow the configured address.
func TestHealthcheckIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	if code := healthcheck([]string{"-listen", ln.Addr().String()}, io.Discard); code != 0 {
		t.Errorf("healthcheck against %s = %d, want 0", ln.Addr(), code)
	}
}

func TestHealthcheckNonOK(t *testing.T) {
	ln := listenLoopback(t)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	var errOut bytes.Buffer
	if code := healthcheck([]string{"-listen", ln.Addr().String()}, &errOut); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "503") {
		t.Errorf("stderr %q does not carry the status", errOut.String())
	}
}

func TestHealthcheckBadArgs(t *testing.T) {
	for _, args := range [][]string{{"-listen", "no-port"}, {"-no-such-flag"}} {
		if code := healthcheck(args, io.Discard); code != 2 {
			t.Errorf("healthcheck(%q) = %d, want 2", args, code)
		}
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("HANDRAIL_TEST_ENVOR", "")
	if got := envOr("HANDRAIL_TEST_ENVOR", "fallback"); got != "fallback" {
		t.Errorf("empty variable: got %q, want the fallback", got)
	}
	t.Setenv("HANDRAIL_TEST_ENVOR", "set")
	if got := envOr("HANDRAIL_TEST_ENVOR", "fallback"); got != "set" {
		t.Errorf("set variable: got %q, want %q", got, "set")
	}
}

// A database that stays down is one line in the log, not one every thirty
// seconds; a different failure, and the recovery, are each said once.
func TestInventoryLogSaysEachChangeOnce(t *testing.T) {
	var buf bytes.Buffer
	report := inventoryLog(slog.New(slog.NewTextHandler(&buf, nil)))
	down, denied := errors.New("connection refused"), errors.New("permission denied")
	for _, err := range []error{nil, nil, down, down, down, denied, denied, nil, nil, down} {
		report(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var got []string
	for _, l := range lines {
		switch {
		case strings.Contains(l, "connection refused"):
			got = append(got, "down")
		case strings.Contains(l, "permission denied"):
			got = append(got, "denied")
		case strings.Contains(l, "being read again"):
			got = append(got, "recovered")
		default:
			got = append(got, "?")
		}
	}
	if strings.Join(got, ",") != "down,denied,recovered,down" {
		t.Errorf("logged %v:\n%s", got, buf.String())
	}
}
