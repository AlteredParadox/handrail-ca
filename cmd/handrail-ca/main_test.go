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
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
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
		if code := run(context.Background(), []string{arg}, &out, io.Discard); code != 0 {
			t.Errorf("run(%q) = %d, want 0", arg, code)
		}
		if got, want := out.String(), "handrail-ca "+version+"\n"; got != want {
			t.Errorf("run(%q) printed %q, want %q", arg, got, want)
		}
	}
}

func TestRunBadFlag(t *testing.T) {
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"-no-such-flag"}, io.Discard, &errOut); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "no-such-flag") {
		t.Errorf("stderr %q does not name the flag", errOut.String())
	}
}

func TestRunListenFailure(t *testing.T) {
	// The port is taken for the length of the test, so the listen must fail.
	ln := listenLoopback(t)
	defer ln.Close()
	var errOut bytes.Buffer
	code := run(context.Background(), []string{"-listen", ln.Addr().String()}, io.Discard, &errOut)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "listen") {
		t.Errorf("stderr %q does not report the listen error", errOut.String())
	}
}

// A cancelled context is the SIGTERM path: run binds, serves and exits 0.
func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := run(ctx, []string{"-listen", "127.0.0.1:0"}, io.Discard, io.Discard); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestServeAndHealthcheck(t *testing.T) {
	ln := listenLoopback(t)
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- serve(ctx, ln, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("GET /healthz = %d %q", resp.StatusCode, body)
	}

	if code := healthcheck([]string{"-listen", addr}, io.Discard); code != 0 {
		t.Errorf("healthcheck against a live server = %d, want 0", code)
	}
	// The container binds the wildcard address; the probe must still dial
	// loopback on that port.
	_, port, _ := net.SplitHostPort(addr)
	if code := healthcheck([]string{"-listen", "0.0.0.0:" + port}, io.Discard); code != 0 {
		t.Errorf("healthcheck with a wildcard listen address = %d, want 0", code)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve returned %d after cancel, want 0", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not return after cancel")
	}

	var errOut bytes.Buffer
	if code := healthcheck([]string{"-listen", addr}, &errOut); code != 1 {
		t.Errorf("healthcheck against a stopped server = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "healthcheck:") {
		t.Errorf("stderr %q does not report the failure", errOut.String())
	}
}

// serve reports a listener that fails underneath it rather than hanging.
func TestServeListenerClosed(t *testing.T) {
	ln := listenLoopback(t)
	ln.Close()
	if code := serve(context.Background(), ln, slog.New(slog.NewTextHandler(io.Discard, nil))); code != 1 {
		t.Errorf("serve on a closed listener = %d, want 1", code)
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
