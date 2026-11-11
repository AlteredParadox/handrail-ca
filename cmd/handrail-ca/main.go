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

// Command handrail-ca serves the step-ca web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	legal "handrail-ca"
	"handrail-ca/internal/web"
)

// version is stamped at build time by `make build`, the Dockerfile and the
// release workflow via -ldflags "-X main.version=vX.Y.Z". Plain `go build`
// reports "dev".
var version = "dev"

// defaultListen is loopback: nothing here is authenticated yet.
const defaultListen = "127.0.0.1:8080"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is main without the process: it returns the exit code, so the tests
// can drive every path. It serves until ctx is cancelled.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintln(stdout, "handrail-ca", version)
			return 0
		case "healthcheck":
			return healthcheck(args[1:], stderr)
		}
	}
	fs := flag.NewFlagSet("handrail-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr("HANDRAIL_LISTEN", defaultListen), "address to listen on (or set HANDRAIL_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "addr", *listen, "err", err)
		return 1
	}
	log.Info("handrail-ca listening", "addr", ln.Addr().String(), "version", version)
	return serve(ctx, ln, log)
}

// serve answers on ln until ctx is cancelled, then drains in-flight
// requests for up to ten seconds.
func serve(ctx context.Context, ln net.Listener, log *slog.Logger) int {
	srv := &http.Server{
		Handler: web.New(web.Options{
			Version:            version,
			License:            legal.License,
			ThirdPartyLicenses: legal.ThirdPartyLicenses,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Error("shutdown", "err", err)
			return 1
		}
	}
	return 0
}

// healthcheck is the container HEALTHCHECK: the distroless image has no
// shell or curl, so the binary probes its own /healthz. It dials loopback
// on the configured port whatever interface the server is bound to; the
// request never leaves the host, which is why it is plain HTTP.
func healthcheck(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr("HANDRAIL_LISTEN", defaultListen), "the server's listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 2
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
