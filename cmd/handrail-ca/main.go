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

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println("handrail-ca", version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
	listen := flag.String("listen", envOr("HANDRAIL_LISTEN", "127.0.0.1:8080"), "address to listen on (or set HANDRAIL_LISTEN)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := &http.Server{
		Addr: *listen,
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "addr", *listen, "err", err)
		os.Exit(1)
	}
	log.Info("handrail-ca listening", "addr", ln.Addr().String(), "version", version)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Error("shutdown", "err", err)
			os.Exit(1)
		}
	}
}

// healthcheck is the container HEALTHCHECK: the distroless image has no
// shell or curl, so the binary probes its own /healthz. It dials loopback
// on the configured port whatever interface the server is bound to.
func healthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	listen := fs.String("listen", envOr("HANDRAIL_LISTEN", "127.0.0.1:8080"), "the server's listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 2
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
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
