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
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	legal "handrail-ca"
	"handrail-ca/internal/ca"
	"handrail-ca/internal/store"
	"handrail-ca/internal/web"
)

// version is stamped at build time by `make build`, the Dockerfile and the
// release workflow via -ldflags "-X main.version=vX.Y.Z". Plain `go build`
// reports "dev".
var version = "dev"

// defaultListen is loopback: reaching handrail-ca from another machine is
// a decision (a public URL, usually a reverse proxy with TLS), not a default.
const defaultListen = "127.0.0.1:8080"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is main without the process: it returns the exit code, so the tests
// can drive every path. It serves until ctx is cancelled.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintln(stdout, "handrail-ca", version)
			return 0
		case "healthcheck":
			return healthcheck(args[1:], stderr)
		case "user":
			return userCommand(ctx, args[1:], stdin, stdout, stderr)
		}
	}
	cfg, code := parseConfig(args, stderr)
	if code != 0 {
		return code
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))

	st, err := store.Open(ctx, cfg.dataDir)
	if err != nil {
		log.Error("opening the store", "err", err)
		return 1
	}
	defer st.Close()

	rootPEM, err := readSmallFile(cfg.caRoot)
	if err != nil {
		log.Error("reading the CA's root certificate", "err", err)
		return 1
	}
	client, err := ca.New(ca.Config{URL: cfg.caURL, RootPEM: rootPEM, UserAgent: "handrail-ca/" + version})
	if err != nil {
		log.Error("CA configuration", "err", err)
		return 1
	}

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Error("listen", "addr", cfg.listen, "err", err)
		return 1
	}
	defer ln.Close()

	publicURL, err := cfg.resolvePublicURL(ln.Addr())
	if err != nil {
		log.Error("configuration", "err", err)
		return 1
	}
	accounts, err := st.CountUsers(ctx)
	if err != nil {
		log.Error("reading the store", "err", err)
		return 1
	}
	if accounts == 0 {
		// With no account nobody can sign in, so nothing is exposed; but a
		// server reachable from elsewhere that nobody can use is a
		// misconfiguration, and it is better to say so than to wait.
		if !isLoopback(ln.Addr()) {
			log.Error("no accounts yet: add one with `handrail-ca user add -role operator NAME` before listening beyond this host")
			return 1
		}
		log.Warn("no accounts yet: add one with `handrail-ca user add -role operator NAME`")
	}

	handler, err := web.New(web.Options{
		Version:            version,
		License:            legal.License,
		ThirdPartyLicenses: legal.ThirdPartyLicenses,
		Store:              st,
		CA:                 client,
		PublicURL:          publicURL,
		TrustedProxies:     cfg.trustedProxies,
		Log:                log,
	})
	if err != nil {
		log.Error("starting", "err", err)
		return 1
	}
	if publicURL.Scheme == "https" && len(cfg.trustedProxies) == 0 {
		// handrail-ca does not speak TLS, so an https address means a
		// proxy is in front, and every visitor arrives from its address.
		log.Warn("no -trusted-proxy (HANDRAIL_TRUSTED_PROXIES) is set: visitors cannot be told apart, " +
			"so sign-in attempts are limited per user name only and the history records the proxy's address")
	}
	go sweepSessions(ctx, st, log)

	log.Info("handrail-ca listening", "addr", ln.Addr().String(), "url", publicURL.String(), "ca", client.URL(), "version", version)
	return serve(ctx, ln, handler, log)
}

// config is what the server is started with. Secrets are never flags: the
// only file named here is the CA's root certificate, which is public.
type config struct {
	listen    string
	dataDir   string
	caURL     string
	caRoot    string
	publicURL string
	// trustedProxies is the -trusted-proxy list, parsed.
	trustedProxies []netip.Prefix
}

func parseConfig(args []string, stderr io.Writer) (config, int) {
	var cfg config
	fs := flag.NewFlagSet("handrail-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.listen, "listen", envOr("HANDRAIL_LISTEN", defaultListen), "address to listen on (or set HANDRAIL_LISTEN)")
	fs.StringVar(&cfg.dataDir, "data", os.Getenv("HANDRAIL_DATA"), "directory for handrail-ca's own store (or set HANDRAIL_DATA)")
	fs.StringVar(&cfg.caURL, "ca-url", os.Getenv("HANDRAIL_CA_URL"), "the CA's address, https://host[:port] (or set HANDRAIL_CA_URL)")
	fs.StringVar(&cfg.caRoot, "ca-root", os.Getenv("HANDRAIL_CA_ROOT"), "file holding the CA's root certificate, a copy of root_ca.crt (or set HANDRAIL_CA_ROOT)")
	fs.StringVar(&cfg.publicURL, "public-url", os.Getenv("HANDRAIL_PUBLIC_URL"), "the address browsers use, http(s)://host[:port][/path]; needed unless listening on loopback (or set HANDRAIL_PUBLIC_URL)")
	proxies := fs.String("trusted-proxy", os.Getenv("HANDRAIL_TRUSTED_PROXIES"), "addresses or CIDR ranges of the reverse proxies in front, comma-separated; only they are believed about who a visitor is (or set HANDRAIL_TRUSTED_PROXIES)")
	if err := fs.Parse(args); err != nil {
		return cfg, 2
	}
	var err error
	if cfg.trustedProxies, err = web.ParseTrustedProxies(*proxies); err != nil {
		fmt.Fprintf(stderr, "handrail-ca: -trusted-proxy: %v\n", err)
		return cfg, 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "handrail-ca: unexpected argument %q\n", fs.Arg(0))
		return cfg, 2
	}
	var missing []string
	for _, need := range []struct{ value, name string }{
		{cfg.dataDir, "-data (HANDRAIL_DATA)"},
		{cfg.caURL, "-ca-url (HANDRAIL_CA_URL)"},
		{cfg.caRoot, "-ca-root (HANDRAIL_CA_ROOT)"},
	} {
		if need.value == "" {
			missing = append(missing, need.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "handrail-ca: not configured: %s. Run with -h for what each one is.\n", strings.Join(missing, ", "))
		return cfg, 2
	}
	return cfg, 0
}

// resolvePublicURL returns the address browsers use. On a loopback listener
// it defaults to that listener; anywhere else it has to be said, because
// the server cannot know what name, scheme or proxy sits in front of it,
// and cookies and the Host check depend on it.
func (c config) resolvePublicURL(listening net.Addr) (*url.URL, error) {
	raw := c.publicURL
	if raw == "" {
		if !isLoopback(listening) {
			return nil, errors.New("-public-url (HANDRAIL_PUBLIC_URL) is required when not listening on a loopback address")
		}
		raw = "http://" + listening.String()
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("-public-url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("-public-url: want http(s)://host[:port][/path]")
	}
	return u, nil
}

func isLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// readSmallFile reads a configuration file that has no business being
// large.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// sweepSessions removes ended sessions from the store now and then. They
// are refused whether or not they have been swept; this only keeps the
// table small.
func sweepSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if _, err := st.DeleteExpiredSessions(ctx, now, now.Add(-web.SessionIdle)); err != nil && ctx.Err() == nil {
				log.Warn("sweeping ended sessions", "err", err)
			}
		}
	}
}

// serve answers on ln until ctx is cancelled, then drains in-flight
// requests for up to ten seconds.
func serve(ctx context.Context, ln net.Listener, handler http.Handler, log *slog.Logger) int {
	srv := &http.Server{
		Handler:           handler,
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
// shell or curl, so the binary probes its own /healthz at the address the
// server was told to listen on (see probeHost). The request goes to the
// host's own listener and never leaves it, which is why it is plain HTTP.
func healthcheck(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr("HANDRAIL_LISTEN", defaultListen), "the server's listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 2
	}
	// Its own transport, not the default one: no proxy from the environment
	// (the probe must reach this host's listener directly) and no kept-alive
	// connection left behind by a one-shot request.
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := client.Get("http://" + net.JoinHostPort(probeHost(host), port) + "/healthz")
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

// probeHost is the host the healthcheck dials for a given listen host. A
// wildcard bind cannot be dialled, so it is reached over loopback of the
// same family; a concrete address or name is probed as configured, since a
// server bound to one interface (or to [::1]) does not answer on 127.0.0.1.
func probeHost(listenHost string) string {
	if listenHost == "" {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(listenHost); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return listenHost
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
