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
	"unicode"

	legal "handrail-ca"
	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/store"
	"handrail-ca/internal/web"
)

// program is the name the binary answers to: in -version and in the
// usage text.
const program = "handrail-ca"

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
			fmt.Fprintln(stdout, program, version)
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

	// The provisioner handrail-ca acts through, unless it is read-only. Its
	// password comes from a file, like every secret; the key it opens is
	// fetched from the CA later and held in memory only.
	var acting *ca.ProvisionerConfig
	if !cfg.readOnly {
		pw, err := readPasswordFile(cfg.provisionerPasswordFile)
		if err != nil {
			log.Error("reading the provisioner password file", "err", err)
			return 1
		}
		acting = &ca.ProvisionerConfig{Name: cfg.provisioner, Password: pw}
	}
	client, err := ca.New(ca.Config{URL: cfg.caURL, Fingerprint: cfg.caFingerprint, UserAgent: "handrail-ca/" + version, Provisioner: acting})
	if err != nil {
		log.Error("CA configuration", "err", err)
		return 1
	}

	// The certificate list is read from the CA's database. The connection
	// string holds a password, so it comes from a file, never from a flag
	// or the environment. Nothing connects yet.
	dbURL, err := readSecretFile(cfg.dbURLFile)
	if err != nil {
		log.Error("reading the database connection file", "err", err)
		return 1
	}
	// A database on another machine is checked against the CA's own root,
	// the one fetched by its fingerprint: the same trust, no second file.
	db, err := inventory.OpenPostgres(dbURL, client.Root)
	if err != nil {
		log.Error("database configuration", "file", cfg.dbURLFile, "err", err)
		return 1
	}
	defer db.Close()
	inv := inventory.New(db)

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
		NoKeyGeneration:    cfg.noKeyGeneration,
		Inventory:          inv,
		Log:                log,
	})
	if err != nil {
		log.Error("starting", "err", err)
		return 1
	}
	if publicURL.Scheme == "http" {
		// Browsers keep cookies for a host name, not for a port.
		log.Warn("the public URL is plain http on a loopback name: a browser sends this site's cookies, the session " +
			"cookie included, to every other web service on that name, whatever its port, and that cookie alone is the " +
			"session. Use it only where all of them are trusted as much as an operator; otherwise put a reverse proxy " +
			"with TLS and a host name of its own in front (README, \"Serving plain HTTP\")")
	}
	if publicURL.Scheme == "https" && len(cfg.trustedProxies) == 0 {
		// handrail-ca does not speak TLS, so an https address means a
		// proxy is in front, and every visitor arrives from its address.
		log.Warn("no -trusted-proxy (HANDRAIL_TRUSTED_PROXIES) is set: visitors cannot be told apart, " +
			"so sign-in attempts are limited per user name only and the history records the proxy's address")
	}
	go sweepSessions(ctx, st, handler.SaveSessionUses, log)
	go inv.Run(ctx, web.InventoryRefresh, inventoryLog(log))
	if cfg.readOnly {
		log.Info("read-only: no provisioner is configured, so certificates cannot be issued or revoked from here")
	} else {
		go openProvisionerKey(ctx, client, provisionerRetry, log)
	}

	log.Info("handrail-ca listening", "addr", ln.Addr().String(), "url", publicURL.String(), "ca", client.URL(), "version", version)
	// Rows of failed sign-ins are written after their answers; when serving
	// ends the last of them may still be on their way to the store.
	defer handler.Settle(5 * time.Second)
	return serve(ctx, ln, handler, log)
}

// adminProvisioner is the name `step ca init` gives the JWK provisioner
// that the CA's administrators authenticate through when remote management
// is on.
const adminProvisioner = "Admin JWK"

// provisionerRetry is how long to wait before trying again to open the
// provisioner's key.
const provisionerRetry = 30 * time.Second

// openProvisionerKey opens the provisioner's key ahead of the first
// revocation, so that a wrong name or password is in the log at start and
// not found when a certificate has to be revoked. It keeps trying, since
// the CA may be down or the provisioner not created yet, and says so once
// per distinct reason. The status page always has the current state.
func openProvisionerKey(ctx context.Context, client *ca.Client, every time.Duration, log *slog.Logger) {
	var last string
	for {
		attempt, cancel := context.WithTimeout(ctx, time.Minute)
		err := client.Unlock(attempt)
		cancel()
		if err == nil {
			st := client.ProvisionerState()
			log.Info("the provisioner's key is open", "provisioner", st.Name, "key_id", st.KeyID)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err.Error() != last {
			log.Warn("the provisioner's key could not be opened, so handrail-ca cannot act on the CA yet; trying again", "err", err)
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// config is what the server is started with. Secrets are never flags: the
// database password and the provisioner password are inside files that are
// only named here. The root's fingerprint is public.
type config struct {
	listen  string
	dataDir string
	caURL   string
	// caFingerprint is the SHA-256 of the CA's root certificate, in hex.
	caFingerprint string
	// dbURLFile names the file holding the connection string for the
	// CA's database.
	dbURLFile string
	publicURL string
	// trustedProxies is the -trusted-proxy list, parsed.
	trustedProxies []netip.Prefix
	// provisioner is the name of the JWK provisioner handrail-ca acts
	// through, and provisionerPasswordFile the file holding its password.
	provisioner             string
	provisionerPasswordFile string
	// readOnly means no provisioner at all: view only.
	readOnly bool
	// noKeyGeneration switches off issuing with a key handrail-ca makes.
	noKeyGeneration bool
	// plainHTTP allows a public URL that is plain http on a loopback
	// name, where the session cookie goes to every web service on that
	// name (README, "Serving plain HTTP"). It has to be asked for.
	plainHTTP bool
}

func parseConfig(args []string, stderr io.Writer) (config, int) {
	var cfg config
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.listen, "listen", envOr("HANDRAIL_LISTEN", defaultListen), "address to listen on (or set HANDRAIL_LISTEN)")
	fs.StringVar(&cfg.dataDir, "data", os.Getenv("HANDRAIL_DATA"), "directory for handrail-ca's own store (or set HANDRAIL_DATA)")
	fs.StringVar(&cfg.caURL, "ca-url", os.Getenv("HANDRAIL_CA_URL"), "the CA's address, https://host[:port] (or set HANDRAIL_CA_URL)")
	fs.StringVar(&cfg.caFingerprint, "ca-fingerprint", os.Getenv("HANDRAIL_CA_FINGERPRINT"), "SHA-256 fingerprint of the CA's root certificate, as printed by 'step certificate fingerprint root_ca.crt' (or set HANDRAIL_CA_FINGERPRINT)")
	fs.StringVar(&cfg.dbURLFile, "db-url-file", os.Getenv("HANDRAIL_DB_URL_FILE"), "file holding the connection string for the CA's PostgreSQL database, for a read-only account: postgres://user:password@host:port/database?sslmode=verify-full (or set HANDRAIL_DB_URL_FILE)")
	fs.StringVar(&cfg.publicURL, "public-url", os.Getenv("HANDRAIL_PUBLIC_URL"), "the address browsers use, http(s)://host[:port][/path]; needed unless listening on loopback (or set HANDRAIL_PUBLIC_URL)")
	fs.StringVar(&cfg.provisioner, "provisioner", os.Getenv("HANDRAIL_PROVISIONER"), "name of the JWK provisioner on the CA that handrail-ca revokes through (or set HANDRAIL_PROVISIONER)")
	fs.StringVar(&cfg.provisionerPasswordFile, "provisioner-password-file", os.Getenv("HANDRAIL_PROVISIONER_PASSWORD_FILE"), "file holding that provisioner's password (or set HANDRAIL_PROVISIONER_PASSWORD_FILE)")
	// Both switches take something away, so a value that is not understood
	// stops the start: read as "off" it would leave in place what its
	// writer meant to remove, without a word.
	// The plain-HTTP switch gives something, and is read as strictly: a
	// value that is not understood is not taken for either.
	readOnly, readOnlyErr := envBool("HANDRAIL_READ_ONLY")
	noKeyGeneration, noKeysErr := envBool("HANDRAIL_NO_KEY_GENERATION")
	plainHTTP, plainErr := envBool("HANDRAIL_PLAIN_HTTP")
	if err := errors.Join(readOnlyErr, noKeysErr, plainErr); err != nil {
		fmt.Fprintf(stderr, "handrail-ca: %v\n", err)
		return cfg, 2
	}
	fs.BoolVar(&cfg.readOnly, "read-only", readOnly, "view only: no provisioner is used and nothing can be issued or revoked (or set HANDRAIL_READ_ONLY=1)")
	fs.BoolVar(&cfg.noKeyGeneration, "no-key-generation", noKeyGeneration, "do not offer to generate private keys: certificates are issued for pasted certificate signing requests only (or set HANDRAIL_NO_KEY_GENERATION=1)")
	fs.BoolVar(&cfg.plainHTTP, "plain-http", plainHTTP, "allow a plain http:// public URL on a loopback name (the default when listening on loopback), where browsers send the session cookie to every web service on that name; see the README (or set HANDRAIL_PLAIN_HTTP=1)")
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
		{cfg.caFingerprint, "-ca-fingerprint (HANDRAIL_CA_FINGERPRINT)"},
		{cfg.dbURLFile, "-db-url-file (HANDRAIL_DB_URL_FILE)"},
	} {
		if need.value == "" {
			missing = append(missing, need.name)
		}
	}
	// Acting on the CA is a decision either way: a provisioner and its
	// password, or read-only said out loud. A missing setting never turns
	// into a mode by itself.
	acting := cfg.provisioner != "" || cfg.provisionerPasswordFile != ""
	switch {
	case cfg.readOnly && acting:
		fmt.Fprintln(stderr, "handrail-ca: -read-only (HANDRAIL_READ_ONLY) is set together with a provisioner. Choose one: read-only uses no provisioner.")
		return cfg, 2
	case cfg.readOnly:
	case !acting:
		missing = append(missing, "-provisioner (HANDRAIL_PROVISIONER) with -provisioner-password-file (HANDRAIL_PROVISIONER_PASSWORD_FILE), or -read-only (HANDRAIL_READ_ONLY=1)")
	case cfg.provisioner == "":
		missing = append(missing, "-provisioner (HANDRAIL_PROVISIONER)")
	case cfg.provisionerPasswordFile == "":
		missing = append(missing, "-provisioner-password-file (HANDRAIL_PROVISIONER_PASSWORD_FILE)")
	case strings.EqualFold(strings.TrimSpace(cfg.provisioner), adminProvisioner):
		// Every operator would be issuing through the provisioner the
		// CA's administrators authenticate with, and the list leaves what
		// is issued through it out as the CA's own (security review N-06).
		fmt.Fprintf(stderr, "handrail-ca: -provisioner (HANDRAIL_PROVISIONER) is %q, the name step-ca gives the provisioner its administrators sign in with. "+
			"handrail-ca does not act through it: give handrail-ca a provisioner of its own (docs/ca-setup.md, section 1).\n", cfg.provisioner)
		return cfg, 2
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
	// An http address beyond loopback is refused whatever the switch says
	// (web.New), with its own message.
	if u.Scheme == "http" && !c.plainHTTP && loopbackHost(u.Hostname()) {
		// Browsers keep cookies for a host name, not for a port.
		return nil, fmt.Errorf("the public URL %s is plain http: browsers would send handrail-ca's session cookie to every other web service on %s, "+
			"whatever its port, and that cookie alone is the session. Set -plain-http (HANDRAIL_PLAIN_HTTP=1) to run this way where every one of them "+
			"is trusted as much as an operator, or put a reverse proxy with TLS in front and set -public-url to its https:// address "+
			"(README, \"Serving plain HTTP\")", u.Redacted(), u.Hostname())
	}
	return u, nil
}

// loopbackHost is the test web.New applies to a plain-HTTP public URL's
// host: localhost, or a loopback address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// inventoryLog reports the reading of the certificate inventory: a
// failure when it starts or changes, and the recovery, not a line for every
// round of a database that stays down. The status page always has the
// current state.
func inventoryLog(log *slog.Logger) func(error) {
	var last string
	return func(err error) {
		switch {
		case err == nil && last != "":
			log.Info("the certificate inventory is being read again")
			last = ""
		case err != nil && err.Error() != last:
			log.Warn("the certificate inventory could not be read; the status page shows how old its picture is", "err", err)
			last = err.Error()
		}
	}
}

// readSecretFile reads a small file that holds a secret, trimmed. Its
// content never goes into an error.
func readSecretFile(path string) (string, error) {
	secret, err := readPasswordFile(path)
	return strings.TrimSpace(secret), err
}

// readPasswordFile reads a small file that holds a password. Only what
// follows the password is trimmed (the newline an editor or `echo` leaves),
// which is what the step CLI does with its own password files: a password
// may begin with a space.
func readPasswordFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const limit = 16 << 10
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if len(data) > limit {
		return "", fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	secret := strings.TrimRightFunc(string(data), unicode.IsSpace)
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}

// sweepSessions removes ended sessions from the store now and then. They
// are refused whether or not they have been swept; this only keeps the
// table small. saveUses first writes the uses of sessions the store could
// not record when they happened (web.Site.SaveSessionUses); until it can,
// idle sessions are not swept, since the store's record of their last use
// is behind.
func sweepSessions(ctx context.Context, st *store.Store, saveUses func(context.Context) error, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			sweepOnce(ctx, st, saveUses, now, log)
		}
	}
}

// sweepOnce is one round of sweepSessions.
func sweepOnce(ctx context.Context, st *store.Store, saveUses func(context.Context) error, now time.Time, log *slog.Logger) {
	if err := saveUses(ctx); err != nil {
		if ctx.Err() == nil {
			log.Warn("not sweeping idle sessions: the uses of sessions could not be saved", "err", err)
		}
	} else if _, err := st.DeleteExpiredSessions(ctx, now, now.Add(-web.SessionIdle)); err != nil && ctx.Err() == nil {
		log.Warn("sweeping ended sessions", "err", err)
	}
	// And the browsers nobody has signed in from for a long time.
	if _, err := st.DeleteUnusedDevices(ctx, now.Add(-store.DeviceLifetime)); err != nil && ctx.Err() == nil {
		log.Warn("sweeping devices that are no longer used", "err", err)
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
		// ctx is cancelled by now, which is why we are here: the draining
		// gets its values but not its cancellation, or it would be over
		// before it began and requests in flight would be cut off.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
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

// envBool reads a yes-or-no setting from the environment. Unset or empty is
// no. A value that is neither a plain yes nor a plain no is an error and
// not a guess: the settings read this way switch something off, and one
// that was misspelt must not be taken for "leave it on".
func envBool(key string) (bool, error) {
	raw := os.Getenv(key)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	}
	return false, fmt.Errorf("%s is set to %q, which is not understood: write 1 to switch it on, or leave it unset", key, clipSetting(raw))
}

// clipSetting bounds a setting's value for an error message.
func clipSetting(value string) string {
	const limit = 40
	if r := []rune(value); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return value
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
