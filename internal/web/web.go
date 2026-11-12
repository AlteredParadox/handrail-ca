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

// Package web is the HTTP surface: sign-in, the pages, a health probe, and
// the legal pages the AGPL requires every network user to be able to reach
// (license, third-party notices, corresponding source).
package web

import (
	"context"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

//go:embed static
var staticFS embed.FS

// repoURL is where the corresponding source lives (AGPL section 13).
const repoURL = "https://github.com/AlteredParadox/handrail-ca"

// healthPath is the probe the container's HEALTHCHECK asks.
const healthPath = "/healthz"

// CA is what the pages need from the CA client (*ca.Client).
type CA interface {
	URL() string
	// RootFingerprint is the configured SHA-256 of the CA's root; Root is
	// the certificate itself, once it has been fetched and matched.
	RootFingerprint() string
	Root(ctx context.Context) (*x509.Certificate, error)
	Health(ctx context.Context) error
	Version(ctx context.Context) (string, error)
	Roots(ctx context.Context) ([]*x509.Certificate, error)
	Intermediates(ctx context.Context) ([]*x509.Certificate, error)
	Provisioners(ctx context.Context) ([]ca.Provisioner, error)
	CRL(ctx context.Context) (ca.CRL, error)
}

// Store is what the pages need from the store (*store.Store).
type Store interface {
	Credentials(ctx context.Context, username string) (store.User, string, error)
	CreateSession(ctx context.Context, userID int64, passwordHash string, token store.TokenHash, now, expires time.Time) error
	ChangePassword(ctx context.Context, userID int64, oldHash, newHash string, now time.Time) error
	Session(ctx context.Context, token store.TokenHash, now time.Time) (store.Session, error)
	TouchSession(ctx context.Context, token store.TokenHash, now time.Time) error
	DeleteSession(ctx context.Context, token store.TokenHash) error
	AppendHistory(ctx context.Context, e store.Event) error
}

// Inventory is what the pages need from the certificate inventory
// (*inventory.Inventory): its picture as last read, and a way to have it
// read again now.
type Inventory interface {
	Snapshot() *inventory.Snapshot
	Refresh(ctx context.Context) error
}

// InventoryRefresh is how often the inventory is read again.
const InventoryRefresh = 30 * time.Second

// Options carries what main hands the server.
type Options struct {
	// Version is the stamped build version (a tag, a git description or
	// "dev").
	Version string
	// License and ThirdPartyLicenses are the embedded legal texts.
	License            []byte
	ThirdPartyLicenses []byte

	Store Store
	CA    CA
	// Inventory is the picture of what the CA has issued.
	Inventory Inventory
	// PublicURL is the address browsers use: scheme://host[:port][/path].
	// Its host is the only Host header answered, its origin the only one
	// forms are accepted from, its scheme decides whether cookies are
	// marked Secure, and its path is the prefix every page is served under.
	PublicURL *url.URL
	// TrustedProxies are the reverse proxies in front of handrail-ca. Only
	// a connection from one of them has its X-Forwarded-For header read to
	// learn the client's address.
	TrustedProxies []netip.Prefix
	Log            *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// server is the state behind the handlers.
type server struct {
	opts   Options
	base   string // path prefix, "" or "/something" (no trailing slash)
	host   string // the public URL's host[:port], as browsers send it
	origin string // scheme://host[:port]
	secure bool   // the public URL is https
	pages  pages
	log    *slog.Logger

	limiter   *limiter
	hashSlots chan struct{} // bounds concurrent password hashing
	dummyHash string        // checked when the user does not exist
	// hash makes the stored form of a new password (password.Hash).
	hash      func(pw string) (string, error)
	status    *statusCache
	strangers strangerBudget

	// Things already warned about once: peers that are not listed
	// proxies (see clientAddr), and host names requests were refused for.
	unlistedPeers onceEach
	refusedHosts  onceEach

	// historyBroken is set while the last history write failed; every page
	// then says that history is not being recorded.
	historyBroken atomic.Bool
}

// New returns the handler for the whole site.
func New(opts Options) (http.Handler, error) {
	_, handler, err := build(opts)
	return handler, err
}

// build is New, also returning the state behind the handler for the tests.
func build(opts Options) (*server, http.Handler, error) {
	if opts.Store == nil || opts.CA == nil || opts.Inventory == nil || opts.PublicURL == nil {
		return nil, nil, errors.New("web: a store, a CA client, an inventory and a public URL are required")
	}
	u := opts.PublicURL
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, errors.New("web: the public URL must be http(s)://host[:port][/path]")
	}
	if u.Scheme == "http" && !loopbackName(u.Hostname()) {
		return nil, nil, errors.New("web: a public URL with http:// is only accepted for a loopback address (localhost, 127.0.0.1, ::1): " +
			"anywhere else, passwords and session cookies would cross the network in the clear. " +
			"Put a reverse proxy with TLS in front and give its https:// address")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	pages, err := loadPages()
	if err != nil {
		return nil, nil, err
	}
	dummy, err := dummyPasswordHash()
	if err != nil {
		return nil, nil, err
	}
	// Browsers leave a scheme's default port out of both Host and Origin,
	// and send the name in lower case.
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else {
		host = strings.TrimSuffix(host, ":80")
	}
	s := &server{
		opts:      opts,
		base:      strings.TrimRight(u.Path, "/"),
		host:      host,
		origin:    u.Scheme + "://" + host,
		secure:    u.Scheme == "https",
		pages:     pages,
		log:       opts.Log,
		limiter:   newLimiter(),
		hashSlots: make(chan struct{}, maxConcurrentHashes),
		dummyHash: dummy,
		hash:      password.Hash,
		status:    &statusCache{},
	}

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	// Open to everyone: the probe, the legal pages, the style sheet, and
	// signing in.
	mux.HandleFunc("GET "+healthPath, s.healthz)
	mux.HandleFunc("GET /license", text(opts.License))
	mux.HandleFunc("GET /third-party-licenses", text(opts.ThirdPartyLicenses))
	mux.HandleFunc("GET /source", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, SourceURL(opts.Version), http.StatusFound)
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /sign-in", s.signInForm)
	mux.HandleFunc("POST /sign-in", s.signIn)
	// Signed-in users only.
	mux.HandleFunc("POST /sign-out", s.signedIn(s.signOut))
	mux.HandleFunc("GET /status", s.signedIn(s.statusPage))
	mux.HandleFunc("GET /account", s.signedIn(s.accountPage))
	mux.HandleFunc("POST /account/password", s.signedIn(s.changePassword))
	mux.HandleFunc("GET /{$}", s.signedIn(s.listPage))
	mux.HandleFunc("POST /refresh", s.signedIn(s.refreshInventory))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "There is no such page.")
	})

	return s, securityHeaders(s.onlyOurHost(s.underBase(s.sameOriginWrites(mux)))), nil
}

// loopbackName reports whether a host name can only mean this machine.
func loopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.opts.Version})
}

func text(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	}
}

// securityHeaders sets the baseline every response carries. The UI is
// same-origin only: no inline script or style, no framing, no third-party
// loads.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// onlyOurHost refuses requests addressed to any name but the public URL's.
// A page reached under another name (DNS rebinding, a stray proxy route)
// would run with that name's cookies and origin, not ours. The health probe
// is exempt: the container's own check reaches it by loopback address, and
// it says nothing but the version.
//
// The usual cause in practice is a reverse proxy that does not pass the
// visitor's Host header on (nginx sends the backend's address unless told
// otherwise), which refuses every page. The log says so once per name.
func (s *server) onlyOurHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe := r.URL.Path == healthPath || r.URL.Path == s.base+healthPath
		if !strings.EqualFold(r.Host, s.host) && !probe {
			// The name is whatever the sender wrote: shortened, and quoted
			// by the log handler.
			if asked := clipHost(r.Host); s.refusedHosts.first(asked) {
				s.log.Warn("refused a request addressed to a host name other than the public URL's. "+
					"If this is your reverse proxy, make it pass the visitor's Host header through "+
					"(nginx: proxy_set_header Host $http_host;)",
					"asked_for", asked, "answering_only", s.host)
			}
			http.Error(w, "handrail-ca is not served under this host name", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clipHost bounds a Host header for the log.
func clipHost(host string) string {
	const limit = 100
	if len(host) > limit {
		return host[:limit] + "…"
	}
	return host
}

// underBase serves the site below the public URL's path. The health probe
// also answers at the root, where a container check looks for it.
func (s *server) underBase(next http.Handler) http.Handler {
	if s.base == "" {
		return next
	}
	stripped := http.StripPrefix(s.base, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == healthPath:
			next.ServeHTTP(w, r)
		case r.URL.Path == s.base:
			http.Redirect(w, r, s.base+"/", http.StatusPermanentRedirect)
		case strings.HasPrefix(r.URL.Path, s.base+"/"):
			stripped.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// sameOriginWrites refuses any request that could change something unless
// the browser says it came from our own pages. Browsers send Origin on
// every form post; a request without it is not from a form of ours. This
// stands beside the per-session form token, not in place of it.
func (s *server) sameOriginWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get("Origin") != s.origin {
				s.errorPage(w, r, http.StatusForbidden, "This request did not come from a handrail-ca page.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

var (
	releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	// `git describe --tags --always --dirty`: v1.2.3-4-gabc1234[-dirty] or a
	// bare abbreviated hash.
	describeHash = regexp.MustCompile(`^(?:.*-g)?([0-9a-f]{7,40})(?:-dirty)?$`)
)

// SourceURL is the source tree a build was made from: the tag for a release,
// the commit for a build between tags, the repository itself when the
// version names neither (a plain `go build` reports "dev").
func SourceURL(version string) string {
	if releaseTag.MatchString(version) {
		return repoURL + "/tree/" + version
	}
	if m := describeHash.FindStringSubmatch(version); m != nil {
		return repoURL + "/tree/" + m[1]
	}
	return repoURL
}
