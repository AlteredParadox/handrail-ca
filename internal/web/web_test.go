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

package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/store"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeCA stands in for the CA client. Each answer can be replaced by an
// error.
type fakeCA struct {
	root, inter *x509.Certificate
	published   []*x509.Certificate // nil means the root
	provs       []ca.Provisioner
	crl         ca.CRL
	version     string

	healthErr, versionErr, rootsErr, intersErr, provsErr, crlErr error
	calls                                                        atomic.Int64
}

func (f *fakeCA) URL() string                       { return "https://ca.internal.example:9000" }
func (f *fakeCA) TrustedRoots() []*x509.Certificate { return []*x509.Certificate{f.root} }
func (f *fakeCA) Health(context.Context) error      { f.calls.Add(1); return f.healthErr }
func (f *fakeCA) Version(context.Context) (string, error) {
	return f.version, f.versionErr
}
func (f *fakeCA) Roots(context.Context) ([]*x509.Certificate, error) {
	if f.published != nil {
		return f.published, f.rootsErr
	}
	return []*x509.Certificate{f.root}, f.rootsErr
}
func (f *fakeCA) Intermediates(context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{f.inter}, f.intersErr
}
func (f *fakeCA) Provisioners(context.Context) ([]ca.Provisioner, error) { return f.provs, f.provsErr }
func (f *fakeCA) CRL(context.Context) (ca.CRL, error)                    { return f.crl, f.crlErr }

func testCert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: t0.Add(-time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	return &fakeCA{
		root:    testCert(t, "Example Root CA", t0.AddDate(9, 0, 0)),
		inter:   testCert(t, "Example Intermediate CA", t0.AddDate(3, 0, 0)),
		version: "0.30.2",
		provs: []ca.Provisioner{
			{Type: "JWK", Name: "handrail", KeyID: "kid", Claims: ca.Claims{MaxTLSCertDuration: 2160 * time.Hour}},
			{Type: "ACME", Name: "acme"},
		},
	}
}

// brokenStore wraps the real store and fails chosen calls.
type brokenStore struct {
	*store.Store
	historyErr, sessionErr, createErr, credentialsErr atomic.Pointer[error]
	// beforeCreate runs between the password check and the session being
	// created, where a concurrent `user passwd` could land.
	beforeCreate func()
}

func (b *brokenStore) AppendHistory(ctx context.Context, e store.Event) error {
	if err := b.historyErr.Load(); err != nil {
		return *err
	}
	return b.Store.AppendHistory(ctx, e)
}

func (b *brokenStore) Session(ctx context.Context, h store.TokenHash, now time.Time) (store.Session, error) {
	if err := b.sessionErr.Load(); err != nil {
		return store.Session{}, *err
	}
	return b.Store.Session(ctx, h, now)
}

func (b *brokenStore) CreateSession(ctx context.Context, id int64, hash string, h store.TokenHash, now, exp time.Time) error {
	if err := b.createErr.Load(); err != nil {
		return *err
	}
	if b.beforeCreate != nil {
		b.beforeCreate()
	}
	return b.Store.CreateSession(ctx, id, hash, h, now, exp)
}

func (b *brokenStore) Credentials(ctx context.Context, name string) (store.User, string, error) {
	if err := b.credentialsErr.Load(); err != nil {
		return store.User{}, "", *err
	}
	return b.Store.Credentials(ctx, name)
}

// cheapHash is an argon2id hash with tiny parameters, so that tests which
// sign in do not each spend 64 MiB and a third of a second.
func cheapHash(pw string) string {
	salt := []byte("saltsaltsaltsalt")
	key := argon2.IDKey([]byte(pw), salt, 1, 64, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

const (
	alicePassword = "alice's long password"
	bobPassword   = "bob's long password"
)

// site is a handrail-ca under test: a real store in a temporary directory,
// a fake CA, a settable clock and a captured log.
type site struct {
	t       *testing.T
	server  *server
	handler http.Handler
	store   *brokenStore
	ca      *fakeCA
	clock   *clock
	log     *bytes.Buffer
	public  *url.URL
}

func newSite(t *testing.T, publicURL string) *site {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if _, err := st.AddUser(ctx, "alice", cheapHash(alicePassword), store.RoleOperator, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, "bob", cheapHash(bobPassword), store.RoleViewer, t0); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	s := &site{t: t, store: &brokenStore{Store: st}, ca: newFakeCA(t), clock: &clock{now: t0}, log: &bytes.Buffer{}, public: u}
	s.server, s.handler, err = build(Options{
		Version: "v1.2.3", License: []byte("LICENSE TEXT"), ThirdPartyLicenses: []byte("NOTICES TEXT"),
		Store: s.store, CA: s.ca, PublicURL: u, Now: s.clock.Now,
		Log: slog.New(slog.NewTextHandler(&syncWriter{buf: s.log}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The stand-in checked for accounts that do not exist: cheap, like the
	// real ones here.
	s.server.dummyHash = cheapHash("nobody has this password")
	return s
}

type syncWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (s *site) history() []store.Event {
	s.t.Helper()
	events, err := s.store.Store.History(context.Background(), store.HistoryQuery{})
	if err != nil {
		s.t.Fatal(err)
	}
	return events
}

// browser is a client with a cookie jar that behaves like a browser on the
// site's own origin: it sends Host, and Origin on posts.
type browser struct {
	s       *site
	cookies map[string]string
	// origin replaces the Origin sent on posts; "-" sends none.
	origin string
	host   string
}

func (s *site) browser() *browser {
	return &browser{s: s, cookies: map[string]string{}}
}

func (b *browser) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	b.s.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.Host = b.s.public.Host
	if b.host != "" {
		req.Host = b.host
	}
	req.RemoteAddr = "10.20.0.5:40000"
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		switch b.origin {
		case "":
			req.Header.Set("Origin", b.s.public.Scheme+"://"+b.s.public.Host)
		case "-":
		default:
			req.Header.Set("Origin", b.origin)
		}
	}
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	b.s.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return rec
}

func (b *browser) get(path string) *httptest.ResponseRecorder { return b.do(http.MethodGet, path, nil) }

var formTokenField = regexp.MustCompile(`name="form_token" value="([0-9a-f]{64})"`)

func tokenIn(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := formTokenField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no form token in the page (status %d)", rec.Code)
	}
	return m[1]
}

// signIn loads the form and posts it, returning the answer to the post.
func (b *browser) signIn(username, pw string) *httptest.ResponseRecorder {
	b.s.t.Helper()
	base := strings.TrimRight(b.s.public.Path, "/")
	token := tokenIn(b.s.t, b.get(base+"/sign-in"))
	return b.do(http.MethodPost, base+"/sign-in", url.Values{"form_token": {token}, "username": {username}, "password": {pw}})
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body: %.300s", rec.Code, status, rec.Body.String())
	}
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		t.Fatalf("got %d to %q, want 303 to %q", rec.Code, rec.Header().Get("Location"), to)
	}
}

func wantBody(t *testing.T, rec *httptest.ResponseRecorder, contains ...string) {
	t.Helper()
	for _, c := range contains {
		if !strings.Contains(rec.Body.String(), c) {
			t.Errorf("the page does not contain %q", c)
		}
	}
}

func TestNewNeedsItsParts(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	good := s.server.opts
	for name, change := range map[string]func(*Options){
		"no store":      func(o *Options) { o.Store = nil },
		"no CA":         func(o *Options) { o.CA = nil },
		"no public URL": func(o *Options) { o.PublicURL = nil },
		"ftp":           func(o *Options) { o.PublicURL = &url.URL{Scheme: "ftp", Host: "x"} },
		"plain HTTP beyond this machine": func(o *Options) {
			o.PublicURL = &url.URL{Scheme: "http", Host: "handrail.internal.example"}
		},
		"plain HTTP on a private address": func(o *Options) { o.PublicURL = &url.URL{Scheme: "http", Host: "10.20.0.9:8080"} },
		"no host":                         func(o *Options) { o.PublicURL = &url.URL{Scheme: "https"} },
		"with query":                      func(o *Options) { o.PublicURL = &url.URL{Scheme: "https", Host: "x", RawQuery: "a=b"} },
	} {
		o := good
		change(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	// The defaults for the clock and the log are filled in.
	good.Now, good.Log = nil, nil
	if _, err := New(good); err != nil {
		t.Errorf("New with defaults: %v", err)
	}
}

func TestPublicRoutes(t *testing.T) {
	b := newSite(t, "http://127.0.0.1:8080").browser()
	tests := []struct {
		path     string
		status   int
		contains string
	}{
		{"/healthz", http.StatusOK, `"version":"v1.2.3"`},
		{"/license", http.StatusOK, "LICENSE TEXT"},
		{"/third-party-licenses", http.StatusOK, "NOTICES TEXT"},
		{"/static/style.css", http.StatusOK, "--accent"},
		{"/sign-in", http.StatusOK, "Sign in"},
		{"/no-such-page", http.StatusNotFound, "There is no such page."},
		{"/static/", http.StatusOK, "style.css"},
		// The templates are not under /static, by any spelling.
		{"/templates/layout.html", http.StatusNotFound, ""},
		{"/static/layout.html", http.StatusNotFound, ""},
		{"/static/../templates/layout.html", http.StatusTemporaryRedirect, "/templates/layout.html"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := b.get(tt.path)
			wantStatus(t, rec, tt.status)
			wantBody(t, rec, tt.contains)
		})
	}
	rec := b.get("/source")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != repoURL+"/tree/v1.2.3" {
		t.Errorf("/source: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSecurityHeaders(t *testing.T) {
	b := newSite(t, "http://127.0.0.1:8080").browser()
	for _, path := range []string{"/healthz", "/sign-in", "/", "/no-such-page", "/static/style.css"} {
		h := b.get(path).Header()
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers = %v", path, h)
		}
	}
	// Nothing in the pages needs what the policy forbids.
	page := b.get("/sign-in").Body.String()
	for _, forbidden := range []string{"<script", "style=", "onclick", "https://fonts"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the sign-in page contains %q", forbidden)
		}
	}
}

func TestPagesNeedASession(t *testing.T) {
	b := newSite(t, "http://127.0.0.1:8080").browser()
	wantRedirect(t, b.get("/"), "/sign-in")
	wantRedirect(t, b.get("/status"), "/sign-in")
	wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{}), "/sign-in")
	// A cookie that is not one of ours is no session.
	b.cookies[sessionCookie] = "not-base64-of-32-bytes"
	wantRedirect(t, b.get("/status"), "/sign-in")
	b.cookies[sessionCookie] = base64.RawURLEncoding.EncodeToString(make([]byte, tokenBytes))
	wantRedirect(t, b.get("/status"), "/sign-in")
}

func TestSignInAndOut(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()

	rec := b.signIn("Alice", alicePassword)
	wantRedirect(t, rec, "/")
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Secure || session.MaxAge != int(sessionLifetime/time.Second) {
		t.Errorf("session cookie = %+v", session)
	}
	if _, ok := b.cookies[formCookie]; ok {
		t.Error("the sign-in form's cookie outlived the sign-in")
	}
	// Only the hash of the token is in the store.
	raw, _ := base64.RawURLEncoding.DecodeString(session.Value)
	if _, err := s.store.Store.Session(context.Background(), store.HashToken(raw), t0); err != nil {
		t.Errorf("the session is not in the store under its token's hash: %v", err)
	}

	wantRedirect(t, b.get("/"), "/status")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "alice (operator)", "Sign out", "ca.internal.example")
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Error("a signed-in page may be cached")
	}
	// Already signed in: the sign-in page moves on.
	wantRedirect(t, b.get("/sign-in"), "/")

	// Signing out needs the session's form token.
	wantStatus(t, b.do(http.MethodPost, "/sign-out", url.Values{}), http.StatusForbidden)
	wantStatus(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {strings.Repeat("0", 64)}}), http.StatusForbidden)
	wantStatus(t, b.get("/status"), http.StatusOK)

	wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {tokenIn(t, page)}}), "/sign-in")
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Error("the session cookie was not cleared")
	}
	// The old cookie is dead even if someone kept it.
	b.cookies[sessionCookie] = session.Value
	wantRedirect(t, b.get("/status"), "/sign-in")

	events := s.history()
	if len(events) != 2 || events[0].Action != store.ActionSignOut || events[1].Action != store.ActionSignIn ||
		events[1].Actor != "alice" || events[1].Outcome != store.OutcomeOK || events[1].Remote != "10.20.0.5" || !events[1].At.Equal(t0) {
		t.Errorf("history = %+v", events)
	}
	if !strings.Contains(s.log.String(), "msg=audit actor=alice action=sign-in outcome=ok") {
		t.Errorf("no audit line in the log: %s", s.log)
	}
	if strings.Contains(s.log.String(), session.Value) || strings.Contains(s.log.String(), alicePassword) {
		t.Error("the log contains a session token or a password")
	}
}

func TestSignInFailures(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	tests := []struct {
		name, username, password, actor string
	}{
		{"wrong password", "alice", "not alice's password", "alice"},
		{"empty password", "alice", "", "alice"},
		{"unknown user", "mallory", alicePassword, unknownActor},
		// A password typed into the user-name field must not end up in the
		// history or the log.
		{"password as user name", "hunter2-hunter2", "x", unknownActor},
		{"malformed user name", "al ice<script>", alicePassword, unknownActor},
		{"empty user name", "", alicePassword, unknownActor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := s.browser()
			rec := b.signIn(tt.username, tt.password)
			wantStatus(t, rec, http.StatusUnauthorized)
			wantBody(t, rec, wrongCredentials)
			if _, ok := b.cookies[sessionCookie]; ok {
				t.Error("a session cookie was set")
			}
			wantRedirect(t, b.get("/status"), "/sign-in")
			last := s.history()[0]
			if last.Action != store.ActionSignIn || last.Outcome != store.OutcomeFailed || last.Actor != tt.actor {
				t.Errorf("history = %+v", last)
			}
			s.server.limiter = newLimiter() // each case starts unthrottled
		})
	}
	if strings.Contains(s.log.String(), "hunter2") {
		t.Error("a mistyped user name reached the log")
	}
	for _, e := range s.history() {
		if strings.Contains(e.Actor+e.Detail, "hunter2") || strings.Contains(e.Actor+e.Detail, "script") {
			t.Errorf("a mistyped user name reached the history: %+v", e)
		}
	}
}

func TestSignInNeedsTheFormsOwnToken(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	creds := func(token string) url.Values {
		return url.Values{"form_token": {token}, "username": {"alice"}, "password": {alicePassword}}
	}

	// No cookie at all: a post made without ever loading the form.
	b := s.browser()
	rec := b.do(http.MethodPost, "/sign-in", creds(strings.Repeat("a", 64)))
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "had expired")

	// A token from another browser's form.
	other := tokenIn(t, s.browser().get("/sign-in"))
	b = s.browser()
	b.get("/sign-in")
	wantStatus(t, b.do(http.MethodPost, "/sign-in", creds(other)), http.StatusForbidden)

	// The right token, from another origin or from none.
	for _, origin := range []string{"https://evil.example", "http://127.0.0.1:9999", "null", "-"} {
		b = s.browser()
		token := tokenIn(t, b.get("/sign-in"))
		b.origin = origin
		rec := b.do(http.MethodPost, "/sign-in", creds(token))
		wantStatus(t, rec, http.StatusForbidden)
		wantBody(t, rec, "did not come from a handrail-ca page")
	}
	for _, c := range s.history() {
		t.Errorf("a refused form reached the password check: %+v", c)
	}

	// The form re-shown after a refusal works.
	b = s.browser()
	rec = b.do(http.MethodPost, "/sign-in", creds("stale"))
	wantRedirect(t, b.do(http.MethodPost, "/sign-in", creds(tokenIn(t, rec))), "/")
}

func TestOversizedFormIsRefused(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	token := tokenIn(t, b.get("/sign-in"))
	big := url.Values{"form_token": {token}, "username": {"alice"}, "password": {strings.Repeat("x", maxForm)}}
	wantStatus(t, b.do(http.MethodPost, "/sign-in", big), http.StatusBadRequest)

	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	big = url.Values{"form_token": {tokenIn(t, page)}, "padding": {strings.Repeat("x", maxForm)}}
	wantStatus(t, b.do(http.MethodPost, "/sign-out", big), http.StatusForbidden)
}

func TestSignInIsThrottled(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	for range limiterAttempts {
		wantStatus(t, s.browser().signIn("alice", "a wrong password"), http.StatusUnauthorized)
	}
	// Now even the right password is refused, without being checked.
	rec := s.browser().signIn("alice", alicePassword)
	wantStatus(t, rec, http.StatusTooManyRequests)
	wantBody(t, rec, "Too many failed sign-ins")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	// The same address is throttled for other names too.
	wantStatus(t, s.browser().signIn("bob", bobPassword), http.StatusTooManyRequests)

	s.clock.advance(limiterWindow)
	wantRedirect(t, s.browser().signIn("alice", alicePassword), "/")

	// A success clears the name's count: four more failures do not lock it.
	s.server.limiter = newLimiter()
	for range limiterAttempts - 1 {
		s.browser().signIn("bob", "wrong")
	}
	wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
	if e := s.server.limiter.entries["user:bob"]; e != nil {
		t.Errorf("bob's failures were kept after a success: %+v", e)
	}
	// The address keeps its four failures, and gets the successful attempt
	// back: one more wrong guess is checked, the one after is not.
	if e := s.server.limiter.entries["addr:10.20.0.5"]; e == nil || e.attempts != limiterAttempts-1 {
		t.Errorf("the address's count after a success: %+v", e)
	}
	wantStatus(t, s.browser().signIn("alice", "wrong"), http.StatusUnauthorized)
	wantStatus(t, s.browser().signIn("alice", alicePassword), http.StatusTooManyRequests)

	// Names that cannot be accounts count against the address as well.
	s.server.limiter = newLimiter()
	for range limiterAttempts {
		wantStatus(t, s.browser().signIn("not a name", "x"), http.StatusUnauthorized)
	}
	wantStatus(t, s.browser().signIn("not a name", "x"), http.StatusTooManyRequests)
}

// Guesses sent all at once queue for a hashing slot; the throttle must hold
// for the queue, not only for requests that arrive one after another.
func TestThrottleHoldsUnderConcurrency(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	const guesses = 30
	browsers := make([]*browser, guesses)
	tokens := make([]string, guesses)
	for i := range browsers {
		browsers[i] = s.browser()
		tokens[i] = tokenIn(t, browsers[i].get("/sign-in"))
	}
	codes := make([]int, guesses)
	var wg sync.WaitGroup
	for i, b := range browsers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := url.Values{"form_token": {tokens[i]}, "username": {"alice"}, "password": {fmt.Sprintf("guess number %d", i)}}
			codes[i] = b.do(http.MethodPost, "/sign-in", form).Code
		}()
	}
	wg.Wait()
	checked, refused := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if checked != limiterAttempts || refused != guesses-limiterAttempts {
		t.Errorf("%d guesses were checked and %d refused; want %d and %d", checked, refused, limiterAttempts, guesses-limiterAttempts)
	}
	if n := len(s.history()); n != limiterAttempts {
		t.Errorf("%d failed sign-ins in the history, want %d", n, limiterAttempts)
	}
}

// `handrail-ca user passwd` signs the account out everywhere. A sign-in
// with the old password that was already past its check when the change
// landed must not come out the other side with a session.
func TestPasswordChangeDuringSignIn(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	ctx := context.Background()
	s.store.beforeCreate = func() {
		if err := s.store.Store.SetPassword(ctx, "alice", cheapHash("a new password entirely"), t0); err != nil {
			t.Error(err)
		}
	}
	b := s.browser()
	rec := b.signIn("alice", alicePassword)
	wantStatus(t, rec, http.StatusUnauthorized)
	wantBody(t, rec, wrongCredentials)
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Error("a session cookie was set with the superseded password")
	}
	last := s.history()[0]
	if last.Outcome != store.OutcomeFailed || last.Actor != "alice" || last.Detail != "the account changed during sign-in" {
		t.Errorf("history = %+v", last)
	}

	// The same for an account removed in that moment.
	s.store.beforeCreate = func() {
		if err := s.store.Store.RemoveUser(ctx, "bob"); err != nil {
			t.Error(err)
		}
	}
	wantStatus(t, s.browser().signIn("bob", bobPassword), http.StatusUnauthorized)

	// And the new password works.
	s.store.beforeCreate = nil
	wantRedirect(t, s.browser().signIn("alice", "a new password entirely"), "/")
}

func TestLimiterStaysBounded(t *testing.T) {
	l := newLimiter()
	for i := range limiterEntries {
		l.begin(t0, fmt.Sprintf("addr:%d", i))
	}
	// Full of live windows: the next attempt clears the table rather than
	// growing it.
	l.begin(t0.Add(time.Second), "addr:new")
	if len(l.entries) != 1 {
		t.Errorf("%d entries after overflow, want 1", len(l.entries))
	}
	// Finished windows are dropped first.
	l = newLimiter()
	for i := range limiterEntries {
		l.begin(t0, fmt.Sprintf("addr:%d", i))
	}
	l.begin(t0.Add(limiterWindow), "addr:new")
	if len(l.entries) != 1 {
		t.Errorf("%d entries after pruning, want 1", len(l.entries))
	}
	if l.blocked(t0, "addr:none") != 0 {
		t.Error("an unknown key is blocked")
	}
	// A refused attempt counts against none of its keys.
	l = newLimiter()
	for range limiterAttempts {
		l.begin(t0, "user:a")
	}
	if l.begin(t0, "user:a", "addr:b") == 0 || l.entries["addr:b"] != nil {
		t.Error("a refused attempt was counted against its other key")
	}
	l.refund("addr:none") // nothing to give back: no effect, no panic
}

func TestSessionsEnd(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")

	// Unused for an hour.
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.clock.advance(sessionIdle - time.Second)
	wantStatus(t, b.get("/status"), http.StatusOK)
	s.clock.advance(sessionIdle)
	wantRedirect(t, b.get("/status"), "/sign-in")

	// Twelve hours after sign-in, however busy.
	b = s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	for range 14 {
		s.clock.advance(50 * time.Minute)
		wantStatus(t, b.get("/status"), http.StatusOK)
	}
	s.clock.advance(50 * time.Minute) // 12h30m after sign-in
	wantRedirect(t, b.get("/status"), "/sign-in")

	// When the account is removed or its password changed.
	b = s.browser()
	wantRedirect(t, b.signIn("bob", bobPassword), "/")
	if err := s.store.Store.RemoveUser(context.Background(), "bob"); err != nil {
		t.Fatal(err)
	}
	wantRedirect(t, b.get("/status"), "/sign-in")
}

func TestStoreFailures(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	boom := errors.New("disk on fire")

	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.store.sessionErr.Store(&boom)
	rec := b.get("/status")
	wantStatus(t, rec, http.StatusInternalServerError)
	wantBody(t, rec, "could not read its own store")
	if strings.Contains(rec.Body.String(), "disk on fire") {
		t.Error("an internal error text was shown to the browser")
	}
	s.store.sessionErr.Store(nil)

	s.store.credentialsErr.Store(&boom)
	wantStatus(t, s.browser().signIn("alice", alicePassword), http.StatusInternalServerError)
	s.store.credentialsErr.Store(nil)

	s.store.createErr.Store(&boom)
	wantStatus(t, s.browser().signIn("alice", alicePassword), http.StatusInternalServerError)
	s.store.createErr.Store(nil)
	if !strings.Contains(s.log.String(), "disk on fire") {
		t.Error("the failures are not in the log")
	}
}

// The audit rule: a history that cannot be written does not stop anything,
// and every page says so until it works again.
func TestHistoryFailureWarnsAndContinues(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	boom := errors.New("database or disk is full")
	s.store.historyErr.Store(&boom)

	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "History is not being recorded")
	wantBody(t, s.browser().get("/sign-in"), "History is not being recorded")
	log := s.log.String()
	if !strings.Contains(log, "history is NOT being recorded") || !strings.Contains(log, "msg=audit actor=alice action=sign-in outcome=ok") {
		t.Errorf("log = %s", log)
	}

	s.store.historyErr.Store(nil)
	wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {tokenIn(t, page)}}), "/sign-in")
	if strings.Contains(b.get("/sign-in").Body.String(), "History is not being recorded") {
		t.Error("the warning stayed after history worked again")
	}
}

func TestOnlyThePublicHostIsAnswered(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example")
	b := s.browser()
	wantStatus(t, b.get("/sign-in"), http.StatusOK)
	for _, host := range []string{"evil.example", "handrail.internal.example:8443", "127.0.0.1:8080", ""} {
		b.host = host
		if host == "" {
			b.host = "localhost"
		}
		wantStatus(t, b.get("/sign-in"), http.StatusMisdirectedRequest)
		wantStatus(t, b.get("/status"), http.StatusMisdirectedRequest)
		// The container's own probe arrives by loopback address.
		wantStatus(t, b.get("/healthz"), http.StatusOK)
	}
}

// A public URL written with its scheme's default port, or in capitals, is
// still the address browsers send: no port, lower case.
func TestPublicURLIsNormalized(t *testing.T) {
	for public, name := range map[string]string{
		"https://Handrail.Internal.Example:443": "handrail.internal.example",
		"http://LocalHost:80/":                  "localhost",
		"http://[::1]:8080":                     "[::1]:8080",
	} {
		s := newSite(t, public)
		b := s.browser()
		b.host = name
		b.origin = s.public.Scheme + "://" + name
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		wantStatus(t, b.get("/status"), http.StatusOK)
		b.host = strings.ToUpper(name)
		wantStatus(t, b.get("/status"), http.StatusOK)
	}
}

func TestSecureCookiesOverHTTPS(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example")
	b := s.browser()
	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-"+sessionCookie {
			found = true
			if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
				t.Errorf("session cookie = %+v", c)
			}
		}
	}
	if !found {
		t.Error("no __Host- session cookie over HTTPS")
	}
	wantStatus(t, b.get("/status"), http.StatusOK)
}

func TestServedUnderABasePath(t *testing.T) {
	s := newSite(t, "https://tools.internal.example/handrail/")
	b := s.browser()

	wantStatus(t, b.get("/healthz"), http.StatusOK)
	wantStatus(t, b.get("/handrail/healthz"), http.StatusOK)
	wantStatus(t, b.get("/sign-in"), http.StatusNotFound)
	wantStatus(t, b.get("/handrailx/sign-in"), http.StatusNotFound)
	if rec := b.get("/handrail"); rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "/handrail/" {
		t.Errorf("/handrail: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	wantRedirect(t, b.get("/handrail/"), "/handrail/sign-in")

	form := b.get("/handrail/sign-in")
	wantBody(t, form, `href="/handrail/static/style.css"`, `action="/handrail/sign-in"`, `href="/handrail/license"`)
	wantStatus(t, b.get("/handrail/static/style.css"), http.StatusOK)

	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/handrail/")
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && (c.Path != "/handrail/" || !c.Secure) {
			t.Errorf("session cookie = %+v", c)
		}
		if strings.HasPrefix(c.Name, "__Host-") {
			t.Errorf("a __Host- cookie cannot be limited to a path: %s", c.Name)
		}
	}
	wantRedirect(t, b.get("/handrail/"), "/handrail/status")
	page := b.get("/handrail/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `action="/handrail/sign-out"`, `href="/handrail/status"`)
	wantRedirect(t, b.do(http.MethodPost, "/handrail/sign-out", url.Values{"form_token": {tokenIn(t, page)}}), "/handrail/sign-in")
}

func TestStatusPage(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("bob", bobPassword), "/")

	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"bob (viewer)", `aria-current="page"`,
		"Reachable", "https://ca.internal.example:9000", "0.30.2", "12:00:00 UTC",
		"Example Root CA", "2035-11-11, in 9 years", grouped(ca.Fingerprint(s.ca.root)),
		"Example Intermediate CA", "2029-11-11, in 3 years",
		"No revocation list", "systems that already trust it are not told",
		"handrail", "90 days", "acme", "CA default",
	)
	for _, absent := range []string{"Not reachable", "Not known", "could not", "does not list"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("a healthy CA's page says %q", absent)
		}
	}
}

func TestStatusPageShowsWhatItCouldNotLearn(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	s.ca.healthErr = errors.New("dial tcp: connection refused")
	s.ca.versionErr = errors.New("no answer")
	s.ca.rootsErr = errors.New("roots unavailable")
	s.ca.intersErr = &ca.StatusError{Status: 404}
	s.ca.provsErr = errors.New(`provisioner "<b>x</b>" is broken`)
	s.ca.crlErr = errors.New("the CA answered 500")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"Not reachable", "connection refused",
		"Not known",
		"Whether the CA still publishes this root could not be checked: roots unavailable",
		"intermediate certificates could not be read: the CA answered 404",
		"Whether the CA publishes a revocation list could not be determined",
		"provisioners could not be read",
		// The configured root is shown whatever the CA says.
		"Example Root CA",
	)
	// Text from the CA is escaped, and a failure is never shown as a no.
	if strings.Contains(page.Body.String(), "<b>x</b>") {
		t.Error("text from the CA was written into the page unescaped")
	}
	if strings.Contains(page.Body.String(), "No revocation list") || strings.Contains(page.Body.String(), ">Reachable<") {
		t.Error("an unknown state is shown as a known one")
	}
}

func TestStatusPageVariants(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	s.ca.crl = ca.CRL{Published: true, Entries: 1, NextUpdate: t0.Add(23 * time.Hour)}
	s.ca.published = []*x509.Certificate{s.ca.inter} // the CA lists some other root
	s.ca.root = testCert(t, "", t0.Add(-48*time.Hour))
	s.ca.provs = nil
	page := b.get("/status")
	wantBody(t, page,
		"Revocation list published", "with 1 revoked certificate;", "next update 2026-11-12, in 23 hours",
		"The CA does not list this certificate among its roots.",
		"Expired", "expired 2 days ago",
		"The CA has no provisioners.",
	)
}

func TestStatusIsReadOncePerInterval(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	b.get("/status")
	b.get("/status")
	if n := s.ca.calls.Load(); n != 1 {
		t.Errorf("the CA was read %d times for two page loads, want 1", n)
	}
	s.clock.advance(statusMaxAge)
	wantBody(t, b.get("/status"), "12:00:15 UTC")
	if n := s.ca.calls.Load(); n != 2 {
		t.Errorf("the CA was read %d times after the interval, want 2", n)
	}
}

func TestWords(t *testing.T) {
	day := 24 * time.Hour
	for d, want := range map[time.Duration]string{
		0: "0 seconds", time.Second: "1 second", 59 * time.Second: "59 seconds",
		time.Minute: "1 minute", 90 * time.Minute: "1 hour", 47 * time.Hour: "47 hours",
		2 * day: "2 days", 59 * day: "59 days", 60 * day: "2 months", 729 * day: "24 months",
		730 * day: "2 years", -3 * day: "3 days",
	} {
		if got := span(d); got != want {
			t.Errorf("span(%v) = %q, want %q", d, got, want)
		}
	}
	for d, want := range map[time.Duration]string{
		0: "CA default", 90 * day: "90 days", day: "1 day", 36 * time.Hour: "36 hours",
		5 * time.Minute: "5 minutes", 90 * time.Second: "1m30s",
	} {
		if got := validity(d); got != want {
			t.Errorf("validity(%v) = %q, want %q", d, got, want)
		}
	}
	if got := expiry(t0, t0); got != "2026-11-11, expired 0 seconds ago" {
		t.Errorf("expiry at the instant = %q", got)
	}
	if got := grouped("0123456789abcdef01"); got != "01234567 89abcdef 01" {
		t.Errorf("grouped = %q", got)
	}
}

func TestSourceURL(t *testing.T) {
	tests := []struct{ version, want string }{
		{"v0.1.0", repoURL + "/tree/v0.1.0"},
		{"v0.1.0-3-gabc1234", repoURL + "/tree/abc1234"},
		{"v0.1.0-3-gabc1234-dirty", repoURL + "/tree/abc1234"},
		{"abc1234", repoURL + "/tree/abc1234"},
		{"abc1234-dirty", repoURL + "/tree/abc1234"},
		{"dev", repoURL},
		{"ci", repoURL},
		{"", repoURL},
		{"v1.2.3-rc1", repoURL},
	}
	for _, tt := range tests {
		if got := SourceURL(tt.version); got != tt.want {
			t.Errorf("SourceURL(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}
