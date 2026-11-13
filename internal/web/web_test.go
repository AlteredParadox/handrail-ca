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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
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
	inters      []*x509.Certificate // nil means inter alone
	published   []*x509.Certificate // nil means the root
	provs       []ca.Provisioner
	crl         ca.CRL
	version     string

	healthErr, versionErr, rootErr, rootsErr, intersErr, provsErr, crlErr error
	calls                                                                 atomic.Int64

	// readOnly is a client with no provisioner; unlockErr is why the
	// provisioner's key cannot be opened, nil when it is open.
	readOnly  bool
	unlockErr error

	// revoke is what the CA does when asked to revoke; newSite sets it to
	// confirm and record the revocation in the site's database, as step-ca
	// does. asked is every revocation it was sent.
	revoke func(ctx context.Context, r ca.Revocation) error
	mu     sync.Mutex
	asked  []ca.Revocation

	// sign is what the CA does when asked to sign; newSite sets it to
	// issue a certificate and store it in the site's database. signed is
	// every signing it was asked for.
	sign   func(ctx context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error)
	signed []signing
}

// signing is one signing request the fake CA received.
type signing struct {
	request  *ca.Request
	validity time.Duration
}

func (f *fakeCA) Sign(ctx context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
	if f.readOnly {
		return nil, &ca.NotSentError{Err: ca.ErrNoProvisioner}
	}
	f.mu.Lock()
	f.signed = append(f.signed, signing{r, validity})
	f.mu.Unlock()
	return f.sign(ctx, r, validity)
}

// signings is every signing the CA was asked for.
func (f *fakeCA) signings() []signing {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]signing{}, f.signed...)
}

func (f *fakeCA) Revoke(ctx context.Context, r ca.Revocation) error {
	if f.readOnly {
		return ca.ErrNoProvisioner
	}
	f.mu.Lock()
	f.asked = append(f.asked, r)
	f.mu.Unlock()
	return f.revoke(ctx, r)
}

// sent is every revocation the CA was asked for.
func (f *fakeCA) sent() []ca.Revocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ca.Revocation{}, f.asked...)
}

const fakeKeyID = "kid-of-the-handrail-key"

func (f *fakeCA) ProvisionerState() ca.ProvisionerState {
	if f.readOnly {
		return ca.ProvisionerState{}
	}
	st := ca.ProvisionerState{Configured: true, Name: "handrail"}
	if f.unlockErr == nil {
		st.Ready, st.KeyID = true, fakeKeyID
	}
	return st
}

func (f *fakeCA) Unlock(context.Context) error {
	if f.readOnly {
		return ca.ErrNoProvisioner
	}
	return f.unlockErr
}

func (f *fakeCA) URL() string             { return "https://ca.internal.example:9000" }
func (f *fakeCA) RootFingerprint() string { return ca.Fingerprint(f.root) }
func (f *fakeCA) Root(context.Context) (*x509.Certificate, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	return f.root, nil
}
func (f *fakeCA) Health(context.Context) error { f.calls.Add(1); return f.healthErr }
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
	if f.inters != nil {
		return f.inters, f.intersErr
	}
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

// fakeRows stands in for the CA's database: an inventory.Source over rows
// held in memory, which can be made to fail.
type fakeRows struct {
	mu          sync.Mutex
	certs       []inventory.RawCertificate
	revocations []inventory.RawRevocation
	err         error
}

func (f *fakeRows) Describe() string { return "a test database" }

func (f *fakeRows) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRows) Serials(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var serials []string
	for _, c := range f.certs {
		serials = append(serials, c.Serial)
	}
	return serials, nil
}

func (f *fakeRows) Certificates(_ context.Context, serials []string) ([]inventory.RawCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var rows []inventory.RawCertificate
	for _, c := range f.certs {
		for _, s := range serials {
			if c.Serial == s {
				rows = append(rows, c)
			}
		}
	}
	return rows, f.err
}

func (f *fakeRows) Revocations(context.Context) ([]inventory.RawRevocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revocations, f.err
}

// leafRow is a certificate row as the CA would store it.
func leafRow(t *testing.T, serial int64, name string, notBefore, notAfter time.Time) inventory.RawCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notBefore, NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.RawCertificate{Serial: fmt.Sprint(serial), DER: der, Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`)}
}

// newFakeRows is a small database: one valid certificate, one expired, one
// revoked, and one row that is not a certificate.
func newFakeRows(t *testing.T) *fakeRows {
	t.Helper()
	day := 24 * time.Hour
	return &fakeRows{
		certs: []inventory.RawCertificate{
			leafRow(t, 101, "web1.internal.example", t0.Add(-day), t0.Add(90*day)),
			leafRow(t, 102, "old.internal.example", t0.Add(-10*day), t0.Add(-day)),
			leafRow(t, 103, "gone.internal.example", t0.Add(-day), t0.Add(90*day)),
			{Serial: "104", DER: []byte("not a certificate")},
		},
		revocations: []inventory.RawRevocation{{Serial: "103", JSON: []byte(`{"Serial":"103","ReasonCode":1,"RevokedAt":"2026-11-11T08:00:00Z"}`)}},
	}
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
	noteErr, setNoteErr                               atomic.Pointer[error]
	// readHistoryErr fails the reading of the history; historyErr, above,
	// the writing of it.
	readHistoryErr atomic.Pointer[error]
	// deviceErr fails looking a device up, rememberErr recording one.
	deviceErr, rememberErr atomic.Pointer[error]
	// touchErr fails recording that a session was used.
	touchErr atomic.Pointer[error]
	// With limitWrites set, only writesLeft more history writes work.
	limitWrites atomic.Bool
	writesLeft  atomic.Int32
	// beforeDelete runs as a session is about to be ended.
	beforeDelete func(store.TokenHash)
	// beforeGap, when set, runs as a row about a gap in the history is
	// about to be written.
	beforeGap func()
	// beforeTouch, when set, runs as a session's use is about to be
	// written.
	beforeTouch func(store.TokenHash, time.Time)
	// appendGate, when set, holds every history write until it is closed.
	appendGate atomic.Pointer[chan struct{}]
	// beforeCreate runs between the password check and the session being
	// created, where a concurrent `user passwd` could land. beforeChange
	// runs at the same point of a change of password.
	beforeCreate, beforeChange func()
}

func (b *brokenStore) ChangePassword(ctx context.Context, id int64, oldHash, newHash string, now time.Time) error {
	if b.beforeChange != nil {
		b.beforeChange()
	}
	return b.Store.ChangePassword(ctx, id, oldHash, newHash, now)
}

func (b *brokenStore) Note(ctx context.Context, serial string) (store.Note, error) {
	if err := b.noteErr.Load(); err != nil {
		return store.Note{}, *err
	}
	return b.Store.Note(ctx, serial)
}

func (b *brokenStore) SetNote(ctx context.Context, n store.Note) error {
	if err := b.setNoteErr.Load(); err != nil {
		return *err
	}
	return b.Store.SetNote(ctx, n)
}

func (b *brokenStore) DeviceUser(ctx context.Context, h store.TokenHash, now time.Time) (string, error) {
	if err := b.deviceErr.Load(); err != nil {
		return "", *err
	}
	return b.Store.DeviceUser(ctx, h, now)
}

func (b *brokenStore) RememberDevice(ctx context.Context, id int64, hash string, h store.TokenHash, now time.Time) error {
	if err := b.rememberErr.Load(); err != nil {
		return *err
	}
	return b.Store.RememberDevice(ctx, id, hash, h, now)
}

func (b *brokenStore) History(ctx context.Context, q store.HistoryQuery) ([]store.Event, error) {
	if err := b.readHistoryErr.Load(); err != nil {
		return nil, *err
	}
	return b.Store.History(ctx, q)
}

func (b *brokenStore) AppendHistory(ctx context.Context, e store.Event) error {
	if gate := b.appendGate.Load(); gate != nil {
		<-*gate
	}
	if err := b.historyErr.Load(); err != nil {
		return *err
	}
	if e.Action == store.ActionHistoryGap && b.beforeGap != nil {
		b.beforeGap()
	}
	if b.limitWrites.Load() && b.writesLeft.Add(-1) < 0 {
		return errors.New("database or disk is full")
	}
	return b.Store.AppendHistory(ctx, e)
}

func (b *brokenStore) DeleteSession(ctx context.Context, h store.TokenHash) (bool, error) {
	if b.beforeDelete != nil {
		b.beforeDelete(h)
	}
	return b.Store.DeleteSession(ctx, h)
}

func (b *brokenStore) TouchSession(ctx context.Context, h store.TokenHash, now time.Time) error {
	if err := b.touchErr.Load(); err != nil {
		return *err
	}
	if b.beforeTouch != nil {
		b.beforeTouch(h, now)
	}
	return b.Store.TouchSession(ctx, h, now)
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
	rows    *fakeRows
	inv     *inventory.Inventory
	clock   *clock
	log     *bytes.Buffer
	public  *url.URL
	// signer is what the fake CA signs certificates with, and nextSerial
	// the serial number of the next one.
	signer     issuer
	nextSerial int64
}

// newSite builds a site at publicURL, with the given addresses or ranges
// as its trusted proxies.
func newSite(t *testing.T, publicURL string, trustedProxies ...string) *site {
	t.Helper()
	proxies, err := ParseTrustedProxies(strings.Join(trustedProxies, ","))
	if err != nil {
		t.Fatal(err)
	}
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
	s := &site{t: t, store: &brokenStore{Store: st}, ca: newFakeCA(t), rows: newFakeRows(t), clock: &clock{now: t0}, log: &bytes.Buffer{}, public: u}
	s.ca.revoke = func(_ context.Context, r ca.Revocation) error {
		s.caRecords(r)
		return nil
	}
	s.signer = newIssuer(t, "Example Issuing CA")
	s.ca.sign = func(_ context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
		issued := s.caSigns(r, validity)
		s.caStores(issued.Certificate)
		return issued, nil
	}
	// The inventory as it is after its first read, on the site's clock.
	s.inv = inventory.New(s.rows)
	s.inv.SetClock(s.clock.Now)
	if err := s.inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	s.server, s.handler, err = build(Options{
		Version: "v1.2.3", License: []byte("LICENSE TEXT"), ThirdPartyLicenses: []byte("NOTICES TEXT"),
		Store: s.store, CA: s.ca, Inventory: s.inv, PublicURL: u, TrustedProxies: proxies, Now: s.clock.Now,
		Log: slog.New(slog.NewTextHandler(&syncWriter{buf: s.log}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The stand-in checked for accounts that do not exist: cheap, like the
	// real ones here.
	s.server.dummyHash = cheapHash("nobody has this password")
	s.server.hash = func(pw string) (string, error) { return cheapHash(pw), nil }
	return s
}

// caSigns makes the certificate step-ca would for a request: the common
// name and names the request was read as, valid for the length asked (a
// day if none) and dated a minute back.
func (s *site) caSigns(r *ca.Request, validity time.Duration) *ca.Issued {
	s.t.Helper()
	if validity == 0 {
		validity = 24 * time.Hour
	}
	s.rows.mu.Lock()
	s.nextSerial++
	serial := 5000 + s.nextSerial
	s.rows.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: r.CommonName},
		DNSNames: r.DNSNames, EmailAddresses: r.EmailAddresses,
		NotBefore: s.clock.Now().Add(-time.Minute), NotAfter: s.clock.Now().Add(validity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, ip := range r.IPAddresses {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	for _, u := range r.URIs {
		parsed, err := url.Parse(u)
		if err != nil {
			s.t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.signer.cert, r.CSR.PublicKey, s.signer.key)
	if err != nil {
		s.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.t.Fatal(err)
	}
	return &ca.Issued{Certificate: cert, Intermediates: []*x509.Certificate{s.signer.cert}}
}

// caStores puts a certificate into the site's database as step-ca would.
func (s *site) caStores(cert *x509.Certificate) {
	s.rows.mu.Lock()
	defer s.rows.mu.Unlock()
	s.rows.certs = append(s.rows.certs, inventory.RawCertificate{
		Serial: cert.SerialNumber.String(), DER: cert.Raw, Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`),
	})
}

// caRecords writes a revocation into the site's database as step-ca
// would, stamped with the site's clock.
func (s *site) caRecords(r ca.Revocation) {
	record, err := json.Marshal(map[string]any{
		"Serial": r.Serial, "ProvisionerID": "p1", "ReasonCode": r.ReasonCode, "Reason": r.Reason,
		"RevokedAt": s.clock.Now().UTC().Format(time.RFC3339), "TokenID": "t", "MTLS": false, "ACME": false,
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.rows.mu.Lock()
	defer s.rows.mu.Unlock()
	s.rows.revocations = append(s.rows.revocations, inventory.RawRevocation{Serial: r.Serial, JSON: record})
}

// attemptsOfDevices is how many sign-in attempts are counted against
// known devices, all together.
func (l *limiter) attemptsOfDevices() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.devices {
		n += e.attempts
	}
	return n
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
	// Rows of failed sign-ins are written after their answers.
	s.server.late.settle()
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
	// remote is the address the connection comes from (10.20.0.5 if not
	// set), and forwardedFor the X-Forwarded-For header sent with it.
	remote       string
	forwardedFor string
	// ctx replaces the request's context, for a browser that goes away.
	ctx context.Context
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
	if b.remote != "" {
		req.RemoteAddr = b.remote
	}
	if b.forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", b.forwardedFor)
	}
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
	if b.ctx != nil {
		req = req.WithContext(b.ctx)
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
		"no inventory":  func(o *Options) { o.Inventory = nil },
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
		{"/static/fonts/OFL.txt", http.StatusOK, "SIL Open Font License"},
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

// Every font the style sheet names is in the binary, and is served as a
// font from this origin, which is all the Content-Security-Policy allows.
func TestFontsAreEmbedded(t *testing.T) {
	b := newSite(t, "http://127.0.0.1:8080").browser()
	css := b.get("/static/style.css").Body.String()
	files := regexp.MustCompile(`url\("(fonts/[^"]+)"\)`).FindAllStringSubmatch(css, -1)
	if len(files) != 5 {
		t.Fatalf("the style sheet names %d font files, want 5", len(files))
	}
	for _, m := range files {
		rec := b.get("/static/" + m[1])
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "font/woff2" || !strings.HasPrefix(rec.Body.String(), "wOF2") {
			t.Errorf("%s: %d %q", m[1], rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if regexp.MustCompile(`(?i)@import|url\(\s*["']?(https?:)?//`).MatchString(css) {
		t.Error("the style sheet loads something from another site")
	}
	// The fonts' license is among the third-party notices the binary serves.
	if notices := string(legalNotices(t)); !strings.Contains(notices, "IBM Plex") || !strings.Contains(notices, "SIL OPEN FONT LICENSE") {
		t.Error("THIRD_PARTY_LICENSES.md does not carry the fonts' license")
	}
}

func legalNotices(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../THIRD_PARTY_LICENSES.md")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSecurityHeaders(t *testing.T) {
	b := newSite(t, "http://127.0.0.1:8080").browser()
	for _, path := range []string{"/healthz", "/sign-in", "/", "/no-such-page", "/static/style.css"} {
		h := b.get(path).Header()
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "same-origin" {
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
	wantRedirect(t, b.get("/history"), "/sign-in")
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

	wantBody(t, b.get("/"), "<h1>Certificates</h1>")
	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, ">alice</a> (operator)", "Sign out", "ca.internal.example")
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
	rec := b.do(http.MethodPost, "/sign-out", big)
	wantStatus(t, rec, http.StatusRequestEntityTooLarge)
	wantBody(t, rec, "What was sent is larger than this form takes.")
	// Nothing in it was acted on: still signed in.
	wantStatus(t, b.get("/status"), http.StatusOK)
}

// The throttle counts by user name and by the visitor's address, where the
// address is known: here, behind a proxy that says who it speaks for.
func TestSignInIsThrottled(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example", "10.20.0.5")
	visitor := func() *browser {
		b := s.browser()
		b.forwardedFor = "203.0.113.7"
		return b
	}
	for range limiterAttempts {
		wantStatus(t, visitor().signIn("alice", "a wrong password"), http.StatusUnauthorized)
	}
	// Now even the right password is refused, without being checked.
	rec := visitor().signIn("alice", alicePassword)
	wantStatus(t, rec, http.StatusTooManyRequests)
	wantBody(t, rec, "Too many failed sign-ins")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	// The same address is throttled for other names too.
	wantStatus(t, visitor().signIn("bob", bobPassword), http.StatusTooManyRequests)

	s.clock.advance(limiterWindow)
	wantRedirect(t, visitor().signIn("alice", alicePassword), "/")

	// A success clears the name's count: four more failures do not lock it.
	s.server.limiter = newLimiter()
	for range limiterAttempts - 1 {
		visitor().signIn("bob", "wrong")
	}
	wantRedirect(t, visitor().signIn("bob", bobPassword), "/")
	if e := s.server.limiter.names["bob"]; e != nil {
		t.Errorf("bob's failures were kept after a success: %+v", e)
	}
	// The address keeps its four failures, and gets the successful attempt
	// back: one more wrong guess is checked, the one after is not.
	if e := s.server.limiter.addrs["203.0.113.7"]; e == nil || e.attempts != limiterAttempts-1 {
		t.Errorf("the address's count after a success: %+v", e)
	}
	wantStatus(t, visitor().signIn("alice", "wrong"), http.StatusUnauthorized)
	wantStatus(t, visitor().signIn("alice", alicePassword), http.StatusTooManyRequests)

	// Names that cannot be accounts count against the address as well.
	s.server.limiter = newLimiter()
	for range limiterAttempts {
		wantStatus(t, visitor().signIn("not a name", "x"), http.StatusUnauthorized)
	}
	wantStatus(t, visitor().signIn("not a name", "x"), http.StatusTooManyRequests)
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
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			// Refused by the throttle, or turned away because the line
			// for a hashing slot was full: unchecked either way.
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

// A full table must not forget who is locked out: forgetting would give a
// locked account five fresh guesses to anyone able to fill the table.
func TestLimiterStaysBoundedWithoutForgetting(t *testing.T) {
	const size = 50
	small := func() *limiter {
		l := newLimiter()
		l.maxLen = size
		return l
	}
	lock := func(l *limiter, name, addr string) {
		for range limiterAttempts {
			if l.begin(t0, name, addr) != 0 {
				t.Fatalf("locking %q/%q: refused early", name, addr)
			}
		}
	}

	t.Run("addresses", func(t *testing.T) {
		l := small()
		lock(l, "alice", "")
		lock(l, "", "203.0.113.1")
		// Fill the address table from many addresses, as malformed user
		// names would: no password hashing involved.
		for i := 0; len(l.addrs) < size; i++ {
			l.begin(t0, "", fmt.Sprintf("2001:db8::%x", i))
		}
		later := t0.Add(time.Minute)
		// More new addresses are let through uncounted; the table does not
		// grow and nothing in it is dropped.
		for i := range 3 * size {
			if l.begin(later, "", fmt.Sprintf("2001:db8:1::%x", i)) != 0 {
				t.Fatal("a new address was refused because the table is full")
			}
		}
		if len(l.addrs) != size {
			t.Errorf("%d addresses tracked, want %d", len(l.addrs), size)
		}
		if l.blocked(later, "alice", "") == 0 || l.begin(later, "alice", "2001:db8:2::1") == 0 {
			t.Error("alice's lockout was lost when the address table filled")
		}
		if l.blocked(later, "", "203.0.113.1") == 0 {
			t.Error("a locked address was forgotten when the table filled")
		}
		// Once windows have run out, their entries make room again.
		after := t0.Add(limiterWindow)
		l.begin(after, "", "198.51.100.1")
		if l.addrs["198.51.100.1"] == nil || len(l.addrs) != 1 {
			t.Errorf("after the windows ended: %d entries", len(l.addrs))
		}
	})

	t.Run("names", func(t *testing.T) {
		l := small()
		lock(l, "alice", "")
		for i := 0; len(l.names) < size; i++ {
			l.begin(t0, fmt.Sprintf("name-%d", i), "")
		}
		later := t0.Add(time.Minute)
		// A name not seen before is refused, and counted nowhere.
		if l.begin(later, "newcomer", "192.0.2.9") == 0 {
			t.Error("a new name was accepted with the table of names full")
		}
		if len(l.names) != size || l.addrs["192.0.2.9"] != nil {
			t.Errorf("a refused attempt was counted: %d names, address %v", len(l.names), l.addrs["192.0.2.9"])
		}
		// Names already there carry on as before.
		if l.begin(later, "name-0", "") != 0 {
			t.Error("a known name with attempts left was refused")
		}
		if l.blocked(later, "alice", "") == 0 {
			t.Error("alice's lockout was lost when the table of names filled")
		}
		if l.begin(t0.Add(limiterWindow), "newcomer", "") != 0 {
			t.Error("a new name is still refused after the windows ended")
		}
	})

	t.Run("bookkeeping", func(t *testing.T) {
		l := small()
		if l.blocked(t0, "nobody", "192.0.2.1") != 0 || l.blocked(t0, "", "") != 0 {
			t.Error("an unknown key is blocked")
		}
		// A refused attempt counts against neither key.
		lock(l, "alice", "")
		if l.begin(t0, "alice", "192.0.2.1") == 0 || l.addrs["192.0.2.1"] != nil {
			t.Error("a refused attempt was counted against its address")
		}
		// Empty keys are never stored.
		l.begin(t0, "", "")
		if l.names[""] != nil || l.addrs[""] != nil {
			t.Error("an empty key was stored")
		}
		l.succeed("nobody", "192.0.2.77") // nothing to clear or give back
		// A used-up window that has ended blocks nothing.
		if l.blocked(t0.Add(limiterWindow), "alice", "") != 0 {
			t.Error("alice is blocked after her window ended")
		}
	})
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

// A reverse proxy that does not pass the visitor's Host header on makes
// every page a 421. The log has to say why, once, and must not become a
// place where whoever sends requests can write as much as they like.
func TestRefusedHostIsExplainedInTheLog(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example")
	b := s.browser()
	b.host = "127.0.0.1:8080" // what nginx sends by default: the backend's address
	for range 3 {
		wantStatus(t, b.get("/sign-in"), http.StatusMisdirectedRequest)
	}
	log := s.log.String()
	if n := strings.Count(log, "refused a request addressed to a host name"); n != 1 {
		t.Fatalf("the refusal was logged %d times, want once: %s", n, log)
	}
	for _, want := range []string{"asked_for=127.0.0.1:8080", "answering_only=handrail.internal.example", "proxy_set_header Host"} {
		if !strings.Contains(log, want) {
			t.Errorf("the log line lacks %q: %s", want, log)
		}
	}

	// Many different names, one of them very long: a bounded number of
	// lines, each of bounded length.
	for i := range 3 * maxDistinctWarnings {
		b.host = fmt.Sprintf("name-%d.example", i)
		b.get("/")
	}
	b.host = strings.Repeat("x", 5000) + ".example"
	b.get("/")
	log = s.log.String()
	if n := strings.Count(log, "refused a request addressed to a host name"); n != maxDistinctWarnings {
		t.Errorf("%d refusals logged, want %d", n, maxDistinctWarnings)
	}
	if strings.Contains(log, strings.Repeat("x", 200)) {
		t.Error("a host name was logged at full length")
	}
	if got := clipHost(strings.Repeat("x", 5000)); len(got) > 110 {
		t.Errorf("clipHost kept %d bytes", len(got))
	}
	// The probe, which is answered under any name, is not a refusal.
	quiet := newSite(t, "https://handrail.internal.example")
	qb := quiet.browser()
	qb.host = "127.0.0.1:8080"
	wantStatus(t, qb.get("/healthz"), http.StatusOK)
	if strings.Contains(quiet.log.String(), "refused a request") {
		t.Error("the health probe was logged as a refusal")
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
	home := b.get("/handrail/")
	wantStatus(t, home, http.StatusOK)
	wantBody(t, home, `action="/handrail/refresh"`, `href="/handrail/?view=all"`, `<form class="card filters" method="get" action="/handrail/">`, `href="/handrail/" aria-current="page"`)
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
		">bob</a> (viewer)", `aria-current="page"`,
		"Reachable", "https://ca.internal.example:9000", "0.30.2", "12:00:00 UTC",
		"Example Root CA", "2035-11-11, in 9 years", grouped(ca.Fingerprint(s.ca.root)),
		"Example Intermediate CA", "2029-11-11, in 3 years",
		"No revocation list", "systems that already trust it are not told",
		"handrail", "90 days", "acme", "CA default",
		// The inventory, as of its last read.
		"Certificate inventory", "Up to date", "a test database",
		"0 seconds ago, at 12:00:00 UTC",
		"4 in all: 1 valid, 1 expired, 1 revoked, 1 unreadable",
		"Read again every 30 seconds",
		// What handrail-ca can do on the CA.
		"Acting on the CA", ">Ready<", fakeKeyID, "held in memory only",
	)
	for _, absent := range []string{"Not reachable", "Not known", "could not", "does not list", "Not ready", "Read-only", "has not been opened"} {
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
		// The root was fetched before things went wrong, and is still shown.
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

// Until a root with the configured fingerprint has been fetched, the page
// shows the fingerprint and says so; it does not show a root it has not
// checked.
func TestStatusPageBeforeTheRootIsFetched(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	down := errors.New("pinning the CA's root: dial tcp: connection refused")
	s.ca.rootErr, s.ca.healthErr, s.ca.rootsErr = down, down, down

	page := b.get("/status")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"Not fetched", grouped(ca.Fingerprint(s.ca.root)),
		"Nothing from the CA is trusted until a root with this fingerprint has been fetched",
		"The root could not be fetched: pinning the CA&#39;s root: dial tcp: connection refused",
		"Not reachable",
	)
	for _, absent := range []string{"Example Root CA", "2035-11-11", "was fetched from the CA and matched"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the page shows %q for a root that was never fetched", absent)
		}
	}
}

// The card for acting on the CA says read-only when that is how
// handrail-ca was started, and why the key is not open when it is not;
// neither is shown as ready.
func TestStatusPageActingStates(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.ca.readOnly = true
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	wantBody(t, page, "Acting on the CA", ">Read-only<", "was started read-only", "nothing can be issued or revoked from here")
	for _, absent := range []string{">Ready<", "Not ready", fakeKeyID, "Key ID", "has not been opened"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("a read-only handrail-ca's page says %q", absent)
		}
	}

	s = newSite(t, "http://127.0.0.1:8080")
	s.ca.unlockErr = errors.New(`provisioner "<handrail>": the configured password does not open its key`)
	b = s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page = b.get("/status")
	wantBody(t, page, "Acting on the CA", ">Not ready<", ">handrail <",
		"The provisioner's key has not been opened, so nothing can be revoked from here: provisioner &#34;&lt;handrail&gt;&#34;: the configured password does not open its key")
	for _, absent := range []string{">Ready<", "Read-only", fakeKeyID, "Key ID", "held in memory only"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the page of a handrail-ca whose key is not open says %q", absent)
		}
	}
}

// The inventory card says how old its picture is and why, and never shows
// a count it does not have.
func TestStatusPageInventoryStates(t *testing.T) {
	ctx := context.Background()

	// Never read: the database was down from the start.
	s := newSite(t, "http://127.0.0.1:8080")
	down := &fakeRows{err: errors.New(`failed to connect to "<db>": connection refused`)}
	never := inventory.New(down)
	never.SetClock(s.clock.Now)
	_ = never.Refresh(ctx)
	s.server.opts.Inventory = never
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/status")
	wantBody(t, page, "Not read", "Never", "Not known",
		"It could not be read: listing certificates: failed to connect to &#34;&lt;db&gt;&#34;: connection refused")
	for _, absent := range []string{"Up to date", "0 in all", "ago, at"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("an unread inventory's card says %q", absent)
		}
	}

	// Read once, then the database goes away: the earlier picture, its
	// age, and the reason.
	s = newSite(t, "http://127.0.0.1:8080")
	b = s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.clock.advance(5 * time.Minute)
	s.rows.fail(errors.New("connection reset by peer"))
	if err := s.inv.Refresh(ctx); err == nil {
		t.Fatal("the refresh succeeded against a failing source")
	}
	page = b.get("/status")
	wantBody(t, page, "Out of date", "5 minutes ago, at 12:00:00 UTC", "4 in all",
		"The last attempt to read it again failed, so this is the picture as it was then: listing certificates: connection reset by peer")
	if strings.Contains(page.Body.String(), "Up to date") {
		t.Error("a stale inventory is called up to date")
	}

	// And back, with what changed meanwhile: a certificate that has
	// expired by now, and revocations for serials never issued.
	s.rows.fail(nil)
	s.rows.mu.Lock()
	s.rows.revocations = append(s.rows.revocations, inventory.RawRevocation{Serial: "9001", JSON: []byte(`{}`)})
	s.rows.mu.Unlock()
	if err := s.inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	page = b.get("/status")
	wantBody(t, page, "Up to date", "1 revocation is recorded for serial numbers that are not among the certificates")
	s.rows.mu.Lock()
	s.rows.revocations = append(s.rows.revocations, inventory.RawRevocation{Serial: "9002", JSON: []byte(`{}`)})
	s.rows.mu.Unlock()
	if err := s.inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	wantBody(t, b.get("/status"), "2 revocations are recorded")
	// The counts are as of now, not as of the read.
	s.clock.advance(100 * 24 * time.Hour)
	b = s.browser() // the session ended long ago
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	wantBody(t, b.get("/status"), "4 in all: 2 expired, 1 revoked, 1 unreadable")
}

// A read that has not come back says nothing, so a picture judged by the
// last error alone would look current for as long as that lasts. Past a
// few refresh intervals it is out of date whatever the last attempt said.
func TestAPictureNotReadAgainGoesStale(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	const reason = "no read of the CA&#39;s database has finished since then"
	pages := []string{"/status", "/", "/names", "/certificates/101", "/certificates/101/revoke"}

	s.clock.advance(staleAfter - time.Second)
	for _, path := range pages {
		page := b.get(path)
		wantStatus(t, page, http.StatusOK)
		if strings.Contains(page.Body.String(), reason) {
			t.Errorf("%s calls a picture just under the limit out of date", path)
		}
	}
	wantBody(t, b.get("/status"), "Up to date")

	// Nothing failed; nothing came back either.
	s.clock.advance(time.Second)
	for _, path := range pages {
		page := b.get(path)
		wantStatus(t, page, http.StatusOK)
		wantBody(t, page, reason, "2 minutes ago")
	}
	status := b.get("/status")
	wantBody(t, status, "Out of date")
	if strings.Contains(status.Body.String(), "Up to date") {
		t.Error("a picture two minutes old with no read since is called up to date")
	}
	wantBody(t, b.get("/certificates/101"), "Not revoked 2 minutes ago")

	// A read that finishes makes it current again.
	if err := s.inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status = b.get("/status")
	wantBody(t, status, "Up to date")
	if strings.Contains(status.Body.String(), reason) {
		t.Error("the picture is still called out of date after a read")
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

// Behind a declared proxy each visitor is throttled by their own address,
// taken from the header the proxy sets.
func TestThrottlePerVisitorBehindATrustedProxy(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example", "10.20.0.5", "10.20.9.0/24")
	visitor := func(forwardedFor string) *browser {
		b := s.browser()
		b.forwardedFor = forwardedFor
		return b
	}
	for range limiterAttempts {
		wantStatus(t, visitor("203.0.113.7").signIn("alice", "wrong"), http.StatusUnauthorized)
	}
	// That visitor has used their attempts, for any name.
	wantStatus(t, visitor("203.0.113.7").signIn("bob", bobPassword), http.StatusTooManyRequests)
	// Putting other addresses in front of the header does not help: the
	// proxy appends the real one, and only what the proxy wrote is read.
	wantStatus(t, visitor("198.51.100.1, 203.0.113.7").signIn("bob", bobPassword), http.StatusTooManyRequests)
	wantStatus(t, visitor("10.20.0.5, 203.0.113.7").signIn("bob", bobPassword), http.StatusTooManyRequests)
	// Through a second trusted proxy, the same visitor is still that visitor.
	wantStatus(t, visitor("203.0.113.7, 10.20.9.4").signIn("bob", bobPassword), http.StatusTooManyRequests)

	// Another visitor is not affected, and the history has their address,
	// not the proxy's.
	wantRedirect(t, visitor("203.0.113.8").signIn("bob", bobPassword), "/")
	if last := s.history()[0]; last.Actor != "bob" || last.Remote != "203.0.113.8" {
		t.Errorf("history = %+v", last)
	}
}

// The regression this guards: behind a proxy every visitor arrives from the
// proxy's address. Counted as one visitor, five wrong sign-ins by anyone
// would block everyone's.
func TestOneVisitorCannotLockEveryoneOutBehindAProxy(t *testing.T) {
	for name, s := range map[string]*site{
		// HTTPS means a proxy is in front; none has been declared.
		"undeclared proxy": newSite(t, "https://handrail.internal.example"),
		// Declared, but it sends no usable X-Forwarded-For.
		"proxy without the header": newSite(t, "https://handrail.internal.example", "10.20.0.5"),
		// Declared under an address that is not the one it arrives from, as
		// with 127.0.0.1 for a proxy that reaches a container over Docker's
		// bridge.
		"proxy listed under another address": newSite(t, "https://handrail.internal.example", "127.0.0.1"),
	} {
		t.Run(name, func(t *testing.T) {
			for range limiterAttempts + 3 {
				s.browser().signIn("nobody-"+name[:5], "wrong")
				s.browser().signIn("not a name", "wrong")
			}
			wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
			// The limit per user name still holds.
			for range limiterAttempts {
				wantStatus(t, s.browser().signIn("alice", "wrong"), http.StatusUnauthorized)
			}
			wantStatus(t, s.browser().signIn("alice", alicePassword), http.StatusTooManyRequests)
			wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
		})
	}
}

// Under an http public URL every browser arrives from this machine's own
// address. Counted as one visitor, five wrong sign-ins by any program on
// the machine would refuse everyone's.
func TestOneLocalClientCannotLockEveryoneOutOnLoopback(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	local := func() *browser {
		b := s.browser()
		b.remote = "127.0.0.1:40000"
		return b
	}
	for range limiterAttempts + 3 {
		local().signIn("not a name", "wrong")
		local().signIn("nobody", "wrong")
	}
	wantRedirect(t, local().signIn("bob", bobPassword), "/")
	// The limit per user name still holds.
	for range limiterAttempts {
		wantStatus(t, local().signIn("alice", "wrong"), http.StatusUnauthorized)
	}
	wantStatus(t, local().signIn("alice", alicePassword), http.StatusTooManyRequests)
	wantRedirect(t, local().signIn("bob", bobPassword), "/")
	if last := s.history()[0]; last.Remote != "127.0.0.1" {
		t.Errorf("history has %q as the address, want the connection's", last.Remote)
	}
}

// Without a trusted proxy in the path the header is the visitor's own
// words, and is not believed.
func TestForwardedHeaderIsIgnoredFromAnUntrustedPeer(t *testing.T) {
	for name, s := range map[string]*site{
		"no proxies configured": newSite(t, "http://127.0.0.1:8080"),
		"peer is not the proxy": newSite(t, "http://127.0.0.1:8080", "10.20.9.0/24"),
	} {
		t.Run(name, func(t *testing.T) {
			for i := range limiterAttempts {
				b := s.browser()
				b.forwardedFor = fmt.Sprintf("203.0.113.%d", i)
				wantStatus(t, b.signIn("nobody", "wrong"), http.StatusUnauthorized)
			}
			// Nothing was counted under the addresses the header named, and
			// the connection's own address is nobody in particular (see
			// clientAddr), so it is not counted either.
			if n := len(s.server.limiter.addrs); n != 0 {
				t.Errorf("%d addresses are being counted: %v", n, s.server.limiter.addrs)
			}
			b := s.browser()
			b.forwardedFor = "203.0.113.99"
			wantRedirect(t, b.signIn("bob", bobPassword), "/")
			if last := s.history()[0]; last.Remote != "10.20.0.5" {
				t.Errorf("history has %q as the address, want the connection's", last.Remote)
			}
		})
	}
}

func TestClientAddr(t *testing.T) {
	behind := newSite(t, "https://handrail.internal.example", "10.20.0.5", "fd00::/8").server
	direct := newSite(t, "http://127.0.0.1:8080").server
	undeclared := newSite(t, "https://handrail.internal.example").server
	directWithProxies := newSite(t, "http://127.0.0.1:8080", "10.20.0.5").server
	gatewayListed := newSite(t, "https://handrail.internal.example", "10.20.0.5", "172.17.0.1").server
	tests := []struct {
		name         string
		s            *server
		remote       string
		forwardedFor []string
		addr         string
		known        bool
	}{
		// Under an http public URL every browser arrives from the machine's
		// own address, which is therefore nobody in particular.
		{"direct", direct, "192.0.2.4:5000", nil, "192.0.2.4", false},
		{"direct, header ignored", direct, "192.0.2.4:5000", []string{"203.0.113.7"}, "192.0.2.4", false},
		{"direct IPv6", direct, "[2001:db8::4]:5000", nil, "2001:db8::4", false},
		{"direct, IPv4 written as IPv6", direct, "[::ffff:192.0.2.4]:5000", nil, "192.0.2.4", false},
		{"no port", direct, "192.0.2.4", nil, "192.0.2.4", false},
		{"not an address", direct, "@", nil, "@", false},
		{"undeclared proxy", undeclared, "192.0.2.4:5000", []string{"203.0.113.7"}, "192.0.2.4", false},
		{"through the proxy", behind, "10.20.0.5:5000", []string{"203.0.113.7"}, "203.0.113.7", true},
		{"rightmost untrusted", behind, "10.20.0.5:5000", []string{"198.51.100.1, 203.0.113.7"}, "203.0.113.7", true},
		{"two proxies", behind, "[fd00::1]:5000", []string{"203.0.113.7, 10.20.0.5"}, "203.0.113.7", true},
		{"several headers", behind, "10.20.0.5:5000", []string{"198.51.100.1", "203.0.113.7"}, "203.0.113.7", true},
		{"with a port", behind, "10.20.0.5:5000", []string{"203.0.113.7:4444"}, "203.0.113.7", true},
		{"IPv6 in brackets", behind, "10.20.0.5:5000", []string{"[2001:db8::7]"}, "2001:db8::7", true},
		{"IPv6 with a port", behind, "10.20.0.5:5000", []string{"[2001:db8::7]:4444"}, "2001:db8::7", true},
		{"no header", behind, "10.20.0.5:5000", nil, "10.20.0.5", false},
		{"only proxies in the header", behind, "10.20.0.5:5000", []string{"10.20.0.5"}, "10.20.0.5", false},
		{"junk at the right", behind, "10.20.0.5:5000", []string{"203.0.113.7, unknown"}, "10.20.0.5", false},
		{"junk to the left is never reached", behind, "10.20.0.5:5000", []string{"<script>, 203.0.113.7"}, "203.0.113.7", true},
		{"a header too long to walk", behind, "10.20.0.5:5000", []string{"203.0.113.7" + strings.Repeat(", 10.20.0.5", maxForwardedHops)}, "10.20.0.5", false},
		// Under https nothing but a proxy connects: an unlisted peer is
		// taken for one, reported, and never believed about the header.
		// Why only a proxy's own address may be listed: with the address
		// visitors arrive from (a NAT, a Docker gateway) listed as well, the
		// walk steps over the real visitor and believes what that visitor
		// wrote in the header. README.md warns against it.
		{"a visitor's gateway listed as a proxy", gatewayListed, "10.20.0.5:5000", []string{"203.0.113.99, 172.17.0.1"}, "203.0.113.99", true},
		{"the same, with only the proxy listed", behind, "10.20.0.5:5000", []string{"203.0.113.99, 172.17.0.1"}, "172.17.0.1", true},
		{"https, not from a listed proxy", behind, "192.0.2.4:5000", []string{"203.0.113.7"}, "192.0.2.4", false},
		{"http, not from a listed proxy", directWithProxies, "192.0.2.4:5000", []string{"203.0.113.7"}, "192.0.2.4", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.forwardedFor {
				r.Header.Add("X-Forwarded-For", v)
			}
			addr, known := tt.s.clientAddr(r)
			if addr != tt.addr || known != tt.known {
				t.Errorf("clientAddr = %q, %v; want %q, %v", addr, known, tt.addr, tt.known)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.20.0.5, 10.20.9.7/24 ,fd00::1,, ::ffff:192.0.2.1 ")
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, p := range got {
		texts = append(texts, p.String())
	}
	if want := "10.20.0.5/32 10.20.9.0/24 fd00::1/128 192.0.2.1/32"; strings.Join(texts, " ") != want {
		t.Errorf("got %v, want %s", texts, want)
	}
	if got, err := ParseTrustedProxies(""); err != nil || got != nil {
		t.Errorf("an empty list: %v, %v", got, err)
	}
	for _, bad := range []string{"proxy.internal.example", "10.20.0.5/40", "10.20.0", "10.20.0.5 10.20.0.6"} {
		if _, err := ParseTrustedProxies(bad); err == nil || !strings.Contains(err.Error(), "IP address or CIDR range") {
			t.Errorf("ParseTrustedProxies(%q): %v", bad, err)
		}
	}
}

// History rows are never deleted, so what a stranger can add to them has to
// be bounded. Behind a proxy that was not declared there is no limit per
// visitor, and a made-up user name is counted against nothing: without a
// cap, anyone who can reach the sign-in page could fill the disk.
func TestStrangersCannotFillTheHistory(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example") // an undeclared proxy
	const attempts = 60
	for i := range attempts {
		b := s.browser()
		if i%2 == 0 {
			wantStatus(t, b.signIn("not a name", "x"), http.StatusUnauthorized)
		} else {
			// Each made-up name is new to the throttle, and costs a hash.
			wantStatus(t, b.signIn(fmt.Sprintf("made-up-%d", i), "x"), http.StatusUnauthorized)
		}
	}
	if n := len(s.history()); n != strangerRows {
		t.Fatalf("%d history rows for %d attempts by nobody, want %d", n, attempts, strangerRows)
	}
	// Every one of them is in the log all the same.
	if n := strings.Count(s.log.String(), `msg=audit actor="(unknown user)" action=sign-in outcome=failed`); n != attempts {
		t.Errorf("%d of %d attempts are in the log", n, attempts)
	}

	// What happens to real accounts is recorded regardless.
	wantStatus(t, s.browser().signIn("alice", "wrong"), http.StatusUnauthorized)
	wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
	events := s.history()
	if len(events) != strangerRows+2 || events[0].Actor != "bob" || events[1].Actor != "alice" || events[1].Outcome != store.OutcomeFailed {
		t.Fatalf("after two real sign-ins: %d rows, newest %+v", len(events), events[0])
	}

	// The next hour's first row says how many went unrecorded before it.
	s.clock.advance(strangerWindow)
	wantStatus(t, s.browser().signIn("not a name", "x"), http.StatusUnauthorized)
	last := s.history()[0]
	if want := fmt.Sprintf("%d more like it since the last one recorded here are in the log only", attempts-strangerRows); last.Actor != unknownActor || !strings.Contains(last.Detail, want) {
		t.Errorf("the first row of the next hour = %+v, want it to mention %q", last, want)
	}
	wantStatus(t, s.browser().signIn("not a name", "x"), http.StatusUnauthorized)
	if last := s.history()[0]; strings.Contains(last.Detail, "more like it") {
		t.Errorf("the count was reported twice: %+v", last)
	}
}

const newPassword = "a brand new password"

// passwordForm is what the change-password form posts.
func passwordForm(token, current, next, again string) url.Values {
	return url.Values{"form_token": {token}, "current_password": {current}, "new_password": {next}, "new_password_again": {again}}
}

func TestAccountPage(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	wantRedirect(t, s.browser().get("/account"), "/sign-in")

	b := s.browser()
	wantRedirect(t, b.signIn("bob", bobPassword), "/")
	page := b.get("/account")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "Your account", "<dd>bob</dd>", "<dd>viewer</dd>", "<dd>2026-11-11</dd>",
		`action="/account/password"`, `autocomplete="new-password"`, `href="/account" aria-current="page"`)
	if strings.Contains(page.Body.String(), "Password changed") {
		t.Error("the page claims a change that did not happen")
	}
	// The link to it is on every signed-in page.
	wantBody(t, b.get("/status"), `<a href="/account">bob</a> (viewer)`)
}

func TestChangeOwnPassword(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	ctx := context.Background()
	here, elsewhere := s.browser(), s.browser()
	wantRedirect(t, here.signIn("alice", alicePassword), "/")
	wantRedirect(t, elsewhere.signIn("alice", alicePassword), "/")
	oldCookie := here.cookies[sessionCookie]
	_, oldHash, _ := s.store.Store.Credentials(ctx, "alice")
	s.clock.advance(time.Hour / 2)

	token := tokenIn(t, here.get("/account"))
	rec := here.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantRedirect(t, rec, "/account?changed=1")

	// This browser stays signed in, under a new session; the other does not.
	if here.cookies[sessionCookie] == oldCookie || here.cookies[sessionCookie] == "" {
		t.Error("the browser kept its old session token across the change")
	}
	page := here.get("/account?changed=1")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `<output class="notice">Password changed. Every other session of this account was signed out.</output>`)
	wantRedirect(t, elsewhere.get("/status"), "/sign-in")
	// The old cookie is dead even in this browser.
	stale := s.browser()
	stale.cookies[sessionCookie] = oldCookie
	wantRedirect(t, stale.get("/status"), "/sign-in")

	u, newHash, _ := s.store.Store.Credentials(ctx, "alice")
	if newHash == oldHash || !u.PasswordChangedAt.Equal(s.clock.Now()) {
		t.Errorf("stored hash changed: %v, at %v", newHash != oldHash, u.PasswordChangedAt)
	}
	wantStatus(t, s.browser().signIn("alice", alicePassword), http.StatusUnauthorized)
	wantRedirect(t, s.browser().signIn("alice", newPassword), "/")

	var change *store.Event
	for _, e := range s.history() {
		if e.Action == store.ActionUserPasswd {
			change = &e
			break
		}
	}
	if change == nil || change.Actor != "alice" || change.Outcome != store.OutcomeOK || change.Remote != "10.20.0.5" {
		t.Errorf("history = %+v", change)
	}
	for _, secret := range []string{alicePassword, newPassword, here.cookies[sessionCookie]} {
		if strings.Contains(s.log.String(), secret) {
			t.Error("the log contains a password or a session token")
		}
	}
	// A viewer can change theirs as well.
	v := s.browser()
	wantRedirect(t, v.signIn("bob", bobPassword), "/")
	wantRedirect(t, v.do(http.MethodPost, "/account/password", passwordForm(tokenIn(t, v.get("/account")), bobPassword, newPassword, newPassword)), "/account?changed=1")
}

func TestChangeOwnPasswordRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	ctx := context.Background()
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))
	_, hash, _ := s.store.Store.Credentials(ctx, "alice")

	tests := []struct {
		name                 string
		current, next, again string
		status               int
		want                 string
	}{
		{"entries differ", alicePassword, newPassword, newPassword + "x", http.StatusBadRequest, "The two entries of the new password differ."},
		{"too short", alicePassword, "short", "short", http.StatusBadRequest, "The new password has 5 characters; the minimum is 12."},
		{"too long", alicePassword, strings.Repeat("x", 1025), strings.Repeat("x", 1025), http.StatusBadRequest, "The new password is longer than 1024 bytes."},
		{"same as current", alicePassword, alicePassword, alicePassword, http.StatusBadRequest, "The new password is the same as the current one."},
		{"empty", alicePassword, "", "", http.StatusBadRequest, "the minimum is 12"},
		{"wrong current", "not alice's password", newPassword, newPassword, http.StatusForbidden, "The current password is wrong."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := b.do(http.MethodPost, "/account/password", passwordForm(token, tt.current, tt.next, tt.again))
			wantStatus(t, rec, tt.status)
			wantBody(t, rec, tt.want, "Change password")
			if _, now, _ := s.store.Store.Credentials(ctx, "alice"); now != hash {
				t.Fatal("a refused change altered the password")
			}
			// Still signed in, with the same session.
			wantStatus(t, b.get("/account"), http.StatusOK)
		})
	}
	// Only the wrong current password was an attempt at anything. It was
	// made from a browser that has signed in as alice, so it is counted
	// against that browser and not against her name.
	if n := s.server.limiter.attemptsOfDevices(); n != 1 {
		t.Errorf("attempts counted for alice's browser: %d, want 1", n)
	}
	if e := s.server.limiter.names["alice"]; e != nil {
		t.Errorf("attempts counted against the name: %+v, want none", e)
	}
	if last := s.history()[0]; last.Action != store.ActionUserPasswd || last.Outcome != store.OutcomeFailed || last.Detail != "wrong current password" {
		t.Errorf("history = %+v", last)
	}

	// The form needs the session's own token and origin, like every other.
	wantStatus(t, b.do(http.MethodPost, "/account/password", passwordForm("", alicePassword, newPassword, newPassword)), http.StatusForbidden)
	b.origin = "https://evil.example"
	wantStatus(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), http.StatusForbidden)
	if _, now, _ := s.store.Store.Credentials(ctx, "alice"); now != hash {
		t.Fatal("a forged form changed the password")
	}
	// And a session: without one there is nothing to change.
	wantRedirect(t, s.browser().do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), "/sign-in")
}

// The form must not be a second, unthrottled place to guess a password:
// someone at a stolen session gets the same five tries as at the sign-in
// page, out of the allowance that browser's sign-ins come from.
func TestChangePasswordIsThrottledLikeSignIn(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))
	for i := range limiterAttempts {
		rec := b.do(http.MethodPost, "/account/password", passwordForm(token, fmt.Sprintf("guess number %d", i), newPassword, newPassword))
		wantStatus(t, rec, http.StatusForbidden)
	}
	rec := b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantStatus(t, rec, http.StatusTooManyRequests)
	wantBody(t, rec, "Too many wrong passwords")
	// The same browser at the sign-in page has no tries left either: the
	// form and the page draw on one allowance.
	same := s.browser()
	same.cookies[deviceCookie] = b.cookies[deviceCookie]
	if again := same.signIn("alice", alicePassword); again.Code != http.StatusTooManyRequests {
		t.Errorf("sign-in from that browser after five wrong guesses in the form: %d, want 429", again.Code)
	}
	// The session itself carries on, and after the window the change works.
	wantStatus(t, b.get("/status"), http.StatusOK)
	s.clock.advance(limiterWindow)
	wantRedirect(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), "/account?changed=1")
	if n := s.server.limiter.attemptsOfDevices(); n != 0 {
		t.Errorf("%d attempts are still counted after a successful change", n)
	}
}

// Without the account's device cookie, the form's guesses come out of the
// name's allowance, the one the sign-in page gives a stranger.
func TestChangePasswordFromAnUnknownBrowserCountsAgainstTheName(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))
	// The session cookie alone, as if it had been taken from the browser.
	thief := s.browser()
	thief.cookies[sessionCookie] = b.cookies[sessionCookie]
	for i := range limiterAttempts {
		rec := thief.do(http.MethodPost, "/account/password", passwordForm(token, fmt.Sprintf("guess number %d", i), newPassword, newPassword))
		wantStatus(t, rec, http.StatusForbidden)
	}
	wantStatus(t, thief.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), http.StatusTooManyRequests)
	if ok := s.browser().signIn("alice", alicePassword); ok.Code != http.StatusTooManyRequests {
		t.Errorf("a stranger's sign-in after five wrong guesses in the form: %d, want 429", ok.Code)
	}
	// Alice, at her own browser, is not held up by any of it.
	wantRedirect(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), "/account?changed=1")
}

func TestChangePasswordWhenTheAccountChangesMeanwhile(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	ctx := context.Background()
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))

	// `user passwd` lands between the check of the current password and
	// the change: its password stands, this one is dropped.
	s.store.beforeChange = func() {
		if err := s.store.Store.SetPassword(ctx, "alice", cheapHash("set from the command line"), t0); err != nil {
			t.Error(err)
		}
	}
	rec := b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantStatus(t, rec, http.StatusConflict)
	s.store.beforeChange = nil
	wantStatus(t, s.browser().signIn("alice", newPassword), http.StatusUnauthorized)
	wantRedirect(t, s.browser().signIn("alice", "set from the command line"), "/")
}

func TestChangePasswordStoreFailures(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	boom := errors.New("disk on fire")

	// The password cannot be read: nothing changes, and it is an error
	// page, not "wrong password".
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))
	s.store.credentialsErr.Store(&boom)
	wantStatus(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), http.StatusInternalServerError)
	s.store.credentialsErr.Store(nil)

	// The new password cannot be hashed.
	s.server.hash = func(string) (string, error) { return "", boom }
	wantStatus(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), http.StatusInternalServerError)
	s.server.hash = func(pw string) (string, error) { return cheapHash(pw), nil }
	wantRedirect(t, s.browser().signIn("alice", alicePassword), "/")

	// The password changes but the new session cannot be opened: the
	// browser is sent to sign in, with the new password.
	s.store.createErr.Store(&boom)
	rec := b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantRedirect(t, rec, "/sign-in")
	s.store.createErr.Store(nil)
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Error("the dead session's cookie was left in place")
	}
	wantRedirect(t, s.browser().signIn("alice", newPassword), "/")
}

func TestAccountPageUnderABasePath(t *testing.T) {
	s := newSite(t, "https://tools.internal.example/handrail")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/handrail/")
	page := b.get("/handrail/account")
	wantBody(t, page, `action="/handrail/account/password"`, `href="/handrail/account"`)
	rec := b.do(http.MethodPost, "/handrail/account/password", passwordForm(tokenIn(t, page), alicePassword, newPassword, newPassword))
	wantRedirect(t, rec, "/handrail/account?changed=1")
	wantStatus(t, b.get("/handrail/account?changed=1"), http.StatusOK)
}

// A proxy listed under the wrong address must not go unnoticed: the log
// names the address requests really come from, once, and what that address
// says about its visitors is still not believed.
func TestUnlistedProxyIsReportedOnce(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example", "127.0.0.1")
	b := s.browser()
	b.remote = "172.17.0.1:51234"
	b.forwardedFor = "203.0.113.7"
	for range 3 {
		wantStatus(t, b.signIn("alice", "wrong"), http.StatusUnauthorized)
	}
	log := s.log.String()
	if n := strings.Count(log, "not in -trusted-proxy"); n != 1 {
		t.Errorf("the warning was logged %d times, want once", n)
	}
	if !strings.Contains(log, "address=172.17.0.1") {
		t.Errorf("the warning does not name the address: %s", log)
	}
	if last := s.history()[0]; last.Remote != "172.17.0.1" {
		t.Errorf("history has %q as the address; the header of an unlisted peer was believed", last.Remote)
	}

	// Only so many addresses are remembered, however many turn up.
	for i := range 3 * maxDistinctWarnings {
		b := s.browser()
		b.remote = fmt.Sprintf("192.0.2.%d:40000", i+1)
		b.get("/sign-in") // no warning: nothing asks who the visitor is
		b.signIn("not a name", "x")
	}
	if n := strings.Count(s.log.String(), "not in -trusted-proxy"); n != maxDistinctWarnings {
		t.Errorf("%d warnings for many addresses, want %d", n, maxDistinctWarnings)
	}

	// Nothing of the kind over plain HTTP on loopback, or from a listed proxy.
	quiet := newSite(t, "http://127.0.0.1:8080")
	quiet.browser().signIn("alice", "wrong")
	listed := newSite(t, "https://handrail.internal.example", "10.20.0.5")
	lb := listed.browser()
	lb.forwardedFor = "203.0.113.7"
	lb.signIn("alice", "wrong")
	if strings.Contains(quiet.log.String()+listed.log.String(), "not in -trusted-proxy") {
		t.Error("a warning was logged where the peer is as expected")
	}
}

// withProvisioner returns a row as issued by another provisioner.
func withProvisioner(row inventory.RawCertificate, name, kind string) inventory.RawCertificate {
	row.Data = []byte(fmt.Sprintf(`{"provisioner":{"id":"id-%s","name":%q,"type":%q}}`, name, name, kind))
	return row
}

// signedInAs returns a browser signed in as alice.
func signedIn(t *testing.T, s *site) *browser {
	t.Helper()
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), strings.TrimRight(s.public.Path, "/")+"/")
	return b
}

// reread has the site's inventory read its rows again.
func (s *site) reread() {
	s.t.Helper()
	if err := s.inv.Refresh(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

func TestListPage(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)

	// The default: what is in date and not revoked.
	page := b.get("/")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page,
		"<h1>Certificates</h1>", `href="/" aria-current="page"`, "Read from the CA's database 0 seconds ago.",
		"web1.internal.example", `<span class="badge ok">Valid</span>`, "2027-02-09 12:00", "in 3 months",
		"handrail <span class=\"sub\">JWK</span>",
		// The serial 101, in hexadecimal.
		`title="65">65</td>`,
		`aria-current="true">Active <span>1</span>`, `>Expired <span>1</span>`, `>Revoked <span>1</span>`, `>Unreadable <span>1</span>`, `>All <span>4</span>`,
		`<option value="handrail">handrail (JWK)</option>`,
		"1 to 1 of 1",
		`<th scope="col" aria-sort="ascending"><a href="/?dir=desc">Expires</a>`,
	)
	for _, absent := range []string{"old.internal.example", "gone.internal.example", "could not be read", "No certificates match", "not shown", "Previous", "Next"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the default list contains %q", absent)
		}
	}
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Error("the list may be cached")
	}

	// Everything, each with what is known about it.
	all := b.get("/?view=all")
	wantBody(t, all,
		"web1.internal.example", "old.internal.example", "gone.internal.example",
		`<span class="badge unknown">Expired</span>`, "24 hours ago",
		`<span class="badge bad">Revoked</span>`, "revoked 2026-11-11",
		`<span class="badge bad">Unreadable</span>`, "This row of the CA's database could not be read as a certificate: the stored value is not a certificate",
		"1 to 4 of 4", `aria-current="true">All <span>4</span>`,
	)
	wantBody(t, b.get("/?view=revoked"), "gone.internal.example", "1 to 1 of 1")
	if strings.Contains(b.get("/?view=revoked").Body.String(), "web1.internal.example") {
		t.Error("the revoked view shows a certificate that is not revoked")
	}
	// A view nobody offers is the default one.
	wantBody(t, b.get("/?view=everything"), `aria-current="true">Active <span>1</span>`)
}

func TestListRowNames(t *testing.T) {
	cert := func(subject string, names ...string) inventory.Row {
		c := &inventory.Certificate{Serial: "1", SerialHex: "1", Subject: subject, NotAfter: t0.Add(time.Hour)}
		for _, n := range names {
			c.Names = append(c.Names, inventory.Name{Kind: inventory.DNS, Value: n})
		}
		return inventory.Row{Certificate: c, Status: inventory.StatusValid}
	}
	for want, row := range map[string]inventory.Row{
		// One name, the same as the subject: said once.
		"":                      cert("a.example", "a.example"),
		"b.example":             cert("a.example", "b.example"),
		"a.example, b.example":  cert("a.example", "a.example", "b.example"),
		"a, b, c and 2 more":    cert("a", "a", "b", "c", "d", "e"),
		"a.example and 40 more": {Certificate: &inventory.Certificate{Serial: "1", Subject: "a.example", Names: []inventory.Name{{Kind: inventory.DNS, Value: "a.example"}}, MoreNames: 40, NotAfter: t0.Add(time.Hour)}},
	} {
		if got := newListRow(row, t0).Names; got != want {
			t.Errorf("names of %v = %q, want %q", row.Names, got, want)
		}
	}
	// Each status says when in its own terms.
	c := &inventory.Certificate{Serial: "1", SerialHex: "1", Subject: "a", NotBefore: t0.Add(time.Hour), NotAfter: t0.Add(48 * time.Hour)}
	if got := newListRow(inventory.Row{Certificate: c, Status: inventory.StatusNotYetValid}, t0).When; got != "valid from 2026-11-11 13:00" {
		t.Errorf("not yet valid: %q", got)
	}
	if got := newListRow(inventory.Row{Certificate: c, Status: inventory.StatusRevoked}, t0).When; got != "revoked" {
		t.Errorf("revoked, with no record of when: %q", got)
	}
	if got := newListRow(inventory.Row{Certificate: c, Status: inventory.StatusUnknown}, t0); got.When != "in 2 days" || got.StatusLabel != "Unknown" {
		t.Errorf("unknown: %+v", got)
	}
}

func TestListSearchAndFilters(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	day := 24 * time.Hour
	s.rows.mu.Lock()
	s.rows.certs = append(s.rows.certs,
		withProvisioner(leafRow(t, 201, "mail.internal.example", t0.Add(-day), t0.Add(30*day)), "acme", "ACME"),
		withProvisioner(leafRow(t, 202, "step", t0.Add(-time.Minute), t0.Add(4*time.Minute)), inventory.AdminProvisioner, "JWK"),
		withProvisioner(leafRow(t, 203, "step", t0.Add(-time.Minute), t0.Add(4*time.Minute)), inventory.AdminProvisioner, "JWK"),
	)
	s.rows.mu.Unlock()
	s.reread()
	b := signedIn(t, s)

	// Search, in the subject, in the names and by serial; kept in the form.
	page := b.get("/?q=MAIL")
	wantBody(t, page, "mail.internal.example", `value="MAIL"`, "1 to 1 of 1", `<a class="clear" href="/">Clear</a>`)
	if strings.Contains(page.Body.String(), "web1.internal.example") {
		t.Error("the search did not narrow the list")
	}
	wantBody(t, b.get("/?q=c9&view=all"), "mail.internal.example") // 201 is 0xc9
	// The counts on the views follow the search.
	wantBody(t, b.get("/?q=gone"), "No certificates match.", `>Revoked <span>1</span>`, `href="/?q=gone&amp;view=revoked"`)

	// What is typed comes back as text, never as markup.
	evil := b.get("/?q=" + url.QueryEscape(`"><script>alert(1)</script>`))
	wantStatus(t, evil, http.StatusOK)
	if strings.Contains(evil.Body.String(), "<script>alert") {
		t.Error("the search text was written into the page unescaped")
	}
	wantBody(t, evil, "No certificates match.", "&lt;script&gt;")
	// A very long search is cut, not refused.
	wantStatus(t, b.get("/?q="+strings.Repeat("x", 5000)), http.StatusOK)

	// By provisioner; one that issued nothing stays selected in the form.
	page = b.get("/?provisioner=acme")
	wantBody(t, page, "mail.internal.example", `<option value="acme" selected>acme (ACME)</option>`, "1 to 1 of 1")
	page = b.get("/?provisioner=nobody")
	wantBody(t, page, "No certificates match.", `<option value="nobody" selected>nobody</option>`)

	// The CA's own admin certificates: left out, and said so.
	page = b.get("/")
	wantBody(t, page, "2 certificates the CA issued to its own admins are not shown.", `href="/?admin=1"`, "1 to 2 of 2")
	withAdmin := b.get("/?admin=1")
	wantBody(t, withAdmin, "1 to 4 of 4", `name="admin" type="checkbox" value="1" checked`, "Admin JWK")
	if strings.Contains(withAdmin.Body.String(), "are not shown") {
		t.Error("the note about hidden admin certificates is shown with them included")
	}
	// Choosing the admin provisioner shows its certificates without the box.
	wantBody(t, b.get("/?provisioner="+url.QueryEscape(inventory.AdminProvisioner)), "1 to 2 of 2")
}

func TestListOrderAndPages(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	day := 24 * time.Hour
	s.rows.mu.Lock()
	for i := range 120 {
		s.rows.certs = append(s.rows.certs, leafRow(t, int64(1000+i), fmt.Sprintf("host%03d.internal.example", i), t0.Add(-day), t0.Add(time.Duration(200+i)*day)))
	}
	s.rows.mu.Unlock()
	s.reread()
	b := signedIn(t, s)

	// 121 active certificates, fifty to a page, soonest to expire first.
	first := b.get("/")
	wantBody(t, first, "1 to 50 of 121", `href="/?page=2" rel="next"`, "web1.internal.example", "host000.internal.example", "host048.internal.example")
	for _, absent := range []string{"host049.internal.example", `rel="prev"`} {
		if strings.Contains(first.Body.String(), absent) {
			t.Errorf("page one contains %q", absent)
		}
	}
	second := b.get("/?page=2")
	wantBody(t, second, "51 to 100 of 121", "host049.internal.example", `href="/" rel="prev"`, `href="/?page=3" rel="next"`)
	last := b.get("/?page=3")
	wantBody(t, last, "101 to 121 of 121", "host119.internal.example", `href="/?page=2" rel="prev"`)
	if strings.Contains(last.Body.String(), `rel="next"`) {
		t.Error("the last page offers a next one")
	}
	// Past the end, or nonsense: the last page, or the first.
	wantBody(t, b.get("/?page=999"), "101 to 121 of 121")
	for _, page := range []string{"0", "-3", "two", "99999999999999999999"} {
		wantBody(t, b.get("/?page="+page), "1 to 50 of 121")
	}

	// Turned round, and by other columns; the heading says which.
	wantBody(t, b.get("/?dir=desc"), "host119.internal.example", `aria-sort="descending"><a href="/">Expires</a>`)
	bySubject := b.get("/?sort=subject")
	wantBody(t, bySubject, `aria-sort="ascending"><a href="/?dir=desc&amp;sort=subject">Subject and names</a>`, `<th scope="col"><a href="/">Expires</a>`, "Sort by date issued")
	wantBody(t, b.get("/?sort=issued"), "Sorted by date issued")
	// The filter form and the page links keep the order.
	wantBody(t, b.get("/?sort=subject&dir=desc&page=2"), `<input type="hidden" name="sort" value="subject">`, `<input type="hidden" name="dir" value="desc">`,
		`href="/?dir=desc&amp;page=3&amp;sort=subject" rel="next"`)
	// A filter or an order starts again from the first page.
	if strings.Contains(b.get("/?page=2").Body.String(), `view=all&amp;page`) || !strings.Contains(b.get("/?page=2").Body.String(), `href="/?view=all"`) {
		t.Error("choosing a view from page two does not start from page one")
	}
}

func TestListWhenTheInventoryIsStaleOrUnread(t *testing.T) {
	ctx := context.Background()

	// Never read.
	s := newSite(t, "http://127.0.0.1:8080")
	never := inventory.New(&fakeRows{err: errors.New("connection refused")})
	never.SetClock(s.clock.Now)
	_ = never.Refresh(ctx)
	s.server.opts.Inventory = never
	b := signedIn(t, s)
	page := b.get("/")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "The certificate list has not been read yet", "It could not be read from the CA's database: listing certificates: connection refused", `href="/status"`)
	for _, absent := range []string{"<table", "No certificates match", "Read from the CA", `class="card filters"`} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("an unread list shows %q", absent)
		}
	}
	// Not tried at all yet: the server has only just started.
	s.server.opts.Inventory = inventory.New(&fakeRows{})
	wantBody(t, b.get("/"), "handrail-ca has only just started")

	// Read, then the database goes away: the list as it was, and a notice
	// that says what that means.
	s = newSite(t, "http://127.0.0.1:8080")
	b = signedIn(t, s)
	s.clock.advance(10 * time.Minute)
	s.rows.fail(errors.New("connection reset by peer"))
	_ = s.inv.Refresh(ctx)
	page = b.get("/")
	wantBody(t, page, "web1.internal.example", `class="stale"`, "This list is as it was 10 minutes ago", "Certificates issued or revoked since then are not shown.", "connection reset by peer")
}

func TestReadAgainNow(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	page := b.get("/?q=internal&view=all&sort=subject")
	token := tokenIn(t, page)
	wantBody(t, page, `<form method="post" action="/refresh">`, `<input type="hidden" name="view" value="all">`)

	// The CA issues another certificate; the page's button reads it in
	// and comes back to the same list.
	s.rows.mu.Lock()
	s.rows.certs = append(s.rows.certs, leafRow(t, 301, "new.internal.example", t0, t0.Add(24*time.Hour)))
	s.rows.mu.Unlock()
	form := url.Values{"form_token": {token}, "q": {"internal"}, "view": {"all"}, "sort": {"subject"}, "dir": {""}}
	rec := b.do(http.MethodPost, "/refresh", form)
	wantRedirect(t, rec, "/?q=internal&sort=subject&view=all")
	wantBody(t, b.get(rec.Header().Get("Location")), "new.internal.example")

	// From a later page it comes back to that page: the form carries the
	// page shown.
	s.rows.mu.Lock()
	for i := range listPageSize + 5 {
		s.rows.certs = append(s.rows.certs, leafRow(t, int64(1000+i), fmt.Sprintf("many%03d.internal.example", i), t0, t0.Add(48*time.Hour)))
	}
	s.rows.mu.Unlock()
	if err := s.inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := b.get("/?view=all&page=2")
	wantBody(t, second, `<input type="hidden" name="page" value="2">`)
	rec = b.do(http.MethodPost, "/refresh", url.Values{"form_token": {token}, "view": {"all"}, "page": {"2"}})
	wantRedirect(t, rec, "/?page=2&view=all")
	// A page past the end shows the last one, and that is the one carried.
	wantBody(t, b.get("/?view=all&page=9"), `<input type="hidden" name="page" value="2">`)
	if strings.Contains(b.get("/?view=all").Body.String(), `name="page"`) {
		t.Error("the first page's refresh form carries a page number")
	}

	// It needs the session's form token and origin like every other form.
	wantStatus(t, b.do(http.MethodPost, "/refresh", url.Values{}), http.StatusForbidden)
	b.origin = "https://evil.example"
	wantStatus(t, b.do(http.MethodPost, "/refresh", form), http.StatusForbidden)
	b.origin = ""
	wantRedirect(t, s.browser().do(http.MethodPost, "/refresh", form), "/sign-in")

	// Where it goes back to is rebuilt from the list's own parameters,
	// never taken as an address.
	rec = b.do(http.MethodPost, "/refresh", url.Values{"form_token": {token}, "q": {"//evil.example/"}, "view": {"https://evil.example"}, "return": {"https://evil.example"}})
	wantRedirect(t, rec, "/?q=%2F%2Fevil.example%2F")

	// A read that fails is not an error page: back to the list, which
	// says how old it is.
	s.rows.fail(errors.New("connection refused"))
	rec = b.do(http.MethodPost, "/refresh", url.Values{"form_token": {token}})
	wantRedirect(t, rec, "/")
	wantBody(t, b.get("/"), `class="stale"`, "connection refused")
	if !strings.Contains(s.log.String(), "could not be read on request") {
		t.Error("the failed read is not in the log")
	}
}

func TestListQueryRoundTrip(t *testing.T) {
	for _, raw := range []string{"", "q=web", "view=all", "admin=1&provisioner=acme&q=a+b&sort=issued&dir=desc&view=expired&page=4"} {
		v, _ := url.ParseQuery(raw)
		q := parseListQuery(v)
		again := parseListQuery(q.values())
		if q != again {
			t.Errorf("%q does not survive a round trip: %+v, then %+v", raw, q, again)
		}
	}
	if got := (listQuery{}).href("/base"); got != "/base/" {
		t.Errorf("the plain list's address = %q", got)
	}
	if got := shortSerial("0123456789abcdef"); got != "0123…cdef" {
		t.Errorf("shortSerial = %q", got)
	}
	if got := shortSerial("65"); got != "65" {
		t.Errorf("a short serial was shortened: %q", got)
	}
}

// A browser fills in the Origin of a form post from the page's referrer
// policy: under "no-referrer" it sends "Origin: null", even to the page's
// own site. Every form here is refused unless its Origin is the public
// URL's, so that policy would lock every browser out, and for a while it
// did: the tests post as a browser was thought to, and no browser had
// been tried. This test posts what Chromium, Firefox and WebKit were seen
// to send under each policy, and pins the policy that works.
func TestFormsWorkWithWhatBrowsersSend(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	page := b.get("/sign-in")
	if got := page.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q. Under no-referrer browsers post with Origin: null, which is refused", got)
	}
	// What a browser sends under the policy the pages carry.
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	// What a browser sends under no-referrer, and from a sandboxed frame or
	// a file opened from disk: refused, as it must be, since "null" is also
	// what a hostile page can arrange to send.
	other := s.browser()
	other.origin = "null"
	if rec := other.signIn("alice", alicePassword); rec.Code != http.StatusForbidden {
		t.Errorf("a form with Origin: null: %d, want 403", rec.Code)
	}
}
