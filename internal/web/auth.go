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
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

const (
	// A session ends twelve hours after sign-in, or after an hour unused,
	// whichever comes first.
	sessionLifetime = 12 * time.Hour
	sessionIdle     = SessionIdle
	// last_seen is written at most this often, not on every request.
	sessionTouchEvery = time.Minute

	// The sign-in form's own cookie, which exists only to bind the form
	// token to the browser that was shown the form.
	formLifetime = time.Hour

	tokenBytes = 32
	// maxForm bounds a posted form. The largest is the change of password:
	// three passwords of up to 1,024 bytes, each of which a browser may
	// send as three bytes of percent-encoding.
	maxForm = 16 << 10
	// maxConcurrentHashes bounds password hashing, which takes 64 MiB each.
	maxConcurrentHashes = 2
)

// SessionIdle is how long a session may go unused before it ends. Exported
// for the sweep that removes ended sessions from the store.
const SessionIdle = time.Hour

// Cookie names. With HTTPS at the root of a host the session cookie takes
// the __Host- prefix, which makes the browser refuse it unless it is Secure,
// host-only and for the whole host.
const (
	sessionCookie = "handrail_session"
	formCookie    = "handrail_form"
	// deviceCookie marks a browser that has signed in to an account
	// before (see knownDevice). It outlives the session and signing out.
	deviceCookie = "handrail_device"
)

func (s *server) cookieName(name string) string {
	if s.secure && s.base == "" {
		return "__Host-" + name
	}
	return name
}

func (s *server) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{
		Name:     s.cookieName(name),
		Value:    value,
		Path:     s.base + "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(maxAge / time.Second),
	}
	if value == "" {
		c.MaxAge = -1 // delete
	}
	http.SetCookie(w, c)
}

// cookieToken returns the random token a cookie carries, or nil if the
// cookie is missing or is not one of ours.
func (s *server) cookieToken(r *http.Request, name string) []byte {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return nil
	}
	token, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(token) != tokenBytes {
		return nil
	}
	return token
}

func newToken() (raw []byte, encoded string, err error) {
	raw = make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, base64.RawURLEncoding.EncodeToString(raw), nil
}

// formToken is the value a form must carry back: an HMAC keyed with the
// cookie's token. Another site can make the browser send the cookie but can
// neither read it nor compute this.
func formToken(cookieToken []byte) string {
	mac := hmac.New(sha256.New, cookieToken)
	mac.Write([]byte("handrail-ca form token"))
	return hex.EncodeToString(mac.Sum(nil))
}

func validFormToken(cookieToken []byte, posted string) bool {
	return cookieToken != nil && hmac.Equal([]byte(formToken(cookieToken)), []byte(posted))
}

// signedInUser is what the session middleware leaves in the request context.
type signedInUser struct {
	user  store.User
	token []byte // the session cookie's token, for the form token
}

type contextKey struct{}

func currentUser(r *http.Request) *signedInUser {
	u, _ := r.Context().Value(contextKey{}).(*signedInUser)
	return u
}

// session returns the signed-in user for a request, or nil if there is no
// valid session. An error means the store could not be asked.
func (s *server) session(r *http.Request) (*signedInUser, error) {
	token := s.cookieToken(r, sessionCookie)
	if token == nil {
		return nil, nil
	}
	hash := store.HashToken(token)
	now := s.opts.Now()
	sess, err := s.opts.Store.Session(r.Context(), hash, now)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if now.Sub(sess.LastSeenAt) >= sessionIdle {
		// Best effort: an idle session is refused whether or not the row
		// could be removed just now.
		_ = s.opts.Store.DeleteSession(r.Context(), hash)
		return nil, nil
	}
	if now.Sub(sess.LastSeenAt) >= sessionTouchEvery {
		if err := s.opts.Store.TouchSession(r.Context(), hash, now); err != nil {
			s.log.Warn("could not record session use", "err", err)
		}
	}
	return &signedInUser{user: sess.User, token: token}, nil
}

// signedIn wraps a handler that needs a session. Without one the browser
// is sent to the sign-in page. A posted form must also carry the session's
// form token.
func (s *server) signedIn(next http.HandlerFunc) http.HandlerFunc {
	return s.signedInUpTo(maxForm, next)
}

// signedInUpTo is signedIn for a form that may be larger than the others.
func (s *server) signedInUpTo(limit int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		u, err := s.session(r)
		if err != nil {
			s.log.Error("reading the session", "err", err)
			s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not read its own store, so it cannot tell who you are. The log has the details.")
			return
		}
		if u == nil {
			http.Redirect(w, r, s.base+"/sign-in", http.StatusSeeOther)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), contextKey{}, u))
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			err := r.ParseForm()
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				s.errorPage(w, r, http.StatusRequestEntityTooLarge, "What was sent is larger than this form takes.")
				return
			}
			if err != nil || !validFormToken(u.token, r.PostForm.Get("form_token")) {
				s.errorPage(w, r, http.StatusForbidden, "This form was not sent from a page of your current session. Go back, reload the page and try again.")
				return
			}
		}
		next(w, r)
	}
}

type signInData struct {
	FormToken string
	Username  string
	Problem   string
}

// signInForm shows the sign-in page, or moves on if already signed in.
func (s *server) signInForm(w http.ResponseWriter, r *http.Request) {
	if u, err := s.session(r); err == nil && u != nil {
		http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
		return
	}
	s.renderSignIn(w, r, http.StatusOK, "", "")
}

// renderSignIn writes the form with a form token bound to this browser by
// a cookie, reusing the cookie the browser already has.
func (s *server) renderSignIn(w http.ResponseWriter, r *http.Request, status int, username, problem string) {
	w.Header().Set("Cache-Control", "no-store")
	token := s.cookieToken(r, formCookie)
	if token == nil {
		var encoded string
		var err error
		if token, encoded, err = newToken(); err != nil {
			s.log.Error("no randomness for a form token", "err", err)
			s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not prepare the sign-in form.")
			return
		}
		s.setCookie(w, formCookie, encoded, formLifetime)
	}
	s.render(w, r, status, "signin.html", "Sign in", signInData{FormToken: formToken(token), Username: username, Problem: problem})
}

const wrongCredentials = "Wrong user name or password."

// signIn checks a posted user name and password and opens a session.
func (s *server) signIn(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "The sign-in form could not be read.")
		return
	}
	typed := r.PostForm.Get("username")
	if !validFormToken(s.cookieToken(r, formCookie), r.PostForm.Get("form_token")) {
		s.renderSignIn(w, r, http.StatusForbidden, "", "The sign-in form had expired. Please try again.")
		return
	}
	// The client's address is a throttle key only when it is known: behind
	// a proxy that does not say who it speaks for, the one address there is
	// belongs to every visitor, and five wrong sign-ins by anyone would
	// lock out everyone.
	addr, known := s.clientAddr(r)
	if !known {
		addr = ""
	}
	// A name that could not be an account is refused like a wrong
	// password, without a lookup.
	username, err := store.NormalizeUsername(typed)
	if err != nil {
		if wait := s.limiter.begin(s.opts.Now(), "", addr); wait > 0 {
			s.tooManySignIns(w, r, wait)
			return
		}
		s.recordSignIn(r, "", false, "no such user")
		s.renderSignIn(w, r, http.StatusUnauthorized, "", wrongCredentials)
		return
	}
	// A browser that has signed in to this account before is counted by
	// itself, apart from what strangers do to the name.
	device := s.knownDevice(r, username)
	who := attempt{name: username, addr: addr, device: device.key()}
	// Refused here without waiting for a hashing slot; checkPassword asks
	// again, and counts, once it has one.
	if wait := s.limiter.blockedFor(s.opts.Now(), who); wait > 0 {
		s.tooManySignIns(w, r, wait)
		return
	}

	checked, err := s.checkPassword(r.Context(), username, r.PostForm.Get("password"), who, device.known())
	if errors.Is(err, errBusy) {
		w.Header().Set("Retry-After", retryWhenBusy)
		s.renderSignIn(w, r, http.StatusServiceUnavailable, "", "handrail-ca is busy checking other sign-ins. Try again in a moment.")
		return
	}
	if err != nil {
		s.log.Error("checking a password", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not check the password. The log has the details.")
		return
	}
	if checked.wait > 0 {
		s.tooManySignIns(w, r, checked.wait)
		return
	}
	if !checked.ok {
		// Only the name of a real account is recorded: what people type
		// into a user-name field by mistake includes passwords.
		s.recordSignIn(r, checked.user.Username, false, "wrong password or no such user")
		s.renderSignIn(w, r, http.StatusUnauthorized, "", wrongCredentials)
		return
	}

	// A fresh token for every sign-in: nothing set before authentication
	// carries over into the session. The store creates the session only if
	// the account still has the password hash that was just checked.
	raw, encoded, err := newToken()
	now := s.opts.Now()
	if err == nil {
		err = s.opts.Store.CreateSession(r.Context(), checked.user.ID, checked.hash, store.HashToken(raw), now, now.Add(sessionLifetime))
	}
	if errors.Is(err, store.ErrNotFound) {
		// The password was changed, or the account removed, while this
		// request was in flight: what was checked no longer opens it.
		s.recordSignIn(r, checked.user.Username, false, "the account changed during sign-in")
		s.renderSignIn(w, r, http.StatusUnauthorized, "", wrongCredentials)
		return
	}
	if err != nil {
		s.log.Error("opening a session", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not open a session. The log has the details.")
		return
	}
	s.limiter.succeedFor(checked.counted)
	s.setCookie(w, sessionCookie, encoded, sessionLifetime)
	s.setCookie(w, formCookie, "", 0)
	s.rememberDevice(w, r, device, checked)
	s.recordSignIn(r, checked.user.Username, true, "")
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

// retryWhenBusy is the Retry-After, in seconds, of an answer that found
// too many others waiting for a password to be checked.
const retryWhenBusy = "5"

func (s *server) tooManySignIns(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
	s.renderSignIn(w, r, http.StatusTooManyRequests, "", "Too many failed sign-ins. Wait a few minutes and try again.")
}

// passwordCheck is the outcome of checkPassword.
type passwordCheck struct {
	ok bool
	// wait is set when the attempt was refused by the throttle, unchecked.
	wait time.Duration
	// user and hash are the account and the hash the password was checked
	// against; zero unless the account exists.
	user store.User
	hash string
	// counted is the attempt as the throttle counted it, for giving it
	// back after a success.
	counted attempt
}

// checkPassword reports whether pw opens the account. It takes about as
// long whether or not the account exists, and at most maxConcurrentHashes
// run at once. The attempt is counted by the throttle (see attempt) after a
// slot is held and before the password is looked at, so requests that
// queued for a slot cannot outnumber the attempts the throttle allows.
// proven is for the hashing slot (see hashGate); the error is errBusy when
// too many were waiting for one, and nothing is counted then.
func (s *server) checkPassword(ctx context.Context, username, pw string, who attempt, proven bool) (passwordCheck, error) {
	release, err := s.hashing.take(ctx, proven)
	if err != nil {
		return passwordCheck{}, err
	}
	defer release()
	counted, wait := s.limiter.beginFor(s.opts.Now(), who)
	if wait > 0 {
		return passwordCheck{wait: wait}, nil
	}
	user, hash, err := s.opts.Store.Credentials(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_, _ = password.Verify(s.dummyHash, pw)
		return passwordCheck{counted: counted}, nil
	}
	if err != nil {
		return passwordCheck{}, err
	}
	ok, err := password.Verify(hash, pw)
	return passwordCheck{ok: ok, user: user, hash: hash, counted: counted}, err
}

// device is a browser's device cookie that the store knows for the
// account being signed in to. The zero value is a browser that is not
// known for it.
type device struct {
	token []byte
	hash  store.TokenHash
}

func (d device) known() bool { return d.token != nil }

// key is what the throttle counts a known device under.
func (d device) key() string {
	if !d.known() {
		return ""
	}
	return hex.EncodeToString(d.hash[:])
}

// knownDevice says whether the request comes from a browser that has
// signed in to this account before: it carries a device cookie whose token
// the store has recorded for the account. A cookie for another account, a
// made-up one, or one the store has forgotten counts for nothing, and so
// does a store that cannot be asked: the browser is then treated as any
// stranger is. Being a known device opens nothing; it only decides which
// allowance of attempts this one is counted against.
func (s *server) knownDevice(r *http.Request, username string) device {
	token := s.cookieToken(r, deviceCookie)
	if token == nil {
		return device{}
	}
	hash := store.HashToken(token)
	owner, err := s.opts.Store.DeviceUser(r.Context(), hash, s.opts.Now())
	if errors.Is(err, store.ErrNotFound) {
		return device{}
	}
	if err != nil {
		s.log.Warn("could not look a device up; this sign-in is counted as a stranger's", "err", err)
		return device{}
	}
	if owner != username {
		return device{}
	}
	return device{token: token, hash: hash}
}

// rememberDevice is called after a successful sign-in. A browser already
// known for the account keeps its cookie, renewed; any other gets a new
// one, recorded for the account. A failure here costs the browser its own
// allowance next time and nothing else, so it is logged and not shown.
func (s *server) rememberDevice(w http.ResponseWriter, r *http.Request, d device, checked passwordCheck) {
	now := s.opts.Now()
	if d.known() {
		if err := s.opts.Store.TouchDevice(r.Context(), d.hash, now); err != nil {
			s.log.Warn("could not record a device's use", "err", err)
		}
		s.setCookie(w, deviceCookie, base64.RawURLEncoding.EncodeToString(d.token), store.DeviceLifetime)
		return
	}
	raw, encoded, err := newToken()
	if err == nil {
		err = s.opts.Store.RememberDevice(r.Context(), checked.user.ID, checked.hash, store.HashToken(raw), now)
	}
	if err != nil {
		s.log.Warn("could not remember this browser as one of the account's", "err", err)
		return
	}
	s.setCookie(w, deviceCookie, encoded, store.DeviceLifetime)
}

// dummyPasswordHash is a hash of a password nobody has, with the current
// parameters, so that a sign-in for a missing account costs the same work.
func dummyPasswordHash() (string, error) {
	pw, err := password.Generate()
	if err != nil {
		return "", err
	}
	return password.Hash(pw)
}

func (s *server) signOut(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if err := s.opts.Store.DeleteSession(r.Context(), store.HashToken(u.token)); err != nil {
		// The cookie is still cleared; the session then ends by itself
		// when it goes idle.
		s.log.Error("ending a session", "err", err)
	}
	s.setCookie(w, sessionCookie, "", 0)
	s.record(r, store.Event{Actor: u.user.Username, Action: store.ActionSignOut, Outcome: store.OutcomeOK})
	http.Redirect(w, r, s.base+"/sign-in", http.StatusSeeOther)
}

const unknownActor = "(unknown user)"

func (s *server) recordSignIn(r *http.Request, username string, ok bool, detail string) {
	e := store.Event{Actor: username, Action: store.ActionSignIn, Outcome: store.OutcomeFailed, Detail: detail}
	if ok {
		e.Outcome = store.OutcomeOK
	}
	if ok {
		s.record(r, e)
		return
	}
	// A failed sign-in is logged now and its history row written after the
	// answer (see recordLater), for an account and for a name that is none
	// alike: a row written first would make the answer for a real account
	// later than the answer for a made-up name by the time the store takes
	// to commit, and whoever can time the page could tell the two apart.
	if username != "" {
		// An account's own failed sign-ins: always in the history. The
		// throttle bounds how many of them there can be.
		s.logEvent(r, &e)
		s.recordLater(e)
		return
	}
	// A failed sign-in for a name that is no account. Anyone who can reach
	// the page can produce these without limit, and history rows are never
	// deleted, so only so many per hour become rows; all of them are logged.
	e.Actor = unknownActor
	write, unrecorded := s.strangers.admit(s.opts.Now())
	if unrecorded > 0 {
		e.Detail += fmt.Sprintf("; %d more like it since the last one recorded here are in the log only", unrecorded)
	}
	s.logEvent(r, &e)
	if write {
		s.recordLater(e)
	}
}

// strangerRows failed sign-ins for names that are not accounts are written
// to the history per strangerWindow; the rest are counted and logged.
const (
	strangerRows   = 12
	strangerWindow = time.Hour
)

// strangerBudget keeps sign-in attempts by nobody in particular from
// filling the history, which is append-only and sits on the same disk as
// the accounts.
type strangerBudget struct {
	mu         sync.Mutex
	start      time.Time
	written    int
	unrecorded int
}

// admit says whether the attempt happening now gets a history row. With a
// yes it also returns how many attempts were passed over since the last
// row, for that row to mention.
func (b *strangerBudget) admit(now time.Time) (write bool, unrecorded int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.start) >= strangerWindow {
		b.start, b.written = now, 0
	}
	if b.written >= strangerRows {
		b.unrecorded++
		return false, 0
	}
	b.written++
	unrecorded, b.unrecorded = b.unrecorded, 0
	return true, unrecorded
}

// logEvent stamps an event with the time and the client's address and
// writes it to the log.
func (s *server) logEvent(r *http.Request, e *store.Event) {
	e.At = s.opts.Now()
	e.Remote, _ = s.clientAddr(r)
	s.log.Info("audit", "actor", e.Actor, "action", e.Action, "outcome", e.Outcome,
		"serial", e.Serial, "subject", e.Subject, "detail", e.Detail, "remote", e.Remote)
}

// record writes an event to the log and to the history. Per the audit rule
// a history that cannot be written never blocks the action: the failure is
// logged and every page says so until a write succeeds again.
func (s *server) record(r *http.Request, e store.Event) {
	s.logEvent(r, &e)
	// Not the request's context: the event is recorded even if the browser
	// has already gone away.
	s.appendHistory(context.WithoutCancel(r.Context()), e)
}

// appendHistory writes an event that logEvent has stamped to the history.
func (s *server) appendHistory(ctx context.Context, e store.Event) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.opts.Store.AppendHistory(ctx, e); err != nil {
		s.historyBroken.Store(true)
		s.log.Error("history is NOT being recorded", "err", err)
		return
	}
	s.historyBroken.Store(false)
}

// maxLateRows bounds how many history rows may be waiting to be written
// after their answers. The hashing slots let only a few failed sign-ins
// through each second, so the line is short unless the store is slow; a
// row that finds it full is written before its answer after all.
const maxLateRows = 64

// lateRows are history rows written after the answer they belong to has
// gone out, in the order they were handed over, by one goroutine that runs
// only while there are any.
type lateRows struct {
	mu      sync.Mutex
	waiting []store.Event
	writing bool
	idle    *sync.Cond // on mu; signalled when writing ends
}

// recordLater writes an event that logEvent has already stamped and logged
// to the history without making the request wait for it. It is for rows
// whose writing must not show in how long the answer took (see
// recordSignIn); everything else uses record. Site.Settle waits for these
// rows when the process ends.
func (s *server) recordLater(e store.Event) {
	l := &s.late
	l.mu.Lock()
	if len(l.waiting) >= maxLateRows {
		l.mu.Unlock()
		s.appendHistory(context.Background(), e)
		return
	}
	l.waiting = append(l.waiting, e)
	if !l.writing {
		l.writing = true
		go s.writeLateRows()
	}
	l.mu.Unlock()
}

func (s *server) writeLateRows() {
	l := &s.late
	for {
		l.mu.Lock()
		if len(l.waiting) == 0 {
			l.writing = false
			l.idle.Broadcast()
			l.mu.Unlock()
			return
		}
		e := l.waiting[0]
		l.waiting = l.waiting[1:]
		l.mu.Unlock()
		s.appendHistory(context.Background(), e)
	}
}

// settle waits until no row is waiting or being written.
func (l *lateRows) settle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for l.writing {
		l.idle.Wait()
	}
}

// limiter slows password guessing: each user name, and each client address,
// gets limiterAttempts sign-in attempts per limiterWindow. An attempt is
// counted when it starts, not when it fails, so attempts running at the
// same time cannot all slip under the limit; a successful sign-in gives its
// attempt back. It is in memory: a restart forgets it, which costs an
// attacker a restart they cannot cause.
//
// Names and addresses are counted in separate, bounded tables, and a full
// table never forgets a live count: forgetting would hand a locked account
// five fresh guesses to whoever can fill the table. What happens to a NEW
// key when its table is full differs by what the limit is for:
//
//   - A new name is refused. The limit per name is the one that bounds
//     guessing at an account, so it fails closed. Filling this table takes
//     thousands of password hashes inside one window, more than the two
//     hashing slots get through.
//   - A new address goes uncounted. Addresses are cheap for an attacker to
//     produce, so refusing new ones would let them lock every other
//     visitor out; the limit per name still applies to whatever they try.
//
// A third table counts known devices: browsers that have signed in to the
// account before (see knownDevice). An attempt from one is counted against
// that device alone, not against the name or the address, so that someone
// who keeps failing on a known user name uses up the allowance strangers
// share and not the one the account's own browsers have. A stolen device
// cookie buys its thief limiterAttempts guesses per window and no more.
// Entries here exist only for devices the store knows, of which an account
// keeps a bounded number; if the table is full all the same, a device is
// counted as a stranger.
//
// A fourth counts each account's changes of password (see change).
type limiter struct {
	mu      sync.Mutex
	names   map[string]*limiterEntry
	addrs   map[string]*limiterEntry
	devices map[string]*limiterEntry
	changes map[string]*limiterEntry
	maxLen  int
}

// change counts one change of an account's password, asked for with the
// right current password, or returns how long to wait if there have been
// limiterAttempts in this window. A change is two password hashes, done
// ahead of strangers' sign-ins (see hashGate), and when it succeeds its
// attempt is given back to the throttle: without a count of its own, one
// account could change its password over and over and keep the hashing
// slots to itself. A change refused here is not given back, so asking
// again runs into the throttle's own limit. The keys are accounts' names,
// of which there are few; were the table full all the same, a change goes
// uncounted.
func (l *limiter) change(now time.Time, name string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := left(l.changes[name], now); wait > 0 {
		return wait
	}
	if e := l.live(l.changes, name, now); e != nil {
		e.attempts++
	}
	return 0
}

// attempt is who a sign-in attempt is counted against: a known device, if
// device is set, and otherwise the user name and the client's address
// (either of which may be empty and is then not counted).
type attempt struct {
	name, addr, device string
}

// blockedFor is blocked for an attempt.
func (l *limiter) blockedFor(now time.Time, a attempt) time.Duration {
	if a.device == "" {
		return l.blocked(now, a.name, a.addr)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return left(l.devices[a.device], now)
}

// beginFor counts an attempt, as begin does, and returns it as it was
// counted: a known device whose table had no room is counted, and
// returned, as a stranger.
func (l *limiter) beginFor(now time.Time, a attempt) (attempt, time.Duration) {
	if a.device != "" {
		l.mu.Lock()
		if wait := left(l.devices[a.device], now); wait > 0 {
			l.mu.Unlock()
			return a, wait
		}
		if e := l.live(l.devices, a.device, now); e != nil {
			e.attempts++
			l.mu.Unlock()
			return a, 0
		}
		l.mu.Unlock()
		a.device = ""
	}
	return a, l.begin(now, a.name, a.addr)
}

// succeedFor records a successful sign-in for an attempt as it was
// counted. A device's count is cleared. The name's is left alone then:
// the account's owner signing in from a known browser says nothing about
// whoever is guessing at the name from elsewhere.
func (l *limiter) succeedFor(a attempt) {
	if a.device == "" {
		l.succeed(a.name, a.addr)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.devices, a.device)
}

type limiterEntry struct {
	attempts int
	start    time.Time
}

const (
	limiterAttempts = 5
	limiterWindow   = 5 * time.Minute
	// limiterEntries bounds each of the tables.
	limiterEntries = 10000
)

func newLimiter() *limiter {
	return &limiter{
		names: map[string]*limiterEntry{}, addrs: map[string]*limiterEntry{},
		devices: map[string]*limiterEntry{}, changes: map[string]*limiterEntry{},
		maxLen: limiterEntries,
	}
}

// blocked returns how long an attempt for this name from this address must
// still wait, zero if not at all. It counts nothing. An empty name or
// address is not looked at.
func (l *limiter) blocked(now time.Time, name, addr string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return max(left(l.names[name], now), left(l.addrs[addr], now))
}

// left is how much of its window a used-up entry has to go.
func left(e *limiterEntry, now time.Time) time.Duration {
	if e == nil || e.attempts < limiterAttempts {
		return 0
	}
	return max(e.start.Add(limiterWindow).Sub(now), 0)
}

// begin counts one attempt for the name and for the address and returns
// zero. If either has no attempt left, or the name is new and the table of
// names is full, nothing is counted and the time to wait is returned. An
// empty name or address is skipped.
func (l *limiter) begin(now time.Time, name, addr string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := max(left(l.names[name], now), left(l.addrs[addr], now)); wait > 0 {
		return wait
	}
	var nameEntry *limiterEntry
	if name != "" {
		if nameEntry = l.live(l.names, name, now); nameEntry == nil {
			return time.Minute // the table of names is full of live counts
		}
	}
	if nameEntry != nil {
		nameEntry.attempts++
	}
	if addr != "" {
		if e := l.live(l.addrs, addr, now); e != nil {
			e.attempts++
		}
	}
	return 0
}

// live returns the entry counting key's current window, starting a new
// window if the last one is over. It returns nil if that would need a new
// entry and the table is full of windows still running.
func (l *limiter) live(table map[string]*limiterEntry, key string, now time.Time) *limiterEntry {
	e := table[key]
	if e != nil && now.Sub(e.start) < limiterWindow {
		return e
	}
	if e == nil && len(table) >= l.maxLen {
		for k, old := range table {
			if now.Sub(old.start) >= limiterWindow {
				delete(table, k)
			}
		}
		if len(table) >= l.maxLen {
			return nil
		}
	}
	e = &limiterEntry{start: now}
	table[key] = e
	return e
}

// succeed records a successful sign-in: the name's count is cleared, since
// its owner has just proved who they are, and the address gets back the
// one attempt that was counted for this sign-in.
func (l *limiter) succeed(name, addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.names, name)
	if e := l.addrs[addr]; e != nil && e.attempts > 0 {
		e.attempts--
	}
}
