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
	// maxForm bounds a posted form: two short fields and a token.
	maxForm = 8 << 10
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
			r.Body = http.MaxBytesReader(w, r.Body, maxForm)
			if err := r.ParseForm(); err != nil || !validFormToken(u.token, r.PostForm.Get("form_token")) {
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
	// Refused here without waiting for a hashing slot; checkPassword asks
	// again, and counts, once it has one.
	if wait := s.limiter.blocked(s.opts.Now(), username, addr); wait > 0 {
		s.tooManySignIns(w, r, wait)
		return
	}

	checked, err := s.checkPassword(r.Context(), username, r.PostForm.Get("password"), addr)
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
	s.limiter.succeed(username, addr)
	s.setCookie(w, sessionCookie, encoded, sessionLifetime)
	s.setCookie(w, formCookie, "", 0)
	s.recordSignIn(r, checked.user.Username, true, "")
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

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
}

// checkPassword reports whether pw opens the account. It takes about as
// long whether or not the account exists, and at most maxConcurrentHashes
// run at once. The attempt is counted by the throttle, for the name and
// for addr (the client's address, empty if not known), after a slot is
// held and before the password is looked at, so requests that queued for a
// slot cannot outnumber the attempts the throttle allows.
func (s *server) checkPassword(ctx context.Context, username, pw, addr string) (passwordCheck, error) {
	select {
	case s.hashSlots <- struct{}{}:
		defer func() { <-s.hashSlots }()
	case <-ctx.Done():
		return passwordCheck{}, ctx.Err()
	}
	if wait := s.limiter.begin(s.opts.Now(), username, addr); wait > 0 {
		return passwordCheck{wait: wait}, nil
	}
	user, hash, err := s.opts.Store.Credentials(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_, _ = password.Verify(s.dummyHash, pw)
		return passwordCheck{}, nil
	}
	if err != nil {
		return passwordCheck{}, err
	}
	ok, err := password.Verify(hash, pw)
	return passwordCheck{ok: ok, user: user, hash: hash}, err
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
	if username == "" {
		e.Actor = unknownActor
	}
	if ok {
		e.Outcome = store.OutcomeOK
	}
	s.record(r, e)
}

// record writes an event to the log and to the history. Per the audit rule
// a history that cannot be written never blocks the action: the failure is
// logged and every page says so until a write succeeds again.
func (s *server) record(r *http.Request, e store.Event) {
	e.At = s.opts.Now()
	e.Remote, _ = s.clientAddr(r)
	s.log.Info("audit", "actor", e.Actor, "action", e.Action, "outcome", e.Outcome,
		"serial", e.Serial, "subject", e.Subject, "detail", e.Detail, "remote", e.Remote)
	// Not the request's context: the event is recorded even if the browser
	// has already gone away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.opts.Store.AppendHistory(ctx, e); err != nil {
		s.historyBroken.Store(true)
		s.log.Error("history is NOT being recorded", "err", err)
		return
	}
	s.historyBroken.Store(false)
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
type limiter struct {
	mu     sync.Mutex
	names  map[string]*limiterEntry
	addrs  map[string]*limiterEntry
	maxLen int
}

type limiterEntry struct {
	attempts int
	start    time.Time
}

const (
	limiterAttempts = 5
	limiterWindow   = 5 * time.Minute
	// limiterEntries bounds each of the two tables.
	limiterEntries = 10000
)

func newLimiter() *limiter {
	return &limiter{names: map[string]*limiterEntry{}, addrs: map[string]*limiterEntry{}, maxLen: limiterEntries}
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
