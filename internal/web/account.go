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
	"errors"
	"net/http"

	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

type accountData struct {
	PasswordSet string // the day the current password was set
	// Changed is set on the page shown right after a successful change.
	Changed bool
	Problem string
}

// accountPage shows the signed-in user's account and the form for changing
// their own password.
func (s *server) accountPage(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, r.URL.Query().Get("changed") == "1", "")
}

func (s *server) renderAccount(w http.ResponseWriter, r *http.Request, status int, changed bool, problem string) {
	u := currentUser(r)
	s.render(w, r, status, "account.html", "Your account", accountData{
		PasswordSet: u.user.PasswordChangedAt.UTC().Format("2006-01-02"),
		Changed:     changed,
		Problem:     problem,
	})
}

// changePassword lets a signed-in user replace their own password. The
// session alone is not enough: the current password is asked for again, so
// that someone at an unattended browser cannot take the account over, and
// those checks are throttled exactly like sign-ins, so the form is not a
// second place to guess a password. A successful change ends every session
// of the account and opens a new one for this browser.
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	current, next := r.PostForm.Get("current_password"), r.PostForm.Get("new_password")

	// What can be refused without checking the current password is, before
	// an attempt is counted or any hashing done.
	var problem string
	switch err := password.Check(next); {
	case next != r.PostForm.Get("new_password_again"):
		problem = "The two entries of the new password differ."
	case err != nil:
		problem = "The new " + err.Error() + "."
	case next == current:
		problem = "The new password is the same as the current one."
	}
	if problem != "" {
		s.renderAccount(w, r, http.StatusBadRequest, false, problem)
		return
	}

	username := u.user.Username
	addr, known := s.clientAddr(r)
	if !known {
		addr = ""
	}
	tooMany := func() {
		s.renderAccount(w, r, http.StatusTooManyRequests, false, "Too many wrong passwords for this account. Wait a few minutes and try again.")
	}
	// Counted as a sign-in is: against this browser alone if it is one of
	// the account's known devices, so that strangers failing on the name
	// cannot keep its owner from changing the password.
	who := attempt{name: username, addr: addr, device: s.knownDevice(r, username).key()}
	if s.limiter.blockedFor(s.opts.Now(), who) > 0 {
		tooMany()
		return
	}
	// A change of password comes with a session, so it does not wait
	// behind strangers' sign-ins for its hashing (see hashGate).
	checked, err := s.checkPassword(r.Context(), username, current, who, true)
	if errors.Is(err, errBusy) {
		s.busyAccount(w, r)
		return
	}
	if err != nil {
		s.log.Error("checking a password", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not check the password. The log has the details.")
		return
	}
	if checked.wait > 0 {
		tooMany()
		return
	}
	if !checked.ok {
		s.record(r, store.Event{Actor: username, Action: store.ActionUserPasswd, Outcome: store.OutcomeFailed, Detail: "wrong current password"})
		s.renderAccount(w, r, http.StatusForbidden, false, "The current password is wrong.")
		return
	}

	// The current password was right. That attempt is given back to the
	// throttle only when the change is made, which it is not past this
	// point more than a few times in a window (see limiter.change).
	if s.limiter.change(s.opts.Now(), username) > 0 {
		s.renderAccount(w, r, http.StatusTooManyRequests, false, "This account's password has been changed several times in the last few minutes. Wait a few minutes and try again.")
		return
	}

	newHash, err := s.hashPassword(r.Context(), next)
	if errors.Is(err, errBusy) {
		// The current password was right, and its attempt is given back.
		s.limiter.succeedFor(checked.counted)
		s.busyAccount(w, r)
		return
	}
	now := s.opts.Now()
	if err == nil {
		// Only if the account still has the hash that was just checked: a
		// change made elsewhere in the meantime is not overwritten.
		err = s.opts.Store.ChangePassword(r.Context(), checked.user.ID, checked.hash, newHash, now)
	}
	if errors.Is(err, store.ErrNotFound) {
		s.record(r, store.Event{Actor: username, Action: store.ActionUserPasswd, Outcome: store.OutcomeFailed, Detail: "the account changed during the request"})
		s.renderAccount(w, r, http.StatusConflict, false, "The account was changed somewhere else while this was in progress, so nothing was changed here. Try again.")
		return
	}
	if err != nil {
		s.log.Error("changing a password", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not change the password. The log has the details.")
		return
	}
	s.limiter.succeedFor(checked.counted)
	s.record(r, store.Event{Actor: username, Action: store.ActionUserPasswd, Outcome: store.OutcomeOK, Detail: "changed by the user; all sessions ended"})

	// The change ended this browser's session with the others. It gets a
	// new one, under a new token.
	raw, encoded, err := newToken()
	if err == nil {
		err = s.opts.Store.CreateSession(r.Context(), checked.user.ID, newHash, store.HashToken(raw), now, now.Add(sessionLifetime))
	}
	if err != nil {
		// The password is changed; only staying signed in did not work.
		s.log.Error("opening a session after a password change", "err", err)
		s.setCookie(w, sessionCookie, "", 0)
		http.Redirect(w, r, s.base+"/sign-in", http.StatusSeeOther)
		return
	}
	s.setCookie(w, sessionCookie, encoded, sessionLifetime)
	// The change also forgot the account's known devices. This browser,
	// which has just given the old password and set the new one, is known
	// again, under a new token.
	checked.hash = newHash
	s.rememberDevice(w, r, device{}, checked)
	http.Redirect(w, r, s.base+"/account?changed=1", http.StatusSeeOther)
}

// busyAccount answers a change of password that found too many others
// waiting for their hashing. Nothing was changed.
func (s *server) busyAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", retryWhenBusy)
	s.renderAccount(w, r, http.StatusServiceUnavailable, false, "handrail-ca is busy checking other passwords, and nothing was changed. Try again in a moment.")
}

// hashPassword hashes a new password, taking one of the hashing slots like
// every password check does. Its caller holds a session (see hashGate).
func (s *server) hashPassword(ctx context.Context, pw string) (string, error) {
	release, err := s.hashing.take(ctx, true)
	if err != nil {
		return "", err
	}
	defer release()
	return s.hash(pw)
}
