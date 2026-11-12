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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/store"
)

// deviceCookieOf is the device cookie an answer sets, nil if it sets none.
func deviceCookieOf(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// exhaust makes strangers use up the sign-in allowance of a user name:
// wrong passwords, each from another address, until the name is refused.
func (s *site) exhaust(username string) {
	s.t.Helper()
	for i := 0; i < limiterAttempts; i++ {
		stranger := s.browser()
		stranger.remote = "10.99.0." + string(rune('1'+i)) + ":40000"
		wantStatus(s.t, stranger.signIn(username, "not the password"), http.StatusUnauthorized)
	}
	stranger := s.browser()
	stranger.remote = "10.99.1.1:40000"
	// Refused with the right password too: that is the lockout.
	wantStatus(s.t, stranger.signIn(username, alicePassword), http.StatusTooManyRequests)
}

func TestSignInRemembersTheBrowser(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()

	// A failed sign-in leaves nothing behind.
	if c := deviceCookieOf(b.signIn("alice", "wrong"), deviceCookie); c != nil {
		t.Errorf("a failed sign-in set a device cookie: %+v", c)
	}
	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	c := deviceCookieOf(rec, deviceCookie)
	if c == nil {
		t.Fatal("no device cookie after signing in")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != int(store.DeviceLifetime/time.Second) || c.Secure {
		t.Errorf("device cookie: %+v", c)
	}
	token, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(token) != tokenBytes {
		t.Fatalf("device cookie value: %q", c.Value)
	}
	// The store knows it for alice, by its hash only.
	if owner, err := s.store.Store.DeviceUser(context.Background(), store.HashToken(token), s.clock.Now()); err != nil || owner != "alice" {
		t.Errorf("the store has the device for %q, %v", owner, err)
	}
	if c.Value == b.cookies[sessionCookie] {
		t.Error("the device cookie is the session cookie")
	}

	// Signing out keeps it; signing in again keeps the same one, renewed.
	page := b.get("/status")
	b.do(http.MethodPost, "/sign-out", map[string][]string{"form_token": {tokenIn(t, page)}})
	if b.cookies[deviceCookie] != c.Value {
		t.Fatal("signing out dropped the device cookie")
	}
	s.clock.advance(24 * time.Hour)
	rec = b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	if again := deviceCookieOf(rec, deviceCookie); again == nil || again.Value != c.Value || again.MaxAge != int(store.DeviceLifetime/time.Second) {
		t.Errorf("signing in again: device cookie %+v, want the same one renewed", again)
	}
	// Renewed in the store too: it is still known a lifetime after the
	// first sign-in.
	if _, err := s.store.Store.DeviceUser(context.Background(), store.HashToken(token), t0.Add(store.DeviceLifetime+time.Hour)); err != nil {
		t.Errorf("the device's use was not recorded: %v", err)
	}
	// The cookie's token is in no log line and no history row.
	if strings.Contains(s.log.String(), c.Value) {
		t.Error("the device cookie is in the log")
	}
}

func TestDeviceCookieOverHTTPS(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example", "10.20.0.5")
	b := s.browser()
	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	c := deviceCookieOf(rec, "__Host-"+deviceCookie)
	if c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" {
		t.Errorf("device cookie over HTTPS: %+v", c)
	}
}

// The point of it: strangers failing on a known user name lock the name
// for strangers, and not for a browser the account has signed in from.
func TestAKnownBrowserIsNotLockedOutByStrangers(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	own := s.browser()
	wantRedirect(t, own.signIn("alice", alicePassword), "/")
	device := own.cookies[deviceCookie]

	s.exhaust("alice")

	// Alice's own browser, signed out, with nothing but its device cookie.
	back := s.browser()
	back.cookies[deviceCookie] = device
	wantRedirect(t, back.signIn("alice", alicePassword), "/")
	wantStatus(t, back.get("/status"), http.StatusOK)

	// Her signing in gave the strangers nothing back.
	stranger := s.browser()
	stranger.remote = "10.99.2.1:40000"
	wantStatus(t, stranger.signIn("alice", alicePassword), http.StatusTooManyRequests)

	// And the lock on the name still ends by itself.
	s.clock.advance(limiterWindow)
	wantRedirect(t, stranger.signIn("alice", alicePassword), "/")
}

// A device cookie is not a way around the limit: it has five tries of its
// own, and then it waits like anyone.
func TestAKnownBrowserHasItsOwnLimit(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	own := s.browser()
	wantRedirect(t, own.signIn("alice", alicePassword), "/")
	thief := s.browser()
	thief.cookies[deviceCookie] = own.cookies[deviceCookie]
	thief.remote = "10.99.3.1:40000"

	for i := 0; i < limiterAttempts; i++ {
		wantStatus(t, thief.signIn("alice", "a guess"), http.StatusUnauthorized)
	}
	wantStatus(t, thief.signIn("alice", alicePassword), http.StatusTooManyRequests)
	// The same cookie from another address is the same device.
	thief.remote = "10.99.3.2:40000"
	wantStatus(t, thief.signIn("alice", alicePassword), http.StatusTooManyRequests)
	// Those guesses are in the history like any failed sign-in.
	failed := 0
	for _, e := range s.history() {
		if e.Action == store.ActionSignIn && e.Outcome == store.OutcomeFailed && e.Actor == "alice" {
			failed++
		}
	}
	if failed != limiterAttempts {
		t.Errorf("%d failed sign-ins recorded, want %d", failed, limiterAttempts)
	}
	// After the window the device has its tries again.
	s.clock.advance(limiterWindow)
	wantRedirect(t, thief.signIn("alice", alicePassword), "/")
}

// What does not count as a known browser: another account's device, a
// made-up cookie, one the store has forgotten, and any at all when the
// store cannot be asked.
func TestWhatIsNotAKnownBrowser(t *testing.T) {
	made := base64.RawURLEncoding.EncodeToString(make([]byte, tokenBytes))
	for name, cookie := range map[string]func(s *site, own, bobs *browser) string{
		"another account's device": func(_ *site, _, bobs *browser) string { return bobs.cookies[deviceCookie] },
		"a made-up cookie":         func(*site, *browser, *browser) string { return made },
		"not a token at all":       func(*site, *browser, *browser) string { return "alice" },
		"a device unused for its lifetime": func(s *site, own, _ *browser) string {
			s.clock.advance(store.DeviceLifetime)
			return own.cookies[deviceCookie]
		},
		"a device from before the password was changed": func(s *site, own, _ *browser) string {
			if err := s.store.Store.SetPassword(context.Background(), "alice", cheapHash(alicePassword), s.clock.Now()); err != nil {
				s.t.Fatal(err)
			}
			return own.cookies[deviceCookie]
		},
		"a store that cannot be asked": func(s *site, own, _ *browser) string {
			broken := errors.New("disk I/O error")
			s.store.deviceErr.Store(&broken)
			return own.cookies[deviceCookie]
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			own, bobs := s.browser(), s.browser()
			wantRedirect(t, own.signIn("alice", alicePassword), "/")
			wantRedirect(t, bobs.signIn("bob", bobPassword), "/")
			value := cookie(s, own, bobs)
			s.exhaust("alice")

			b := s.browser()
			b.cookies[deviceCookie] = value
			b.remote = "10.99.4.1:40000"
			wantStatus(t, b.signIn("alice", alicePassword), http.StatusTooManyRequests)
			if n := s.server.limiter.attemptsOfDevices(); n != 0 {
				t.Errorf("%d attempts were counted against a device", n)
			}
		})
	}
}

// A browser whose device has been forgotten is a stranger once, and known
// again from its next successful sign-in, under a new token.
func TestAForgottenBrowserIsRememberedAgain(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	old := b.cookies[deviceCookie]
	delete(b.cookies, sessionCookie)
	s.clock.advance(store.DeviceLifetime + time.Hour)

	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	fresh := deviceCookieOf(rec, deviceCookie)
	if fresh == nil || fresh.Value == old {
		t.Fatalf("after its device was forgotten: %+v, want a new device cookie", fresh)
	}
}

// Signing in does not depend on the device being recorded.
func TestSignInWhenTheDeviceCannotBeRemembered(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	full := errors.New("database or disk is full")
	s.store.rememberErr.Store(&full)
	b := s.browser()
	rec := b.signIn("alice", alicePassword)
	wantRedirect(t, rec, "/")
	if c := deviceCookieOf(rec, deviceCookie); c != nil {
		t.Errorf("a device that was not recorded got a cookie: %+v", c)
	}
	wantStatus(t, b.get("/status"), http.StatusOK)
	if !strings.Contains(s.log.String(), "could not remember this browser") {
		t.Error("the log does not say the browser was not remembered")
	}
}

// Changing the password forgets every known browser of the account but
// the one it was changed from, which is known again under a new token.
func TestChangingThePasswordKeepsOnlyThisBrowserKnown(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	here, elsewhere := s.browser(), s.browser()
	wantRedirect(t, here.signIn("alice", alicePassword), "/")
	wantRedirect(t, elsewhere.signIn("alice", alicePassword), "/")
	before := here.cookies[deviceCookie]

	token := tokenIn(t, here.get("/account"))
	rec := here.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantRedirect(t, rec, "/account?changed=1")
	after := deviceCookieOf(rec, deviceCookie)
	if after == nil || after.Value == before {
		t.Fatalf("after the change: %+v, want a new device cookie", after)
	}

	s.exhaust("alice")
	// This browser signs in with the new password although the name is
	// locked; the other, and this one's old cookie, do not.
	again := s.browser()
	again.cookies[deviceCookie] = after.Value
	wantRedirect(t, again.signIn("alice", newPassword), "/")
	for name, value := range map[string]string{"the other browser": elsewhere.cookies[deviceCookie], "this browser's old cookie": before} {
		b := s.browser()
		b.cookies[deviceCookie] = value
		if rec := b.signIn("alice", newPassword); rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s: %d, want 429", name, rec.Code)
		}
	}
}

func TestLimiterCountsDevicesApart(t *testing.T) {
	l := newLimiter()
	now := t0
	who := attempt{name: "alice", addr: "10.0.0.1", device: "d1"}
	for i := 0; i < limiterAttempts; i++ {
		if counted, wait := l.beginFor(now, who); wait != 0 || counted != who {
			t.Fatalf("attempt %d: counted %+v, wait %s", i, counted, wait)
		}
	}
	if _, wait := l.beginFor(now, who); wait == 0 || l.blockedFor(now, who) == 0 {
		t.Error("a device's sixth attempt was let through")
	}
	// Nothing was counted against the name or the address, and another
	// device of the same account is not held up.
	if l.blocked(now, "alice", "10.0.0.1") != 0 || len(l.names) != 0 || len(l.addrs) != 0 {
		t.Error("a device's attempts were counted against the name or the address")
	}
	if _, wait := l.beginFor(now, attempt{name: "alice", addr: "10.0.0.1", device: "d2"}); wait != 0 {
		t.Error("one device's attempts held up another")
	}
	// A success clears the device and leaves the name's count alone.
	l.begin(now, "alice", "")
	l.succeedFor(attempt{name: "alice", device: "d2"})
	if l.devices["d2"] != nil || l.names["alice"] == nil || l.names["alice"].attempts != 1 {
		t.Errorf("after a device's success: devices %v, name %+v", l.devices, l.names["alice"])
	}

	// With no room in the table of devices, a device is counted, and
	// reported, as a stranger; a success then gives that back.
	for _, d := range []string{"d4", "d5"} {
		l.beginFor(now, attempt{device: d})
	}
	l.maxLen = len(l.devices) // three: full for devices, not for the one name
	stranger := attempt{name: "bob", addr: "10.0.0.2"}
	counted, wait := l.beginFor(now, attempt{name: "bob", addr: "10.0.0.2", device: "d3"})
	if wait != 0 || counted != stranger || l.names["bob"] == nil {
		t.Errorf("a device with no room: counted %+v, wait %s", counted, wait)
	}
	l.succeedFor(counted)
	if l.names["bob"] != nil {
		t.Error("the stranger's count was kept after a success")
	}
}
