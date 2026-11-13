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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"handrail-ca/internal/store"
)

// waiting is how many requests stand in each of a gate's lines.
func (g *hashGate) waiting() (proven, strangers int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.proven), len(g.strangers)
}

// eventually waits for something another goroutine is about to do.
func eventually(t *testing.T, what string, done func() bool) {
	t.Helper()
	for range 5000 {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("still waiting for %s", what)
}

// hold takes every slot of a site's hashing gate and returns the function
// that gives them back.
func (s *site) holdHashing() (release func()) {
	s.t.Helper()
	var held []func()
	for range maxConcurrentHashes {
		r, err := s.server.hashing.take(context.Background(), false)
		if err != nil {
			s.t.Fatal(err)
		}
		held = append(held, r)
	}
	return func() {
		for _, r := range held {
			r()
		}
	}
}

func TestHashGateServesThoseWhoHaveShownSomethingFirst(t *testing.T) {
	g := newHashGate(1)
	g.wait = time.Minute
	ctx := context.Background()
	release, err := g.take(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 3)
	var wg sync.WaitGroup
	queue := func(name string, proven bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := g.take(ctx, proven)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			order <- name
			r()
		}()
	}
	// The strangers were there first.
	queue("a stranger", false)
	eventually(t, "the first stranger to queue", func() bool { _, n := g.waiting(); return n == 1 })
	queue("another stranger", false)
	eventually(t, "the second stranger to queue", func() bool { _, n := g.waiting(); return n == 2 })
	queue("a known browser", true)
	eventually(t, "the known browser to queue", func() bool { n, _ := g.waiting(); return n == 1 })

	release()
	wg.Wait()
	if first := <-order; first != "a known browser" {
		t.Errorf("%s was served first", first)
	}
	if second := <-order; second != "a stranger" {
		t.Errorf("%s was served second: the strangers' line is not first come, first served", second)
	}
	if g.free != 1 {
		t.Errorf("%d slots free at the end, want 1", g.free)
	}
}

func TestHashGateKeepsTheLinesShort(t *testing.T) {
	g := newHashGate(1)
	g.wait = time.Minute
	release, err := g.take(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, leave := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range maxWaitingForHash {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.take(ctx, false); !errors.Is(err, context.Canceled) {
				t.Errorf("a queued stranger whose browser went away: %v", err)
			}
		}()
	}
	eventually(t, "the strangers' line to fill", func() bool { _, n := g.waiting(); return n == maxWaitingForHash })

	// One more stranger is turned away at once, without waiting.
	began := time.Now()
	if _, err := g.take(context.Background(), false); !errors.Is(err, errBusy) {
		t.Errorf("a stranger past the line's length: %v, want errBusy", err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("turning a stranger away took %v", took)
	}
	// The other line is not the strangers' to fill.
	served := make(chan error, 1)
	go func() {
		r, err := g.take(context.Background(), true)
		if err == nil {
			r()
		}
		served <- err
	}()
	eventually(t, "the known browser to queue", func() bool { n, _ := g.waiting(); return n == 1 })

	// Those who leave the line leave nothing behind.
	leave()
	wg.Wait()
	if _, strangers := g.waiting(); strangers != 0 {
		t.Errorf("%d strangers are still in line after their browsers went away", strangers)
	}
	release()
	if err := <-served; err != nil {
		t.Errorf("a known browser behind a full line of strangers: %v", err)
	}
	if proven, strangers := g.waiting(); proven != 0 || strangers != 0 || g.free != 1 {
		t.Errorf("after everyone left: %d and %d waiting, %d free", proven, strangers, g.free)
	}
}

func TestHashGateSendsAQueuedStrangerAwayAfterAWhile(t *testing.T) {
	g := newHashGate(1)
	g.wait = 30 * time.Millisecond
	release, err := g.take(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	if _, err := g.take(context.Background(), false); !errors.Is(err, errBusy) {
		t.Errorf("a stranger who waited out the limit: %v, want errBusy", err)
	}
	if took := time.Since(began); took < g.wait {
		t.Errorf("sent away after %v, before the limit of %v", took, g.wait)
	}
	// Someone who has shown something waits for as long as it takes.
	served := make(chan error, 1)
	go func() {
		r, err := g.take(context.Background(), true)
		if err == nil {
			r()
		}
		served <- err
	}()
	eventually(t, "the known browser to queue", func() bool { n, _ := g.waiting(); return n == 1 })
	time.Sleep(3 * g.wait)
	select {
	case err := <-served:
		t.Fatalf("a known browser did not wait for the slot: %v", err)
	default:
	}
	release()
	if err := <-served; err != nil {
		t.Error(err)
	}
	if proven, strangers := g.waiting(); proven != 0 || strangers != 0 || g.free != 1 {
		t.Errorf("at the end: %d and %d waiting, %d free", proven, strangers, g.free)
	}
}

// With every hashing slot taken, a sign-in from a browser nobody knows is
// told to come back, and costs nothing: no hash, no counted attempt, no
// history row. One from a browser the account has used waits its turn.
func TestSignInWhenHashingIsBusy(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example", "10.20.0.5")
	known := s.browser()
	wantRedirect(t, known.signIn("alice", alicePassword), "/")
	rows := len(s.history())

	s.server.hashing.wait = 30 * time.Millisecond
	release := s.holdHashing()
	rec := s.browser().signIn("alice", alicePassword)
	wantStatus(t, rec, http.StatusServiceUnavailable)
	wantBody(t, rec, "busy checking other sign-ins")
	if got := rec.Header().Get("Retry-After"); got != retryWhenBusy {
		t.Errorf("Retry-After = %q", got)
	}
	if e := s.server.limiter.names["alice"]; e != nil {
		t.Errorf("an attempt was counted for a sign-in that was never checked: %+v", e)
	}
	if n := len(s.history()); n != rows {
		t.Errorf("%d history rows were written for it", n-rows)
	}

	again := s.browser()
	again.cookies = map[string]string{"__Host-" + deviceCookie: known.cookies["__Host-"+deviceCookie]}
	if again.cookies["__Host-"+deviceCookie] == "" {
		t.Fatal("the first sign-in left no device cookie")
	}
	answer := make(chan *httptest.ResponseRecorder, 1)
	go func() { answer <- again.signIn("alice", alicePassword) }()
	eventually(t, "the known browser to queue", func() bool { n, _ := s.server.hashing.waiting(); return n == 1 })
	time.Sleep(3 * s.server.hashing.wait)
	select {
	case rec := <-answer:
		t.Fatalf("the known browser was answered %d while every slot was taken", rec.Code)
	default:
	}
	release()
	wantRedirect(t, <-answer, "/")
}

// A change of password waits with the known browsers. If even that line is
// full, nothing is changed and the attempt is not held against anyone.
func TestChangePasswordWhenHashingIsBusy(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))

	release := s.holdHashing()
	ctx, leave := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range maxWaitingForHash {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.server.hashing.take(ctx, true)
		}()
	}
	eventually(t, "the line to fill", func() bool { n, _ := s.server.hashing.waiting(); return n == maxWaitingForHash })

	rec := b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword))
	wantStatus(t, rec, http.StatusServiceUnavailable)
	wantBody(t, rec, "nothing was changed")
	if got := rec.Header().Get("Retry-After"); got != retryWhenBusy {
		t.Errorf("Retry-After = %q", got)
	}
	leave()
	wg.Wait()
	release()
	if n := s.server.limiter.attemptsOfDevices(); n != 0 {
		t.Errorf("%d attempts are counted against the browser for a change that was never tried", n)
	}
	// The password is the old one still, and the change then goes through.
	wantRedirect(t, b.do(http.MethodPost, "/account/password", passwordForm(token, alicePassword, newPassword, newPassword)), "/account?changed=1")
}

// Changes of password are hashed ahead of strangers' sign-ins, so one
// account may make only so many in a window.
func TestChangesOfPasswordAreLimitedPerAccount(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	current := alicePassword
	change := func() *httptest.ResponseRecorder {
		next := fmt.Sprintf("a new password, number %d", len(s.history()))
		rec := b.do(http.MethodPost, "/account/password", passwordForm(tokenIn(t, b.get("/account")), current, next, next))
		if rec.Code == http.StatusSeeOther {
			current = next
		}
		return rec
	}
	for range limiterAttempts {
		wantRedirect(t, change(), "/account?changed=1")
	}
	rec := change()
	wantStatus(t, rec, http.StatusTooManyRequests)
	wantBody(t, rec, "changed several times")
	// Asking again and again is held against the browser, as wrong guesses
	// are, although the password given was right.
	for range limiterAttempts - 1 {
		wantStatus(t, change(), http.StatusTooManyRequests)
	}
	rec = change()
	wantStatus(t, rec, http.StatusTooManyRequests)
	wantBody(t, rec, "Too many wrong passwords")

	s.clock.advance(limiterWindow)
	wantRedirect(t, change(), "/account?changed=1")
}

// A failed sign-in is answered before its history row is written, for an
// account and for a name that is none alike: written first, the row would
// make the two answers take different times.
func TestFailedSignInsAreAnsweredBeforeTheirHistoryRow(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	gate := make(chan struct{})
	s.store.appendGate.Store(&gate)
	for _, tt := range []struct{ username, password string }{
		{"alice", "not alice's password"},
		{"alice", strings.Repeat("x", 1025)},
		{"mallory", "not anyone's password"},
		{"mallory", strings.Repeat("x", 1025)},
	} {
		answer := make(chan *httptest.ResponseRecorder, 1)
		go func() { answer <- s.browser().signIn(tt.username, tt.password) }()
		select {
		case rec := <-answer:
			wantStatus(t, rec, http.StatusUnauthorized)
		case <-time.After(10 * time.Second):
			t.Fatalf("the answer to a failed sign-in as %q waits for its history row", tt.username)
		}
	}
	// The log has them already; it is the rows that follow.
	if log := s.log.String(); strings.Count(log, "msg=audit actor=alice action=sign-in outcome=failed") != 2 ||
		strings.Count(log, `msg=audit actor="(unknown user)" action=sign-in outcome=failed`) != 2 {
		t.Errorf("log = %s", log)
	}
	close(gate)
	var actors []string
	for _, e := range s.history() {
		if e.Action != store.ActionSignIn || e.Outcome != store.OutcomeFailed {
			t.Errorf("history has %+v", e)
		}
		actors = append(actors, e.Actor)
	}
	// Newest first, in the order the attempts were made.
	if got, want := strings.Join(actors, ","), unknownActor+","+unknownActor+",alice,alice"; got != want {
		t.Errorf("rows for %s, want %s", got, want)
	}
}

// Only so many rows wait to be written after their answers. One more is
// written before its answer, as rows were before: none is dropped.
func TestLateHistoryRowsAreBounded(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	gate := make(chan struct{})
	s.store.appendGate.Store(&gate)
	event := func(i int) store.Event {
		return store.Event{At: s.clock.Now(), Actor: "alice", Action: store.ActionSignIn, Outcome: store.OutcomeFailed, Detail: fmt.Sprint(i)}
	}
	// The first is taken up by the writer, which then waits at the gate;
	// the line fills behind it.
	s.server.recordLater(event(0))
	eventually(t, "the writer to take the first row", func() bool {
		s.server.late.mu.Lock()
		defer s.server.late.mu.Unlock()
		return len(s.server.late.waiting) == 0
	})
	for i := range maxLateRows {
		s.server.recordLater(event(i + 1))
	}
	written := make(chan struct{})
	go func() {
		s.server.recordLater(event(maxLateRows + 1))
		close(written)
	}()
	select {
	case <-written:
		t.Fatal("a row that found the line full was handed over all the same")
	case <-time.After(100 * time.Millisecond):
	}

	// The end of the process waits for the rows, but not for ever.
	whole := &Site{Handler: s.handler, server: s.server}
	began := time.Now()
	whole.Settle(50 * time.Millisecond)
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("Settle took %v with the store not answering", took)
	}

	close(gate)
	<-written
	whole.Settle(time.Minute)
	events, err := s.store.Store.History(context.Background(), store.HistoryQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != maxLateRows+2 {
		t.Errorf("%d rows were written, want %d", len(events), maxLateRows+2)
	}
}
