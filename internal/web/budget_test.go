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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"handrail-ca/internal/store"
)

// countActions counts the history rows of each action.
func countActions(events []store.Event) map[string]int {
	n := map[string]int{}
	for _, e := range events {
		n[e.Action]++
	}
	return n
}

// An account can sign in and out as often as it likes, and history rows
// are never deleted: past routineRows an hour its sign-ins and sign-outs
// are logged and counted, not written, and the next row written says how
// many were passed over.
func TestAnAccountCannotFillTheHistoryBySigningInAndOut(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	const cycles = 40 // 80 events
	for range cycles {
		b := s.browser()
		wantRedirect(t, b.signIn("bob", bobPassword), "/")
		wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {tokenIn(t, b.get("/account"))}}), "/sign-in")
	}
	n := countActions(s.history())
	if got := n[store.ActionSignIn] + n[store.ActionSignOut]; got != routineRows {
		t.Fatalf("%d sign-in and sign-out rows for %d events, want %d", got, 2*cycles, routineRows)
	}
	log := s.log.String()
	if got := strings.Count(log, "msg=audit actor=bob action=sign-in outcome=ok") + strings.Count(log, "msg=audit actor=bob action=sign-out outcome=ok"); got != 2*cycles {
		t.Errorf("%d of %d events are in the log", got, 2*cycles)
	}

	// Another account has a budget of its own.
	wantRedirect(t, s.browser().signIn("alice", alicePassword), "/")
	if e := s.history()[0]; e.Actor != "alice" || e.Action != store.ActionSignIn {
		t.Fatalf("alice's sign-in was not written: newest row %+v", e)
	}

	// The next hour's first row says how many went unrecorded.
	s.clock.advance(accountWindow)
	wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
	want := fmt.Sprintf("%d more sign-ins and sign-outs by this account since the last one recorded here are in the log only", 2*cycles-routineRows)
	if e := s.history()[0]; e.Actor != "bob" || e.Detail != want {
		t.Errorf("the first row of the next hour = %+v, want detail %q", e, want)
	}
	wantRedirect(t, s.browser().signIn("bob", bobPassword), "/")
	if e := s.history()[0]; e.Detail != "" {
		t.Errorf("the count was reported twice: %+v", e)
	}
}

// Issuing, revoking and failed sign-ins are not counted against the
// budget: bob's budget used up, his revocation still has its rows.
func TestTheBudgetLeavesOtherRowsAlone(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	for range routineRows {
		wantRedirect(t, s.browser().signIn("alice", alicePassword), "/")
	}
	wantStatus(t, s.browser().signIn("alice", "wrong"), http.StatusUnauthorized)
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	if e := s.history()[0]; e.Action != store.ActionSignIn || e.Outcome != store.OutcomeFailed {
		t.Fatalf("the failed sign-in was not written: newest row %+v", e)
	}
	page := b.get("/certificates/101")
	wantRedirect(t, b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {tokenIn(t, page)}, "note": {"kept"}}), "/certificates/101?saved=note#note")
	if e := s.history()[0]; e.Action != store.ActionNote {
		t.Errorf("the note's row was not written: newest row %+v", e)
	}
}

// A note changed without its history row would be a change nobody can
// trace, so past noteSaves an hour a save is refused, not left unrecorded.
func TestNoteSavesAreBoundedNotUnrecorded(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/certificates/101"))
	save := func(text string) *http.Response {
		return b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {text}}).Result()
	}
	for i := range noteSaves {
		if code := save(fmt.Sprint("note ", i)).StatusCode; code != http.StatusSeeOther {
			t.Fatalf("save %d: %d", i, code)
		}
	}
	if code := save("one too many").StatusCode; code != http.StatusTooManyRequests {
		t.Fatalf("save past the bound: %d, want 429", code)
	}
	if got := s.note("101").Text; got != fmt.Sprint("note ", noteSaves-1) {
		t.Errorf("the refused save changed the note to %q", got)
	}
	s.server.late.settle()
	notes, err := s.store.Store.History(t.Context(), store.HistoryQuery{Action: store.ActionNote, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(notes); got != noteSaves {
		t.Errorf("%d note rows for %d saves", got, noteSaves)
	}
	s.clock.advance(accountWindow)
	if code := save("next hour").StatusCode; code != http.StatusSeeOther {
		t.Errorf("a save the next hour: %d", code)
	}
}

// A session signed out of by two requests at once is one sign-out: only
// the request that ended it writes the row.
func TestOnlyTheSignOutThatEndsTheSessionIsRecorded(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/account"))
	// The other request got there first: the session is gone by the time
	// this one ends it.
	s.store.beforeDelete = func(h store.TokenHash) {
		if _, err := s.store.Store.DeleteSession(t.Context(), h); err != nil {
			t.Error(err)
		}
	}
	wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {token}}), "/sign-in")
	if got := countActions(s.history())[store.ActionSignOut]; got != 0 {
		t.Errorf("%d sign-out rows from a request that ended nothing", got)
	}
	if !strings.Contains(s.log.String(), "msg=audit actor=alice action=sign-in outcome=ok") {
		t.Error("the sign-in is not in the log")
	}

	// The one that does end it is recorded.
	s.store.beforeDelete = nil
	b = s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	wantRedirect(t, b.do(http.MethodPost, "/sign-out", url.Values{"form_token": {tokenIn(t, b.get("/account"))}}), "/sign-in")
	if got := countActions(s.history())[store.ActionSignOut]; got != 1 {
		t.Errorf("%d sign-out rows after one sign-out", got)
	}
}

// A store that cannot be written to (a full disk) cannot record that a
// session is being used; the session is not ended for that while it is.
func TestASessionInUseOutlastsAStoreThatCannotRecordIt(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	full := errors.New("database or disk is full")
	s.store.touchErr.Store(&full)
	for range 4 {
		s.clock.advance(sessionIdle - time.Minute)
		wantStatus(t, b.get("/status"), http.StatusOK)
	}
	// Left alone, it still ends when idle.
	s.clock.advance(sessionIdle)
	wantRedirect(t, b.get("/status"), "/sign-in")
	if len(s.server.touches.at) != 0 {
		t.Errorf("%d uses still remembered for a session that ended", len(s.server.touches.at))
	}
}

// Rows that could not be written are not forgotten when a later write
// works: the alarm stays until a row saying how many are missing is in
// the history.
func TestAGapInTheHistoryIsWrittenDown(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/certificates/101"))
	boom := errors.New("database or disk is full")
	s.store.historyErr.Store(&boom)
	from := s.clock.Now()
	for _, text := range []string{"first", "second"} {
		wantRedirect(t, b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {text}}), "/certificates/101?saved=note#note")
		s.clock.advance(time.Minute)
	}
	wantBody(t, b.get("/status"), "History is not being recorded")

	// The next write works, and so does the row about the gap.
	s.store.historyErr.Store(nil)
	wantRedirect(t, b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"third"}}), "/certificates/101?saved=note#note")
	events := s.history()
	gap := events[0]
	want := fmt.Sprintf("2 history rows could not be written since %s; the log has them", from.UTC().Format(time.RFC3339))
	if gap.Action != store.ActionHistoryGap || gap.Actor != store.ActorHandrail || gap.Outcome != store.OutcomeFailed || gap.Detail != want {
		t.Fatalf("newest row = %+v, want a gap row saying %q", gap, want)
	}
	if events[1].Action != store.ActionNote {
		t.Errorf("the row before the gap row = %+v, want the third note's", events[1])
	}
	if strings.Contains(b.get("/status").Body.String(), "History is not being recorded") {
		t.Error("the alarm stayed after the gap was written down")
	}
	wantBody(t, b.get("/history?action="+store.ActionHistoryGap), "Rows missing", "2 history rows could not be written")
}

// A write that works while the row about the gap does not leaves the
// alarm up, and the gap is written with the next write that works.
func TestTheAlarmStaysUntilTheGapIsWritten(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	boom := errors.New("database or disk is full")
	s.store.historyErr.Store(&boom)
	s.server.appendHistory(t.Context(), store.Event{At: s.clock.Now(), Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK})

	// The event's own row goes in, the gap row does not.
	s.store.writesLeft.Store(1)
	s.store.limitWrites.Store(true)
	s.store.historyErr.Store(nil)
	s.server.appendHistory(t.Context(), store.Event{At: s.clock.Now(), Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK})
	if !s.server.historyBroken.Load() {
		t.Fatal("the alarm went down with the gap not written")
	}
	s.store.limitWrites.Store(false)
	s.server.appendHistory(t.Context(), store.Event{At: s.clock.Now(), Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK})
	if s.server.historyBroken.Load() {
		t.Error("the alarm stayed up after the gap was written")
	}
	if n := countActions(s.history())[store.ActionHistoryGap]; n != 1 {
		t.Errorf("%d gap rows, want 1", n)
	}
}

// Two writers that work at once after rows were lost report the gap once,
// and the count of rows missing does not go below what was lost.
func TestAGapIsReportedOnceByWritersAtOnce(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	boom := errors.New("database or disk is full")
	ev := store.Event{At: s.clock.Now(), Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK}
	s.store.historyErr.Store(&boom)
	for range 3 {
		s.server.appendHistory(t.Context(), ev)
	}
	s.store.historyErr.Store(nil)

	// The first gap row is held until the second writer has written its
	// own row and come to the gap.
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	s.store.beforeGap = func() {
		entered <- struct{}{}
		<-release
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.server.appendHistory(t.Context(), ev)
		}()
	}
	<-entered
	time.Sleep(100 * time.Millisecond) // the other writer's row is in; it waits for the gap
	close(release)
	wg.Wait()
	s.store.beforeGap = nil

	n := countActions(s.history())[store.ActionHistoryGap]
	if n != 1 {
		t.Fatalf("%d gap rows for one gap, want 1", n)
	}
	if s.server.missing.n != 0 || s.server.historyBroken.Load() {
		t.Fatalf("after the gap was reported: %d missing, alarm %v", s.server.missing.n, s.server.historyBroken.Load())
	}
	// One more lost row is one more gap, and the alarm is up for it.
	s.store.historyErr.Store(&boom)
	s.server.appendHistory(t.Context(), ev)
	s.store.historyErr.Store(nil)
	if !s.server.historyBroken.Load() {
		t.Fatal("a row lost after the gap was reported left the alarm down")
	}
	s.server.appendHistory(t.Context(), ev)
	if got := s.history()[0]; got.Action != store.ActionHistoryGap || !strings.HasPrefix(got.Detail, "1 history rows") {
		t.Errorf("the second gap: newest row %+v", got)
	}
}

// fred's case: a write outage of over an hour, a session in use all the
// while, the store writable again, and the sweep running before the
// session's next request. The session goes on.
func TestASweepAfterAnOutageLeavesASessionInUse(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	full := errors.New("database or disk is full")
	s.store.touchErr.Store(&full)
	for range 3 {
		s.clock.advance(sessionIdle - time.Minute)
		wantStatus(t, b.get("/status"), http.StatusOK)
	}
	s.store.touchErr.Store(nil)

	site := &Site{server: s.server}
	if err := site.SaveSessionUses(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := s.clock.Now()
	if _, err := s.store.Store.DeleteExpiredSessions(t.Context(), now, now.Add(-sessionIdle)); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, b.get("/status"), http.StatusOK)
	if n := len(s.server.touches.at); n != 0 {
		t.Errorf("%d uses still remembered after they were saved", n)
	}

	// While the uses cannot be saved, SaveSessionUses says so (and the
	// sweep is not run: TestSweepWaitsForTheUsesOfSessionsToBeSaved).
	s.store.touchErr.Store(&full)
	s.clock.advance(sessionIdle - time.Minute)
	wantStatus(t, b.get("/status"), http.StatusOK)
	if err := site.SaveSessionUses(t.Context()); !errors.Is(err, full) {
		t.Errorf("saving uses on a full store: %v", err)
	}
}
