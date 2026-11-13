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

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// plan is how SQLite would run a history query, as it says itself.
func plan(t *testing.T, s *Store, q HistoryQuery) string {
	t.Helper()
	query, args := historyStatement(q, 100)
	rows, err := s.read.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		steps = append(steps, detail)
	}
	return strings.Join(steps, "; ")
}

// The history only grows, and anyone signed in can ask for a part of it.
// A lookup that reads all of it to answer costs more with every row, and
// everyone who needs the store pays. Each narrowed lookup has to be
// answered from an index.
func TestHistoryLookupsDoNotReadTheWholeTable(t *testing.T) {
	s := newStore(t)
	for name, tt := range map[string]struct {
		q    HistoryQuery
		uses string
	}{
		"one certificate":                      {HistoryQuery{Serial: "1234"}, "history_serial"},
		"one certificate, a page further":      {HistoryQuery{Serial: "1234", Before: 50}, "history_serial"},
		"one kind of event":                    {HistoryQuery{Action: ActionRevoke}, "history_action"},
		"one kind of event, a page further":    {HistoryQuery{Action: ActionRevoke, Before: 50}, "history_action"},
		"one certificate and one kind":         {HistoryQuery{Serial: "1234", Action: ActionRevoke}, "history_serial"},
		"one certificate, one kind, a page on": {HistoryQuery{Serial: "1234", Action: ActionRevoke, Before: 50}, "history_serial"},
		"a page further":                       {HistoryQuery{Before: 50}, "PRIMARY KEY"},
	} {
		t.Run(name, func(t *testing.T) {
			got := plan(t, s, tt.q)
			if strings.Contains(got, "SCAN") || !strings.Contains(got, tt.uses) {
				t.Errorf("planned as %q, want a search using %s", got, tt.uses)
			}
		})
	}
}

// The statement is put together from pieces; what it selects has to be
// what the one fixed statement before it selected.
func TestHistoryFiltersSelectWhatTheySay(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var all []Event
	for i := range 60 {
		e := Event{At: t0.Add(time.Duration(i) * time.Second), Actor: "alice", Action: []string{ActionSignIn, ActionRevoke, ActionIssue}[i%3], Outcome: OutcomeOK}
		if i%2 == 0 {
			e.Serial = fmt.Sprint(1000 + i%4)
		}
		if err := s.AppendHistory(ctx, e); err != nil {
			t.Fatal(err)
		}
		e.ID = int64(i + 1)
		all = append(all, e)
	}
	for _, q := range []HistoryQuery{
		{}, {Serial: "1000"}, {Serial: "1002", Before: 30}, {Action: ActionRevoke}, {Action: ActionIssue, Before: 31},
		{Serial: "1000", Action: ActionSignIn}, {Serial: "1002", Action: ActionRevoke, Before: 40}, {Serial: "no such"}, {Before: 10}, {Limit: 7},
	} {
		var want []int64
		for i := len(all) - 1; i >= 0; i-- {
			e := all[i]
			if (q.Serial == "" || e.Serial == q.Serial) && (q.Action == "" || e.Action == q.Action) && (q.Before <= 0 || e.ID < q.Before) {
				want = append(want, e.ID)
			}
		}
		limit := 100
		if q.Limit > 0 {
			limit = q.Limit
		}
		if len(want) > limit {
			want = want[:limit]
		}
		events, err := s.History(ctx, q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		var got []int64
		for _, e := range events {
			got = append(got, e.ID)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%+v: rows %v, want %v", q, got, want)
		}
	}
}

func TestOpenAddsTheHistoryIndexToAnOlderStore(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	dir := t.TempDir()
	ctx := context.Background()

	migrations = saved[:3]
	old := open(t, dir)
	if err := old.AppendHistory(ctx, Event{At: t0, Actor: "alice", Action: ActionRevoke, Outcome: OutcomeOK, Serial: "1234"}); err != nil {
		t.Fatal(err)
	}
	if got := plan(t, old, HistoryQuery{Action: ActionRevoke}); strings.Contains(got, "history_action") {
		t.Fatalf("the older schema already has the index: %s", got)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	migrations = saved
	s := open(t, dir)
	if got := plan(t, s, HistoryQuery{Action: ActionRevoke}); !strings.Contains(got, "history_action") {
		t.Errorf("after the upgrade a lookup by kind is planned as %q", got)
	}
	if events, err := s.History(ctx, HistoryQuery{Action: ActionRevoke}); err != nil || len(events) != 1 {
		t.Errorf("history after the upgrade: %v, %v", events, err)
	}
}

// Reading goes through connections of its own, which cannot write. With
// every one of them in the middle of a read, a history row, a new session
// and an account change are still written at once: page loads, however
// many, do not stand in front of the record of a revocation.
func TestWritesDoNotWaitForReaders(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, err := s.AddUser(ctx, "alice", "hash", RoleOperator, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.read.ExecContext(ctx, `INSERT INTO history (at, actor, action, outcome) VALUES (1, 'x', 'x', 'x')`); err == nil {
		t.Fatal("a reading connection wrote to the store")
	}

	// Every reader is held in a transaction that has read something.
	var held []*sql.Tx
	for range readConns {
		tx, err := s.read.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM history`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		held = append(held, tx)
	}
	release := func() {
		for _, tx := range held {
			_ = tx.Rollback()
		}
		held = nil
	}
	defer release()

	soon, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.AppendHistory(soon, Event{At: t0, Actor: "alice", Action: ActionRevoke, Outcome: OutcomeOK, Serial: "1234"}); err != nil {
		t.Errorf("a history row while every reader is busy: %v", err)
	}
	token := HashToken([]byte("a session token"))
	if err := s.CreateSession(soon, alice.ID, "hash", token, t0, t0.Add(time.Hour)); err != nil {
		t.Errorf("a new session while every reader is busy: %v", err)
	}
	if err := s.SetPassword(soon, "alice", "another hash", t0); err != nil {
		t.Errorf("a change of password while every reader is busy: %v", err)
	}
	// A read, meanwhile, does wait for a reader, and gives up with its
	// caller.
	brief, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, err := s.History(brief, HistoryQuery{}); err == nil {
		t.Error("a read went ahead with every reading connection taken")
	}

	// What was written meanwhile is there for the readers once they look.
	release()
	if events, err := s.History(ctx, HistoryQuery{Serial: "1234"}); err != nil || len(events) != 1 {
		t.Errorf("the row written meanwhile: %v, %v", events, err)
	}
}

// What is removed from the store is not left lying in its files, where a
// backup would carry it on: the password hash of a removed account or of a
// replaced password, and the text of a removed note.
func TestWhatIsRemovedIsNotLeftInTheFiles(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	ctx := context.Background()
	const (
		removedHash  = "$argon2id$v=19$m=65536,t=3,p=4$REMOVED-ACCOUNT-MARKER$0000000000000000000000000000000000000000000"
		replacedHash = "$argon2id$v=19$m=65536,t=3,p=4$REPLACED-PASSWORD-MARKER$000000000000000000000000000000000000000000"
		removedNote  = "REMOVED-NOTE-MARKER: the firewall rule for this one is in the old ticket system"
	)
	// Enough other rows that what is freed is not simply the last page.
	for i := range 40 {
		if _, err := s.AddUser(ctx, fmt.Sprintf("user%02d", i), "a hash that stays", RoleViewer, t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddUser(ctx, "leaver", removedHash, RoleViewer, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(ctx, "stayer", replacedHash, RoleViewer, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNote(ctx, Note{Serial: "1234", Text: removedNote, Labels: []string{"removed-label-marker"}, UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	holds := func(when string, present bool) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{"REMOVED-ACCOUNT-MARKER", "REPLACED-PASSWORD-MARKER", "REMOVED-NOTE-MARKER", "removed-label-marker"} {
				if strings.Contains(string(data), marker) {
					found[marker] = true
					if !present {
						t.Errorf("%s: %s still holds %s", when, e.Name(), marker)
					}
				}
			}
		}
		if present && len(found) != 4 {
			t.Fatalf("%s: only %v found in the files: this test would prove nothing", when, found)
		}
	}
	holds("while they are in use", true)

	if err := s.RemoveUser(ctx, "leaver"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, "stayer", "a new hash", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNote(ctx, Note{Serial: "1234", UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	holds("after their removal, with the store open", false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	holds("after their removal, with the store closed", false)
}

// The writer's busy timeout is set aside for the moment the log is folded
// in, and has to be back afterwards whatever becomes of the request that
// caused it: without it every later write fails at once when another
// process holds the lock, instead of waiting.
func TestTheWritersBusyTimeoutSurvivesARequestThatGoesAway(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	timeout := func() int64 {
		t.Helper()
		var ms int64
		if err := s.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&ms); err != nil {
			t.Fatal(err)
		}
		return ms
	}
	want := busyTimeout.Milliseconds()
	if got := timeout(); got != want {
		t.Fatalf("the writer starts with a busy timeout of %d ms, want %d", got, want)
	}
	if _, err := s.AddUser(ctx, "alice", "hash", RoleOperator, t0); err != nil {
		t.Fatal(err)
	}

	// The request goes away at the worst moment: after the timeout was set
	// aside and before it is put back.
	request, leave := context.WithCancel(ctx)
	saved := whileScrubbing
	t.Cleanup(func() { whileScrubbing = saved })
	left := false
	// (The hook must not ask the store anything: the one connection for
	// writing is in use at that moment, by what is being tested.)
	whileScrubbing = func() {
		leave()
		left = true
	}
	if err := s.SetNote(request, Note{Serial: "1234", Text: "a note", UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	if !left {
		t.Fatal("saving a note did not fold the log in: this test would prove nothing")
	}
	if got := timeout(); got != want {
		t.Errorf("after a request that went away in the middle the busy timeout is %d ms, want %d", got, want)
	}

	// And with nothing going wrong it is as it was.
	whileScrubbing = saved
	if err := s.SetPassword(ctx, "alice", "another hash", t0); err != nil {
		t.Fatal(err)
	}
	if got := timeout(); got != want {
		t.Errorf("after a change of password the busy timeout is %d ms, want %d", got, want)
	}
}
