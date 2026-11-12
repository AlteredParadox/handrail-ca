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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNotes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Nobody has written about it: empty, and no error.
	n, err := s.Note(ctx, "101")
	if err != nil || !n.Empty() || n.Serial != "101" || !n.UpdatedAt.IsZero() || n.UpdatedBy != "" {
		t.Fatalf("a certificate without a note: %+v, %v", n, err)
	}

	// Saved as typed, tidied: line ends, outer space, label case and order.
	err = s.SetNote(ctx, Note{Serial: "101", Text: "  The intranet's front end.\r\nAsked for by Sam.  \n", Labels: []string{"Web", "prod", "web"}, UpdatedAt: t0, UpdatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	n, err = s.Note(ctx, "101")
	want := Note{Serial: "101", Text: "The intranet's front end.\nAsked for by Sam.", Labels: []string{"prod", "web"}, UpdatedAt: t0, UpdatedBy: "alice"}
	if err != nil || !reflect.DeepEqual(n, want) {
		t.Fatalf("read back %+v, %v; want %+v", n, err, want)
	}

	// Replaced whole: the old labels do not linger.
	later := t0.Add(time.Hour)
	if err := s.SetNote(ctx, Note{Serial: "101", Text: "Moved to the new host.", Labels: []string{"staging"}, UpdatedAt: later, UpdatedBy: "bob"}); err != nil {
		t.Fatal(err)
	}
	n, _ = s.Note(ctx, "101")
	want = Note{Serial: "101", Text: "Moved to the new host.", Labels: []string{"staging"}, UpdatedAt: later, UpdatedBy: "bob"}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("after replacing: %+v", n)
	}
	// Another certificate's note is its own.
	if other, err := s.Note(ctx, "102"); err != nil || !other.Empty() {
		t.Errorf("another certificate's note: %+v, %v", other, err)
	}
	// Labels alone are a note; so is text alone.
	if err := s.SetNote(ctx, Note{Serial: "102", Labels: []string{"db"}, UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Note(ctx, "102"); n.Text != "" || !reflect.DeepEqual(n.Labels, []string{"db"}) || n.UpdatedBy != "alice" {
		t.Errorf("labels alone: %+v", n)
	}

	// Emptied: nothing is left, labels included.
	if err := s.SetNote(ctx, Note{Serial: "101", Text: "  ", UpdatedAt: later, UpdatedBy: "bob"}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Note(ctx, "101"); err != nil || !n.Empty() || !n.UpdatedAt.IsZero() {
		t.Errorf("after emptying: %+v, %v", n, err)
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM cert_notes WHERE serial = '101') + (SELECT COUNT(*) FROM cert_labels WHERE serial = '101')`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("an emptied note left %d rows (%v)", rows, err)
	}
}

func TestSetNoteRefusals(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	good := Note{Serial: "101", Text: "kept", Labels: []string{"web"}, UpdatedAt: t0, UpdatedBy: "alice"}
	if err := s.SetNote(ctx, good); err != nil {
		t.Fatal(err)
	}
	with := func(change func(*Note)) Note {
		n := good
		n.Labels = append([]string{}, good.Labels...)
		change(&n)
		return n
	}
	var many []string
	for i := range MaxLabels + 1 {
		many = append(many, fmt.Sprintf("l%d", i))
	}
	for name, tc := range map[string]struct {
		note    Note
		invalid bool
	}{
		"no serial":       {with(func(n *Note) { n.Serial = "" }), false},
		"no author":       {with(func(n *Note) { n.UpdatedBy = "" }), false},
		"no time":         {with(func(n *Note) { n.UpdatedAt = time.Time{} }), false},
		"too long":        {with(func(n *Note) { n.Text = strings.Repeat("é", MaxNote+1) }), true},
		"not text":        {with(func(n *Note) { n.Text = "a\xffb" }), true},
		"a NUL":           {with(func(n *Note) { n.Text = "a\x00b" }), true},
		"a bad label":     {with(func(n *Note) { n.Labels = []string{"ok", "<script>"} }), true},
		"too many labels": {with(func(n *Note) { n.Labels = many }), true},
	} {
		err := s.SetNote(ctx, tc.note)
		if err == nil || errors.Is(err, ErrInvalidNote) != tc.invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Nothing that was refused replaced what was there.
	if n, _ := s.Note(ctx, "101"); n.Text != "kept" || !reflect.DeepEqual(n.Labels, []string{"web"}) {
		t.Errorf("a refused note changed the stored one: %+v", n)
	}
	// The longest note that is allowed is.
	if err := s.SetNote(ctx, with(func(n *Note) { n.Text = strings.Repeat("é", MaxNote) })); err != nil {
		t.Errorf("a note of exactly the limit: %v", err)
	}
}

func TestParseLabels(t *testing.T) {
	for typed, want := range map[string][]string{
		"":                            nil,
		"  , ,\n":                     nil,
		"web":                         {"web"},
		"Web, PROD web\tdb\n":         {"db", "prod", "web"},
		"team:infra,env-2,a.b_c":      {"a.b_c", "env-2", "team:infra"},
		strings.Repeat("a", MaxLabel): {strings.Repeat("a", MaxLabel)},
	} {
		got, err := ParseLabels(typed)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ParseLabels(%q) = %v, %v; want %v", typed, got, err, want)
		}
	}
	for typed, reason := range map[string]string{
		"<b>":                           "is not",
		"-leading":                      "is not",
		"sp@ce":                         "is not",
		"naïve":                         "is not",
		strings.Repeat("a", MaxLabel+1): "at most 32 characters",
		"a b c d e f g h i j k l m":     "at most 12 labels; this is 13",
	} {
		_, err := ParseLabels(typed)
		if !errors.Is(err, ErrInvalidNote) || !strings.Contains(err.Error(), reason) {
			t.Errorf("ParseLabels(%q): %v, want a refusal saying %q", typed, err, reason)
		}
	}
}

// A store made before notes existed gains them when it is next opened, and
// keeps what it had.
func TestOpenAddsNotesToAnOlderStore(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	dir := t.TempDir()
	ctx := context.Background()

	migrations = saved[:1]
	old := open(t, dir)
	if _, err := old.AddUser(ctx, "alice", "hash", RoleOperator, t0); err != nil {
		t.Fatal(err)
	}
	if err := old.AppendHistory(ctx, Event{At: t0, Actor: "alice", Action: ActionSignIn, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if err := old.SetNote(ctx, Note{Serial: "1", Text: "x", UpdatedAt: t0, UpdatedBy: "alice"}); err == nil {
		t.Fatal("the older schema took a note")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	migrations = saved
	s := open(t, dir)
	if users, err := s.Users(ctx); err != nil || len(users) != 1 {
		t.Errorf("accounts after the upgrade: %v, %v", users, err)
	}
	if events, err := s.History(ctx, HistoryQuery{}); err != nil || len(events) != 1 {
		t.Errorf("history after the upgrade: %v, %v", events, err)
	}
	if err := s.SetNote(ctx, Note{Serial: "1", Text: "x", Labels: []string{"web"}, UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Errorf("a note after the upgrade: %v", err)
	}
}

// A note read while another save replaces it is one save's or the
// other's: never one's text with the other's labels.
func TestNoteIsReadWhole(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	versions := []Note{
		{Serial: "101", Text: "first", Labels: []string{"a", "b"}, UpdatedAt: t0, UpdatedBy: "alice"},
		{Serial: "101", Text: "second", Labels: []string{"c"}, UpdatedAt: t0.Add(time.Hour), UpdatedBy: "bob"},
	}
	if err := s.SetNote(ctx, versions[0]); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if err := s.SetNote(ctx, versions[i%2]); err != nil {
				done <- err
				return
			}
		}
	}()
	for range 300 {
		n, err := s.Note(ctx, "101")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(n, versions[0]) && !reflect.DeepEqual(n, versions[1]) {
			t.Fatalf("a note that was never saved: %+v", n)
		}
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
