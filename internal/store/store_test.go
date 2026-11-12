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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return open(t, t.TempDir())
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("err = %v, want one containing %q", err, contains)
	}
}

func TestOpenCreatesAnOwnerOnlyStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "nested", "data")
	s := open(t, dir)
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	// Write something, so the journal files exist too.
	if _, err := s.AddUser(ctx, "alice", "hash", RoleViewer, t0); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("data directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no files in the data directory")
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v: readable beyond its owner", e.Name(), info.Mode().Perm())
		}
	}
}

func TestOpenFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, ""); err == nil {
		t.Error("opened a store with no data directory")
	}

	// A data directory that is a file.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, file); err == nil {
		t.Error("opened a store inside a regular file")
	}

	// A file that is not a database.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, dir); err == nil {
		t.Error("opened a file that is not a database")
	}
}

func TestOpenInAnAwkwardlyNamedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "da ta?mode=memory#x%41")
	s := open(t, dir)
	if _, err := s.AddUser(context.Background(), "alice", "hash", RoleViewer, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The file is where it was asked for, and the data is in it.
	if info, err := os.Stat(filepath.Join(dir, FileName)); err != nil || info.Size() == 0 {
		t.Fatalf("store file: %v", err)
	}
	if n, err := open(t, dir).CountUsers(context.Background()); err != nil || n != 1 {
		t.Errorf("after reopening: %d users, %v", n, err)
	}
}

func TestReopenKeepsDataAndSchema(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := open(t, dir)
	if _, err := s.AddUser(ctx, "alice", "hash", RoleOperator, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, dir)
	users, err := s.Users(ctx)
	if err != nil || len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("after reopening: %+v, %v", users, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != len(migrations) {
		t.Errorf("schema version = %d, %v; want %d", version, err, len(migrations))
	}
}

func TestOpenRefusesANewerFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := open(t, dir)
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, dir)
	wantErr(t, err, "newer than this handrail-ca")
}

func TestAFailedSchemaStepChangesNothing(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	dir := t.TempDir()
	ctx := context.Background()
	open(t, dir).Close()

	migrations = append(append([]string{}, saved...), `CREATE TABLE extra (id INTEGER PRIMARY KEY); CREATE TABLE users (id INTEGER);`)
	_, err := Open(ctx, dir)
	wantErr(t, err, fmt.Sprintf("schema step %d", len(saved)+1))

	// Neither the first statement of the failed step nor its version stuck.
	migrations = saved
	s := open(t, dir)
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'extra'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("half of a failed step was kept (%d, %v)", n, err)
	}
}

// Opening a new store from several places at once must work for all of
// them: the server starting while a `user` command runs is two processes
// setting the same file up.
func TestConcurrentOpenOfANewStore(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(context.Background(), dir)
			if err == nil {
				err = s.Close()
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Errorf("concurrent open: %v", err)
		}
	}
}

func TestUsers(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if n, err := s.CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("a new store has %d users, %v", n, err)
	}
	alice, err := s.AddUser(ctx, " Alice ", "hash-a", RoleOperator, t0)
	if err != nil {
		t.Fatal(err)
	}
	if alice.Username != "alice" || alice.Role != RoleOperator || alice.ID == 0 || !alice.CreatedAt.Equal(t0) {
		t.Errorf("AddUser = %+v", alice)
	}
	if _, err := s.AddUser(ctx, "bob", "hash-b", RoleViewer, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(ctx, "ALICE", "other", RoleViewer, t0); !errors.Is(err, ErrUserExists) {
		t.Errorf("a second alice: %v, want ErrUserExists", err)
	}

	users, err := s.Users(ctx)
	if err != nil || len(users) != 2 || users[0].Username != "alice" || users[1].Username != "bob" {
		t.Fatalf("Users = %+v, %v", users, err)
	}
	if n, _ := s.CountUsers(ctx); n != 2 {
		t.Errorf("CountUsers = %d", n)
	}

	u, hash, err := s.Credentials(ctx, "Alice")
	if err != nil || hash != "hash-a" || u != alice {
		t.Errorf("Credentials = %+v, %q, %v", u, hash, err)
	}
	if _, _, err := s.Credentials(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Credentials(nobody): %v", err)
	}

	later := t0.Add(time.Hour)
	if err := s.SetPassword(ctx, "ALICE", "hash-a2", later); err != nil {
		t.Fatal(err)
	}
	u, hash, _ = s.Credentials(ctx, "alice")
	if hash != "hash-a2" || !u.PasswordChangedAt.Equal(later) || !u.CreatedAt.Equal(t0) {
		t.Errorf("after SetPassword: %+v, %q", u, hash)
	}
	if err := s.SetPassword(ctx, "nobody", "h", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPassword(nobody): %v", err)
	}
	if err := s.SetPassword(ctx, "alice", "", later); err == nil {
		t.Error("SetPassword accepted an empty hash")
	}

	if err := s.RemoveUser(ctx, "Bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing bob twice: %v", err)
	}
}

func TestAddUserRefusals(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tests := []struct {
		name, username, hash string
		role                 Role
		want                 string
	}{
		{"empty name", "", "h", RoleViewer, "user name"},
		{"space inside", "al ice", "h", RoleViewer, "user name"},
		{"leading dash", "-alice", "h", RoleViewer, "user name"},
		{"markup", "<b>", "h", RoleViewer, "user name"},
		{"too long", strings.Repeat("a", 65), "h", RoleViewer, "user name"},
		{"unknown role", "alice", "h", "admin", "unknown role"},
		{"no role", "alice", "h", "", "unknown role"},
		{"no hash", "alice", "", RoleViewer, "no password hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.AddUser(ctx, tt.username, tt.hash, tt.role, t0)
			wantErr(t, err, tt.want)
		})
	}
	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Errorf("%d users were created by refused calls", n)
	}
	if name, err := NormalizeUsername("Ops.Team_2-x"); err != nil || name != "ops.team_2-x" {
		t.Errorf("NormalizeUsername = %q, %v", name, err)
	}
	// The schema refuses a role the code would not write.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, created_at, password_changed_at) VALUES ('x', 'h', 'root', 0, 0)`); err == nil {
		t.Error("the schema accepted an unknown role")
	}
}

func TestSessions(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, err := s.AddUser(ctx, "alice", "hash", RoleOperator, t0)
	if err != nil {
		t.Fatal(err)
	}
	token := HashToken([]byte("the cookie value"))
	expires := t0.Add(12 * time.Hour)

	if err := s.CreateSession(ctx, alice.ID, "hash", token, t0, t0); err == nil {
		t.Error("created a session that is already over")
	}
	if err := s.CreateSession(ctx, 9999, "hash", token, t0, expires); !errors.Is(err, ErrNotFound) {
		t.Error("created a session for a user that does not exist")
	}
	if err := s.CreateSession(ctx, alice.ID, "hash", token, t0, expires); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, alice.ID, "hash", token, t0, expires); err == nil {
		t.Error("the same token was stored twice")
	}
	// The session is tied to the password that was checked: with any other
	// hash on the account, none is created.
	if err := s.CreateSession(ctx, alice.ID, "an older hash", HashToken([]byte("another")), t0, expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("a session for a superseded password: %v, want ErrNotFound", err)
	}

	sess, err := s.Session(ctx, token, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sess.User != alice || !sess.CreatedAt.Equal(t0) || !sess.LastSeenAt.Equal(t0) || !sess.ExpiresAt.Equal(expires) {
		t.Errorf("Session = %+v", sess)
	}
	if _, err := s.Session(ctx, HashToken([]byte("another value")), t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown token: %v", err)
	}
	// Expiry is exclusive: at the expiry time the session is over.
	if _, err := s.Session(ctx, token, expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("at expiry: %v, want ErrNotFound", err)
	}

	seen := t0.Add(30 * time.Minute)
	if err := s.TouchSession(ctx, token, seen); err != nil {
		t.Fatal(err)
	}
	if sess, _ := s.Session(ctx, token, seen); !sess.LastSeenAt.Equal(seen) {
		t.Errorf("LastSeenAt = %v after touching", sess.LastSeenAt)
	}

	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, token); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	if _, err := s.Session(ctx, token, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("after deleting: %v", err)
	}
}

func TestOnlyTheTokenHashIsStored(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	ctx := context.Background()
	alice, _ := s.AddUser(ctx, "alice", "hash", RoleViewer, t0)
	const token = "session-token-that-must-not-be-on-disk"
	if err := s.CreateSession(ctx, alice.ID, "hash", HashToken([]byte(token)), t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), token) {
			t.Errorf("%s contains the session token", e.Name())
		}
	}
}

func TestSessionsEndWithTheAccountOrItsPassword(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, _ := s.AddUser(ctx, "alice", "hash", RoleOperator, t0)
	bob, _ := s.AddUser(ctx, "bob", "hash", RoleViewer, t0)
	a1, a2, b1 := HashToken([]byte("a1")), HashToken([]byte("a2")), HashToken([]byte("b1"))
	for token, id := range map[TokenHash]int64{a1: alice.ID, a2: alice.ID, b1: bob.ID} {
		if err := s.CreateSession(ctx, id, "hash", token, t0, t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	alive := func(token TokenHash) bool {
		_, err := s.Session(ctx, token, t0)
		return err == nil
	}

	if err := s.SetPassword(ctx, "alice", "new-hash", t0); err != nil {
		t.Fatal(err)
	}
	if alive(a1) || alive(a2) {
		t.Error("alice's sessions survived her password change")
	}
	if !alive(b1) {
		t.Error("bob's session ended with alice's password change")
	}
	if err := s.RemoveUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if alive(b1) {
		t.Error("bob's session survived his removal")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, _ := s.AddUser(ctx, "alice", "hash", RoleOperator, t0)
	fresh, idle, over := HashToken([]byte("fresh")), HashToken([]byte("idle")), HashToken([]byte("over"))
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.CreateSession(ctx, alice.ID, "hash", fresh, t0, t0.Add(12*time.Hour)))
	must(s.CreateSession(ctx, alice.ID, "hash", idle, t0, t0.Add(12*time.Hour)))
	must(s.CreateSession(ctx, alice.ID, "hash", over, t0, t0.Add(time.Hour)))
	now := t0.Add(2 * time.Hour)
	must(s.TouchSession(ctx, fresh, now.Add(-time.Minute)))

	n, err := s.DeleteExpiredSessions(ctx, now, now.Add(-time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("removed %d sessions, %v; want 2", n, err)
	}
	if _, err := s.Session(ctx, fresh, now); err != nil {
		t.Errorf("the session in use was removed: %v", err)
	}
}

func TestHistory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	events := []Event{
		{At: t0, Actor: "alice", Action: ActionSignIn, Outcome: OutcomeOK, Remote: "10.20.0.5"},
		{At: t0.Add(time.Minute), Actor: "alice", Action: ActionRevoke, Outcome: OutcomeAttempt, Serial: "1234", Subject: "web1.internal.example"},
		{At: t0.Add(2 * time.Minute), Actor: "alice", Action: ActionRevoke, Outcome: OutcomeOK, Serial: "1234", Subject: "web1.internal.example", Detail: "key compromise"},
		{At: t0.Add(3 * time.Minute), Actor: ActorCommandLine, Action: ActionUserAdd, Outcome: OutcomeOK, Detail: "bob (viewer)"},
	}
	for _, e := range events {
		if err := s.AppendHistory(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.History(ctx, HistoryQuery{})
	if err != nil || len(all) != 4 {
		t.Fatalf("History = %d events, %v", len(all), err)
	}
	// Newest first, and everything that went in comes out.
	newest := events[3]
	newest.ID = all[0].ID
	if all[0] != newest || all[3].Action != ActionSignIn || all[3].Remote != "10.20.0.5" {
		t.Errorf("History[0] = %+v", all[0])
	}

	forCert, err := s.History(ctx, HistoryQuery{Serial: "1234"})
	if err != nil || len(forCert) != 2 || forCert[0].Outcome != OutcomeOK || forCert[1].Outcome != OutcomeAttempt {
		t.Errorf("History(serial) = %+v, %v", forCert, err)
	}

	page, err := s.History(ctx, HistoryQuery{Limit: 2})
	if err != nil || len(page) != 2 {
		t.Fatalf("first page = %d events, %v", len(page), err)
	}
	next, err := s.History(ctx, HistoryQuery{Limit: 2, Before: page[1].ID})
	if err != nil || len(next) != 2 || next[0].ID >= page[1].ID {
		t.Errorf("second page = %+v, %v", next, err)
	}
	if capped, _ := s.History(ctx, HistoryQuery{Limit: 1_000_000}); len(capped) != 4 {
		t.Errorf("a huge limit returned %d events", len(capped))
	}
}

func TestHistoryRefusesIncompleteEvents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	good := Event{At: t0, Actor: "alice", Action: ActionSignIn, Outcome: OutcomeOK}
	for name, change := range map[string]func(*Event){
		"no time":    func(e *Event) { e.At = time.Time{} },
		"no actor":   func(e *Event) { e.Actor = "" },
		"no action":  func(e *Event) { e.Action = "" },
		"no outcome": func(e *Event) { e.Outcome = "" },
	} {
		e := good
		change(&e)
		if err := s.AppendHistory(ctx, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHistoryBoundsItsFields(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	long := strings.Repeat("é", 5000)
	if err := s.AppendHistory(ctx, Event{At: t0, Actor: long, Action: long, Outcome: long, Serial: long, Subject: long, Detail: long, Remote: long}); err != nil {
		t.Fatal(err)
	}
	got, err := s.History(ctx, HistoryQuery{})
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	e := got[0]
	for name, field := range map[string]string{"actor": e.Actor, "action": e.Action, "outcome": e.Outcome, "remote": e.Remote} {
		if n := len([]rune(field)); n != maxShortField+1 {
			t.Errorf("%s kept %d characters", name, n)
		}
	}
	for name, field := range map[string]string{"subject": e.Subject, "detail": e.Detail} {
		if n := len([]rune(field)); n != maxDetail+1 {
			t.Errorf("%s kept %d characters", name, n)
		}
	}
}

func TestHistoryCannotBeRewritten(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.AppendHistory(ctx, Event{At: t0, Actor: "alice", Action: ActionRevoke, Outcome: OutcomeOK, Serial: "1"}); err != nil {
		t.Fatal(err)
	}
	// Even with the database handle itself, the schema refuses.
	for _, stmt := range []string{
		`UPDATE history SET actor = 'mallory'`,
		`DELETE FROM history`,
	} {
		_, err := s.db.ExecContext(ctx, stmt)
		wantErr(t, err, "history rows are never")
	}
	if got, _ := s.History(ctx, HistoryQuery{}); len(got) != 1 || got[0].Actor != "alice" {
		t.Errorf("history after the attempts: %+v", got)
	}
}

func TestHistoryOutlivesTheAccount(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.AddUser(ctx, "alice", "hash", RoleOperator, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendHistory(ctx, Event{At: t0, Actor: "alice", Action: ActionSignIn, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.History(ctx, HistoryQuery{}); len(got) != 1 || got[0].Actor != "alice" {
		t.Errorf("history after removing the account: %+v", got)
	}
}

func TestClosedStoreReportsErrors(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	token := HashToken([]byte("t"))
	checks := map[string]error{
		"Ping":         s.Ping(ctx),
		"AppendHist":   s.AppendHistory(ctx, Event{At: t0, Actor: "a", Action: "b", Outcome: "c"}),
		"SetPassword":  s.SetPassword(ctx, "alice", "h", t0),
		"RemoveUser":   s.RemoveUser(ctx, "alice"),
		"Create":       s.CreateSession(ctx, 1, "hash", token, t0, t0.Add(time.Hour)),
		"Touch":        s.TouchSession(ctx, token, t0),
		"Delete":       s.DeleteSession(ctx, token),
		"migrate":      s.migrate(ctx),
		"sql.ErrNoRow": nil,
	}
	delete(checks, "sql.ErrNoRow")
	if _, err := s.AddUser(ctx, "alice", "h", RoleViewer, t0); err == nil {
		t.Error("AddUser on a closed store: no error")
	}
	if _, err := s.Users(ctx); err == nil {
		t.Error("Users on a closed store: no error")
	}
	if _, err := s.CountUsers(ctx); err == nil {
		t.Error("CountUsers on a closed store: no error")
	}
	if _, _, err := s.Credentials(ctx, "alice"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Credentials on a closed store: %v", err)
	}
	if _, err := s.Session(ctx, token, t0); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Session on a closed store: %v", err)
	}
	if _, err := s.History(ctx, HistoryQuery{}); err == nil {
		t.Error("History on a closed store: no error")
	}
	if _, err := s.DeleteExpiredSessions(ctx, t0, t0); err == nil {
		t.Error("DeleteExpiredSessions on a closed store: no error")
	}
	for name, err := range checks {
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s on a closed store: %v", name, err)
		}
	}
}

// lockedStoreFile creates the store's file in dir and returns it held
// under an exclusive lock, as another process in the middle of setting it
// up would hold it. release lets go.
func lockedStoreFile(t *testing.T, dir string) (release func()) {
	t.Helper()
	other, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, FileName)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	released := false
	release = func() {
		if !released {
			released = true
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			_ = conn.Close()
			_ = other.Close()
		}
	}
	t.Cleanup(release)
	return release
}

func TestOpenWaitsForAStoreThatIsBusy(t *testing.T) {
	dir := t.TempDir()
	release := lockedStoreFile(t, dir)
	// Let go shortly after Open has started trying.
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()

	start := time.Now()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open did not wait out the other holder: %v (after %v)", err, time.Since(start))
	}
	defer s.Close()
	if _, err := s.AddUser(context.Background(), "alice", "hash", RoleViewer, t0); err != nil {
		t.Errorf("the store is not usable after the wait: %v", err)
	}
}

func TestOpenGivesUpOnAStoreThatStaysBusy(t *testing.T) {
	savedRetry, savedBusy := openRetryFor, busyTimeout
	t.Cleanup(func() { openRetryFor, busyTimeout = savedRetry, savedBusy })
	openRetryFor, busyTimeout = 300*time.Millisecond, 50*time.Millisecond
	dir := t.TempDir()
	lockedStoreFile(t, dir)

	// After openRetryFor, with SQLite's own word for it.
	start := time.Now()
	_, err := Open(context.Background(), dir)
	if err == nil || !isBusy(err) || !strings.Contains(err.Error(), FileName) {
		t.Fatalf("err = %v, want a busy error naming the file", err)
	}
	if took := time.Since(start); took < openRetryFor || took > 5*time.Second {
		t.Errorf("gave up after %v, want a little over %v", took, openRetryFor)
	}

	// Sooner, if the caller's own deadline comes first.
	openRetryFor = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	if _, err := Open(ctx, dir); err == nil {
		t.Fatal("opened a store another connection holds exclusively")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Open took %v to give up on a 200ms deadline", took)
	}
}

func TestIsBusy(t *testing.T) {
	if isBusy(nil) || isBusy(errors.New("database is locked")) || isBusy(context.DeadlineExceeded) {
		t.Error("an error that is not SQLite's is called busy")
	}
}

func TestChangePassword(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, _ := s.AddUser(ctx, "alice", "old-hash", RoleOperator, t0)
	bob, _ := s.AddUser(ctx, "bob", "old-hash", RoleViewer, t0)
	a, b := HashToken([]byte("a")), HashToken([]byte("b"))
	if err := s.CreateSession(ctx, alice.ID, "old-hash", a, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, bob.ID, "old-hash", b, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(time.Minute)

	// Not with a hash the account does not have, nor for nobody, nor to
	// nothing.
	if err := s.ChangePassword(ctx, alice.ID, "some-other-hash", "new-hash", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("with the wrong old hash: %v, want ErrNotFound", err)
	}
	if err := s.ChangePassword(ctx, 9999, "old-hash", "new-hash", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("for an account that does not exist: %v, want ErrNotFound", err)
	}
	if err := s.ChangePassword(ctx, alice.ID, "old-hash", "", later); err == nil {
		t.Error("accepted an empty hash")
	}
	if _, hash, _ := s.Credentials(ctx, "alice"); hash != "old-hash" {
		t.Fatalf("a refused change altered the hash to %q", hash)
	}
	if _, err := s.Session(ctx, a, t0); err != nil {
		t.Fatalf("a refused change ended alice's session: %v", err)
	}

	if err := s.ChangePassword(ctx, alice.ID, "old-hash", "new-hash", later); err != nil {
		t.Fatal(err)
	}
	u, hash, _ := s.Credentials(ctx, "alice")
	if hash != "new-hash" || !u.PasswordChangedAt.Equal(later) {
		t.Errorf("after the change: %q, %v", hash, u.PasswordChangedAt)
	}
	if _, err := s.Session(ctx, a, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("alice's session survived her password change: %v", err)
	}
	// Nobody else is touched, same old hash or not.
	if _, hash, _ := s.Credentials(ctx, "bob"); hash != "old-hash" {
		t.Errorf("bob's hash is now %q", hash)
	}
	if _, err := s.Session(ctx, b, t0); err != nil {
		t.Errorf("bob's session ended with alice's change: %v", err)
	}
	// The same request again finds the old hash gone.
	if err := s.ChangePassword(ctx, alice.ID, "old-hash", "third-hash", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("a repeated change: %v, want ErrNotFound", err)
	}
}
