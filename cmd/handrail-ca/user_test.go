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

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

// user runs `handrail-ca user ...` through run, as main does.
func user(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), append([]string{"user"}, args...), strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

var shownPassword = regexp.MustCompile(`(?m)^Password \(shown once, not stored\): (\S{20})$`)

func TestUserAddGeneratesAPassword(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := user(t, "", "add", "-data", dir, "-role", "operator", "Alice")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Added operator alice.") {
		t.Errorf("output = %q", out)
	}
	m := shownPassword.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no generated password in %q", out)
	}

	st := openStore(t, dir)
	u, hash, err := st.Credentials(context.Background(), "alice")
	if err != nil || u.Role != store.RoleOperator {
		t.Fatalf("stored user = %+v, %v", u, err)
	}
	if ok, err := password.Verify(hash, m[1]); err != nil || !ok {
		t.Errorf("the printed password does not open the account (%v, %v)", ok, err)
	}
	if strings.Contains(hash, m[1]) {
		t.Error("the password itself is in the store")
	}
	events, _ := st.History(context.Background(), store.HistoryQuery{})
	if len(events) != 1 || events[0].Action != store.ActionUserAdd || events[0].Actor != store.ActorCommandLine ||
		events[0].Detail != "alice (operator)" || strings.Contains(events[0].Detail, m[1]) {
		t.Errorf("history = %+v", events)
	}
}

func TestUserAddWithAPasswordFile(t *testing.T) {
	dir := t.TempDir()
	const pw = "a chosen pass phrase"
	file := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(file, []byte(pw+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := user(t, "", "add", "-data", dir, "-password-file", file, "bob")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out, pw) || strings.Contains(out, "Password") {
		t.Errorf("a supplied password was echoed: %q", out)
	}
	st := openStore(t, dir)
	u, hash, _ := st.Credentials(context.Background(), "bob")
	if u.Role != store.RoleViewer {
		t.Errorf("default role = %q, want viewer", u.Role)
	}
	if ok, _ := password.Verify(hash, pw); !ok {
		t.Error("the password from the file does not open the account")
	}

	// From standard input.
	code, _, errOut = user(t, "typed on standard input\n", "add", "-data", dir, "-password-file", "-", "carol")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	_, hash, _ = st.Credentials(context.Background(), "carol")
	if ok, _ := password.Verify(hash, "typed on standard input"); !ok {
		t.Error("the password from standard input does not open the account")
	}
}

func TestUserAddRefusals(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := user(t, "", "add", "-data", dir, "alice"); code != 0 {
		t.Fatal(errOut)
	}
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("too short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(t.TempDir(), "long")
	if err := os.WriteFile(long, []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"taken name", []string{"add", "-data", dir, "ALICE"}, 1, "already exists"},
		{"bad name", []string{"add", "-data", dir, "al ice"}, 1, "user name"},
		{"bad role", []string{"add", "-data", dir, "-role", "admin", "dave"}, 1, "unknown role"},
		{"short password", []string{"add", "-data", dir, "-password-file", short, "dave"}, 1, "the minimum is 12"},
		{"long password", []string{"add", "-data", dir, "-password-file", long, "dave"}, 1, "longer than"},
		{"missing password file", []string{"add", "-data", dir, "-password-file", filepath.Join(dir, "none"), "dave"}, 1, "reading the password"},
		{"no name", []string{"add", "-data", dir}, 2, "wrong number of arguments"},
		{"flag after the name", []string{"add", "-data", dir, "dave", "-role", "operator"}, 2, "flags come before the user name"},
		{"unknown flag", []string{"add", "-data", dir, "-admin", "dave"}, 2, "flag provided but not defined"},
		{"no data directory", []string{"add", "dave"}, 2, "no data directory"},
		{"unknown command", []string{"promote", "dave"}, 2, `unknown command "promote"`},
		{"no command", nil, 2, "Manage handrail-ca's accounts"},
		{"list with a name", []string{"list", "-data", dir, "dave"}, 2, "wrong number of arguments"},
	}
	t.Setenv("HANDRAIL_DATA", "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := user(t, "", tt.args...)
			if code != tt.code || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q; want %d and %q", code, errOut, tt.code, tt.want)
			}
			if shownPassword.MatchString(out) {
				t.Error("a password was printed for an account that was not created")
			}
		})
	}
	if n, _ := openStore(t, dir).CountUsers(context.Background()); n != 1 {
		t.Errorf("%d accounts after the refusals, want 1", n)
	}
}

func TestUserPasswdSignsOut(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := user(t, "", "add", "-data", dir, "alice"); code != 0 {
		t.Fatal(errOut)
	}
	st := openStore(t, dir)
	ctx := context.Background()
	alice, oldHash, _ := st.Credentials(ctx, "alice")
	token := store.HashToken([]byte("cookie"))
	if err := st.CreateSession(ctx, alice.ID, oldHash, token, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := user(t, "", "passwd", "-data", dir, "alice")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	m := shownPassword.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "signed them out everywhere") {
		t.Fatalf("output = %q", out)
	}
	_, newHash, _ := st.Credentials(ctx, "alice")
	if newHash == oldHash {
		t.Error("the hash did not change")
	}
	if ok, _ := password.Verify(newHash, m[1]); !ok {
		t.Error("the new password does not open the account")
	}
	if _, err := st.Session(ctx, token, time.Now()); err == nil {
		t.Error("the session opened with the old password is still valid")
	}

	code, out, errOut = user(t, "", "passwd", "-data", dir, "nobody")
	if code != 1 || !strings.Contains(errOut, `no user named "nobody"`) || shownPassword.MatchString(out) {
		t.Errorf("passwd for an unknown user: exit %d, %q, %q", code, out, errOut)
	}
	if code, _, errOut := user(t, "", "passwd", "-data", dir, "not a name"); code != 1 || !strings.Contains(errOut, "user name") {
		t.Errorf("passwd with a malformed name: exit %d, %q", code, errOut)
	}
}

func TestUserRemoveAndList(t *testing.T) {
	dir := t.TempDir()
	// The environment variable works in place of -data.
	t.Setenv("HANDRAIL_DATA", dir)

	code, out, _ := user(t, "", "list")
	if code != 0 || !strings.Contains(out, "No accounts.") {
		t.Fatalf("list of an empty store: exit %d, %q", code, out)
	}
	for _, args := range [][]string{{"add", "-role", "operator", "alice"}, {"add", "bob"}} {
		if code, _, errOut := user(t, "", args...); code != 0 {
			t.Fatal(errOut)
		}
	}
	code, out, _ = user(t, "", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 3 || !strings.HasPrefix(lines[0], "NAME") ||
		!regexp.MustCompile(`^alice\s+operator\s+\d{4}-\d\d-\d\d\s+\d{4}-\d\d-\d\d$`).MatchString(lines[1]) ||
		!strings.HasPrefix(lines[2], "bob") {
		t.Fatalf("list = %q", out)
	}
	if strings.Contains(out, "argon2") {
		t.Error("list shows password hashes")
	}

	code, out, errOut := user(t, "", "remove", "Bob")
	if code != 0 || !strings.Contains(out, "Removed bob.") {
		t.Fatalf("remove: exit %d, %q, %q", code, out, errOut)
	}
	if code, _, errOut := user(t, "", "remove", "bob"); code != 1 || !strings.Contains(errOut, `no user named "bob"`) {
		t.Errorf("removing twice: exit %d, %q", code, errOut)
	}
	if code, _, errOut := user(t, "", "remove", "b/ob"); code != 1 || !strings.Contains(errOut, "user name") {
		t.Errorf("removing a malformed name: exit %d, %q", code, errOut)
	}

	events, _ := openStore(t, dir).History(context.Background(), store.HistoryQuery{})
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	if got := strings.Join(actions, ","); got != "user-remove,user-add,user-add" {
		t.Errorf("history actions = %s", got)
	}
}

func TestUserReportsAnUnusableDataDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := user(t, "", "list", "-data", file)
	if code != 1 || !strings.Contains(errOut, "handrail-ca user:") {
		t.Errorf("exit %d, %q", code, errOut)
	}
}
