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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

const userUsage = `Manage handrail-ca's accounts. Flags come before the user name.

  handrail-ca user add    [-data DIR] [-role viewer|operator] [-password-file FILE] NAME
  handrail-ca user passwd [-data DIR] [-password-file FILE] NAME
  handrail-ca user remove [-data DIR] NAME
  handrail-ca user list   [-data DIR]

-data            the data directory (or set HANDRAIL_DATA)
-role            viewer (reads) or operator (also issues and revokes); default viewer
-password-file   read the password from FILE, or from standard input if FILE is "-".
                 Without it a password is generated and printed once.
`

// userCommand runs `handrail-ca user ...` and returns the exit code. The
// accounts live in the store, so this needs the data directory and nothing
// else: no CA, no network.
func userCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stderr, userUsage)
		return 2
	}
	verb := args[0]
	if verb != "add" && verb != "passwd" && verb != "remove" && verb != "list" {
		fmt.Fprintf(stderr, "handrail-ca user: unknown command %q\n\n%s", verb, userUsage)
		return 2
	}

	fs := flag.NewFlagSet("handrail-ca user "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, userUsage) }
	dataDir := fs.String("data", os.Getenv("HANDRAIL_DATA"), "")
	role := fs.String("role", string(store.RoleViewer), "")
	passwordFile := fs.String("password-file", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	wantName := verb != "list"
	if (wantName && fs.NArg() != 1) || (!wantName && fs.NArg() != 0) {
		fmt.Fprintf(stderr, "handrail-ca user %s: wrong number of arguments (flags come before the user name)\n\n%s", verb, userUsage)
		return 2
	}
	if *dataDir == "" {
		fmt.Fprintln(stderr, "handrail-ca user: no data directory: give -data or set HANDRAIL_DATA")
		return 2
	}

	st, err := store.Open(ctx, *dataDir)
	if err != nil {
		fmt.Fprintln(stderr, "handrail-ca user:", err)
		return 1
	}
	defer st.Close()

	u := userAdmin{store: st, stdin: stdin, stdout: stdout, stderr: stderr, now: time.Now()}
	switch verb {
	case "add":
		err = u.add(ctx, fs.Arg(0), *role, *passwordFile)
	case "passwd":
		err = u.passwd(ctx, fs.Arg(0), *passwordFile)
	case "remove":
		err = u.remove(ctx, fs.Arg(0))
	case "list":
		err = u.list(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "handrail-ca user %s: %v\n", verb, err)
		return 1
	}
	return 0
}

type userAdmin struct {
	store          *store.Store
	stdin          io.Reader
	stdout, stderr io.Writer
	now            time.Time
}

func (u userAdmin) add(ctx context.Context, name, roleName, passwordFile string) error {
	role, err := store.ParseRole(roleName)
	if err != nil {
		return err
	}
	// Checked before the password is hashed or shown, so a mistyped name
	// costs nothing.
	name, err = store.NormalizeUsername(name)
	if err != nil {
		return err
	}
	pw, generated, err := u.password(passwordFile)
	if err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	if _, err := u.store.AddUser(ctx, name, hash, role, u.now); err != nil {
		return err
	}
	u.record(ctx, store.ActionUserAdd, fmt.Sprintf("%s (%s)", name, role))
	fmt.Fprintf(u.stdout, "Added %s %s.\n", role, name)
	u.show(pw, generated)
	return nil
}

func (u userAdmin) passwd(ctx context.Context, name, passwordFile string) error {
	name, err := store.NormalizeUsername(name)
	if err != nil {
		return err
	}
	if _, _, err := u.store.Credentials(ctx, name); err != nil {
		return notFound(err, name)
	}
	pw, generated, err := u.password(passwordFile)
	if err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	if err := u.store.SetPassword(ctx, name, hash, u.now); err != nil {
		return notFound(err, name)
	}
	u.record(ctx, store.ActionUserPasswd, name)
	fmt.Fprintf(u.stdout, "Changed the password of %s and signed them out everywhere.\n", name)
	u.show(pw, generated)
	return nil
}

func (u userAdmin) remove(ctx context.Context, name string) error {
	name, err := store.NormalizeUsername(name)
	if err != nil {
		return err
	}
	if err := u.store.RemoveUser(ctx, name); err != nil {
		return notFound(err, name)
	}
	u.record(ctx, store.ActionUserRemove, name)
	fmt.Fprintf(u.stdout, "Removed %s. Their history is kept.\n", name)
	return nil
}

func (u userAdmin) list(ctx context.Context) error {
	users, err := u.store.Users(ctx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Fprintln(u.stdout, "No accounts. Add one with: handrail-ca user add -role operator NAME")
		return nil
	}
	w := tabwriter.NewWriter(u.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tROLE\tADDED\tPASSWORD SET")
	const day = "2006-01-02"
	for _, user := range users {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", user.Username, user.Role, user.CreatedAt.Format(day), user.PasswordChangedAt.Format(day))
	}
	return w.Flush()
}

// password returns the password to set: the content of passwordFile (one
// trailing line break dropped), or a generated one when no file is named.
func (u userAdmin) password(passwordFile string) (pw string, generated bool, err error) {
	if passwordFile == "" {
		pw, err = password.Generate()
		return pw, true, err
	}
	var data []byte
	// One byte more than the longest password, to tell "too long" from
	// "exactly the limit" without reading an unbounded file.
	const limit = password.MaxLength + 3
	if passwordFile == "-" {
		data, err = io.ReadAll(io.LimitReader(u.stdin, limit))
	} else {
		var f *os.File
		if f, err = os.Open(passwordFile); err == nil {
			data, err = io.ReadAll(io.LimitReader(f, limit))
			_ = f.Close()
		}
	}
	if err != nil {
		return "", false, fmt.Errorf("reading the password: %w", err)
	}
	pw = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if err := password.Check(pw); err != nil {
		return "", false, err
	}
	return pw, false, nil
}

// show prints a generated password, the only time it is ever shown.
func (u userAdmin) show(pw string, generated bool) {
	if generated {
		fmt.Fprintf(u.stdout, "Password (shown once, not stored): %s\n", pw)
	}
}

// record writes the change to the history. Per the plan's audit rule a
// history that cannot be written does not undo or block the change: it is
// reported, loudly, and the command still succeeds.
func (u userAdmin) record(ctx context.Context, action, detail string) {
	err := u.store.AppendHistory(ctx, store.Event{
		At: u.now, Actor: store.ActorCommandLine, Action: action, Outcome: store.OutcomeOK, Detail: detail,
	})
	if err != nil {
		fmt.Fprintf(u.stderr, "WARNING: the change was made, but could not be written to the history: %v\n", err)
	}
}

func notFound(err error, name string) error {
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user named %q", name)
	}
	return err
}
