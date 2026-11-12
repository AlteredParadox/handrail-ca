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

// Package store is handrail-ca's own small database: accounts, sessions and
// the history of what was done through it. One SQLite file in the data
// directory. It never holds anything that can mint a certificate (no
// provisioner key or password, no one-time token, no private key), and the
// CA's database stays the only record of what was issued and revoked.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite" // registers the "sqlite" database/sql driver, pure Go
)

// FileName is the store's file inside the data directory.
const FileName = "handrail.db"

// migrations bring an empty file to the current schema, one step per
// entry. The file's schema version (SQLite's user_version) is the number of
// steps already applied. Entries are never edited once released: a change
// to the schema is a new entry.
var migrations = []string{
	// 1: accounts, sessions, history.
	`
CREATE TABLE users (
	id                  INTEGER PRIMARY KEY,
	username            TEXT    NOT NULL UNIQUE,
	password_hash       TEXT    NOT NULL,
	role                TEXT    NOT NULL CHECK (role IN ('viewer', 'operator')),
	created_at          INTEGER NOT NULL,
	password_changed_at INTEGER NOT NULL
) STRICT;

-- Only the SHA-256 of a session token is kept: reading this file does not
-- yield a usable cookie.
CREATE TABLE sessions (
	token_hash   BLOB    PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

-- The actor is kept by name, not by reference: history outlives accounts.
CREATE TABLE history (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	at      INTEGER NOT NULL,
	actor   TEXT    NOT NULL,
	action  TEXT    NOT NULL,
	outcome TEXT    NOT NULL,
	serial  TEXT    NOT NULL DEFAULT '',
	subject TEXT    NOT NULL DEFAULT '',
	detail  TEXT    NOT NULL DEFAULT '',
	remote  TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX history_serial ON history (serial) WHERE serial <> '';

-- History is only ever appended.
CREATE TRIGGER history_no_update BEFORE UPDATE ON history
BEGIN SELECT RAISE(ABORT, 'history rows are never changed'); END;
CREATE TRIGGER history_no_delete BEFORE DELETE ON history
BEGIN SELECT RAISE(ABORT, 'history rows are never deleted'); END;
`,
	// 2: notes and labels on certificates.
	`
-- What the CA does not record about a certificate. By serial number: the
-- store holds no certificates, and a serial here need not still be in the
-- CA's database.
CREATE TABLE cert_notes (
	serial     TEXT    PRIMARY KEY,
	note       TEXT    NOT NULL,
	updated_at INTEGER NOT NULL,
	updated_by TEXT    NOT NULL
) STRICT, WITHOUT ROWID;

-- A row per label, so that the certificates with a label can be found.
CREATE TABLE cert_labels (
	serial TEXT NOT NULL REFERENCES cert_notes (serial) ON DELETE CASCADE,
	label  TEXT NOT NULL,
	PRIMARY KEY (serial, label)
) STRICT, WITHOUT ROWID;
CREATE INDEX cert_labels_label ON cert_labels (label);
`,
	// 3: the browsers that have signed in to an account.
	`
-- Only the SHA-256 of a device's token is kept, as with sessions. A device
-- is not a credential: it only decides which sign-in allowance an attempt
-- is counted against.
CREATE TABLE devices (
	token_hash   BLOB    PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX devices_user ON devices (user_id);
`,
}

// Store is an open store. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens the store in dataDir, creating the directory and the file if
// they are missing (owner-only), and brings the schema up to date. A file
// written by a newer handrail-ca is refused.
func Open(ctx context.Context, dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("store: no data directory given")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	path := filepath.Join(dataDir, FileName)
	// Created here, not by SQLite, so that it never exists with wider
	// permissions; SQLite gives its journal files the same mode.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	// synchronous=FULL: a history row that was reported written survives a
	// power cut. The write volume is a handful of rows per action.
	// The path is percent-encoded: SQLite reads this as a URI, where "?",
	// "#" and "%" in a directory name would otherwise end or alter it.
	dsn := "file:" + (&url.URL{Path: filepath.ToSlash(path)}).EscapedPath() +
		fmt.Sprintf("?_pragma=busy_timeout(%d)", busyTimeout.Milliseconds()) +
		"&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_txlock=immediate"
	// Two processes opening a new store at the same moment (the server
	// starting while a `user` command runs, or two commands) collide on
	// the file's first-time set-up: switching it to WAL needs the file to
	// itself, and SQLite answers "busy" at once there instead of waiting
	// out busy_timeout. That is transient, so the whole open is tried
	// again, from a fresh connection, until it works or openRetryFor has
	// passed. Anything else is final.
	start := time.Now()
	for wait := 5 * time.Millisecond; ; wait = min(2*wait, 250*time.Millisecond) {
		s, err := openOnce(ctx, dsn)
		if err == nil {
			return s, nil
		}
		if !isBusy(err) || time.Since(start) >= openRetryFor {
			return nil, fmt.Errorf("store %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("store %s: %w", path, ctx.Err())
		case <-time.After(wait):
		}
	}
}

// busyTimeout is how long a statement waits for another connection's lock
// before SQLite reports "busy". openRetryFor is how long Open keeps
// retrying a store that is busy being set up by another process; Open can
// outlast it, and the caller's deadline, by one busyTimeout, which SQLite
// sits out without looking at the context. Variables so that the tests
// need not wait.
var (
	busyTimeout  = 5 * time.Second
	openRetryFor = 15 * time.Second
)

// openOnce connects and brings the schema up to date, once.
func openOnce(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: writes are rare and short, and a single writer never
	// waits on itself. The `user` subcommands open the same file from
	// another process; busy_timeout covers that once the file is set up.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// isBusy reports whether err is SQLite saying another connection holds the
// lock it needs (SQLITE_BUSY and its extended codes).
func isBusy(err error) bool {
	const sqliteBusy = 5 // the primary result code, in the low byte
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqliteBusy
}

// Close releases the file.
func (s *Store) Close() error { return s.db.Close() }

// Ping reports whether the store can be read.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

func (s *Store) migrate(ctx context.Context) error {
	for {
		done, err := s.migrateStep(ctx)
		if err != nil || done {
			return err
		}
	}
}

// migrateStep applies the next schema step, if there is one. The version is
// read, the step run and the version raised inside one write transaction,
// so a step is never half-applied, and two processes starting together
// cannot both apply it.
func (s *Store) migrateStep(ctx context.Context) (done bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }() // no effect after Commit

	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return false, err
	}
	switch {
	case version == len(migrations):
		return true, nil
	case version > len(migrations) || version < 0:
		return false, fmt.Errorf("schema version %d is newer than this handrail-ca understands (%d); use the newer binary", version, len(migrations))
	}
	if _, err := tx.ExecContext(ctx, migrations[version]); err != nil {
		return false, fmt.Errorf("schema step %d: %w", version+1, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
		return false, fmt.Errorf("schema step %d: %w", version+1, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("schema step %d: %w", version+1, err)
	}
	return false, nil
}

// unix turns a stored timestamp (whole seconds) back into a time. Times
// are handed out in UTC, so two that are the same instant compare equal.
func unix(seconds int64) time.Time { return time.Unix(seconds, 0).UTC() }
