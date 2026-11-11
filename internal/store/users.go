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
	"regexp"
	"strings"
	"time"
)

// Role is what an account may do.
type Role string

const (
	// RoleViewer reads.
	RoleViewer Role = "viewer"
	// RoleOperator also issues, revokes and edits notes.
	RoleOperator Role = "operator"
)

// ParseRole reads a role name.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer, RoleOperator:
		return Role(s), nil
	}
	return "", fmt.Errorf("unknown role %q: want viewer or operator", s)
}

// User is an account, without its password hash.
type User struct {
	ID                int64
	Username          string
	Role              Role
	CreatedAt         time.Time
	PasswordChangedAt time.Time
}

var (
	// ErrNotFound is returned when the user or session asked for does not
	// exist (or, for a session, has expired).
	ErrNotFound = errors.New("not found")
	// ErrUserExists is returned by AddUser for a name already taken.
	ErrUserExists = errors.New("a user with that name already exists")
)

var usernameForm = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// NormalizeUsername lower-cases a user name and checks its form: up to 64
// letters, digits, dots, dashes and underscores, starting with a letter or
// digit. Names are compared in this form everywhere.
func NormalizeUsername(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !usernameForm.MatchString(name) {
		return "", errors.New("user name: want 1 to 64 of a-z, 0-9, dot, dash and underscore, starting with a letter or digit")
	}
	return name, nil
}

// AddUser creates an account. passwordHash comes from the password package.
func (s *Store) AddUser(ctx context.Context, username, passwordHash string, role Role, now time.Time) (User, error) {
	username, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	if _, err := ParseRole(string(role)); err != nil {
		return User{}, err
	}
	if passwordHash == "" {
		return User{}, errors.New("no password hash")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, created_at, password_changed_at)
		 VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT (username) DO NOTHING`,
		username, passwordHash, string(role), now.Unix())
	if err != nil {
		return User{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return User{}, ErrUserExists
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	at := unix(now.Unix())
	return User{ID: id, Username: username, Role: role, CreatedAt: at, PasswordChangedAt: at}, nil
}

// SetPassword replaces an account's password hash and signs the account out
// everywhere: a password is changed because the old one is no longer
// trusted, and neither are sessions opened with it.
func (s *Store) SetPassword(ctx context.Context, username, passwordHash string, now time.Time) error {
	if passwordHash == "" {
		return errors.New("no password hash")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no effect after Commit

	var id int64
	err = tx.QueryRowContext(ctx,
		`UPDATE users SET password_hash = ?, password_changed_at = ? WHERE username = ? RETURNING id`,
		passwordHash, now.Unix(), strings.ToLower(username)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ChangePassword replaces the password hash of the account that currently
// has oldHash, and signs it out everywhere, in one transaction. It is for a
// user changing their own password: oldHash is the hash their current
// password was just checked against, so a change made elsewhere in the
// meantime (`user passwd`, or the same form in another window) is not
// overwritten. ErrNotFound if the account is gone or no longer has oldHash.
func (s *Store) ChangePassword(ctx context.Context, userID int64, oldHash, newHash string, now time.Time) error {
	if newHash == "" {
		return errors.New("no password hash")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no effect after Commit

	res, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ? AND password_hash = ?`,
		newHash, now.Unix(), userID, oldHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveUser deletes an account and its sessions. Its history stays.
func (s *Store) RemoveUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, strings.ToLower(username))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Users lists the accounts by name.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, role, created_at, password_changed_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var (
			u                User
			role             string
			created, changed int64
		)
		if err := rows.Scan(&u.ID, &u.Username, &role, &created, &changed); err != nil {
			return nil, err
		}
		u.Role, u.CreatedAt, u.PasswordChangedAt = Role(role), unix(created), unix(changed)
		users = append(users, u)
	}
	return users, rows.Err()
}

// CountUsers is the number of accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Credentials returns an account and its password hash, for sign-in.
// ErrNotFound if there is no such account.
func (s *Store) Credentials(ctx context.Context, username string) (User, string, error) {
	var (
		u                User
		role, hash       string
		created, changed int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, password_changed_at, password_hash FROM users WHERE username = ?`,
		strings.ToLower(strings.TrimSpace(username))).Scan(&u.ID, &u.Username, &role, &created, &changed, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err != nil {
		return User{}, "", err
	}
	u.Role, u.CreatedAt, u.PasswordChangedAt = Role(role), unix(created), unix(changed)
	return u, hash, nil
}
