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
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// TokenHash is the SHA-256 of a session token. The token itself is only
// ever in the browser's cookie and in memory for the length of a request.
type TokenHash [sha256.Size]byte

// HashToken hashes a session token for storage and lookup.
func HashToken(token []byte) TokenHash { return sha256.Sum256(token) }

// Session is a signed-in browser.
type Session struct {
	User       User
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateSession records a new session, valid until expires, for the account
// whose password was just checked against passwordHash. The session is
// created only if the account still has that hash, in the same statement:
// a password changed between the check and this call ends every session of
// the account, and must not be followed by a new one opened with the old
// password. ErrNotFound if the account is gone or its password has changed.
func (s *Store) CreateSession(ctx context.Context, userID int64, passwordHash string, token TokenHash, now, expires time.Time) error {
	if !expires.After(now) {
		return errors.New("session would expire before it starts")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)
		 SELECT ?1, id, ?2, ?2, ?3 FROM users WHERE id = ?4 AND password_hash = ?5`,
		token[:], now.Unix(), expires.Unix(), userID, passwordHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Session looks a session up by its token's hash and returns it with its
// user as the account is now, so a changed role applies at once.
// ErrNotFound if there is none or it has expired.
func (s *Store) Session(ctx context.Context, token TokenHash, now time.Time) (Session, error) {
	var (
		sess                                      Session
		role                                      string
		created, lastSeen, expires, uCreated, uPw int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT s.created_at, s.last_seen_at, s.expires_at,
		        u.id, u.username, u.role, u.created_at, u.password_changed_at
		   FROM sessions s JOIN users u ON u.id = s.user_id
		  WHERE s.token_hash = ? AND s.expires_at > ?`,
		token[:], now.Unix()).Scan(&created, &lastSeen, &expires,
		&sess.User.ID, &sess.User.Username, &role, &uCreated, &uPw)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = unix(created), unix(lastSeen), unix(expires)
	sess.User.Role, sess.User.CreatedAt, sess.User.PasswordChangedAt = Role(role), unix(uCreated), unix(uPw)
	return sess, nil
}

// TouchSession records that a session was used at now. It never moves
// the record back: a use written late (web.Site.SaveSessionUses) must not
// overwrite a later one written meanwhile, or a sweep would take the
// session for idle.
func (s *Store) TouchSession(ctx context.Context, token TokenHash, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ? AND last_seen_at < ?`,
		now.Unix(), token[:], now.Unix())
	return err
}

// DeleteSession ends a session, and reports whether there was one to end.
// Ending one that does not exist is not an error: signing out twice is
// still signed out.
func (s *Store) DeleteSession(ctx context.Context, token TokenHash) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, token[:])
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteExpiredSessions removes sessions that expired at or before now, or
// were last used at or before idleSince, and reports how many.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now, idleSince time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?`, now.Unix(), idleSince.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
