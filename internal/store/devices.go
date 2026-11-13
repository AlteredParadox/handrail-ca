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
	"time"
)

// A device is a browser that has signed in to an account before. It is
// remembered so that the sign-in throttle can tell the account's own
// browsers from strangers guessing at its name: a known device has an
// allowance of attempts to itself, which nobody else can use up. Being a
// known device proves nothing and opens nothing: the password is still
// what signs in.

const (
	// DeviceLifetime is how long a device is remembered without being used
	// to sign in.
	DeviceLifetime = 90 * 24 * time.Hour
	// MaxDevices is how many devices an account keeps. Each has its own
	// allowance of sign-in attempts, so this also bounds how many guesses
	// stolen device cookies could add.
	MaxDevices = 10
)

// RememberDevice records a new device for the account whose password was
// just checked against passwordHash, and forgets the account's least
// recently used devices beyond MaxDevices. Like CreateSession it does
// nothing unless the account still has that hash: ErrNotFound then.
func (s *Store) RememberDevice(ctx context.Context, userID int64, passwordHash string, token TokenHash, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no effect after Commit

	res, err := tx.ExecContext(ctx,
		`INSERT INTO devices (token_hash, user_id, created_at, last_used_at)
		 SELECT ?1, id, ?2, ?2 FROM users WHERE id = ?3 AND password_hash = ?4`,
		token[:], now.Unix(), userID, passwordHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM devices WHERE user_id = ?1 AND token_hash NOT IN (
		   SELECT token_hash FROM devices WHERE user_id = ?1
		    ORDER BY last_used_at DESC, created_at DESC, token_hash LIMIT ?2)`,
		userID, MaxDevices); err != nil {
		return err
	}
	return tx.Commit()
}

// DeviceUser returns the name of the account a device has signed in to.
// ErrNotFound if the device is not known, or was last used more than
// DeviceLifetime before now.
func (s *Store) DeviceUser(ctx context.Context, token TokenHash, now time.Time) (string, error) {
	var username string
	err := s.read.QueryRowContext(ctx,
		`SELECT u.username FROM devices d JOIN users u ON u.id = d.user_id
		  WHERE d.token_hash = ? AND d.last_used_at > ?`,
		token[:], now.Add(-DeviceLifetime).Unix()).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return username, err
}

// TouchDevice records that a device signed in at now.
func (s *Store) TouchDevice(ctx context.Context, token TokenHash, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_used_at = ? WHERE token_hash = ?`, now.Unix(), token[:])
	return err
}

// DeleteUnusedDevices forgets the devices last used at or before
// unusedSince, and reports how many.
func (s *Store) DeleteUnusedDevices(ctx context.Context, unusedSince time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE last_used_at <= ?`, unusedSince.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
