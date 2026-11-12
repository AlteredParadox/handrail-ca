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
	"time"
)

// Actions and outcomes recorded in the history. The columns are free text
// so that a newer version can add to them without a schema change.
const (
	ActionSignIn     = "sign-in"
	ActionSignOut    = "sign-out"
	ActionIssue      = "issue"
	ActionRevoke     = "revoke"
	ActionNote       = "note"
	ActionUserAdd    = "user-add"
	ActionUserPasswd = "user-passwd"
	ActionUserRemove = "user-remove"

	// OutcomeAttempt is written before an issue or revoke is sent to the
	// CA, so that an action whose result was never learned still shows.
	OutcomeAttempt = "attempted"
	OutcomeOK      = "ok"
	OutcomeFailed  = "failed"
	// OutcomeUnknown is written when an action was sent to the CA and what
	// became of it could not be learned.
	OutcomeUnknown = "unknown"
)

// ActorCommandLine is the actor recorded for the `handrail-ca user`
// subcommands, which run as whoever has a shell on the host.
const ActorCommandLine = "(command line)"

// Event is one row of the history.
type Event struct {
	ID      int64
	At      time.Time
	Actor   string // user name, or ActorCommandLine
	Action  string
	Outcome string
	Serial  string // decimal certificate serial, when the event has one
	Subject string
	Detail  string
	Remote  string // the client's address, for events that came over HTTP
}

// Field bounds: what goes in comes partly from requests and from the CA.
const (
	maxShortField = 256
	maxDetail     = 2000
)

// AppendHistory adds an event. There is no way to change or remove one.
func (s *Store) AppendHistory(ctx context.Context, e Event) error {
	if e.Actor == "" || e.Action == "" || e.Outcome == "" || e.At.IsZero() {
		return errors.New("history: an event needs a time, an actor, an action and an outcome")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO history (at, actor, action, outcome, serial, subject, detail, remote) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), clip(e.Actor, maxShortField), clip(e.Action, maxShortField), clip(e.Outcome, maxShortField),
		clip(e.Serial, maxShortField), clip(e.Subject, maxDetail), clip(e.Detail, maxDetail), clip(e.Remote, maxShortField))
	return err
}

// HistoryQuery selects events, newest first.
type HistoryQuery struct {
	// Serial limits the result to one certificate's events.
	Serial string
	// Before limits the result to events older than this ID, for paging.
	Before int64
	// Limit is the most rows returned; 0 means 100, and 1000 is the cap.
	Limit int
}

// History returns events, newest first.
func (s *Store) History(ctx context.Context, q HistoryQuery) ([]Event, error) {
	limit := q.Limit
	switch {
	case limit <= 0:
		limit = 100
	case limit > 1000:
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, outcome, serial, subject, detail, remote FROM history
		  WHERE (?1 = '' OR serial = ?1) AND (?2 <= 0 OR id < ?2)
		  ORDER BY id DESC LIMIT ?3`, q.Serial, q.Before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var (
			e  Event
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Outcome, &e.Serial, &e.Subject, &e.Detail, &e.Remote); err != nil {
			return nil, err
		}
		e.At = unix(at)
		events = append(events, e)
	}
	return events, rows.Err()
}

// clip bounds a stored string, on a character boundary.
func clip(s string, limit int) string {
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}
