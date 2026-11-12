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
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits on a note. They are checked, not clipped to: what a person typed
// is either saved whole or refused with the reason.
const (
	// MaxNote is the longest note, in characters. A form holding one fits
	// the size the web server allows a posted form.
	MaxNote = 1000
	// MaxLabels is how many labels a certificate can have; MaxLabel how
	// long one can be.
	MaxLabels = 12
	MaxLabel  = 32
)

// Note is what handrail-ca's users have recorded about a certificate that
// the CA does not: free text, and labels. It is kept by serial number; the
// store holds no certificates.
type Note struct {
	// Serial is the certificate's decimal serial number.
	Serial string
	Text   string
	// Labels are in alphabetical order, each one once.
	Labels []string
	// UpdatedAt and UpdatedBy say when and by whom it was last changed.
	// Zero and empty when there is no note.
	UpdatedAt time.Time
	UpdatedBy string
}

// Empty reports whether there is nothing in the note.
func (n Note) Empty() bool { return n.Text == "" && len(n.Labels) == 0 }

// ErrInvalidNote wraps every reason a note is refused; its text is fit to
// show to the person who typed the note.
var ErrInvalidNote = errors.New("invalid note")

func invalidNote(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidNote, fmt.Sprintf(format, args...))
}

// CleanNote prepares note text as typed into a form for saving: line ends
// made uniform, space at the ends removed. It refuses text that is too
// long or is not text.
func CleanNote(text string) (string, error) {
	text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"))
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return "", invalidNote("the note is not text")
	}
	if n := utf8.RuneCountInString(text); n > MaxNote {
		return "", invalidNote("the note is %d characters long; the most that can be kept is %d", n, MaxNote)
	}
	return text, nil
}

var labelForm = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)

// ParseLabels reads labels as typed: separated by commas or spaces, in any
// case. It returns them in lower case, in order, each one once. A label is
// letters, digits, and . _ : - after the first character.
func ParseLabels(typed string) ([]string, error) {
	seen := map[string]bool{}
	var labels []string
	for _, label := range strings.FieldsFunc(strings.ToLower(typed), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		if seen[label] {
			continue
		}
		if len(label) > MaxLabel {
			return nil, invalidNote("a label can be at most %d characters long", MaxLabel)
		}
		if !labelForm.MatchString(label) {
			return nil, invalidNote("a label is made of letters, digits, dots, colons, hyphens and underscores, and starts with a letter or digit; %q is not", label)
		}
		seen[label] = true
		labels = append(labels, label)
	}
	if len(labels) > MaxLabels {
		return nil, invalidNote("a certificate can have at most %d labels; this is %d", MaxLabels, len(labels))
	}
	sort.Strings(labels)
	return labels, nil
}

// Note returns what is recorded about a certificate. A certificate nobody
// has written about has an empty note, which is not an error.
func (s *Store) Note(ctx context.Context, serial string) (Note, error) {
	n := Note{Serial: serial}
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT note, updated_at, updated_by FROM cert_notes WHERE serial = ?`, serial).Scan(&n.Text, &at, &n.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return n, nil
	}
	if err != nil {
		return Note{}, err
	}
	n.UpdatedAt = unix(at)
	rows, err := s.db.QueryContext(ctx, `SELECT label FROM cert_labels WHERE serial = ? ORDER BY label`, serial)
	if err != nil {
		return Note{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			return Note{}, err
		}
		n.Labels = append(n.Labels, label)
	}
	return n, rows.Err()
}

// SetNote replaces what is recorded about a certificate: its text and all
// its labels, together or not at all. An empty note removes the record.
// The text and labels are checked again here, whatever checked them
// before: ErrInvalidNote if they would not pass CleanNote and ParseLabels.
func (s *Store) SetNote(ctx context.Context, n Note) error {
	if n.Serial == "" || len(n.Serial) > maxShortField || n.UpdatedBy == "" || n.UpdatedAt.IsZero() {
		return errors.New("note: a serial, a time and a name are needed")
	}
	text, err := CleanNote(n.Text)
	if err != nil {
		return err
	}
	labels, err := ParseLabels(strings.Join(n.Labels, " "))
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// The labels go with the row they belong to.
	if _, err := tx.ExecContext(ctx, `DELETE FROM cert_notes WHERE serial = ?`, n.Serial); err != nil {
		return err
	}
	if text != "" || len(labels) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cert_notes (serial, note, updated_at, updated_by) VALUES (?, ?, ?, ?)`,
			n.Serial, text, n.UpdatedAt.Unix(), clip(n.UpdatedBy, maxShortField)); err != nil {
			return err
		}
		for _, label := range labels {
			if _, err := tx.ExecContext(ctx, `INSERT INTO cert_labels (serial, label) VALUES (?, ?)`, n.Serial, label); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
