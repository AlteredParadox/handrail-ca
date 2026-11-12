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

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/store"
)

const (
	// maxRevokeNote bounds the free text sent to the CA with a revocation.
	maxRevokeNote = 200
	// revokeTimeout bounds one revocation: the request to the CA and the
	// reading of its database afterwards. It is not the browser's to cut
	// short (see revoke).
	revokeTimeout = 45 * time.Second
	// maxConfirmWord is the longest subject a person is asked to type.
	maxConfirmWord = 64
	// oursWithin is how far before the request a revocation record's time
	// may lie and still be taken for that request's: the CA stamps the
	// record with its own clock.
	oursWithin = 2 * time.Minute
)

// revokeReasons are the reasons offered, in the order shown: RFC 5280's,
// less the ones that do not describe an operator revoking a certificate (a
// compromised CA, a hold, removal from a list).
var revokeReasons = []int{0, 1, 4, 3, 5, 9}

type revokeData struct {
	Serial string // decimal, the certificate's address
	Title  string

	Subject         string
	Names           string
	SerialHex       string
	Expires         string
	ExpiresDay      string
	Expired         bool
	Provisioner     string
	ProvisionerType string

	// What a revocation will mean on this CA: CRLKnown is false when the
	// CA could not be asked whether it publishes a revocation list.
	CRLKnown, CRLPublished bool

	// Stale is set when the certificate list could not be read lately:
	// the certificate may have been revoked since.
	Stale    string
	LastRead string

	Reasons []reasonOption
	Note    string
	MaxNote int
	// ConfirmWhat names what is to be typed, ConfirmWord is it.
	ConfirmWhat, ConfirmWord string

	// Problem is why the form was not accepted; nothing was sent.
	Problem string
	// Failure is what is known after a revocation that was sent did not
	// come back confirmed.
	Failure *revokeFailure
	// Unrecorded is set when the CA confirmed a revocation that its
	// database did not show afterwards; the page then says so, with no
	// form.
	Unrecorded *unrecorded
}

// unrecorded describes a confirmed revocation whose record was not seen.
type unrecorded struct {
	// Database is why the CA's database could not be read, empty if it
	// was read and did not show the record.
	Database string
}

type reasonOption struct {
	Code     int
	Label    string
	Selected bool
}

// revokeFailure describes a revocation that was sent and not confirmed.
type revokeFailure struct {
	// Unknown means the outcome could not be learned; otherwise the
	// certificate was not revoked when the CA's database was read.
	Unknown bool
	// CA is what the CA said, or why it could not be asked.
	CA string
	// Clock is set when the CA's clock and ours differ enough to explain a
	// refusal.
	Clock string
	// Database is why the CA's database could not be read to check.
	Database string
}

// mayRevoke refuses whoever may not revoke, and says why. Read-only comes
// first: it holds for everyone.
func (s *server) mayRevoke(w http.ResponseWriter, r *http.Request) bool {
	if !s.opts.CA.ProvisionerState().Configured {
		s.errorPage(w, r, http.StatusForbidden, "handrail-ca was started read-only, so nothing can be revoked from here. On the CA's host, `step ca revoke` does it.")
		return false
	}
	if currentUser(r).user.Role != store.RoleOperator {
		s.errorPage(w, r, http.StatusForbidden, "Only operators can revoke a certificate.")
		return false
	}
	return true
}

// revocable finds the certificate a revocation is asked for. It works from
// the inventory's picture alone: the page must come up while the CA's
// database is down, which is when a certificate may most need revoking.
// Only a certificate in the inventory can be revoked from here; the CA
// itself would accept any serial number.
func (s *server) revocable(w http.ResponseWriter, r *http.Request) (*inventory.Snapshot, *inventory.Certificate, bool) {
	snap := s.opts.Inventory.Snapshot()
	c := snap.Certificate(r.PathValue("serial"))
	switch {
	case c == nil:
		s.errorPage(w, r, http.StatusNotFound, "The CA's database has no certificate with that serial number, as far as handrail-ca has read it.")
		return nil, nil, false
	case c.Problem != "":
		s.errorPage(w, r, http.StatusNotFound, "That row of the CA's database is not a certificate, so there is nothing here to revoke.")
		return nil, nil, false
	}
	return snap, c, true
}

func (s *server) revokeForm(w http.ResponseWriter, r *http.Request) {
	if !s.mayRevoke(w, r) {
		return
	}
	snap, c, ok := s.revocable(w, r)
	if !ok {
		return
	}
	if snap.Revocation(c.Serial) != nil {
		// Nothing to ask: its page says when and why it was revoked.
		http.Redirect(w, r, s.certificateURL(c.Serial), http.StatusSeeOther)
		return
	}
	s.renderRevoke(w, r, http.StatusOK, s.newRevokeData(r, snap, c, 0, ""))
}

func (s *server) certificateURL(serial string) string {
	return s.base + "/certificates/" + url.PathEscape(serial)
}

func (s *server) renderRevoke(w http.ResponseWriter, r *http.Request, code int, data revokeData) {
	s.render(w, r, code, "revoke.html", "Revoke "+data.Title, data)
}

func (s *server) newRevokeData(r *http.Request, snap *inventory.Snapshot, c *inventory.Certificate, reason int, note string) revokeData {
	now := s.opts.Now()
	row := newListRow(inventory.Row{Certificate: c, Status: snap.Status(c, now)}, now)
	data := revokeData{
		Serial: c.Serial, Title: c.Subject,
		Subject: c.Subject, Names: row.Names, SerialHex: groupedBy(c.SerialHex, 4),
		Expires: expiry(c.NotAfter, now), ExpiresDay: c.NotAfter.UTC().Format("2006-01-02"), Expired: !c.NotAfter.After(now),
		Provisioner: c.Provisioner.Name, ProvisionerType: c.Provisioner.Type,
		Stale: snap.State.Problem,
		Note:  note, MaxNote: maxRevokeNote,
	}
	if data.Title == "" {
		data.Title = "serial " + shortSerial(c.SerialHex)
	}
	if !snap.State.LoadedAt.IsZero() {
		data.LastRead = span(now.Sub(snap.State.LoadedAt)) + " ago"
	}
	data.ConfirmWhat, data.ConfirmWord = confirmation(c)
	for _, code := range revokeReasons {
		data.Reasons = append(data.Reasons, reasonOption{Code: code, Label: revocationReasons[code], Selected: code == reason})
	}
	status := s.status.get(r.Context(), s.opts.CA, s.opts.Now)
	data.CRLKnown, data.CRLPublished = status.CRLProblem == "", status.CRL.Published
	return data
}

// confirmation is what an operator types to confirm a revocation, and what
// to call it: the certificate's subject, when that is something a person
// can type, else the end of its serial number.
func confirmation(c *inventory.Certificate) (what, word string) {
	if typeable(c.Subject) {
		return "the certificate's subject", c.Subject
	}
	word = c.SerialHex
	if len(word) > 8 {
		word = word[len(word)-8:]
	}
	return "the last characters of the serial number", word
}

func typeable(s string) bool {
	if s == "" || len(s) > maxConfirmWord || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// cleanRevokeNote checks the free text that goes into the CA's record: one
// line, bounded, nothing that does not print.
func cleanRevokeNote(typed string) (string, error) {
	note := strings.TrimSpace(typed)
	if !utf8.ValidString(note) {
		return "", errors.New("the note is not valid text")
	}
	if utf8.RuneCountInString(note) > maxRevokeNote {
		return "", fmt.Errorf("the note is longer than %d characters", maxRevokeNote)
	}
	for _, r := range note {
		if !unicode.IsPrint(r) {
			return "", errors.New("the note must be one line of plain text")
		}
	}
	return note, nil
}

func parseRevokeReason(typed string) (int, error) {
	code, err := strconv.Atoi(typed)
	if err == nil {
		for _, offered := range revokeReasons {
			if code == offered {
				return code, nil
			}
		}
	}
	return 0, errors.New("choose a reason from the list")
}

// revoke sends a revocation to the CA and reports what became of it.
//
// The order matters. The attempt is written to the history before anything
// is sent, so that a revocation whose answer never arrives still shows.
// The request goes out once. Then, whatever the CA said, its database is
// read again, and what the page and the history say comes from the two
// together: the CA can store a revocation and still answer with an error,
// and an answer can be lost on the way back.
func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	if !s.mayRevoke(w, r) {
		return
	}
	snap, c, ok := s.revocable(w, r)
	if !ok {
		return
	}
	if snap.Revocation(c.Serial) != nil {
		http.Redirect(w, r, s.certificateURL(c.Serial), http.StatusSeeOther)
		return
	}
	u := currentUser(r)
	typedNote := r.PostForm.Get("note")
	reason, err := parseRevokeReason(r.PostForm.Get("reason"))
	var note string
	if err == nil {
		note, err = cleanRevokeNote(typedNote)
	}
	if _, word := confirmation(c); err == nil && !strings.EqualFold(strings.TrimSpace(r.PostForm.Get("confirm")), word) {
		err = errors.New("what was typed to confirm is not " + word)
	}
	if err != nil {
		data := s.newRevokeData(r, snap, c, reason, typedNote)
		data.Problem = err.Error()
		s.renderRevoke(w, r, http.StatusUnprocessableEntity, data)
		return
	}

	asked := "reason: " + revocationReasons[reason]
	if note != "" {
		asked += "; note: " + note
	}
	event := store.Event{Actor: u.user.Username, Action: store.ActionRevoke, Serial: c.Serial, Subject: c.Subject}
	attempt := event
	attempt.Outcome, attempt.Detail = store.OutcomeAttempt, asked
	s.record(r, attempt)

	// Not the request's context: once sent, a revocation is seen through
	// and recorded whether or not the browser is still there.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), revokeTimeout)
	defer cancel()
	started := s.opts.Now()
	sendErr := s.opts.CA.Revoke(ctx, ca.Revocation{Serial: c.Serial, ReasonCode: reason, Reason: note})
	readErr := s.opts.Inventory.Refresh(ctx)
	rev := s.opts.Inventory.Snapshot().Revocation(c.Serial)

	outcome := revokeOutcome(sendErr, readErr, rev, reason, note, started)
	event.Outcome, event.Detail = outcome.outcome, asked+"; "+outcome.detail
	s.record(r, event)
	switch {
	case rev != nil:
		// It is revoked, by this request or by another: its page shows the
		// record, and says which.
		said := "before"
		if outcome.outcome == store.OutcomeOK {
			said = "now"
		}
		http.Redirect(w, r, s.certificateURL(c.Serial)+"?revoked="+said+"#revocation", http.StatusSeeOther)
	case outcome.outcome == store.OutcomeOK:
		// Confirmed, but the record was not seen. The certificate's page
		// would say "not revoked", or not come up at all, so say it here.
		data := s.newRevokeData(r, s.opts.Inventory.Snapshot(), c, reason, typedNote)
		data.Unrecorded = &unrecorded{}
		if readErr != nil {
			data.Unrecorded.Database = readErr.Error()
		}
		s.renderRevoke(w, r, http.StatusOK, data)
	default:
		data := s.newRevokeData(r, s.opts.Inventory.Snapshot(), c, reason, typedNote)
		data.Failure = outcome.failure
		s.renderRevoke(w, r, http.StatusBadGateway, data)
	}
}

// revoked is what became of a revocation, for the history and the page.
type revoked struct {
	outcome, detail string
	failure         *revokeFailure
}

// revokeOutcome works out what became of a revocation from what the CA
// answered (sendErr), whether its database could be read afterwards
// (readErr), and the revocation record found there, if any.
func revokeOutcome(sendErr, readErr error, rev *inventory.Revocation, reason int, note string, started time.Time) revoked {
	switch {
	case sendErr == nil && readErr != nil:
		return revoked{outcome: store.OutcomeOK, detail: "confirmed by the CA; its database could not be read afterwards: " + readErr.Error()}
	case sendErr == nil && rev == nil:
		return revoked{outcome: store.OutcomeOK, detail: "confirmed by the CA; its database did not show the record when read afterwards"}
	case sendErr == nil:
		return revoked{outcome: store.OutcomeOK, detail: "confirmed by the CA and recorded in its database"}
	}

	failure := &revokeFailure{CA: sendErr.Error()}
	var refused *ca.StatusError
	if errors.As(sendErr, &refused) && refused.ClockDifference != 0 {
		failure.Clock = clockWords(refused.ClockDifference)
	}
	switch {
	case readErr != nil:
		failure.Unknown, failure.Database = true, readErr.Error()
		return revoked{outcome: store.OutcomeUnknown, failure: failure,
			detail: "not confirmed: " + sendErr.Error() + "; the CA's database could not be read to check: " + readErr.Error()}
	case rev == nil:
		return revoked{outcome: store.OutcomeFailed, failure: failure,
			detail: "not revoked: " + sendErr.Error() + "; the CA's database held no revocation for it when read afterwards"}
	case ours(rev, reason, note, started):
		return revoked{outcome: store.OutcomeOK,
			detail: "the CA's answer was not a confirmation (" + sendErr.Error() + "), but its database holds this revocation"}
	}
	return revoked{outcome: store.OutcomeFailed,
		detail: "revoked already by another request; the CA's database holds a revocation that is not this one (" + sendErr.Error() + ")"}
}

// ours says whether a revocation record is the one a request asked for:
// the same reason and note, stamped no earlier than the request.
func ours(rev *inventory.Revocation, reason int, note string, started time.Time) bool {
	return rev.Problem == "" && rev.ReasonCode == reason && rev.Reason == note &&
		!rev.ACME && !rev.MTLS && !rev.RevokedAt.Before(started.Add(-oursWithin))
}

func clockWords(d time.Duration) string {
	if d > 0 {
		return "The CA's clock is " + span(d) + " ahead of this machine's."
	}
	return "The CA's clock is " + span(d) + " behind this machine's."
}
