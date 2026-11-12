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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/store"
)

// revokeForm is a filled-in revocation form for the certificate whose
// subject is confirm.
func revokeFormValues(token, reason, note, confirm string) url.Values {
	return url.Values{"form_token": {token}, "reason": {reason}, "note": {note}, "confirm": {confirm}}
}

// revokeEvents are the history's revocation rows, oldest first.
func (s *site) revokeEvents() []store.Event {
	s.t.Helper()
	var events []store.Event
	for _, e := range s.history() {
		if e.Action == store.ActionRevoke {
			events = append([]store.Event{e}, events...)
		}
	}
	return events
}

func TestRevoke(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	// The certificate's page offers it to an operator.
	wantBody(t, b.get("/certificates/101"), `<a class="button danger" href="/certificates/101/revoke">Revoke…</a>`)

	form := b.get("/certificates/101/revoke")
	wantStatus(t, form, http.StatusOK)
	wantBody(t, form,
		"Revoke this certificate?", `<a href="/certificates/101">web1.internal.example</a>`,
		`<dd class="strong">web1.internal.example</dd>`, "2027-02-09, in 3 months", "handrail <span",
		// What it means here: the test CA publishes no revocation list.
		"refuses to renew it", "It cannot be undone",
		"This CA does not publish a revocation list.", "will keep accepting it until it expires on 2027-02-09",
		`<form method="post" action="/certificates/101/revoke" class="card revoke">`,
		`<option value="0" selected>Unspecified</option>`, `<option value="1">Key compromise</option>`, `<option value="4">Superseded</option>`,
		`<option value="3">Affiliation changed</option>`, `<option value="5">Cessation of operation</option>`, `<option value="9">Privilege withdrawn</option>`,
		`Type the certificate&#39;s subject to confirm: <span class="mono ink">web1.internal.example</span>`,
		`<a class="cancel" href="/certificates/101">Cancel</a>`,
	)
	for _, absent := range []string{"CA compromise", "Certificate hold", "Remove from CRL", "AA compromise", "Nothing was sent", "was not revoked"} {
		if strings.Contains(form.Body.String(), absent) {
			t.Errorf("the form says %q", absent)
		}
	}
	if len(s.ca.sent()) != 0 || len(s.revokeEvents()) != 0 {
		t.Fatal("looking at the form did something")
	}

	// Sent, with the subject typed as a person might.
	s.clock.advance(time.Minute)
	rec := b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(tokenIn(t, form), "1", "  laptop <stolen>  ", " WEB1.internal.example "))
	wantRedirect(t, rec, "/certificates/101?revoked=now#revocation")
	sent := s.ca.sent()
	if len(sent) != 1 || sent[0] != (ca.Revocation{Serial: "101", ReasonCode: 1, Reason: "laptop <stolen>"}) {
		t.Fatalf("the CA was asked for %+v", sent)
	}

	// Its page shows the record the CA made, without waiting for the next
	// timed read of the database.
	page := b.get("/certificates/101?revoked=now")
	wantBody(t, page, `<span class="badge bad">Revoked</span>`, "Revoked. The CA confirmed it, and this is its record.",
		"2026-11-11 12:01 UTC", "Key compromise", "laptop &lt;stolen&gt;")
	for _, absent := range []string{"Revoke…", "/certificates/101/revoke", "already revoked when"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("a revoked certificate's page has %q", absent)
		}
	}
	// The plain page does not claim anything about a request.
	if strings.Contains(b.get("/certificates/101").Body.String(), "The CA confirmed it") {
		t.Error("a page not reached from a revocation says the CA confirmed one")
	}
	// Nor does a link made up for a certificate that is not revoked.
	if body := b.get("/certificates/102?revoked=now").Body.String(); strings.Contains(body, "The CA confirmed it") || strings.Contains(body, "already revoked when") {
		t.Error("a made-up address makes the page of a certificate that is not revoked speak of a revocation")
	}

	// The history has the attempt, written first, and the outcome.
	events := s.revokeEvents()
	if len(events) != 2 {
		t.Fatalf("history: %+v", events)
	}
	for i, want := range []store.Event{
		{Outcome: store.OutcomeAttempt, Detail: "reason: Key compromise; note: laptop <stolen>"},
		{Outcome: store.OutcomeOK, Detail: "reason: Key compromise; note: laptop <stolen>; confirmed by the CA and recorded in its database"},
	} {
		got := events[i]
		if got.Actor != "alice" || got.Serial != "101" || got.Subject != "web1.internal.example" || got.Outcome != want.Outcome || got.Detail != want.Detail || got.Remote != "10.20.0.5" {
			t.Errorf("history row %d: %+v", i, got)
		}
	}

	// Asked for again, there is nothing to ask: its page says it is revoked.
	wantRedirect(t, b.get("/certificates/101/revoke"), "/certificates/101")
	wantRedirect(t, b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(tokenIn(t, page), "1", "", "web1.internal.example")), "/certificates/101")
	if len(s.ca.sent()) != 1 || len(s.revokeEvents()) != 2 {
		t.Error("a certificate already revoked was sent to the CA again")
	}
}

// Nothing is sent, and nothing is recorded as attempted, unless an operator
// confirmed a well-formed request.
func TestRevokeRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/certificates/101/revoke"))
	long := strings.Repeat("é", maxRevokeNote+1)

	for name, tt := range map[string]struct {
		form url.Values
		want string
	}{
		"nothing typed to confirm":     {revokeFormValues(token, "1", "", ""), "Nothing was sent: what was typed to confirm is not web1.internal.example."},
		"another certificate's name":   {revokeFormValues(token, "1", "", "old.internal.example"), "what was typed to confirm is not web1.internal.example"},
		"part of the name":             {revokeFormValues(token, "1", "", "web1"), "what was typed to confirm is not"},
		"no reason":                    {revokeFormValues(token, "", "", "web1.internal.example"), "Nothing was sent: choose a reason from the list."},
		"a reason that is not offered": {revokeFormValues(token, "2", "", "web1.internal.example"), "choose a reason from the list"},
		"a reason that is no number":   {revokeFormValues(token, "key compromise", "", "web1.internal.example"), "choose a reason from the list"},
		"a note that is too long":      {revokeFormValues(token, "1", long, "web1.internal.example"), "the note is longer than 200 characters"},
		"a note of two lines":          {revokeFormValues(token, "1", "one\ntwo", "web1.internal.example"), "the note must be one line of plain text"},
		"a note that is not text":      {revokeFormValues(token, "1", "a\xffb", "web1.internal.example"), "the note is not valid text"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := b.do(http.MethodPost, "/certificates/101/revoke", tt.form)
			wantStatus(t, rec, http.StatusUnprocessableEntity)
			wantBody(t, rec, tt.want, "Revoke this certificate?", `action="/certificates/101/revoke"`)
			// What was typed to confirm is never put back.
			if strings.Contains(rec.Body.String(), `name="confirm" type="text" value`) {
				t.Error("the confirmation was filled in")
			}
		})
	}
	// The reason and the note come back as they were left.
	rec := b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(token, "4", `replaced by "web2"`, "nope"))
	wantBody(t, rec, `<option value="4" selected>Superseded</option>`, `value="replaced by &#34;web2&#34;"`)

	// Without the session's form token, or from another origin, it is not
	// looked at.
	wantStatus(t, b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues("", "1", "", "web1.internal.example")), http.StatusForbidden)
	other := s.browser()
	other.cookies = b.cookies
	other.origin = "https://evil.example"
	wantStatus(t, other.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(token, "1", "", "web1.internal.example")), http.StatusForbidden)

	// A viewer cannot revoke, and is not offered it.
	viewer := s.browser()
	wantRedirect(t, viewer.signIn("bob", bobPassword), "/")
	if body := viewer.get("/certificates/101").Body.String(); strings.Contains(body, "Revoke…") || strings.Contains(body, "/revoke") {
		t.Error("a viewer's page offers revoking")
	}
	rec = viewer.get("/certificates/101/revoke")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "Only operators can revoke a certificate.")
	viewerToken := tokenIn(t, viewer.get("/certificates/101"))
	rec = viewer.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(viewerToken, "1", "", "web1.internal.example"))
	wantStatus(t, rec, http.StatusForbidden)

	// Nobody who is not signed in gets as far as being refused.
	wantRedirect(t, s.browser().get("/certificates/101/revoke"), "/sign-in")

	// Only a certificate in the inventory: not a serial nobody issued, and
	// not a row that is no certificate.
	wantStatus(t, b.get("/certificates/999/revoke"), http.StatusNotFound)
	wantStatus(t, b.do(http.MethodPost, "/certificates/999/revoke", revokeFormValues(token, "1", "", "999")), http.StatusNotFound)
	rec = b.get("/certificates/104/revoke")
	wantStatus(t, rec, http.StatusNotFound)
	wantBody(t, rec, "is not a certificate, so there is nothing here to revoke")
	wantStatus(t, b.do(http.MethodPost, "/certificates/104/revoke", revokeFormValues(token, "1", "", "104")), http.StatusNotFound)

	if sent := s.ca.sent(); len(sent) != 0 {
		t.Errorf("the CA was asked for %+v", sent)
	}
	if events := s.revokeEvents(); len(events) != 0 {
		t.Errorf("history has revocations nobody made: %+v", events)
	}
	if rev := s.inv.Snapshot().Revocation("101"); rev != nil {
		t.Error("the certificate is revoked")
	}
}

// A read-only handrail-ca refuses outright, for operators too, and its
// pages say so in place of offering.
func TestRevokeReadOnly(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.ca.readOnly = true
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	page := b.get("/certificates/101")
	wantBody(t, page, "handrail-ca was started read-only, so it cannot revoke this certificate.")
	if strings.Contains(page.Body.String(), "/certificates/101/revoke") {
		t.Error("a read-only handrail-ca offers revoking")
	}
	rec := b.get("/certificates/101/revoke")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "handrail-ca was started read-only, so nothing can be revoked from here.")
	rec = b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(tokenIn(t, page), "1", "", "web1.internal.example"))
	wantStatus(t, rec, http.StatusForbidden)
	if len(s.ca.sent()) != 0 || len(s.revokeEvents()) != 0 {
		t.Error("a read-only handrail-ca sent or recorded a revocation")
	}
	// A viewer is told the same, not that operators could.
	viewer := s.browser()
	wantRedirect(t, viewer.signIn("bob", bobPassword), "/")
	wantBody(t, viewer.get("/certificates/101/revoke"), "started read-only")
}

// What the page and the history say after a revocation was sent comes from
// the CA's answer and its database together.
func TestRevokeOutcomes(t *testing.T) {
	refused := &ca.StatusError{Status: 401, Message: "The request lacked necessary authorization to be completed.", ClockDifference: 5 * time.Minute}
	already := &ca.StatusError{Status: 400, Message: "certificate with serial number '101' is already revoked"}
	lost := errors.New(`Post "https://ca.internal.example:9000/1.0/revoke": context deadline exceeded`)
	down := errors.New("connection refused")

	tests := []struct {
		name string
		// ca is what the CA does: what it records, and what it answers.
		ca func(s *site, r ca.Revocation) error
		// dbDown makes the database unreadable once the request has been
		// sent.
		dbDown bool

		status   int
		redirect string
		page     []string
		absent   []string
		outcome  string
		detail   string
	}{
		{
			name:   "refused, and nothing recorded",
			ca:     func(*site, ca.Revocation) error { return refused },
			status: http.StatusBadGateway,
			page: []string{"The certificate was not revoked", "The CA did not confirm the request: the CA answered 401: The request lacked necessary authorization",
				"holds no revocation for this certificate. Nothing was changed.",
				"The CA&#39;s clock is 5 minutes ahead of this machine&#39;s.", "within a minute of its own time",
				// The form is there to send again, with the note kept.
				`action="/certificates/101/revoke"`, `value="rotated"`, `<option value="4" selected>`},
			absent:  []string{"It is not known", "The CA confirmed"},
			outcome: store.OutcomeFailed,
			detail:  "not revoked: the CA answered 401: The request lacked necessary authorization to be completed.; the CA's database held no revocation for it when read afterwards",
		},
		{
			name:     "the answer was lost, and the record is there",
			ca:       func(s *site, r ca.Revocation) error { s.caRecords(r); return lost },
			redirect: "/certificates/101?revoked=now#revocation",
			outcome:  store.OutcomeOK,
			detail:   "the CA's answer was not a confirmation (" + lost.Error() + "), but its database holds this revocation",
		},
		{
			name: "revoked by someone else in the meantime",
			ca: func(s *site, _ ca.Revocation) error {
				s.caRecords(ca.Revocation{Serial: "101", ReasonCode: 1, Reason: "by another operator"})
				return already
			},
			redirect: "/certificates/101?revoked=before#revocation",
			outcome:  store.OutcomeFailed,
			detail:   "revoked already by another request; the CA's database holds a revocation that is not this one (the CA answered 400: certificate with serial number '101' is already revoked)",
		},
		{
			name:   "not confirmed, and the database cannot be read",
			ca:     func(*site, ca.Revocation) error { return lost },
			dbDown: true,
			status: http.StatusBadGateway,
			page: []string{"It is not known whether the certificate was revoked", "the CA did not confirm it: Post &#34;https://ca.internal.example:9000/1.0/revoke&#34;: context deadline exceeded",
				"could not be read to see whether the revocation was recorded all the same: listing certificates: connection refused",
				"Sending it again is safe", `action="/certificates/101/revoke"`},
			absent:  []string{"The certificate was not revoked", "Nothing was changed", "clock"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the CA's database could not be read to check: listing certificates: connection refused",
		},
		{
			name:   "confirmed, and the database cannot be read",
			ca:     func(s *site, r ca.Revocation) error { s.caRecords(r); return nil },
			dbDown: true,
			status: http.StatusOK,
			page: []string{"The CA confirmed the revocation", "Its database could not be read afterwards to see the record: listing certificates: connection refused",
				"Nothing needs to be sent again", `<a href="/certificates/101">certificate's page</a>`},
			absent:  []string{`action="/certificates/101/revoke"`, "Revoke this certificate?", "not revoked"},
			outcome: store.OutcomeOK,
			detail:  "confirmed by the CA; its database could not be read afterwards: listing certificates: connection refused",
		},
		{
			name:    "confirmed, and the database does not show it",
			ca:      func(*site, ca.Revocation) error { return nil },
			status:  http.StatusOK,
			page:    []string{"The CA confirmed the revocation", "Its database did not show the record when it was read just afterwards."},
			absent:  []string{`action="/certificates/101/revoke"`, "could not be read"},
			outcome: store.OutcomeOK,
			detail:  "confirmed by the CA; its database did not show the record when read afterwards",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			token := tokenIn(t, b.get("/certificates/101/revoke"))
			s.ca.revoke = func(_ context.Context, r ca.Revocation) error {
				err := tt.ca(s, r)
				if tt.dbDown {
					s.rows.fail(down)
				}
				return err
			}
			rec := b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(token, "4", "rotated", "web1.internal.example"))
			if tt.redirect != "" {
				wantRedirect(t, rec, tt.redirect)
			} else {
				wantStatus(t, rec, tt.status)
				wantBody(t, rec, tt.page...)
				for _, absent := range tt.absent {
					if strings.Contains(rec.Body.String(), absent) {
						t.Errorf("the page says %q", absent)
					}
				}
			}
			// Sent once, whatever came back.
			if sent := s.ca.sent(); len(sent) != 1 {
				t.Errorf("the CA was asked %d times", len(sent))
			}
			events := s.revokeEvents()
			if len(events) != 2 || events[0].Outcome != store.OutcomeAttempt {
				t.Fatalf("history: %+v", events)
			}
			if got := events[1]; got.Outcome != tt.outcome || got.Detail != "reason: Superseded; note: rotated; "+tt.detail {
				t.Errorf("history says %q, %q\nwant %q, %q", got.Outcome, got.Detail, tt.outcome, "reason: Superseded; note: rotated; "+tt.detail)
			}
		})
	}
}

// The page of a certificate found revoked by someone else says whose
// record it is showing.
func TestRevokedBeforeTheRequest(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/certificates/103?revoked=before")
	wantBody(t, page, "This certificate was already revoked when the request reached the CA.", "nothing was changed")
	if strings.Contains(page.Body.String(), "The CA confirmed it") {
		t.Error("the page says the CA confirmed a revocation")
	}
}

func TestRevokeOutcomeTellsOursFromAnothers(t *testing.T) {
	started := t0
	failed := errors.New("no answer")
	record := func(change func(*inventory.Revocation)) *inventory.Revocation {
		rev := &inventory.Revocation{ReasonCode: 4, Reason: "rotated", RevokedAt: started.Add(2 * time.Second)}
		change(rev)
		return rev
	}
	for name, tt := range map[string]struct {
		rev  *inventory.Revocation
		want string
	}{
		"the same request":               {record(func(*inventory.Revocation) {}), store.OutcomeOK},
		"the CA's clock a minute behind": {record(func(r *inventory.Revocation) { r.RevokedAt = started.Add(-time.Minute) }), store.OutcomeOK},
		"made an hour ago":               {record(func(r *inventory.Revocation) { r.RevokedAt = started.Add(-time.Hour) }), store.OutcomeFailed},
		"no time recorded":               {record(func(r *inventory.Revocation) { r.RevokedAt = time.Time{} }), store.OutcomeFailed},
		"another reason":                 {record(func(r *inventory.Revocation) { r.ReasonCode = 1 }), store.OutcomeFailed},
		"another note":                   {record(func(r *inventory.Revocation) { r.Reason = "" }), store.OutcomeFailed},
		"made through ACME":              {record(func(r *inventory.Revocation) { r.ACME = true }), store.OutcomeFailed},
		"made over mutual TLS":           {record(func(r *inventory.Revocation) { r.MTLS = true }), store.OutcomeFailed},
		"a record that cannot be read":   {record(func(r *inventory.Revocation) { r.Problem = "not JSON" }), store.OutcomeFailed},
	} {
		got := revokeOutcome(failed, nil, tt.rev, 4, "rotated", started)
		if got.outcome != tt.want || got.failure != nil {
			t.Errorf("%s: outcome %q (%s), want %q and no failure to show", name, got.outcome, got.detail, tt.want)
		}
	}
	// With the CA's confirmation there is nothing to tell apart.
	if got := revokeOutcome(nil, nil, record(func(r *inventory.Revocation) { r.ReasonCode = 1 }), 4, "rotated", started); got.outcome != store.OutcomeOK {
		t.Errorf("confirmed by the CA: %+v", got)
	}
	if clockWords(-90*time.Second) != "The CA's clock is 1 minute behind this machine's." {
		t.Errorf("clockWords = %q", clockWords(-90*time.Second))
	}
}

// What the page says revoking will mean depends on the CA and on the
// certificate, and an unknown is never said as a yes or a no.
func TestRevokePageSaysWhatRevokingMeans(t *testing.T) {
	const noList, list, unknown, expired = "This CA does not publish a revocation list.", "This CA publishes a revocation list.",
		"Whether this CA publishes a revocation list could not be determined.", "This certificate has already expired"
	for name, tt := range map[string]struct {
		prepare func(s *site)
		serial  string
		want    string
	}{
		"no list":            {func(*site) {}, "101", noList},
		"a list":             {func(s *site) { s.ca.crl = ca.CRL{Published: true} }, "101", list},
		"the CA is down":     {func(s *site) { s.ca.crlErr = errors.New("connection refused") }, "101", unknown},
		"expired, no list":   {func(*site) {}, "102", expired},
		"expired, with list": {func(s *site) { s.ca.crl = ca.CRL{Published: true} }, "102", expired},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			tt.prepare(s)
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			page := b.get("/certificates/" + tt.serial + "/revoke")
			wantStatus(t, page, http.StatusOK)
			for _, said := range []string{noList, list, unknown, expired} {
				if strings.Contains(page.Body.String(), said) != (said == tt.want) {
					t.Errorf("the page says %q: %v, want only %q", said, strings.Contains(page.Body.String(), said), tt.want)
				}
			}
		})
	}
}

// The CA's database being down must not stand in the way: the page comes
// up from the picture handrail-ca has, says how old that is, and the
// revocation goes to the CA.
func TestRevokeWhileTheDatabaseIsDown(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.clock.advance(10 * time.Minute)
	s.rows.fail(errors.New("connection refused"))
	_ = s.inv.Refresh(context.Background())

	form := b.get("/certificates/101/revoke")
	wantStatus(t, form, http.StatusOK)
	wantBody(t, form, "The certificate list is as it was 10 minutes ago", "If this certificate has been revoked since then, the CA will say so when asked.",
		"listing certificates: connection refused", `action="/certificates/101/revoke"`)
	rec := b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(tokenIn(t, form), "1", "", "web1.internal.example"))
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "The CA confirmed the revocation")
	if sent := s.ca.sent(); len(sent) != 1 || sent[0].Serial != "101" {
		t.Errorf("the CA was asked for %+v", sent)
	}
}

// Once sent, a revocation is seen through and recorded although the
// browser has gone away.
func TestRevokeIsSeenThroughWhenTheBrowserLeaves(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/certificates/101/revoke"))

	gone, leave := context.WithCancel(context.Background())
	s.ca.revoke = func(ctx context.Context, r ca.Revocation) error {
		leave()
		if err := ctx.Err(); err != nil {
			return err
		}
		s.caRecords(r)
		return nil
	}
	b.ctx = gone
	b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(token, "1", "", "web1.internal.example"))
	if rev := s.inv.Snapshot().Revocation("101"); rev == nil {
		t.Error("the revocation was given up, or the database was not read afterwards")
	}
	if events := s.revokeEvents(); len(events) != 2 || events[1].Outcome != store.OutcomeOK {
		t.Errorf("history: %+v", events)
	}
}

// A history that cannot be written does not stop a revocation.
func TestRevokeWhenHistoryCannotBeWritten(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/certificates/101/revoke"))
	full := errors.New("disk full")
	s.store.historyErr.Store(&full)
	rec := b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(token, "1", "", "web1.internal.example"))
	wantRedirect(t, rec, "/certificates/101?revoked=now#revocation")
	if len(s.ca.sent()) != 1 {
		t.Error("the revocation was not sent")
	}
	wantBody(t, b.get("/certificates/101"), "History is not being recorded")
	// The log has what the history could not take.
	for _, want := range []string{"action=revoke outcome=attempted serial=101", "action=revoke outcome=ok serial=101"} {
		if !strings.Contains(s.log.String(), want) {
			t.Errorf("the log lacks %q", want)
		}
	}
}

// subjectRow is a certificate whose subject is exactly cn, with one DNS
// name, as the CA would store it.
func subjectRow(t *testing.T, serial *big.Int, cn string) inventory.RawCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"host.internal.example"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.RawCertificate{Serial: serial.String(), DER: der}
}

// A subject nobody can be asked to type is not what confirms: the end of
// the serial number is.
func TestRevokeConfirmsBySerialWhenTheSubjectCannotBeTyped(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	serial, _ := new(big.Int).SetString("1a2b3c4d5e6f708192a3", 16)
	next := new(big.Int).Add(serial, big.NewInt(1))
	s.addRows(
		subjectRow(t, serial, "Bücher für alle"),
		subjectRow(t, next, ""),
		subjectRow(t, big.NewInt(0x1f), strings.Repeat("a", maxConfirmWord+1)),
		subjectRow(t, big.NewInt(0x2f), " padded "),
	)
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	form := b.get("/certificates/" + serial.String() + "/revoke")
	wantStatus(t, form, http.StatusOK)
	wantBody(t, form, `Type the last characters of the serial number to confirm: <span class="mono ink">708192a3</span>`, "Bücher für alle")
	token := tokenIn(t, form)
	// The subject does not confirm it; the end of the serial does.
	wantStatus(t, b.do(http.MethodPost, "/certificates/"+serial.String()+"/revoke", revokeFormValues(token, "0", "", "Bücher für alle")), http.StatusUnprocessableEntity)
	wantRedirect(t, b.do(http.MethodPost, "/certificates/"+serial.String()+"/revoke", revokeFormValues(token, "0", "", "708192A3")),
		"/certificates/"+serial.String()+"?revoked=now#revocation")

	// No subject at all: the page still has a name for it, and the serial
	// confirms.
	form = b.get("/certificates/" + next.String() + "/revoke")
	wantBody(t, form, `<span class="mono ink">708192a4</span>`, `<span class="muted">Empty</span>`, "serial 1a2b…92a4</a>")
	// A short serial is typed whole.
	wantBody(t, b.get("/certificates/31/revoke"), `<span class="mono ink">1f</span>`)
	wantBody(t, b.get("/certificates/47/revoke"), `<span class="mono ink">2f</span>`)
}
