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
	"regexp"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/store"
)

// append writes events straight into the site's history.
func (s *site) appendHistory(events ...store.Event) {
	s.t.Helper()
	for _, e := range events {
		if e.At.IsZero() {
			e.At = s.clock.Now()
		}
		if err := s.store.Store.AppendHistory(context.Background(), e); err != nil {
			s.t.Fatal(err)
		}
	}
}

// rowsOf is the body rows of the page's table, in order.
func rowsOf(body string) []string {
	tbody := regexp.MustCompile(`(?s)<tbody>(.*?)</tbody>`).FindStringSubmatch(body)
	if tbody == nil {
		return nil
	}
	return regexp.MustCompile(`(?s)<tr>.*?</tr>`).FindAllString(tbody[1], -1)
}

func TestHistoryPage(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.clock.advance(time.Minute)
	form := b.get("/certificates/101/revoke")
	wantRedirect(t, b.do(http.MethodPost, "/certificates/101/revoke", revokeFormValues(tokenIn(t, form), "1", "<b>stolen</b>", "web1.internal.example")),
		"/certificates/101?revoked=now#revocation")
	s.clock.advance(time.Minute)
	// What a newer version might have written, and a certificate that is
	// not in the list.
	s.appendHistory(
		store.Event{Actor: "carol", Action: "rekey", Outcome: "postponed", Serial: "555", Subject: "elsewhere.internal.example", Remote: "10.20.0.9"},
		store.Event{Actor: store.ActorCommandLine, Action: store.ActionUserAdd, Outcome: store.OutcomeOK, Detail: "dave (viewer)"},
	)

	page := b.get("/history")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `<a href="/history" aria-current="page">History</a>`, "Rows are only ever added.")
	rows := rowsOf(page.Body.String())
	if len(rows) != 5 {
		t.Fatalf("%d rows, want the sign-in, two for the revocation and the two written directly:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	// Newest first.
	for i, want := range [][]string{
		{"2026-11-11 12:02 UTC", "(command line)", "Account added", `<span class="badge ok">Done</span>`, "dave (viewer)"},
		// An action and an outcome this version has no words for are shown
		// as they were written; a certificate that is not in the list is
		// named and not linked.
		{"carol", "<td>rekey</td>", `<span class="badge unknown">postponed</span>`, `<span class="strong">elsewhere.internal.example</span>`, "10.20.0.9"},
		{"2026-11-11 12:01 UTC", "alice", "<td>Revoke</td>", `<span class="badge ok">Done</span>`,
			`<a class="strong" href="/certificates/101">web1.internal.example</a>`, `title="101"`,
			"reason: Key compromise; note: &lt;b&gt;stolen&lt;/b&gt;; confirmed by the CA and recorded in its database", "10.20.0.5"},
		{"alice", "<td>Revoke</td>", `<span class="badge unknown">Attempted</span>`, "reason: Key compromise; note: &lt;b&gt;stolen&lt;/b&gt;"},
		{"2026-11-11 12:00 UTC", "alice", "<td>Sign in</td>", `<span class="badge ok">Done</span>`, "10.20.0.5"},
	} {
		for _, w := range want {
			if !strings.Contains(rows[i], w) {
				t.Errorf("row %d lacks %q:\n%s", i, w, rows[i])
			}
		}
	}
	if strings.Contains(page.Body.String(), "<b>stolen</b>") {
		t.Error("a note is on the page unescaped")
	}
	if strings.Contains(rows[1], "<a ") {
		t.Errorf("a certificate that is not in the list is linked:\n%s", rows[1])
	}
	for _, absent := range []string{"Older", "Back to the newest", "Clear", "matches", "could not be read"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the whole history, on one page, says %q", absent)
		}
	}

	// A viewer reads it too.
	viewer := s.browser()
	wantRedirect(t, viewer.signIn("bob", bobPassword), "/")
	wantStatus(t, viewer.get("/history"), http.StatusOK)
}

func TestHistoryPageNarrowed(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.appendHistory(
		store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: "101", Subject: "web1.internal.example", Detail: "note and labels changed"},
		store.Event{Actor: "alice", Action: store.ActionRevoke, Outcome: store.OutcomeFailed, Serial: "102", Subject: "old.internal.example"},
		store.Event{Actor: "alice", Action: store.ActionRevoke, Outcome: store.OutcomeUnknown, Serial: "101", Subject: "web1.internal.example"},
		store.Event{Actor: "alice", Action: store.ActionRevoke, Outcome: store.OutcomeOK, Serial: "777", Subject: "never-listed.internal.example"},
	)

	// One kind of event.
	page := b.get("/history?action=revoke")
	rows := rowsOf(page.Body.String())
	if len(rows) != 3 || strings.Contains(page.Body.String(), "Sign in</td>") || strings.Contains(page.Body.String(), "<td>Note</td>") {
		t.Errorf("narrowed to revocations: %d rows", len(rows))
	}
	wantBody(t, page, `<option value="revoke" selected>Revocations</option>`, `<a class="clear" href="/history">Clear</a>`,
		`<span class="badge warn">Not known</span>`, `<span class="badge bad">Failed</span>`)

	// One certificate, and both together.
	page = b.get("/history?serial=101")
	if rows := rowsOf(page.Body.String()); len(rows) != 2 {
		t.Errorf("narrowed to a certificate: %d rows", len(rows))
	}
	wantBody(t, page, `Only what was done to <a href="/certificates/101">web1.internal.example</a> with serial number <span class="mono small">101</span>.`,
		`<input type="hidden" name="serial" value="101">`)
	page = b.get("/history?serial=101&action=note")
	if rows := rowsOf(page.Body.String()); len(rows) != 1 || !strings.Contains(rows[0], "<td>Note</td>") {
		t.Errorf("narrowed to a certificate's notes: %v", rows)
	}

	// A serial the list does not have is said to be so, and not linked.
	page = b.get("/history?serial=777")
	wantBody(t, page, "Only what was done to the certificate with serial number", "That serial number is not in the certificate list as handrail-ca has read it.")
	if strings.Contains(page.Body.String(), `href="/certificates/777"`) {
		t.Error("a certificate that is not in the list is linked")
	}
	// Nothing matches, said as that and not as an empty history.
	page = b.get("/history?serial=31337")
	wantBody(t, page, "Nothing in the history matches.")

	// An action that is not one, a serial too long to be one, and a page
	// marker that is no number are dropped, not searched for.
	page = b.get("/history?action=%3Cscript%3E&before=soon&serial=" + strings.Repeat("9", maxKeyInAddress+1))
	wantStatus(t, page, http.StatusOK)
	if rows := rowsOf(page.Body.String()); len(rows) != 5 || strings.Contains(page.Body.String(), "script") || strings.Contains(page.Body.String(), "Clear") {
		t.Errorf("made-up narrowing: %d rows", len(rows))
	}
}

func TestHistoryPagePages(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	// With the sign-in, 2 pages and 21 rows.
	for i := 1; i <= 2*historyPageSize+20; i++ {
		s.appendHistory(store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: "101", Detail: fmt.Sprintf("change %d.", i)})
	}
	next := "/history?action=note"
	seen := 0
	for page := 1; next != ""; page++ {
		rec := b.get(next)
		wantStatus(t, rec, http.StatusOK)
		rows := rowsOf(rec.Body.String())
		// Each page continues where the last one stopped, newest first.
		for i, row := range rows {
			if want := fmt.Sprintf("change %d.", 2*historyPageSize+20-seen-i); !strings.Contains(row, want) {
				t.Fatalf("page %d row %d lacks %q", page, i, want)
			}
		}
		seen += len(rows)
		if (page > 1) != strings.Contains(rec.Body.String(), `<a href="/history?action=note">Back to the newest</a>`) {
			t.Errorf("page %d: the way back to the newest is wrong", page)
		}
		older := regexp.MustCompile(`<a href="(/history\?action=note&amp;before=\d+)" rel="next">Older</a>`).FindStringSubmatch(rec.Body.String())
		next = ""
		if older != nil {
			next = strings.ReplaceAll(older[1], "&amp;", "&")
		}
		if page > 3 {
			t.Fatal("the history never ends")
		}
	}
	if seen != 2*historyPageSize+20 {
		t.Errorf("saw %d rows over the pages, want %d", seen, 2*historyPageSize+20)
	}
	// Exactly one page has no older one.
	s2 := newSite(t, "http://127.0.0.1:8080")
	b2 := s2.browser()
	wantRedirect(t, b2.signIn("alice", alicePassword), "/")
	for i := 1; i < historyPageSize; i++ {
		s2.appendHistory(store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK})
	}
	rec := b2.get("/history")
	if rows := rowsOf(rec.Body.String()); len(rows) != historyPageSize || strings.Contains(rec.Body.String(), "Older") {
		t.Errorf("a history of exactly one page: %d rows, older link %v", len(rows), strings.Contains(rec.Body.String(), "Older"))
	}
}

func TestHistoryThatCannotBeRead(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	broken := errors.New("database disk image is malformed")
	s.store.readHistoryErr.Store(&broken)

	page := b.get("/history")
	wantStatus(t, page, http.StatusInternalServerError)
	wantBody(t, page, "The history could not be read", "could not read the history from its own store")
	for _, absent := range []string{"Nothing has been recorded yet", "malformed", "<table"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the page says %q", absent)
		}
	}
	if !strings.Contains(s.log.String(), "malformed") {
		t.Error("the reason is not in the log")
	}
	// A certificate's page still comes up, and does not say there is no
	// history.
	cert := b.get("/certificates/101")
	wantStatus(t, cert, http.StatusOK)
	wantBody(t, cert, "The history could not be read from handrail-ca's store just now. That does not mean there is none.")
	if strings.Contains(cert.Body.String(), "Nothing has been done to this certificate") {
		t.Error("a history that could not be read is shown as an empty one")
	}
}

// A certificate's own page shows the last things done to it and leads to
// the rest.
func TestCertificatePageShowsItsHistory(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	page := b.get("/certificates/101")
	wantBody(t, page, `<section class="card" id="history">`, "Nothing has been done to this certificate through handrail-ca.")
	if strings.Contains(page.Body.String(), `href="/history?serial=101"`) {
		t.Error("a certificate with no history links to it")
	}

	s.appendHistory(store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: "101", Detail: "the <first> change"})
	s.appendHistory(store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: "102", Detail: "another certificate's"})
	page = b.get("/certificates/101")
	wantBody(t, page, `<a href="/history?serial=101">On the history page</a>`, `<span class="strong">alice</span> Note <span class="badge ok">Done</span>`, "the &lt;first&gt; change")
	for _, absent := range []string{"another certificate's", "Earlier entries", "Nothing has been done"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("the page says %q", absent)
		}
	}

	for i := 2; i <= certificateHistory+1; i++ {
		s.appendHistory(store.Event{Actor: "alice", Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: "101", Detail: fmt.Sprintf("change %d.", i)})
	}
	page = b.get("/certificates/101")
	wantBody(t, page, `<a href="/history?serial=101">All of it</a>`, "Earlier entries are on the", "change 6.", "change 2.")
	if strings.Contains(page.Body.String(), "the &lt;first&gt; change") {
		t.Error("more than the last few entries are on the certificate's page")
	}
	// A row that is not a certificate has no history card.
	if strings.Contains(b.get("/certificates/104").Body.String(), `id="history"`) {
		t.Error("a row that is not a certificate has a history card")
	}
}
