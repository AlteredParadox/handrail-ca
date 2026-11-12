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
	"net/http"
	"net/url"
	"strings"
	"testing"

	"handrail-ca/internal/store"
)

func (s *site) note(serial string) store.Note {
	s.t.Helper()
	n, err := s.store.Store.Note(context.Background(), serial)
	if err != nil {
		s.t.Fatal(err)
	}
	return n
}

func TestCertificateNote(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	// An operator sees the form, empty.
	page := b.get("/certificates/101")
	wantBody(t, page, `<section class="card" id="note">`, `<form method="post" action="/certificates/101/note" class="note">`,
		`<textarea id="note-text" name="note" rows="4" maxlength="1000" spellcheck="true"></textarea>`, `name="labels" type="text" value=""`)
	token := tokenIn(t, page)

	// Saved, and the page comes back saying so, with the note in the form.
	rec := b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"The intranet's <front> end.\r\nAsked for by Sam."}, "labels": {"Web, PROD"}})
	wantRedirect(t, rec, "/certificates/101?saved=note#note")
	page = b.get("/certificates/101?saved=note")
	wantBody(t, page, `<output class="notice">Saved.</output>`, "The intranet&#39;s &lt;front&gt; end.\nAsked for by Sam.</textarea>",
		`value="prod, web"`, "Last changed 2026-11-11 12:00 UTC by alice")
	if strings.Contains(page.Body.String(), "<front>") {
		t.Error("the note is on the page unescaped")
	}
	if got := s.note("101"); got.Text != "The intranet's <front> end.\nAsked for by Sam." || strings.Join(got.Labels, " ") != "prod web" || got.UpdatedBy != "alice" || !got.UpdatedAt.Equal(t0) {
		t.Errorf("stored: %+v", got)
	}
	// The plain page does not say "Saved".
	if strings.Contains(b.get("/certificates/101").Body.String(), "Saved.") {
		t.Error("a page not reached from a save says Saved")
	}
	// The change is in the history, without the text.
	last := s.history()[0]
	if last.Action != store.ActionNote || last.Actor != "alice" || last.Serial != "101" || last.Subject != "web1.internal.example" || last.Outcome != store.OutcomeOK || strings.Contains(last.Detail, "intranet") {
		t.Errorf("history: %+v", last)
	}

	// A viewer reads it, and has no form.
	viewer := s.browser()
	viewer.signIn("bob", bobPassword)
	seen := viewer.get("/certificates/101")
	wantBody(t, seen, `<p class="note-text">The intranet&#39;s &lt;front&gt; end.`, `<ul class="labels"><li>prod</li><li>web</li></ul>`, "Last changed 2026-11-11 12:00 UTC by alice")
	for _, absent := range []string{"<textarea", `action="/certificates/101/note"`} {
		if strings.Contains(seen.Body.String(), absent) {
			t.Errorf("a viewer's page has %q", absent)
		}
	}
	wantBody(t, viewer.get("/certificates/102"), "Nothing has been noted about this certificate.")
	// And cannot save one, with a form token of their own or not.
	rec = viewer.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {tokenIn(t, viewer.get("/account"))}, "note": {"defaced"}})
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "Only operators can change")
	if got := s.note("101"); strings.Contains(got.Text, "defaced") {
		t.Error("a viewer changed a note")
	}

	// Emptied by an operator: gone, and the history says removed.
	wantRedirect(t, b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"  "}, "labels": {""}}), "/certificates/101?saved=note#note")
	if got := s.note("101"); !got.Empty() {
		t.Errorf("after emptying: %+v", got)
	}
	if last := s.history()[0]; last.Detail != "note and labels removed" {
		t.Errorf("history after emptying: %+v", last)
	}
}

func TestCertificateNoteRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	token := tokenIn(t, b.get("/certificates/101"))
	post := func(path string, form url.Values) int {
		t.Helper()
		return b.do(http.MethodPost, path, form).Code
	}
	good := url.Values{"form_token": {token}, "note": {"kept"}, "labels": {"web"}}
	if code := post("/certificates/101/note", good); code != http.StatusSeeOther {
		t.Fatalf("saving = %d", code)
	}
	events := len(s.history())

	// What cannot be kept comes back with the reason and what was typed,
	// and changes nothing.
	long := strings.Repeat("x", store.MaxNote+1)
	rec := b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {long}, "labels": {"web"}})
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, `role="alert">Not saved: the note is 1001 characters long; the most that can be kept is 1000.</p>`, long+"</textarea>")
	rec = b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"new text"}, "labels": {"web, <b>bad</b>"}})
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "Not saved: a label is made of letters", "new text</textarea>", `value="web, &lt;b&gt;bad&lt;/b&gt;"`)
	if strings.Contains(rec.Body.String(), "<b>bad") {
		t.Error("a refused label is on the page unescaped")
	}
	if got := s.note("101"); got.Text != "kept" || len(s.history()) != events {
		t.Errorf("a refused note changed something: %+v, %d events", got, len(s.history()))
	}

	// Without the session's form token, from another origin, or signed
	// out: refused like every other form.
	if code := post("/certificates/101/note", url.Values{"note": {"x"}}); code != http.StatusForbidden {
		t.Errorf("without a form token: %d", code)
	}
	b.origin = "https://evil.example"
	if code := post("/certificates/101/note", good); code != http.StatusForbidden {
		t.Errorf("from another origin: %d", code)
	}
	b.origin = ""
	wantRedirect(t, s.browser().do(http.MethodPost, "/certificates/101/note", good), "/sign-in")

	// Only about a certificate the CA's database has, and one that is a
	// certificate.
	if code := post("/certificates/999/note", good); code != http.StatusNotFound {
		t.Errorf("a serial the CA never issued: %d", code)
	}
	if code := post("/certificates/104/note", good); code != http.StatusNotFound {
		t.Errorf("a row that is not a certificate: %d", code)
	}
	if got := s.note("999"); !got.Empty() {
		t.Errorf("a note about nothing was kept: %+v", got)
	}
	// There is nothing to GET there.
	wantStatus(t, b.get("/certificates/101/note"), http.StatusNotFound)
}

func TestCertificateNoteWhenTheStoreFails(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := signedIn(t, s)
	token := tokenIn(t, b.get("/certificates/101"))
	if code := b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"kept"}}).Code; code != http.StatusSeeOther {
		t.Fatalf("saving = %d", code)
	}

	// The note cannot be read: the certificate's page still shows, says
	// so, and offers no form that would overwrite what it could not read.
	broken := errors.New("disk I/O error")
	s.store.noteErr.Store(&broken)
	page := b.get("/certificates/101")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "<h1>web1.internal.example</h1>", "The note could not be read from handrail-ca's store just now. That does not mean there is none.")
	for _, absent := range []string{"<textarea", "Nothing has been noted", "disk I/O"} {
		if strings.Contains(page.Body.String(), absent) {
			t.Errorf("with the note unreadable the page has %q", absent)
		}
	}
	if !strings.Contains(s.log.String(), "disk I/O error") {
		t.Error("the log does not say why the note could not be read")
	}
	s.store.noteErr.Store(nil)

	// The note cannot be saved: an error, nothing changed, nothing in the
	// history claiming otherwise.
	events := len(s.history())
	s.store.setNoteErr.Store(&broken)
	rec := b.do(http.MethodPost, "/certificates/101/note", url.Values{"form_token": {token}, "note": {"lost"}})
	wantStatus(t, rec, http.StatusInternalServerError)
	wantBody(t, rec, "could not save the note in its store, so nothing was changed")
	s.store.setNoteErr.Store(nil)
	if got := s.note("101"); got.Text != "kept" || len(s.history()) != events {
		t.Errorf("after a failed save: %+v, %d events", got, len(s.history()))
	}
}
