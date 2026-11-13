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
	"net/http"
	"net/url"
	"strconv"

	"handrail-ca/internal/store"
)

// historyPageSize is how many events the history page shows at once.
const historyPageSize = 50

// certificateHistory is how many of a certificate's events its own page
// shows.
const certificateHistory = 5

// historyActions are the actions the history can be narrowed to, in the
// order offered, with the words for each.
var historyActions = []struct{ action, label string }{
	{store.ActionRevoke, "Revocations"},
	{store.ActionIssue, "Issued certificates"},
	{store.ActionNote, "Notes and labels"},
	{store.ActionSignIn, "Sign-ins"},
	{store.ActionSignOut, "Sign-outs"},
	{store.ActionUserAdd, "Accounts added"},
	{store.ActionUserPasswd, "Passwords set"},
	{store.ActionUserRemove, "Accounts removed"},
	{store.ActionHistoryGap, "Gaps in the history"},
}

// actionWords says an action as the history shows it. An action this
// version does not know is shown as it was written.
var actionWords = map[string]string{
	store.ActionRevoke:     "Revoke",
	store.ActionIssue:      "Issue",
	store.ActionNote:       "Note",
	store.ActionSignIn:     "Sign in",
	store.ActionSignOut:    "Sign out",
	store.ActionUserAdd:    "Account added",
	store.ActionUserPasswd: "Password set",
	store.ActionUserRemove: "Account removed",
	store.ActionHistoryGap: "Rows missing",
}

// outcomeLook is how each outcome is shown.
var outcomeLook = map[string]struct{ label, badge string }{
	store.OutcomeOK:      {"Done", "ok"},
	store.OutcomeFailed:  {"Failed", "bad"},
	store.OutcomeAttempt: {"Attempted", "unknown"},
	store.OutcomeUnknown: {"Not known", "warn"},
}

type historyData struct {
	// Problem is why the history could not be read; nothing else is
	// filled in then.
	Problem string

	Events []eventView
	// Serial and Action are what the page is narrowed to, if anything;
	// Subject is that certificate's, when handrail-ca knows it.
	Serial, Subject, Action string
	Actions                 []actionOption
	// CertificateURL is the page of the certificate the history is
	// narrowed to, when it has one.
	CertificateURL string
	// OlderURL is the next page; NewestURL leads back to the first when
	// this is not it. AllURL drops the narrowing.
	OlderURL, NewestURL, AllURL string
}

type actionOption struct {
	Action, Label string
	Selected      bool
}

type eventView struct {
	When, Actor, What   string
	Outcome, Badge      string
	Serial, SerialShort string
	Subject, Detail     string
	Remote              string
	// URL is the certificate's page, when the inventory has it.
	URL string
}

func (s *server) newEventView(e store.Event) eventView {
	v := eventView{
		When: e.At.UTC().Format(stamp), Actor: e.Actor, What: actionWords[e.Action],
		Serial: e.Serial, SerialShort: shortSerial(e.Serial), Subject: e.Subject, Detail: e.Detail, Remote: e.Remote,
	}
	if v.What == "" {
		v.What = e.Action
	}
	look, known := outcomeLook[e.Outcome]
	if !known {
		look.label, look.badge = e.Outcome, "unknown"
	}
	v.Outcome, v.Badge = look.label, look.badge
	if e.Serial != "" && s.opts.Inventory.Snapshot().Certificate(e.Serial) != nil {
		if path, ok := certificatePath(e.Serial); ok {
			v.URL = s.base + path
		}
	}
	return v
}

// historyURL is the address of the history narrowed as given.
func (s *server) historyURL(serial, action string, before int64) string {
	q := url.Values{}
	if serial != "" {
		q.Set("serial", serial)
	}
	if action != "" {
		q.Set("action", action)
	}
	if before > 0 {
		q.Set("before", strconv.FormatInt(before, 10))
	}
	if len(q) == 0 {
		return s.base + "/history"
	}
	return s.base + "/history?" + q.Encode()
}

// historyAsked reads what the page was asked to show. What cannot be a
// serial number, an action or a page marker narrows to nothing: it is
// dropped, not searched for.
func historyAsked(asked url.Values) (data historyData, before int64) {
	if serial := asked.Get("serial"); len(serial) <= maxKeyInAddress {
		data.Serial = serial
	}
	for _, a := range historyActions {
		selected := a.action == asked.Get("action")
		if selected {
			data.Action = a.action
		}
		data.Actions = append(data.Actions, actionOption{Action: a.action, Label: a.label, Selected: selected})
	}
	before, err := strconv.ParseInt(asked.Get("before"), 10, 64)
	if err != nil || before < 0 {
		before = 0
	}
	return data, before
}

func (s *server) historyPage(w http.ResponseWriter, r *http.Request) {
	data, before := historyAsked(r.URL.Query())
	// One more than a page, to know whether there is an older one.
	events, err := s.opts.Store.History(r.Context(), store.HistoryQuery{Serial: data.Serial, Action: data.Action, Before: before, Limit: historyPageSize + 1})
	if err != nil {
		s.log.Error("reading the history", "err", err)
		data.Problem = "handrail-ca could not read the history from its own store. The log has the details."
		s.render(w, r, http.StatusInternalServerError, "history.html", "History", data)
		return
	}
	if len(events) > historyPageSize {
		events = events[:historyPageSize]
		data.OlderURL = s.historyURL(data.Serial, data.Action, events[len(events)-1].ID)
	}
	for _, e := range events {
		data.Events = append(data.Events, s.newEventView(e))
	}
	if before > 0 {
		data.NewestURL = s.historyURL(data.Serial, data.Action, 0)
	}
	if data.Serial != "" || data.Action != "" {
		data.AllURL = s.historyURL("", "", 0)
	}
	s.nameNarrowedCertificate(&data)
	s.render(w, r, http.StatusOK, "history.html", "History", data)
}

// nameNarrowedCertificate fills in the subject and the page of the
// certificate the history is narrowed to, when the inventory has it.
func (s *server) nameNarrowedCertificate(data *historyData) {
	if data.Serial == "" {
		return
	}
	c := s.opts.Inventory.Snapshot().Certificate(data.Serial)
	if c == nil {
		return
	}
	data.Subject = c.Subject
	if path, ok := certificatePath(data.Serial); ok {
		data.CertificateURL = s.base + path
	}
}

// certificateEvents is what a certificate's own page shows of its history.
type certificateEvents struct {
	Events []eventView
	// More is set when there are more than are shown.
	More bool
	URL  string
	// Unread is set when the history could not be read.
	Unread bool
}

func (s *server) certificateEvents(r *http.Request, serial string) *certificateEvents {
	out := &certificateEvents{URL: s.historyURL(serial, "", 0)}
	events, err := s.opts.Store.History(r.Context(), store.HistoryQuery{Serial: serial, Limit: certificateHistory + 1})
	if err != nil {
		s.log.Error("reading a certificate's history", "serial", serial, "err", err)
		out.Unread = true
		return out
	}
	if len(events) > certificateHistory {
		events, out.More = events[:certificateHistory], true
	}
	for _, e := range events {
		out.Events = append(out.Events, s.newEventView(e))
	}
	return out
}
