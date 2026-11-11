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
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"handrail-ca/internal/inventory"
)

const (
	// listPageSize is how many certificates one page of the list shows.
	listPageSize = 50
	// maxSearch bounds the search text taken from the query string.
	maxSearch = 200
	// refreshTimeout bounds a refresh asked for from the page.
	refreshTimeout = 20 * time.Second
)

// listQuery is the list's query string, parsed: what to show and how.
type listQuery struct {
	inventory.Query
	Page int
}

// parseListQuery reads the list's parameters, from a query string or from
// a posted form. Anything it does not recognise becomes the default; it
// never fails.
func parseListQuery(v url.Values) listQuery {
	q := listQuery{Page: 1}
	q.Search = strings.TrimSpace(v.Get("q"))
	if r := []rune(q.Search); len(r) > maxSearch {
		q.Search = string(r[:maxSearch])
	}
	q.Provisioner = v.Get("provisioner")
	if len(q.Provisioner) > maxSearch {
		q.Provisioner = ""
	}
	q.IncludeAdmin = v.Get("admin") == "1"
	q.View = inventory.ParseView(v.Get("view"))
	q.Order = inventory.ParseOrder(v.Get("sort"))
	q.Reverse = v.Get("dir") == "desc"
	if n, err := strconv.Atoi(v.Get("page")); err == nil && n > 1 && n < 1_000_000 {
		q.Page = n
	}
	return q
}

// values is the query string for q, leaving out everything that is at its
// default, so that the plain list has a plain address.
func (q listQuery) values() url.Values {
	v := url.Values{}
	if q.Search != "" {
		v.Set("q", q.Search)
	}
	if q.Provisioner != "" {
		v.Set("provisioner", q.Provisioner)
	}
	if q.IncludeAdmin {
		v.Set("admin", "1")
	}
	// A listQuery that was not parsed has neither set; that is the default
	// too.
	if q.View != inventory.ViewActive && q.View != "" {
		v.Set("view", string(q.View))
	}
	if q.Order != inventory.ByExpiry && q.Order != "" {
		v.Set("sort", string(q.Order))
	}
	if q.Reverse {
		v.Set("dir", "desc")
	}
	if q.Page > 1 {
		v.Set("page", strconv.Itoa(q.Page))
	}
	return v
}

// href is the list's address for q under the site's base path.
func (q listQuery) href(base string) string {
	if enc := q.values().Encode(); enc != "" {
		return base + "/?" + enc
	}
	return base + "/"
}

// with returns q changed by change, on its first page: a different filter
// or order starts from the top.
func (q listQuery) with(change func(*listQuery)) listQuery {
	q.Page = 1
	change(&q)
	return q
}

// listData is what the list page shows.
type listData struct {
	// Read is false until the inventory has been read once; then there is
	// no list, only the reason.
	Read     bool
	LastRead string
	Problem  string

	// The filter form's current values, and its hidden fields.
	Search       string
	Provisioner  string
	IncludeAdmin bool
	View         string
	Sort         string
	Dir          string
	Filtered     bool // anything but the plain default list
	ClearURL     string

	Views        []viewLink
	Provisioners []provisionerOption
	Columns      map[string]columnLink

	Rows        []listRow
	Total       int // certificates in the view, on all pages
	From, To    int
	PrevURL     string
	NextURL     string
	AdminHidden int
	AdminURL    string
}

type viewLink struct {
	Label   string
	Count   int
	URL     string
	Current bool
}

type provisionerOption struct {
	Name, Label string
	Selected    bool
}

// columnLink is a sortable column heading: where clicking it leads, and
// whether the list is sorted by it now ("ascending", "descending" or "").
type columnLink struct {
	URL    string
	Sorted string
}

type listRow struct {
	// Badge is the status badge's style; StatusLabel its text.
	Badge, StatusLabel string
	Subject            string
	Names              string
	Provisioner        string
	ProvisionerType    string
	Expires            string
	When               string
	// Serial is the hexadecimal serial shortened for the column; SerialFull
	// the whole of it.
	Serial, SerialFull string
	Problem            string
}

// statusLook is how each status is shown.
var statusLook = map[inventory.Status]struct{ label, badge string }{
	inventory.StatusValid:       {"Valid", "ok"},
	inventory.StatusExpiring:    {"Expiring", "warn"},
	inventory.StatusNotYetValid: {"Not yet valid", "unknown"},
	inventory.StatusExpired:     {"Expired", "unknown"},
	inventory.StatusRevoked:     {"Revoked", "bad"},
	inventory.StatusUnknown:     {"Unknown", "unknown"},
	inventory.StatusUnreadable:  {"Unreadable", "bad"},
}

func (s *server) listPage(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r.URL.Query())
	now := s.opts.Now()
	snap := s.opts.Inventory.Snapshot()
	st := snap.State

	data := listData{
		Read:         !st.LoadedAt.IsZero(),
		Problem:      st.Problem,
		Search:       q.Search,
		Provisioner:  q.Provisioner,
		IncludeAdmin: q.IncludeAdmin,
		View:         string(q.View),
		Sort:         string(q.Order),
		Filtered:     len(q.with(func(*listQuery) {}).values()) > 0,
		ClearURL:     listQuery{}.href(s.base),
	}
	if q.Reverse {
		data.Dir = "desc"
	}
	if !data.Read {
		s.render(w, r, http.StatusOK, "list.html", "Certificates", data)
		return
	}
	data.LastRead = span(now.Sub(st.LoadedAt)) + " ago"

	res := snap.Select(q.Query, now)
	data.Total = len(res.Rows)
	data.AdminHidden = res.AdminHidden
	data.AdminURL = q.with(func(c *listQuery) { c.IncludeAdmin = true }).href(s.base)

	for _, v := range []struct {
		view  inventory.View
		label string
	}{
		{inventory.ViewActive, "Active"}, {inventory.ViewExpiring, "Expiring"}, {inventory.ViewExpired, "Expired"},
		{inventory.ViewRevoked, "Revoked"}, {inventory.ViewUnreadable, "Unreadable"}, {inventory.ViewAll, "All"},
	} {
		// Unreadable rows are an anomaly: offered only when there are some.
		if v.view == inventory.ViewUnreadable && res.InView[v.view] == 0 && q.View != v.view {
			continue
		}
		data.Views = append(data.Views, viewLink{
			Label: v.label, Count: res.InView[v.view], Current: q.View == v.view,
			URL: q.with(func(c *listQuery) { c.View = v.view }).href(s.base),
		})
	}

	known := false
	for _, p := range snap.Provisioners() {
		label := p.Name
		if p.Type != "" {
			label += " (" + p.Type + ")"
		}
		data.Provisioners = append(data.Provisioners, provisionerOption{Name: p.Name, Label: label, Selected: p.Name == q.Provisioner})
		known = known || p.Name == q.Provisioner
	}
	if q.Provisioner != "" && !known {
		// Asked for by address, not from the menu: keep it selected, so
		// that the form says what the empty list is filtered by.
		data.Provisioners = append(data.Provisioners, provisionerOption{Name: q.Provisioner, Label: q.Provisioner, Selected: true})
	}

	data.Columns = map[string]columnLink{}
	for _, order := range []inventory.Order{inventory.BySubject, inventory.ByIssued, inventory.ByExpiry} {
		col := columnLink{URL: q.with(func(c *listQuery) { c.Order, c.Reverse = order, false }).href(s.base)}
		if q.Order == order {
			// Sorted by this already: the heading turns it round.
			col.Sorted = "ascending"
			if q.Reverse {
				col.Sorted = "descending"
			}
			col.URL = q.with(func(c *listQuery) { c.Reverse = !q.Reverse }).href(s.base)
		}
		data.Columns[string(order)] = col
	}

	// One page of it. A page number past the end shows the last page.
	pages := max((data.Total+listPageSize-1)/listPageSize, 1)
	page := min(q.Page, pages)
	start := (page - 1) * listPageSize
	end := min(start+listPageSize, data.Total)
	if data.Total > 0 {
		data.From, data.To = start+1, end
	}
	if page > 1 {
		data.PrevURL = q.with(func(c *listQuery) { c.Page = page - 1 }).href(s.base)
	}
	if page < pages {
		data.NextURL = q.with(func(c *listQuery) { c.Page = page + 1 }).href(s.base)
	}
	for _, row := range res.Rows[start:end] {
		data.Rows = append(data.Rows, newListRow(row, now))
	}
	s.render(w, r, http.StatusOK, "list.html", "Certificates", data)
}

func newListRow(row inventory.Row, now time.Time) listRow {
	look := statusLook[row.Status]
	out := listRow{
		Badge: look.badge, StatusLabel: look.label,
		Subject:         row.Subject,
		Provisioner:     row.Provisioner.Name,
		ProvisionerType: row.Provisioner.Type,
		SerialFull:      row.SerialHex,
		Serial:          shortSerial(row.SerialHex),
		Problem:         row.Problem,
	}
	if row.Problem != "" {
		// All that is known of an unreadable row is its key.
		out.SerialFull, out.Serial = row.Serial, shortSerial(row.Serial)
		return out
	}
	const shown = 3
	var names []string
	for i, n := range row.Names {
		if i == shown {
			break
		}
		names = append(names, n.Value)
	}
	out.Names = strings.Join(names, ", ")
	if more := len(row.Names) - len(names) + row.MoreNames; more > 0 {
		out.Names += fmt.Sprintf(" and %d more", more)
	}
	// The usual certificate has one name, the same as its subject: not
	// worth saying twice.
	if len(row.Names) == 1 && row.MoreNames == 0 && row.Names[0].Value == row.Subject {
		out.Names = ""
	}
	out.Expires = row.NotAfter.UTC().Format("2006-01-02 15:04")
	switch row.Status {
	case inventory.StatusRevoked:
		out.When = "revoked"
		if rev := row.Revocation; rev != nil && !rev.RevokedAt.IsZero() {
			out.When = "revoked " + rev.RevokedAt.UTC().Format("2006-01-02")
		}
	case inventory.StatusExpired:
		out.When = span(now.Sub(row.NotAfter)) + " ago"
	case inventory.StatusNotYetValid:
		out.When = "valid from " + row.NotBefore.UTC().Format("2006-01-02 15:04")
	default:
		out.When = "in " + span(row.NotAfter.Sub(now))
	}
	return out
}

// shortSerial shortens a serial number for a table column: its first and
// last four characters.
func shortSerial(s string) string {
	if len(s) <= 10 {
		return s
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// refreshInventory reads the CA's database again now, on request, and goes
// back to the list as it was being looked at. A read that fails is not an
// error page: the list says how old its picture is and why.
func (s *server) refreshInventory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), refreshTimeout)
	defer cancel()
	if err := s.opts.Inventory.Refresh(ctx); err != nil {
		s.log.Warn("the certificate inventory could not be read on request", "err", err)
	}
	http.Redirect(w, r, parseListQuery(r.PostForm).href(s.base), http.StatusSeeOther)
}
