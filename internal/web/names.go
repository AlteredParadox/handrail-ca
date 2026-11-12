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

	"handrail-ca/internal/inventory"
)

// How much of the names summary one page shows. The counts are always of
// everything; what is cut is said.
const (
	maxNameGroups = 100
	maxGroupNames = 200
)

// namesData is what the "names in use" page shows.
type namesData struct {
	// Read, LastRead and Problem are as on the list.
	Read     bool
	LastRead string
	Problem  string

	// All is true when every certificate is counted, ended or not; the
	// default is those in date and not revoked.
	All               bool
	ActiveURL, AllURL string
	Certificates      int
	Wildcards         int
	Kinds             []namesKind
}

type namesKind struct {
	Title  string // "DNS names"
	Column string // what a group is: "Domain", "Network"
	Note   string // what a name policy does with this kind
	Names  int
	Groups []namesGroup
	// MoreGroups is how many groups are not shown.
	MoreGroups int
}

type namesGroup struct {
	Label        string
	Count        int // names in the group
	Certificates int
	Names        []namesUse
	// MoreNames is how many names are not shown.
	MoreNames int
}

type namesUse struct {
	// Value is the name, shortened if it is very long; the certificates
	// it links to show it whole.
	Value        string
	Certificates int
	// URL is the list, searched for this name.
	URL string
}

// kindWords is how each kind of name is presented. The notes say only
// what docs/ca-setup.md, section 2, records as checked on a real step-ca.
var kindWords = map[inventory.NameKind]struct{ title, column, alone, note string }{
	inventory.DNS: {"DNS names", "Domain", "Single-label names",
		"A rule for *.internal.example covers the names exactly one label under internal.example: each domain here needs a rule of its own, and so does each single-label name."},
	inventory.IP:    {"IP addresses", "Network", "Not read as an address", "A rule allows an address or a range. The networks here are only a grouping, a /24 or a /64; allow the ranges you mean to."},
	inventory.Email: {"Email addresses", "Domain", "Without a domain", ""},
	inventory.URI:   {"URIs", "Scheme and host", "Without a host", ""},
	inventory.CommonName: {"Common names that are not among the certificate's names", "", "Common names",
		"step-ca checks a certificate's common name against the policy too, so these need to be allowed as well."},
}

func (s *server) namesPage(w http.ResponseWriter, r *http.Request) {
	now := s.opts.Now()
	snap := s.opts.Inventory.Snapshot()
	st := snap.State
	view := inventory.ViewActive
	if r.URL.Query().Get("view") == string(inventory.ViewAll) {
		view = inventory.ViewAll
	}
	data := namesData{
		Read: !st.LoadedAt.IsZero(), Problem: st.Problem, All: view == inventory.ViewAll,
		ActiveURL: s.base + "/names", AllURL: s.base + "/names?view=all",
	}
	if !data.Read {
		s.render(w, r, http.StatusOK, "names.html", "Names in use", data)
		return
	}
	data.LastRead = span(now.Sub(st.LoadedAt)) + " ago"

	usage := snap.NamesInUse(view, now)
	data.Certificates, data.Wildcards = usage.Certificates, usage.Wildcards
	for _, ku := range usage.Kinds {
		data.Kinds = append(data.Kinds, s.newNamesKind(ku, view))
	}
	s.render(w, r, http.StatusOK, "names.html", "Names in use", data)
}

// newNamesKind is one kind of name as the page shows it: its first
// maxNameGroups groups, and how many more there are.
func (s *server) newNamesKind(ku inventory.KindUsage, view inventory.View) namesKind {
	words := kindWords[ku.Kind]
	kind := namesKind{Title: words.title, Column: words.column, Note: words.note, Names: ku.Names}
	groups := ku.Groups
	if len(groups) > maxNameGroups {
		groups, kind.MoreGroups = groups[:maxNameGroups], len(groups)-maxNameGroups
	}
	for _, g := range groups {
		group := s.newNamesGroup(g, view)
		if group.Label == "" {
			group.Label = words.alone
		}
		kind.Groups = append(kind.Groups, group)
	}
	return kind
}

// newNamesGroup is one group as the page shows it: its first
// maxGroupNames names, each with a link to its certificates, and how many
// more there are.
func (s *server) newNamesGroup(g inventory.NameGroup, view inventory.View) namesGroup {
	group := namesGroup{Label: g.Label, Count: len(g.Names), Certificates: g.Certificates}
	names := g.Names
	if len(names) > maxGroupNames {
		names, group.MoreNames = names[:maxGroupNames], len(names)-maxGroupNames
	}
	for _, n := range names {
		// The name's certificates: the list, searched for it, over the
		// same certificates this page counts, the CA's own admin
		// certificates among them. A search is only so long; the start
		// of a longer name finds it.
		search := n.Value
		if r := []rune(search); len(r) > maxSearch {
			search = string(r[:maxSearch])
		}
		q := listQuery{Search: search, View: view, IncludeAdmin: true}
		group.Names = append(group.Names, namesUse{Value: shownName(n.Value), Certificates: n.Certificates, URL: q.href(s.base)})
	}
	return group
}

// maxShownName is how much of one name the summary shows.
const maxShownName = 256

// shownName shortens a very long name for the page.
func shownName(name string) string {
	if r := []rune(name); len(r) > maxShownName {
		return string(r[:maxShownName]) + "…"
	}
	return name
}
