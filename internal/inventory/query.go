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

package inventory

import (
	"sort"
	"strings"
	"time"
)

// AdminProvisioner is the name step-ca gives the provisioner it creates
// for remote management. A CA managed that way issues its admins a
// five-minute certificate from it for every management command, and stores
// each like any other; on a CA that is administered often they outnumber
// everything else, so the list leaves them out unless asked.
const AdminProvisioner = "Admin JWK"

// View is which certificates a list shows, by status.
type View string

// The views. ViewActive is the default: what is in date and not revoked.
const (
	ViewActive     View = "active"
	ViewExpiring   View = "expiring"
	ViewExpired    View = "expired"
	ViewRevoked    View = "revoked"
	ViewUnreadable View = "unreadable"
	ViewAll        View = "all"
)

// ParseView reads a view's name; anything else is the default.
func ParseView(s string) View {
	switch v := View(s); v {
	case ViewExpiring, ViewExpired, ViewRevoked, ViewUnreadable, ViewAll:
		return v
	}
	return ViewActive
}

// includes reports whether a certificate with this status is in the view.
func (v View) includes(s Status) bool {
	switch v {
	case ViewAll:
		return true
	case ViewExpiring:
		return s == StatusExpiring
	case ViewExpired:
		return s == StatusExpired
	case ViewRevoked:
		return s == StatusRevoked
	case ViewUnreadable:
		return s == StatusUnreadable
	}
	// Active: in date and not known to be revoked. That includes "unknown"
	// (in date, revocations not read): hiding those would hide the whole
	// list exactly when something is wrong, and each row says its status.
	return s == StatusValid || s == StatusExpiring || s == StatusNotYetValid || s == StatusUnknown
}

// Order is what a list is sorted by.
type Order string

// The orders. Each has a natural direction, which Query.Reverse flips.
const (
	// ByExpiry: soonest end of validity first.
	ByExpiry Order = "expires"
	// ByIssued: most recently issued first.
	ByIssued Order = "issued"
	// BySubject: alphabetical.
	BySubject Order = "subject"
)

// ParseOrder reads an order's name; anything else is ByExpiry.
func ParseOrder(s string) Order {
	switch o := Order(s); o {
	case ByIssued, BySubject:
		return o
	}
	return ByExpiry
}

// Query selects certificates from a snapshot.
type Query struct {
	// Search is matched, without regard to case, against the subject, the
	// names and the serial number in decimal and in hexadecimal. Empty
	// matches everything.
	Search string
	// Provisioner limits the result to one provisioner's certificates, by
	// name. Empty means all.
	Provisioner string
	// IncludeAdmin shows the CA's own admin certificates too. They are
	// also shown when Provisioner asks for exactly them.
	IncludeAdmin bool
	View         View
	Order        Order
	Reverse      bool
}

// Row is one certificate of a result, with its status at the time asked.
type Row struct {
	*Certificate
	Status     Status
	Revocation *Revocation
}

// Result is what a query selects.
type Result struct {
	// Rows are the certificates in the view, in order.
	Rows []Row
	// InView counts, for every view, the certificates that match the rest
	// of the query: what choosing that view instead would show.
	InView map[View]int
	// AdminHidden is how many certificates matched but are left out as the
	// CA's own admin certificates.
	AdminHidden int
}

// Select runs a query against the snapshot, with statuses as of now.
func (s *Snapshot) Select(q Query, now time.Time) Result {
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	res := Result{InView: map[View]int{}}
	views := []View{ViewActive, ViewExpiring, ViewExpired, ViewRevoked, ViewUnreadable, ViewAll}
	for _, c := range s.Certificates {
		if q.Provisioner != "" && c.Provisioner.Name != q.Provisioner {
			continue
		}
		if needle != "" && !c.matches(needle) {
			continue
		}
		if c.Provisioner.Name == AdminProvisioner && !q.IncludeAdmin && q.Provisioner != AdminProvisioner {
			res.AdminHidden++
			continue
		}
		status := s.Status(c, now)
		for _, v := range views {
			if v.includes(status) {
				res.InView[v]++
			}
		}
		if q.View.includes(status) {
			res.Rows = append(res.Rows, Row{Certificate: c, Status: status, Revocation: s.revoked[c.Serial]})
		}
	}
	sortRows(res.Rows, q.Order, q.Reverse)
	return res
}

// matches reports whether a lower-case needle occurs in what a certificate
// can be searched by.
func (c *Certificate) matches(needle string) bool {
	if strings.Contains(strings.ToLower(c.Subject), needle) || strings.Contains(c.Serial, needle) || strings.Contains(c.SerialHex, needle) {
		return true
	}
	for _, n := range c.Names {
		if strings.Contains(strings.ToLower(n.Value), needle) {
			return true
		}
	}
	return false
}

// sortRows orders rows; ties, and rows without the field sorted by
// (unreadable ones have no dates), fall back to the serial so that the
// order is the same on every request.
func sortRows(rows []Row, order Order, reverse bool) {
	less := func(a, b *Certificate) bool {
		switch order {
		case ByIssued:
			if !a.NotBefore.Equal(b.NotBefore) {
				return a.NotBefore.After(b.NotBefore)
			}
		case BySubject:
			if x, y := strings.ToLower(a.Subject), strings.ToLower(b.Subject); x != y {
				return x < y
			}
		default:
			if !a.NotAfter.Equal(b.NotAfter) {
				return a.NotAfter.Before(b.NotAfter)
			}
		}
		return a.Serial < b.Serial
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].Certificate, rows[j].Certificate
		// Unreadable rows have nothing to sort by: always last.
		if (a.Problem == "") != (b.Problem == "") {
			return a.Problem == ""
		}
		if reverse {
			return less(b, a)
		}
		return less(a, b)
	})
}

// ProvisionerCount is a provisioner and how many certificates it issued.
type ProvisionerCount struct {
	Provisioner
	Certificates int
}

// Provisioners lists the provisioners that issued the certificates in the
// snapshot, by name, with how many each issued. Certificates the CA
// recorded no provisioner for are not counted here.
func (s *Snapshot) Provisioners() []ProvisionerCount {
	byName := map[string]*ProvisionerCount{}
	for _, c := range s.Certificates {
		if c.Provisioner.Name == "" {
			continue
		}
		pc := byName[c.Provisioner.Name]
		if pc == nil {
			pc = &ProvisionerCount{Provisioner: c.Provisioner}
			byName[c.Provisioner.Name] = pc
		}
		pc.Certificates++
	}
	list := make([]ProvisionerCount, 0, len(byName))
	for _, pc := range byName {
		list = append(list, *pc)
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	return list
}
