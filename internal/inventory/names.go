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
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CommonName is the kind given, in a summary of names in use, to a
// subject's common name that is not also one of the certificate's
// subject alternative names. step-ca checks the common name against its
// name policy too (docs/ca-setup.md, section 2), so it has to be allowed.
const CommonName NameKind = "common name"

// NameUse is one name and how many of the certificates counted carry it.
type NameUse struct {
	Value        string
	Certificates int
}

// NameGroup is the names of one kind that belong together: the DNS names
// one label under the same domain, the addresses in the same network, the
// email addresses at the same domain, the URIs with the same scheme and
// host.
type NameGroup struct {
	// Label is what the names share: "internal.example", "10.20.0.0/24".
	// Empty for the names that share nothing: single-label DNS names,
	// common names, and whatever could not be read as its kind.
	Label string
	// Names are in alphabetical order.
	Names []NameUse
	// Certificates is how many certificates carry at least one of them.
	Certificates int
}

// KindUsage is every name of one kind, in groups: the group with the most
// certificates first.
type KindUsage struct {
	Kind   NameKind
	Groups []NameGroup
	// Names is how many different names there are, over all groups.
	Names int
}

// NameUsage is a summary of the names in a set of certificates.
type NameUsage struct {
	// Certificates is how many certificates were counted.
	Certificates int
	// Kinds are DNS, IP, email, URI and common name, in that order, the
	// kinds with no names left out.
	Kinds []KindUsage
	// Wildcards is how many different DNS names are literal wildcards,
	// which a name policy refuses unless told to allow them.
	Wildcards int
}

// NamesInUse summarises every name in the certificates of a view, as of
// now: all of each certificate's subject alternative names, however many,
// and its common name where that is not one of them. step-ca has no such
// list, and it is what a CA-wide name policy has to allow: a name left out
// stops being issued and renewed. Rows that are not certificates have no
// names to count.
func (s *Snapshot) NamesInUse(view View, now time.Time) NameUsage {
	tallies := nameTallies{}
	var usage NameUsage
	for _, c := range s.Certificates {
		if c.Problem != "" || !view.includes(s.Status(c, now)) {
			continue
		}
		usage.Certificates++
		tallies.countCertificate(c)
	}
	for _, kind := range []NameKind{DNS, IP, Email, URI, CommonName} {
		if len(tallies[kind]) == 0 {
			continue
		}
		ku := tallies.usage(kind)
		if kind == DNS {
			usage.Wildcards = wildcards(ku)
		}
		usage.Kinds = append(usage.Kinds, ku)
	}
	return usage
}

// nameTallies counts names by kind, then by group.
type nameTallies map[NameKind]map[string]*groupTally

// groupTally and nameTally count certificates; last is the certificate
// counted most recently, so that one carrying a name twice, or two names
// of a group, is counted once. Certificates are visited one at a time.
type groupTally struct {
	names        map[string]*nameTally
	certificates int
	last         *Certificate
}

type nameTally struct {
	certificates int
	last         *Certificate
}

// countCertificate counts every name of one certificate, whole: its
// subject alternative names, and its common name if none of them is the
// same.
func (t nameTallies) countCertificate(c *Certificate) {
	names, commonName := wholeNames(c)
	named := !c.hasCommonName
	for _, name := range names {
		t.count(c, name.Kind, name.Value)
		named = named || strings.EqualFold(name.Value, commonName)
	}
	if !named {
		t.count(c, CommonName, commonName)
	}
}

// wholeNames is a certificate's subject alternative names and its common
// name, none of them shortened: Names and Subject, unless those were
// shortened for showing.
func wholeNames(c *Certificate) (names []Name, commonName string) {
	if c.exactNames == nil {
		return c.Names, c.Subject
	}
	commonName = c.Subject
	for _, name := range c.exactNames {
		if name.Kind == CommonName {
			commonName = name.Value
			continue
		}
		names = append(names, name)
	}
	return names, commonName
}

// count adds one name of a certificate to its group.
func (t nameTallies) count(c *Certificate, kind NameKind, value string) {
	label, value := groupOf(kind, value)
	groups := t[kind]
	if groups == nil {
		groups = map[string]*groupTally{}
		t[kind] = groups
	}
	g := groups[label]
	if g == nil {
		g = &groupTally{names: map[string]*nameTally{}}
		groups[label] = g
	}
	if g.last != c {
		g.last = c
		g.certificates++
	}
	n := g.names[value]
	if n == nil {
		n = &nameTally{}
		g.names[value] = n
	}
	if n.last != c {
		n.last = c
		n.certificates++
	}
}

// usage puts what was counted of one kind in order: the group with the
// most certificates first, the names of each alphabetically.
func (t nameTallies) usage(kind NameKind) KindUsage {
	ku := KindUsage{Kind: kind}
	for label, g := range t[kind] {
		group := NameGroup{Label: label, Certificates: g.certificates}
		for value, n := range g.names {
			group.Names = append(group.Names, NameUse{Value: value, Certificates: n.certificates})
		}
		sort.Slice(group.Names, func(i, j int) bool { return group.Names[i].Value < group.Names[j].Value })
		ku.Names += len(group.Names)
		ku.Groups = append(ku.Groups, group)
	}
	sort.Slice(ku.Groups, func(i, j int) bool {
		a, b := ku.Groups[i], ku.Groups[j]
		if a.Certificates != b.Certificates {
			return a.Certificates > b.Certificates
		}
		return a.Label < b.Label
	})
	return ku
}

// wildcards counts the DNS names that are literal wildcards.
func wildcards(dns KindUsage) int {
	n := 0
	for _, group := range dns.Groups {
		for _, name := range group.Names {
			if strings.HasPrefix(name.Value, "*.") {
				n++
			}
		}
	}
	return n
}

// groupOf says which group a name belongs to, and the name as it is
// counted: DNS names and email domains without regard to case.
func groupOf(kind NameKind, value string) (label, counted string) {
	switch kind {
	case DNS:
		name := strings.ToLower(strings.TrimSuffix(value, "."))
		// One label under a domain: the names a rule for "*.domain"
		// covers. A single-label name is under nothing.
		if _, parent, ok := strings.Cut(name, "."); ok && parent != "" {
			return parent, name
		}
		return "", name
	case IP:
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return "", value
		}
		bits := 24
		if addr = addr.Unmap(); addr.Is6() {
			bits = 64
		}
		network, err := addr.Prefix(bits)
		if err != nil {
			return "", value
		}
		return network.String(), addr.String()
	case Email:
		if at := strings.LastIndex(value, "@"); at >= 0 && at < len(value)-1 {
			domain := strings.ToLower(value[at+1:])
			return domain, value[:at+1] + domain
		}
		return "", value
	case URI:
		if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.Host != "" {
			return strings.ToLower(u.Scheme + "://" + u.Host), value
		}
		return "", value
	}
	return "", value
}
