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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// snapshotOf reads rows into a snapshot as of now.
func snapshotOf(t *testing.T, src *fakeSource, now time.Time) *Snapshot {
	t.Helper()
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return inv.Snapshot()
}

func subjects(rows []Row) string {
	var names []string
	for _, r := range rows {
		if r.Problem != "" {
			names = append(names, "("+r.Serial+")")
		} else {
			names = append(names, strings.TrimSuffix(r.Subject, ".handrail.test"))
		}
	}
	return strings.Join(names, " ")
}

func TestSelectOnARealCAsRows(t *testing.T) {
	f, src := loadFixture(t)
	// An hour after the capture: the five-minute and thirty-minute
	// certificates have expired, the rest have not.
	now := f.Captured.Add(time.Hour)
	snap := snapshotOf(t, src, f.Captured)

	// The default: in date, not revoked, without the CA's admin
	// certificates, soonest to expire first.
	res := snap.Select(Query{}, now)
	if got := subjects(res.Rows); got != "renewed renewed acme1 acme2 web2 git web1" {
		t.Errorf("default view = %s", got)
	}
	if res.AdminHidden != 5 {
		t.Errorf("%d admin certificates hidden, want 5", res.AdminHidden)
	}
	// What each view would show for the same query, for the filter bar.
	if v := res.InView; v[ViewActive] != 7 || v[ViewExpiring] != 0 || v[ViewExpired] != 3 || v[ViewRevoked] != 1 || v[ViewUnreadable] != 0 || v[ViewAll] != 11 {
		t.Errorf("counts by view = %v", res.InView)
	}
	for _, r := range res.Rows {
		if r.Status != StatusValid && r.Status != StatusExpiring {
			t.Errorf("%s is %v in the active view", r.Subject, r.Status)
		}
	}

	if got := subjects(snap.Select(Query{View: ViewExpired}, now).Rows); got != "brief1 brief2 soon" {
		t.Errorf("expired = %s", got)
	}
	revoked := snap.Select(Query{View: ViewRevoked}, now)
	if got := subjects(revoked.Rows); got != "gone" {
		t.Errorf("revoked = %s", got)
	}
	if r := revoked.Rows[0]; r.Status != StatusRevoked || r.Revocation == nil || r.Revocation.Reason != "development seed" {
		t.Errorf("the revoked row = %+v, %+v", r.Status, r.Revocation)
	}
	if n := len(snap.Select(Query{View: ViewAll}, now).Rows); n != 11 {
		t.Errorf("all = %d rows", n)
	}
	// With the admin certificates asked for, either way.
	if n := len(snap.Select(Query{View: ViewAll, IncludeAdmin: true}, now).Rows); n != 16 {
		t.Errorf("all, with admin certificates = %d rows", n)
	}
	admin := snap.Select(Query{View: ViewAll, Provisioner: AdminProvisioner}, now)
	if len(admin.Rows) != 5 || admin.AdminHidden != 0 {
		t.Errorf("the admin provisioner's own: %d rows, %d hidden", len(admin.Rows), admin.AdminHidden)
	}

	// By provisioner.
	if got := subjects(snap.Select(Query{Provisioner: "acme"}, now).Rows); got != "acme1 acme2" {
		t.Errorf("acme = %s", got)
	}
	if n := len(snap.Select(Query{Provisioner: "no such provisioner", View: ViewAll}, now).Rows); n != 0 {
		t.Errorf("an unknown provisioner matched %d rows", n)
	}
	provs := snap.Provisioners()
	if len(provs) != 3 || provs[0].Name != "acme" || provs[0].Certificates != 2 || provs[0].Type != "ACME" ||
		provs[1].Name != "Admin JWK" || provs[1].Certificates != 5 || provs[2].Name != "handrail" || provs[2].Certificates != 9 {
		t.Errorf("provisioners = %+v", provs)
	}
}

func TestSearch(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	snap := snapshotOf(t, src, now)
	all := func(search string) string {
		return subjects(snap.Select(Query{Search: search, View: ViewAll, Order: BySubject}, now).Rows)
	}
	web2 := snap.Select(Query{Search: "web2", View: ViewAll}, now).Rows[0]

	for search, want := range map[string]string{
		"web":              "web1 web2",
		"  WEB2.Handrail ": "web2",
		// A name that is only among the alternative names.
		"10.20.0.14": "web2",
		"10.20.0":    "git web2",
		// The serial number, as the CA keys it and as tools print it.
		web2.Serial:                           "web2",
		web2.SerialHex:                        "web2",
		strings.ToUpper(web2.SerialHex[4:14]): "web2",
		"nothing matches this":                "",
		// Markup and wildcards are just characters.
		"<script>": "",
		"%":        "",
		"*":        "",
	} {
		if got := all(search); got != want {
			t.Errorf("search %q = %q, want %q", search, got, want)
		}
	}
	if len(web2.SerialHex) < 20 || strings.ToLower(web2.SerialHex) != web2.SerialHex {
		t.Errorf("SerialHex = %q", web2.SerialHex)
	}
	// The counts by view follow the search.
	res := snap.Select(Query{Search: "gone"}, now)
	if len(res.Rows) != 0 || res.InView[ViewRevoked] != 1 || res.InView[ViewAll] != 1 || res.InView[ViewActive] != 0 {
		t.Errorf("search for the revoked one: %d rows, %v", len(res.Rows), res.InView)
	}
	// Admin certificates that match are counted as hidden, not shown.
	if res := snap.Select(Query{Search: "step", View: ViewAll}, now); len(res.Rows) != 0 || res.AdminHidden != 5 {
		t.Errorf("search for the admin subject: %d rows, %d hidden", len(res.Rows), res.AdminHidden)
	}
}

func TestOrder(t *testing.T) {
	day := 24 * time.Hour
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	row := func(serial, name string, issued, lifetime time.Duration) RawCertificate {
		return RawCertificate{Serial: serial, DER: newDER(t, serial, func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: name}
			c.NotBefore, c.NotAfter = base.Add(issued), base.Add(issued+lifetime)
		})}
	}
	src := &fakeSource{certs: map[string]RawCertificate{}}
	for _, r := range []RawCertificate{
		row("11", "Bravo", 2*day, 300*day),
		row("12", "alpha", 3*day, 100*day),
		row("13", "charlie", 1*day, 200*day),
		// The same end of validity and the same subject as 13.
		row("14", "charlie", 51*day, 150*day),
		{Serial: "99", DER: []byte("junk")},
		{Serial: "98", DER: []byte("junk")},
	} {
		src.certs[r.Serial] = r
	}
	now := base.Add(60 * day)
	snap := snapshotOf(t, src, now)
	serials := func(q Query) string {
		q.View = ViewAll
		var s []string
		for _, r := range snap.Select(q, now).Rows {
			s = append(s, r.Serial)
		}
		return strings.Join(s, " ")
	}
	for name, tt := range map[string]struct {
		q    Query
		want string
	}{
		// Unreadable rows have nothing to sort by: last, whatever the
		// order, by serial among themselves.
		"soonest to expire first": {Query{}, "12 13 14 11 98 99"},
		"latest to expire first":  {Query{Reverse: true}, "11 14 13 12 99 98"},
		"most recently issued":    {Query{Order: ByIssued}, "14 12 11 13 98 99"},
		"earliest issued":         {Query{Order: ByIssued, Reverse: true}, "13 11 12 14 99 98"},
		"by subject":              {Query{Order: BySubject}, "12 11 13 14 98 99"},
		"by subject, reversed":    {Query{Order: BySubject, Reverse: true}, "14 13 11 12 99 98"},
	} {
		if got := serials(tt.q); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
	// The unreadable view is those rows alone.
	res := snap.Select(Query{View: ViewUnreadable}, now)
	if len(res.Rows) != 2 || res.Rows[0].Status != StatusUnreadable || res.InView[ViewUnreadable] != 2 || res.InView[ViewActive] != 4 {
		t.Errorf("unreadable view: %d rows, %v", len(res.Rows), res.InView)
	}
}

func TestParseViewAndOrder(t *testing.T) {
	for in, want := range map[string]View{"": ViewActive, "active": ViewActive, "expiring": ViewExpiring, "expired": ViewExpired,
		"revoked": ViewRevoked, "unreadable": ViewUnreadable, "all": ViewAll, "ALL": ViewActive, "valid'; --": ViewActive} {
		if got := ParseView(in); got != want {
			t.Errorf("ParseView(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]Order{"": ByExpiry, "expires": ByExpiry, "issued": ByIssued, "subject": BySubject, "serial": ByExpiry} {
		if got := ParseOrder(in); got != want {
			t.Errorf("ParseOrder(%q) = %q", in, got)
		}
	}
	// Until revocations have been read, what is in date shows in the
	// active view as "unknown", not hidden and not called valid.
	for _, s := range []Status{StatusValid, StatusExpiring, StatusNotYetValid, StatusUnknown} {
		if !ViewActive.includes(s) {
			t.Errorf("the active view leaves out %v", s)
		}
	}
	for _, s := range []Status{StatusExpired, StatusRevoked, StatusUnreadable} {
		if ViewActive.includes(s) {
			t.Errorf("the active view includes %v", s)
		}
	}
}

// A certificate with more names than the list keeps for display must still
// be found by every one of them, of whatever kind. Being told that no
// certificate matches a name the CA has issued one for would be a wrong
// answer, not a short one.
func TestSearchFindsNamesBeyondTheOnesKept(t *testing.T) {
	u, _ := url.Parse("spiffe://handrail.test/workload/far-down-the-list")
	src := &fakeSource{certs: map[string]RawCertificate{}}
	src.certs["4001"] = RawCertificate{Serial: "4001", DER: newDER(t, "4001", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Many.Names.Handrail.Test"}
		for i := range maxNames + 30 {
			c.DNSNames = append(c.DNSNames, fmt.Sprintf("Host-%03d.handrail.test", i))
		}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.99.7"), net.ParseIP("2001:db8::99")}
		c.EmailAddresses = []string{"Ops@Handrail.Test"}
		c.URIs = []*url.URL{u}
	})}
	src.certs["4002"] = newRow(t, "4002", "other.handrail.test")
	src.certs["4003"] = RawCertificate{Serial: "4003", DER: []byte("junk")}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	snap := snapshotOf(t, src, now)
	found := func(search string) string {
		var serials []string
		for _, r := range snap.Select(Query{Search: search, View: ViewAll}, now).Rows {
			serials = append(serials, r.Serial)
		}
		return strings.Join(serials, " ")
	}

	many := snap.Select(Query{Search: "many.names", View: ViewAll}, now).Rows[0]
	if len(many.Names) != maxNames || many.MoreNames != 30+4 {
		t.Fatalf("%d names kept, %d more", len(many.Names), many.MoreNames)
	}
	for search, want := range map[string]string{
		"host-000.handrail.test": "4001", // among the names kept
		"host-049":               "4001", // the last of them
		"host-050":               "4001", // the first one left out
		"HOST-079.handrail.test": "4001", // the last DNS name
		"10.20.99.7":             "4001", // other kinds, all past the cut
		"2001:db8::99":           "4001",
		"ops@handrail.test":      "4001",
		"far-down-the-list":      "4001",
		"host-080":               "",
		"handrail.test":          "4001 4002",
		// An unreadable row can be found by its key.
		"4003": "4003",
		// A match does not run from one name into the next, and a second
		// line of search text is dropped.
		"host-001.handrail.test\nhost-002": "4001",
		"test\nhost":                       "4001 4002",
		"000.handrail.testhost-001":        "",
	} {
		if got := found(search); got != want {
			t.Errorf("search %q found %q, want %q", search, got, want)
		}
	}
}
