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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGroupOf(t *testing.T) {
	for _, tc := range []struct {
		kind                  NameKind
		value, label, counted string
	}{
		{DNS, "web1.internal.example", "internal.example", "web1.internal.example"},
		{DNS, "Web1.Internal.Example.", "internal.example", "web1.internal.example"},
		{DNS, "a.apps.internal.example", "apps.internal.example", "a.apps.internal.example"},
		{DNS, "*.internal.example", "internal.example", "*.internal.example"},
		{DNS, "internal.example", "example", "internal.example"},
		{DNS, "git", "", "git"},
		{DNS, "odd.", "", "odd"},
		{IP, "10.20.3.7", "10.20.3.0/24", "10.20.3.7"},
		{IP, "::ffff:10.20.3.7", "10.20.3.0/24", "10.20.3.7"},
		{IP, "fd00:1:2:3::7", "fd00:1:2:3::/64", "fd00:1:2:3::7"},
		{IP, "not an address", "", "not an address"},
		{Email, "Ops@Internal.Example", "internal.example", "Ops@internal.example"},
		{Email, "nodomain@", "", "nodomain@"},
		{Email, "nothing", "", "nothing"},
		{URI, "spiffe://Internal.Example/app/one", "spiffe://internal.example", "spiffe://Internal.Example/app/one"},
		{URI, "urn:uuid:1234", "", "urn:uuid:1234"},
		{URI, "://bad", "", "://bad"},
		{CommonName, "Some Service", "", "Some Service"},
	} {
		if label, counted := groupOf(tc.kind, tc.value); label != tc.label || counted != tc.counted {
			t.Errorf("groupOf(%s, %q) = %q, %q; want %q, %q", tc.kind, tc.value, label, counted, tc.label, tc.counted)
		}
	}
}

func TestNamesInUse(t *testing.T) {
	src := &fakeSource{certs: map[string]RawCertificate{}}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	add := func(serial string, shape func(*x509.Certificate)) {
		src.add(RawCertificate{Serial: serial, DER: newDER(t, serial, shape)})
	}
	spiffe, _ := url.Parse("spiffe://internal.example/app")
	add("1", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "web1.internal.example"}
		c.DNSNames = []string{"web1.internal.example", "WEB1.internal.example", "www.internal.example"}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.0.7")}
	})
	add("2", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "web1.internal.example"}
		c.DNSNames = []string{"web1.internal.example", "a.apps.internal.example", "git", "*.internal.example"}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.0.8"), net.ParseIP("10.20.9.1"), net.ParseIP("fd00::7")}
		c.EmailAddresses = []string{"ops@internal.example"}
		c.URIs = []*url.URL{spiffe}
	})
	// A common name that is not one of the names; one with no common
	// name at all; an expired one; a revoked one; a row that is nothing.
	add("3", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "Backup Service"}
		c.DNSNames = []string{"backup.internal.example"}
	})
	add("4", func(c *x509.Certificate) {
		c.Subject = pkix.Name{Organization: []string{"Example"}}
		c.DNSNames = []string{"anon.other.example"}
	})
	add("5", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "old.legacy.example"}
		c.DNSNames = []string{"old.legacy.example"}
		c.NotBefore, c.NotAfter = now.AddDate(0, -2, 0), now.AddDate(0, -1, 0)
	})
	add("6", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "gone.revoked.example"}
		c.DNSNames = []string{"gone.revoked.example"}
	})
	src.revocations = []RawRevocation{{Serial: "6", JSON: []byte(`{"Serial":"6","ReasonCode":1,"RevokedAt":"2026-11-10T00:00:00Z"}`)}}
	src.add(RawCertificate{Serial: "7", DER: []byte("junk")})

	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()

	got := snap.NamesInUse(ViewActive, now)
	want := NameUsage{
		Certificates: 4,
		Wildcards:    1,
		Kinds: []KindUsage{
			{Kind: DNS, Names: 7, Groups: []NameGroup{
				// web1 is in two certificates, and twice in one of them.
				{Label: "internal.example", Certificates: 3, Names: []NameUse{
					{"*.internal.example", 1}, {"backup.internal.example", 1}, {"web1.internal.example", 2}, {"www.internal.example", 1},
				}},
				{Label: "", Certificates: 1, Names: []NameUse{{"git", 1}}},
				{Label: "apps.internal.example", Certificates: 1, Names: []NameUse{{"a.apps.internal.example", 1}}},
				{Label: "other.example", Certificates: 1, Names: []NameUse{{"anon.other.example", 1}}},
			}},
			{Kind: IP, Names: 4, Groups: []NameGroup{
				{Label: "10.20.0.0/24", Certificates: 2, Names: []NameUse{{"10.20.0.7", 1}, {"10.20.0.8", 1}}},
				{Label: "10.20.9.0/24", Certificates: 1, Names: []NameUse{{"10.20.9.1", 1}}},
				{Label: "fd00::/64", Certificates: 1, Names: []NameUse{{"fd00::7", 1}}},
			}},
			{Kind: Email, Names: 1, Groups: []NameGroup{{Label: "internal.example", Certificates: 1, Names: []NameUse{{"ops@internal.example", 1}}}}},
			{Kind: URI, Names: 1, Groups: []NameGroup{{Label: "spiffe://internal.example", Certificates: 1, Names: []NameUse{{"spiffe://internal.example/app", 1}}}}},
			{Kind: CommonName, Names: 1, Groups: []NameGroup{{Label: "", Certificates: 1, Names: []NameUse{{"Backup Service", 1}}}}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names in use among active certificates:\n got %+v\nwant %+v", got, want)
	}

	// Every certificate, ended or not: the expired and the revoked one's
	// names too. The row that is not a certificate has none.
	all := snap.NamesInUse(ViewAll, now)
	if all.Certificates != 6 || all.Kinds[0].Names != 9 {
		t.Errorf("over all certificates: %d certificates, %d DNS names", all.Certificates, all.Kinds[0].Names)
	}
	// Nothing to count: nothing claimed.
	if none := snap.NamesInUse(ViewUnreadable, now); none.Certificates != 0 || len(none.Kinds) != 0 {
		t.Errorf("names in rows that are not certificates: %+v", none)
	}
}

// A certificate with more names than the list keeps for display still has
// every one of them counted.
func TestNamesInUseLeavesNoneOut(t *testing.T) {
	src := &fakeSource{certs: map[string]RawCertificate{}}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	const names = maxNames + 25
	src.add(RawCertificate{Serial: "1", DER: newDER(t, "1", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "n0.many.example"}
		for i := range names {
			c.DNSNames = append(c.DNSNames, fmt.Sprintf("n%d.many.example", i))
		}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.0.7")}
	})})
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	if c := snap.Certificates[0]; len(c.Names) != maxNames || c.MoreNames != 26 {
		t.Fatalf("the summary keeps %d names and counts %d more", len(c.Names), c.MoreNames)
	}
	usage := snap.NamesInUse(ViewActive, now)
	if len(usage.Kinds) != 2 || usage.Kinds[0].Names != names || usage.Kinds[1].Names != 1 {
		t.Errorf("names counted: %+v", usage.Kinds)
	}
}

// Names too long to show whole are still counted whole: two that differ
// only past the point where they are cut for display are two names, and
// the summary has the name itself, not the shortened one.
func TestNamesInUseCountsLongNamesWhole(t *testing.T) {
	src := &fakeSource{certs: map[string]RawCertificate{}}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	long := "spiffe://internal.example/" + strings.Repeat("a", maxText)
	one, _ := url.Parse(long + "/one")
	two, _ := url.Parse(long + "/two")
	longCN := strings.Repeat("service ", 40) + "one"
	src.add(RawCertificate{Serial: "1", DER: newDER(t, "1", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: longCN}
		c.DNSNames = []string{"short.internal.example"}
		c.URIs = []*url.URL{one, two}
	})})
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	// For showing, the names are bounded as before.
	c := snap.Certificates[0]
	if len(c.Names) != 3 || c.MoreNames != 0 || c.Names[1].Value != clip(one.String()) || c.Names[1].Value == one.String() || c.Subject == longCN {
		t.Fatalf("the names kept for showing: %+v, subject %d characters", c.Names, len(c.Subject))
	}
	usage := snap.NamesInUse(ViewActive, now)
	want := []KindUsage{
		{Kind: DNS, Names: 1, Groups: []NameGroup{{Label: "internal.example", Certificates: 1, Names: []NameUse{{"short.internal.example", 1}}}}},
		{Kind: URI, Names: 2, Groups: []NameGroup{{Label: "spiffe://internal.example", Certificates: 1, Names: []NameUse{{one.String(), 1}, {two.String(), 1}}}}},
		{Kind: CommonName, Names: 1, Groups: []NameGroup{{Label: "", Certificates: 1, Names: []NameUse{{longCN, 1}}}}},
	}
	if !reflect.DeepEqual(usage.Kinds, want) {
		t.Errorf("long names in use:\n got %+v\nwant %+v", usage.Kinds, want)
	}
}
