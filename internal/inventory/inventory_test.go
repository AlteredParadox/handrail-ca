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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is testdata/devca.json: the rows of a freshly seeded development
// CA (deploy/dev/capture-fixtures.sh), exactly as step-ca wrote them.
type fixture struct {
	Captured     time.Time `json:"captured"`
	Certificates []struct {
		Serial string  `json:"serial"`
		DER    string  `json:"der"`
		Data   *string `json:"data"`
	} `json:"certificates"`
	Revocations []struct {
		Serial string `json:"serial"`
		JSON   string `json:"json"`
	} `json:"revocations"`
}

func loadFixture(t *testing.T) (*fixture, *fakeSource) {
	t.Helper()
	data, err := os.ReadFile("testdata/devca.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{certs: map[string]RawCertificate{}}
	for _, c := range f.Certificates {
		der, err := base64.StdEncoding.DecodeString(c.DER)
		if err != nil {
			t.Fatal(err)
		}
		row := RawCertificate{Serial: c.Serial, DER: der}
		if c.Data != nil {
			row.Data = []byte(*c.Data)
		}
		src.certs[c.Serial] = row
	}
	for _, r := range f.Revocations {
		src.revocations = append(src.revocations, RawRevocation{Serial: r.Serial, JSON: []byte(r.JSON)})
	}
	return &f, src
}

// fakeSource is a Source over rows held in memory, with switches to fail.
type fakeSource struct {
	mu          sync.Mutex
	certs       map[string]RawCertificate
	revocations []RawRevocation

	serialsErr, certsErr, revocationsErr error
	// fetched records every serial asked for, in order.
	fetched []string
	batches []int
}

func (f *fakeSource) Describe() string { return "a test source" }

func (f *fakeSource) Serials(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.serialsErr != nil {
		return nil, f.serialsErr
	}
	var serials []string
	for s := range f.certs {
		serials = append(serials, s)
	}
	return serials, nil
}

func (f *fakeSource) Certificates(_ context.Context, serials []string) ([]RawCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certsErr != nil {
		return nil, f.certsErr
	}
	f.fetched = append(f.fetched, serials...)
	f.batches = append(f.batches, len(serials))
	var rows []RawCertificate
	for _, s := range serials {
		if row, ok := f.certs[s]; ok {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (f *fakeSource) Revocations(context.Context) ([]RawRevocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revocationsErr != nil {
		return nil, f.revocationsErr
	}
	return append([]RawRevocation(nil), f.revocations...), nil
}

func (f *fakeSource) add(row RawCertificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[row.Serial] = row
}

// newInventory is an inventory over src whose clock is the given time.
func newInventory(src Source, now *time.Time) *Inventory {
	inv := New(src)
	inv.SetClock(func() time.Time { return *now })
	return inv
}

func bySubject(s *Snapshot) map[string][]*Certificate {
	m := map[string][]*Certificate{}
	for _, c := range s.Certificates {
		m[c.Subject] = append(m[c.Subject], c)
	}
	return m
}

func TestReadsARealCAsRows(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	inv := newInventory(src, &now)

	// Before the first read: nothing, and nothing claimed.
	empty := inv.Snapshot()
	if len(empty.Certificates) != 0 || !empty.State.LoadedAt.IsZero() || empty.State.RevocationsKnown || empty.State.Source != "a test source" {
		t.Fatalf("a new inventory's state = %+v", empty.State)
	}

	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	if len(snap.Certificates) != 16 {
		t.Fatalf("%d certificates, want the 16 of the fixture", len(snap.Certificates))
	}
	if st := snap.State; !st.LoadedAt.Equal(now) || st.Problem != "" || !st.RevocationsKnown || st.OrphanRevocations != 0 {
		t.Errorf("state = %+v", st)
	}
	for _, c := range snap.Certificates {
		if c.Problem != "" {
			t.Errorf("%s (%s) is unreadable: %s", c.Serial, c.Subject, c.Problem)
		}
	}
	// Latest end of validity first.
	for i := 1; i < len(snap.Certificates); i++ {
		if snap.Certificates[i].NotAfter.After(snap.Certificates[i-1].NotAfter) {
			t.Fatalf("certificates are not sorted by end of validity at %d", i)
		}
	}

	certs := bySubject(snap)
	web2 := certs["web2.handrail.test"]
	if len(web2) != 1 {
		t.Fatalf("web2: %d certificates", len(web2))
	}
	if got := fmt.Sprint(web2[0].Names); got != "[{DNS web2.handrail.test} {IP 10.20.0.14}]" {
		t.Errorf("web2 names = %s", got)
	}
	if p := web2[0].Provisioner; p.Name != "handrail" || p.Type != "JWK" || p.ID == "" {
		t.Errorf("web2 provisioner = %+v", p)
	}
	if web2[0].NotAfter.Sub(web2[0].NotBefore) < 719*time.Hour {
		t.Errorf("web2 validity = %v to %v", web2[0].NotBefore, web2[0].NotAfter)
	}
	// What other provisioners issued is there too: ACME, and the CA's own
	// short-lived admin certificates.
	if c := certs["acme1.handrail.test"]; len(c) != 1 || c[0].Provisioner.Type != "ACME" || c[0].Provisioner.Name != "acme" {
		t.Errorf("acme1 = %+v", c)
	}
	if c := certs["step"]; len(c) != 5 || c[0].Provisioner.Name != "Admin JWK" {
		t.Errorf("admin certificates: %d", len(c))
	}
	// A renewal is a second certificate under the same name.
	if c := certs["renewed.handrail.test"]; len(c) != 2 || c[0].Serial == c[1].Serial {
		t.Errorf("renewed: %d certificates", len(c))
	}

	// The one revocation, as step-ca recorded it.
	gone := certs["gone.handrail.test"][0]
	rev := snap.Revocation(gone.Serial)
	if rev == nil || rev.ReasonCode != 1 || rev.Reason != "development seed" || rev.Problem != "" || rev.ACME || rev.MTLS ||
		rev.RevokedAt.IsZero() || rev.ProvisionerID != gone.Provisioner.ID {
		t.Errorf("revocation of gone = %+v", rev)
	}
	if snap.Revocation(web2[0].Serial) != nil {
		t.Error("web2 is recorded as revoked")
	}
}

func TestStatusOverTime(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	certs := bySubject(snap)
	status := func(subject string, at time.Time) Status { return snap.Status(certs[subject][0], at) }

	// The seed issues brief1 for five minutes, soon for thirty, web1 for
	// ninety days; the capture is a few minutes after the seed.
	at := f.Captured
	for subject, want := range map[string]Status{
		"web1.handrail.test":  StatusValid,
		"soon.handrail.test":  StatusValid, // thirty minutes in all, more than a third left
		"gone.handrail.test":  StatusRevoked,
		"acme1.handrail.test": StatusValid,
	} {
		if got := status(subject, at); got != want {
			t.Errorf("at capture, %s is %v, want %v", subject, got, want)
		}
	}
	// A short-lived certificate is expiring in its last third, not from
	// the day it is issued.
	brief := certs["brief1.handrail.test"][0]
	if got := snap.Status(brief, brief.NotBefore.Add(time.Minute)); got != StatusValid {
		t.Errorf("a five-minute certificate, one minute old, is %v", got)
	}
	if got := snap.Status(brief, brief.NotAfter.Add(-time.Minute)); got != StatusExpiring {
		t.Errorf("a five-minute certificate with a minute left is %v", got)
	}
	if got := snap.Status(brief, brief.NotAfter); got != StatusExpired {
		t.Errorf("at the instant its validity ends it is %v, want expired", got)
	}
	if got := snap.Status(brief, brief.NotBefore.Add(-time.Second)); got != StatusNotYetValid {
		t.Errorf("before its validity starts it is %v", got)
	}
	// A long-lived one is expiring inside the window.
	web1 := certs["web1.handrail.test"][0]
	if got := snap.Status(web1, web1.NotAfter.Add(-DefaultExpiringWindow-time.Hour)); got != StatusValid {
		t.Errorf("31 days before its end, web1 is %v", got)
	}
	if got := snap.Status(web1, web1.NotAfter.Add(-DefaultExpiringWindow+time.Hour)); got != StatusExpiring {
		t.Errorf("29 days before its end, web1 is %v", got)
	}
	// Revoked stays revoked after it would have expired.
	gone := certs["gone.handrail.test"][0]
	if got := snap.Status(gone, gone.NotAfter.Add(time.Hour)); got != StatusRevoked {
		t.Errorf("a revoked certificate past its end is %v", got)
	}

	counts := snap.Counts(f.Captured.Add(time.Hour))
	if counts[StatusRevoked] != 1 || counts[StatusExpired] != 8 || counts[StatusValid]+counts[StatusExpiring] != 7 {
		t.Errorf("an hour after capture: %v", counts)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 16 {
		t.Errorf("counts add up to %d", total)
	}
	for s, want := range map[Status]string{StatusUnknown: "unknown", StatusUnreadable: "unreadable", StatusRevoked: "revoked",
		StatusExpired: "expired", StatusNotYetValid: "not yet valid", StatusExpiring: "expiring", StatusValid: "valid"} {
		if s.String() != want {
			t.Errorf("Status(%d) = %q", s, s)
		}
	}
}

// Nothing is called valid on the strength of dates alone: until the
// revocation table has been read, a certificate inside its validity is
// "unknown". What does not depend on revocation is still said.
func TestNoRevocationsNoValid(t *testing.T) {
	f, src := loadFixture(t)
	src.revocationsErr = errors.New("permission denied for table revoked_x509_certs")
	now := f.Captured
	inv := newInventory(src, &now)

	err := inv.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reading revocations") {
		t.Fatalf("Refresh = %v", err)
	}
	snap := inv.Snapshot()
	st := snap.State
	if !st.LoadedAt.IsZero() || st.RevocationsKnown || !st.AttemptedAt.Equal(now) || !strings.Contains(st.Problem, "permission denied") {
		t.Errorf("state = %+v", st)
	}
	if len(snap.Certificates) != 0 {
		t.Errorf("a failed first read left %d certificates", len(snap.Certificates))
	}

	// With the certificates read earlier and the revocations lost since,
	// the picture is the earlier one, with its age.
	src.revocationsErr = nil
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	loaded := now
	now = now.Add(time.Minute)
	src.revocationsErr = errors.New("connection reset")
	if err := inv.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded without revocations")
	}
	snap = inv.Snapshot()
	if st := snap.State; !st.LoadedAt.Equal(loaded) || !st.AttemptedAt.Equal(now) || st.Problem == "" || !st.RevocationsKnown {
		t.Errorf("state after a failed re-read = %+v", st)
	}
	if len(snap.Certificates) != 16 || snap.Revocation(bySubject(snap)["gone.handrail.test"][0].Serial) == nil {
		t.Error("the earlier picture was not kept")
	}

	// A snapshot that never had revocations says unknown, not valid.
	never := &Snapshot{Certificates: snap.Certificates, revoked: map[string]*Revocation{}, window: DefaultExpiringWindow}
	web1 := bySubject(snap)["web1.handrail.test"][0]
	if got := never.Status(web1, f.Captured); got != StatusUnknown {
		t.Errorf("without revocations, web1 is %v, want unknown", got)
	}
	brief := bySubject(snap)["brief1.handrail.test"][0]
	if got := never.Status(brief, brief.NotAfter.Add(time.Hour)); got != StatusExpired {
		t.Errorf("without revocations, an expired certificate is %v", got)
	}
}

func TestRefreshFailuresKeepThePicture(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := inv.Snapshot()

	for name, breakIt := range map[string]func(){
		"listing": func() { src.serialsErr = errors.New("dial tcp: connection refused") },
		"certificates": func() {
			src.certsErr = errors.New("statement timeout")
			src.add(newRow(t, "5001", "new.handrail.test"))
		},
	} {
		src.serialsErr, src.certsErr = nil, nil
		breakIt()
		now = now.Add(time.Minute)
		if err := inv.Refresh(context.Background()); err == nil {
			t.Fatalf("%s: Refresh succeeded", name)
		}
		snap := inv.Snapshot()
		if len(snap.Certificates) != len(before.Certificates) || snap.State.Problem == "" || !snap.State.LoadedAt.Equal(before.State.LoadedAt) {
			t.Errorf("%s: %d certificates, state %+v", name, len(snap.Certificates), snap.State)
		}
	}
	// And it recovers by itself.
	src.serialsErr, src.certsErr = nil, nil
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snap := inv.Snapshot(); len(snap.Certificates) != 17 || snap.State.Problem != "" || !snap.State.LoadedAt.Equal(now) {
		t.Errorf("after recovery: %d certificates, state %+v", len(snap.Certificates), snap.State)
	}
}

// A certificate never changes once issued, so a refresh fetches only what
// it has not seen, in bounded batches.
func TestRefreshFetchesOnlyWhatIsNew(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	inv := newInventory(src, &now)
	ctx := context.Background()
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if len(src.fetched) != 16 {
		t.Fatalf("first read fetched %d certificates", len(src.fetched))
	}
	src.fetched, src.batches = nil, nil
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if len(src.fetched) != 0 {
		t.Errorf("a second read fetched %v again", src.fetched)
	}

	for i := range fetchBatch + 3 {
		src.add(newRow(t, fmt.Sprint(900000+i), fmt.Sprintf("host%d.handrail.test", i)))
	}
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(src.batches) != fmt.Sprintf("[%d 3]", fetchBatch) {
		t.Errorf("batches = %v", src.batches)
	}
	if n := len(inv.Snapshot().Certificates); n != 16+fetchBatch+3 {
		t.Errorf("%d certificates after the additions", n)
	}

	// A row that has gone from the database goes from the inventory.
	delete(src.certs, "900000")
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(inv.Snapshot().Certificates); n != 16+fetchBatch+2 {
		t.Errorf("%d certificates after a row was removed", n)
	}
	// A serial listed but gone by the time it is fetched is left out, not
	// kept as an empty entry.
	src.mu.Lock()
	src.certs["900999"] = RawCertificate{}
	src.mu.Unlock()
	src.certs["900999"] = RawCertificate{Serial: "something-else"}
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range inv.Snapshot().Certificates {
		if c == nil || c.Serial == "900999" {
			t.Errorf("a vanished row is in the inventory: %+v", c)
		}
	}
}

// newRow makes a certificate row with the given serial and DNS name.
func newRow(t *testing.T, serial, name string) RawCertificate {
	t.Helper()
	return RawCertificate{Serial: serial, DER: newDER(t, serial, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: name}
		c.DNSNames = []string{name}
	}), Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`)}
}

var testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

func newDER(t *testing.T, serial string, shape func(*x509.Certificate)) []byte {
	t.Helper()
	n, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		t.Fatalf("serial %q", serial)
	}
	tmpl := &x509.Certificate{
		SerialNumber: n,
		NotBefore:    time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC),
	}
	shape(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testKey.PublicKey, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Rows are another program's data. One that is not what it should be is
// kept and shown as unreadable, with what could still be learned about it.
func TestUnreadableRowsAreKeptAndSaidSo(t *testing.T) {
	good := newRow(t, "1001", "ok.handrail.test")
	rows := map[string]RawCertificate{
		"1001": good,
		"1002": {Serial: "1002", DER: []byte("not DER at all"), Data: good.Data},
		"1003": {Serial: "1003", TooLarge: true},
		"1004": {Serial: "1004", DER: nil},
		// The certificate stored under 1005 says it is 1001.
		"1005":                   {Serial: "1005", DER: good.DER},
		"not-a-serial":           {Serial: "not-a-serial", DER: good.DER},
		strings.Repeat("9", 500): {Serial: strings.Repeat("9", 500), DER: good.DER},
		"1006\xff\xfe":           {Serial: "1006\xff\xfe", DER: good.DER},
	}
	src := &fakeSource{certs: rows}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	if len(snap.Certificates) != len(rows) {
		t.Fatalf("%d of %d rows are in the inventory", len(snap.Certificates), len(rows))
	}
	// The readable one first, the rest after it.
	if first := snap.Certificates[0]; first.Serial != "1001" || first.Problem != "" {
		t.Errorf("first = %+v", first)
	}
	want := map[string]string{
		"1002": "is not a certificate",
		"1003": "too large",
		"1004": "is not a certificate",
		"1005": "not the serial number of the certificate stored under it",
	}
	unreadable := 0
	for _, c := range snap.Certificates[1:] {
		unreadable++
		if c.Problem == "" || c.Subject != "" || len(c.Names) != 0 || !c.NotAfter.IsZero() {
			t.Errorf("%q: problem %q, subject %q", c.Serial, c.Problem, c.Subject)
		}
		if snap.Status(c, now) != StatusUnreadable {
			t.Errorf("%q has status %v", c.Serial, snap.Status(c, now))
		}
		if w, ok := want[c.Serial]; ok && !strings.Contains(c.Problem, w) {
			t.Errorf("%s: problem %q, want %q", c.Serial, c.Problem, w)
		}
		if len([]rune(c.Serial)) > maxSerial+1 {
			t.Errorf("a key of %d characters was kept whole", len(c.Serial))
		}
	}
	if unreadable != len(rows)-1 {
		t.Errorf("%d unreadable", unreadable)
	}
	// What the CA recorded about the issuer survives an unreadable value.
	for _, c := range snap.Certificates {
		if c.Serial == "1002" && c.Provisioner.Name != "handrail" {
			t.Errorf("1002's provisioner = %+v", c.Provisioner)
		}
	}
	if n := snap.Counts(now)[StatusUnreadable]; n != len(rows)-1 {
		t.Errorf("Counts: %d unreadable", n)
	}
}

func TestSummaryIsBounded(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".handrail.test"
	u, _ := url.Parse("spiffe://handrail.test/workload/one")
	der := newDER(t, "2001", func(c *x509.Certificate) {
		c.Subject = pkix.Name{Organization: []string{"Example"}, OrganizationalUnit: []string{strings.Repeat("unit ", 200)}}
		for i := range maxNames + 20 {
			c.DNSNames = append(c.DNSNames, fmt.Sprintf("n%d.%s", i, long))
		}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.0.9"), net.ParseIP("2001:db8::9")}
		c.EmailAddresses = []string{"ops@handrail.test"}
		c.URIs = []*url.URL{u}
	})
	c := summarise(RawCertificate{Serial: "2001", DER: der, Data: []byte(`{"provisioner":{"id":"` + strings.Repeat("x", 5000) + `","name":"n","type":"JWK"},"ra":{}}`)})
	if c.Problem != "" {
		t.Fatal(c.Problem)
	}
	// No common name: the whole subject, bounded.
	if !strings.HasPrefix(c.Subject, "OU=unit unit") || len([]rune(c.Subject)) != maxText+1 {
		t.Errorf("subject = %d characters: %.60s", len([]rune(c.Subject)), c.Subject)
	}
	if len(c.Names) != maxNames || c.MoreNames != 20+4 {
		t.Errorf("%d names kept, %d more", len(c.Names), c.MoreNames)
	}
	if len([]rune(c.Provisioner.ID)) > maxText+1 {
		t.Errorf("provisioner id of %d characters kept", len(c.Provisioner.ID))
	}

	// Every kind of name, in a certificate small enough to keep them all.
	der = newDER(t, "2002", func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "all-kinds"}
		c.DNSNames = []string{"a.handrail.test"}
		c.IPAddresses = []net.IP{net.ParseIP("10.20.0.9"), net.ParseIP("2001:db8::9")}
		c.EmailAddresses = []string{"ops@handrail.test"}
		c.URIs = []*url.URL{u}
	})
	c = summarise(RawCertificate{Serial: "2002", DER: der})
	if got := fmt.Sprint(c.Names); got != "[{DNS a.handrail.test} {IP 10.20.0.9} {IP 2001:db8::9} {email ops@handrail.test} {URI spiffe://handrail.test/workload/one}]" {
		t.Errorf("names = %s", got)
	}
	if c.Provisioner != (Provisioner{}) {
		t.Errorf("a provisioner out of nowhere: %+v", c.Provisioner)
	}
	// An issuance record that is not what step-ca writes is ignored; the
	// certificate is still a certificate.
	for _, data := range []string{`not json`, `{"provisioner":"handrail"}`, `[]`, `{}`} {
		c = summarise(RawCertificate{Serial: "2002", DER: der, Data: []byte(data)})
		if c.Problem != "" || c.Subject != "all-kinds" || c.Provisioner != (Provisioner{}) {
			t.Errorf("with issuance record %q: %+v", data, c)
		}
	}
}

func TestRevocationRecords(t *testing.T) {
	src := &fakeSource{certs: map[string]RawCertificate{"3001": newRow(t, "3001", "a.handrail.test"), "3002": newRow(t, "3002", "b.handrail.test")}}
	src.revocations = []RawRevocation{
		{Serial: "3001", JSON: []byte(`{"Serial":"3001","ProvisionerID":"acme/acme","ReasonCode":4,"Reason":"` + strings.Repeat("r", 1000) + `","RevokedAt":"2026-11-10T08:00:00+02:00","ExpiresAt":"2027-01-01T00:00:00Z","TokenID":"t","MTLS":true,"ACME":true}`)},
		// A record that cannot be read: the CA still treats the
		// certificate as revoked, and so does the inventory.
		{Serial: "3002", JSON: nil},
		// step-ca records a revocation for any serial it is asked to
		// revoke, issued or not.
		{Serial: "777", JSON: []byte(`{"Serial":"777","ReasonCode":0}`)},
		{Serial: "778", JSON: []byte(`{"RevokedAt":"yesterday"}`)},
	}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	if snap.State.OrphanRevocations != 2 {
		t.Errorf("%d revocations without a certificate, want 2", snap.State.OrphanRevocations)
	}
	r := snap.Revocation("3001")
	if r == nil || r.ReasonCode != 4 || !r.ACME || !r.MTLS || r.ProvisionerID != "acme/acme" || len([]rune(r.Reason)) != maxText+1 ||
		!r.RevokedAt.Equal(time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)) || r.RevokedAt.Location() != time.UTC {
		t.Errorf("revocation of 3001 = %+v", r)
	}
	for _, serial := range []string{"3002", "778"} {
		if r := snap.Revocation(serial); r == nil || !strings.Contains(r.Problem, "could not be read") {
			t.Errorf("revocation of %s = %+v", serial, r)
		}
	}
	for _, c := range snap.Certificates {
		if snap.Status(c, now) != StatusRevoked {
			t.Errorf("%s is %v", c.Serial, snap.Status(c, now))
		}
	}
	if snap.Revocation("no such serial") != nil {
		t.Error("a revocation out of nowhere")
	}
}

func TestRunRefreshesUntilStopped(t *testing.T) {
	_, src := loadFixture(t)
	inv := New(src)
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var reported []error
	done := make(chan struct{})
	src.serialsErr = errors.New("database is starting up")
	go func() {
		inv.Run(ctx, 5*time.Millisecond, func(err error) {
			mu.Lock()
			reported = append(reported, err)
			mu.Unlock()
		})
		close(done)
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(reported) >= 2 })
	// The database comes up: the next round reads it, with nobody asking.
	src.mu.Lock()
	src.serialsErr = nil
	src.mu.Unlock()
	waitFor(t, func() bool { return len(inv.Snapshot().Certificates) == 16 })
	// Every round is reported: the failures, then the first success.
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return reported[len(reported)-1] == nil })
	mu.Lock()
	if reported[0] == nil || reported[1] == nil {
		t.Errorf("the first rounds were reported as %v, %v", reported[0], reported[1])
	}
	mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if s := inv.Snapshot().State; s.Problem != "" || s.LoadedAt.IsZero() {
		t.Errorf("state = %+v", s)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 1000 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting")
}

func TestDER(t *testing.T) {
	f, src := loadFixture(t)
	src.add(RawCertificate{Serial: "5005", DER: []byte("junk")})
	now := f.Captured
	inv := newInventory(src, &now)
	ctx := context.Background()

	// Nothing can be fetched that the inventory has not listed.
	if _, err := inv.DER(ctx, f.Certificates[0].Serial); !errors.Is(err, ErrNotFound) {
		t.Errorf("before the first read: %v", err)
	}
	if err := inv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap := inv.Snapshot()
	web1 := bySubject(snap)["web1.handrail.test"][0]
	if snap.Certificate(web1.Serial) != web1 {
		t.Error("Certificate(serial) is not the summary in the list")
	}
	if snap.Certificate("12345") != nil || snap.Certificate("") != nil {
		t.Error("a summary out of nowhere")
	}

	der, err := inv.DER(ctx, web1.Serial)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.Subject.CommonName != "web1.handrail.test" || cert.SerialNumber.String() != web1.Serial {
		t.Fatalf("DER is not web1's certificate: %v", err)
	}

	for _, serial := range []string{"12345", "", "not-a-serial", web1.Serial + "0", "' OR 1=1 --"} {
		if _, err := inv.DER(ctx, serial); !errors.Is(err, ErrNotFound) {
			t.Errorf("DER(%q) = %v, want ErrNotFound", serial, err)
		}
	}
	// A row that is not a certificate: said so, with the reason.
	if _, err := inv.DER(ctx, "5005"); !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "is not a certificate") {
		t.Errorf("DER of an unreadable row: %v", err)
	}

	// What is fetched is checked again. If the row now holds something
	// else than the certificate that was listed, it is not handed out.
	src.mu.Lock()
	other := bySubject(snap)["web2.handrail.test"][0]
	swapped := src.certs[other.Serial]
	swapped.Serial = web1.Serial
	original := src.certs[web1.Serial]
	src.certs[web1.Serial] = swapped
	src.mu.Unlock()
	if _, err := inv.DER(ctx, web1.Serial); !errors.Is(err, ErrUnreadable) {
		t.Errorf("another certificate stored under the serial: %v, want ErrUnreadable", err)
	}
	src.mu.Lock()
	src.certs[web1.Serial] = RawCertificate{Serial: web1.Serial, DER: []byte("junk")}
	src.mu.Unlock()
	if _, err := inv.DER(ctx, web1.Serial); !errors.Is(err, ErrUnreadable) {
		t.Errorf("junk stored under the serial: %v, want ErrUnreadable", err)
	}
	// The row has gone since it was listed.
	src.mu.Lock()
	delete(src.certs, web1.Serial)
	src.mu.Unlock()
	if _, err := inv.DER(ctx, web1.Serial); !errors.Is(err, ErrNotFound) {
		t.Errorf("a row that has gone: %v, want ErrNotFound", err)
	}
	// The database cannot be asked.
	src.mu.Lock()
	src.certs[web1.Serial] = original
	src.certsErr = errors.New("connection refused")
	src.mu.Unlock()
	if _, err := inv.DER(ctx, web1.Serial); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("with the database down: %v", err)
	}
}

// gatedSource holds each listing of serials until the test lets it go on,
// or until its caller gives up.
type gatedSource struct {
	*fakeSource
	entered, release chan struct{}
}

func (g *gatedSource) Serials(ctx context.Context) ([]string, error) {
	g.entered <- struct{}{}
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.fakeSource.Serials(ctx)
}

// A refresh asked for while another is reading waits its turn only as long
// as its caller does, and one that is given up leaves the state alone: it
// has learned nothing about the database.
func TestRefreshThatIsGivenUpChangesNothing(t *testing.T) {
	f, src := loadFixture(t)
	gate := &gatedSource{fakeSource: src, entered: make(chan struct{}, 8), release: make(chan struct{})}
	inv := New(gate)
	now := f.Captured
	inv.SetClock(func() time.Time { return now })
	within := func(what string, done <-chan error) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not return", what)
			return nil
		}
	}
	start := func(ctx context.Context) <-chan error {
		done := make(chan error, 1)
		go func() { done <- inv.Refresh(ctx) }()
		return done
	}

	// The background read is under way and slow.
	background := start(context.Background())
	<-gate.entered

	// Someone asks for a read and leaves; someone else's time runs out.
	// Both return at once, though the first read still holds its turn.
	left, leave := context.WithCancel(context.Background())
	waiting := start(left)
	leave()
	if err := within("a refresh whose caller left", waiting); !errors.Is(err, context.Canceled) {
		t.Errorf("a refresh whose caller left returned %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := within("a refresh out of time", start(short)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a refresh that ran out of time waiting returned %v", err)
	}
	// One already given up when it asks does not read either.
	if err := inv.Refresh(left); !errors.Is(err, context.Canceled) {
		t.Errorf("a refresh with a finished context returned %v", err)
	}
	if st := inv.Snapshot().State; st.Problem != "" || !st.AttemptedAt.IsZero() {
		t.Errorf("refreshes that never had their turn changed the state: %+v", st)
	}

	// The background read finishes, and its result stands.
	gate.release <- struct{}{}
	if err := within("the background refresh", background); err != nil {
		t.Fatal(err)
	}
	good := inv.Snapshot().State
	if good.Problem != "" || !good.LoadedAt.Equal(now) || len(inv.Snapshot().Certificates) != 16 {
		t.Fatalf("after the background read: %+v", good)
	}
	select {
	case <-gate.entered:
		t.Fatal("a refresh that was given up read the database afterwards")
	default:
	}

	// Given up while reading: still nothing learned, nothing changed.
	now = now.Add(time.Minute)
	reading, stop := context.WithCancel(context.Background())
	done := start(reading)
	<-gate.entered
	stop()
	if err := within("a refresh cancelled while reading", done); !errors.Is(err, context.Canceled) {
		t.Errorf("a refresh cancelled while reading returned %v", err)
	}
	if st := inv.Snapshot().State; st != good {
		t.Errorf("a cancelled read changed the state: %+v, was %+v", st, good)
	}

	// Out of time while reading is a fact about the database: the picture
	// is kept, and the state says the last attempt failed.
	slow, cancelSlow := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSlow()
	if err := within("a refresh out of time while reading", start(slow)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a read that ran out of time returned %v", err)
	}
	st := inv.Snapshot().State
	if !strings.Contains(st.Problem, "deadline exceeded") || !st.LoadedAt.Equal(good.LoadedAt) || !st.AttemptedAt.Equal(now) || len(inv.Snapshot().Certificates) != 16 {
		t.Errorf("after a read that ran out of time: %+v", st)
	}
}
