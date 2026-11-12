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

// Package inventory is handrail-ca's picture of what the CA has issued:
// every certificate in the CA's database, summarised in memory, with what
// the CA recorded about who issued it and whether it was revoked.
//
// step-ca has no API that lists certificates, so the picture is read from
// the CA's own database through a Source, with an account that can read
// three tables and change nothing (docs/PLAN.md, D1 and section 3). The
// rows are another program's data: each is validated and bounded, and one
// that cannot be read is kept and shown as unreadable, never dropped.
package inventory

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Source is where the rows come from: the three tables of the CA's
// database that hold issued certificates, what issued them, and
// revocations.
type Source interface {
	// Serials lists the key of every row in the certificate table. Keys
	// are the certificates' serial numbers as decimal strings.
	Serials(ctx context.Context) ([]string, error)
	// Certificates returns the rows for the given keys. A key with no row
	// is simply absent from the answer.
	Certificates(ctx context.Context, serials []string) ([]RawCertificate, error)
	// Revocations returns every row of the revocation table.
	Revocations(ctx context.Context) ([]RawRevocation, error)
	// Describe says where the rows come from, for the status page. It
	// carries no credentials.
	Describe() string
}

// RawCertificate is one row of the certificate table, joined with the row
// of the same key in the table that records the provisioner.
type RawCertificate struct {
	Serial string
	// DER is the certificate. Nil with TooLarge set when the stored value
	// was larger than a certificate has any business being.
	DER      []byte
	TooLarge bool
	// Data is the JSON the CA stored about the issuance, nil if none.
	Data []byte
}

// RawRevocation is one row of the revocation table.
type RawRevocation struct {
	Serial string
	JSON   []byte
}

// NameKind is the kind of a subject alternative name.
type NameKind string

// The kinds of name a certificate can carry.
const (
	DNS   NameKind = "DNS"
	IP    NameKind = "IP"
	Email NameKind = "email"
	URI   NameKind = "URI"
)

// Name is one subject alternative name.
type Name struct {
	Kind  NameKind
	Value string
}

// Provisioner is what the CA recorded about the provisioner that issued a
// certificate. All empty when it recorded nothing.
type Provisioner struct {
	ID, Name, Type string
}

// Certificate is the summary kept in memory for one issued certificate. It
// is never changed after it is built; the certificate itself is fetched
// again from the Source when its detail is wanted.
type Certificate struct {
	// Serial is the decimal serial number, the row's key.
	Serial string
	// SerialHex is the same number in lower-case hexadecimal, the form
	// most tools print. Empty for a row that could not be read.
	SerialHex string
	// Subject is the common name, or the whole subject when there is none.
	Subject string
	// Names are the subject alternative names, at most maxNames of them;
	// MoreNames counts the rest.
	Names     []Name
	MoreNames int
	NotBefore time.Time
	NotAfter  time.Time
	// Provisioner is who issued it, as far as the CA recorded.
	Provisioner Provisioner
	// Problem is set when the row could not be read as a certificate. The
	// other fields except Serial are then empty.
	Problem string

	// haystack is everything the certificate can be found by, in lower
	// case, one item to a line: the serial in decimal and hexadecimal, the
	// subject, and every subject alternative name, including the ones
	// beyond maxNames that Names leaves out. A certificate that carries a
	// name must be found by it, however many others it carries. It is as
	// bounded as the certificate itself, which the Source caps.
	haystack string
}

// Revocation is what the CA recorded when a certificate was revoked.
type Revocation struct {
	ReasonCode    int
	Reason        string
	RevokedAt     time.Time
	ProvisionerID string
	// ACME and MTLS say how the revocation was asked for.
	ACME, MTLS bool
	// Problem is set when the row exists but could not be read. The
	// certificate still counts as revoked: the CA will treat it so.
	Problem string
}

// Status is what can be said about a certificate at a given moment.
type Status int

// The statuses, most severe first after Unknown. A certificate has exactly
// one: the first that applies.
const (
	// StatusUnknown: it looks valid by its dates, but the revocation table
	// could not be read, so it may have been revoked.
	StatusUnknown Status = iota
	StatusUnreadable
	StatusRevoked
	StatusExpired
	StatusNotYetValid
	StatusExpiring
	StatusValid
)

func (s Status) String() string {
	switch s {
	case StatusUnreadable:
		return "unreadable"
	case StatusRevoked:
		return "revoked"
	case StatusExpired:
		return "expired"
	case StatusNotYetValid:
		return "not yet valid"
	case StatusExpiring:
		return "expiring"
	case StatusValid:
		return "valid"
	}
	return "unknown"
}

// Limits on what is read and kept.
const (
	// fetchBatch is how many new certificates are fetched per query.
	fetchBatch = 500
	// maxNames is how many names of one certificate are kept in memory.
	maxNames = 50
	// maxText bounds each string taken out of a certificate or a row.
	maxText = 256
	// maxSerial bounds a row key: a serial number has at most 49 digits.
	maxSerial = 64

	// DefaultExpiringWindow is how long before its end a certificate is
	// called expiring, unless a third of its lifetime is shorter.
	DefaultExpiringWindow = 30 * 24 * time.Hour
)

// State says how current the inventory is.
type State struct {
	// Source describes where the rows come from.
	Source string
	// LoadedAt is when the inventory was last read completely; zero if it
	// never has been.
	LoadedAt time.Time
	// AttemptedAt is when a read was last tried.
	AttemptedAt time.Time
	// Problem is why the last attempt failed, empty if it did not. With a
	// problem, what is shown is what was read at LoadedAt.
	Problem string
	// RevocationsKnown is false when the revocation table has not been
	// read successfully: no certificate may then be called valid.
	RevocationsKnown bool
	// OrphanRevocations counts revocation rows whose serial is not among
	// the certificates. step-ca records a revocation for any serial it is
	// asked to revoke, issued or not.
	OrphanRevocations int
}

// Snapshot is the inventory at one moment. It is shared, not copied: do
// not change what it holds.
type Snapshot struct {
	State State
	// Certificates are sorted by the end of their validity, latest first;
	// unreadable rows come last.
	Certificates []*Certificate
	// bySerial finds a row by its key in the CA's database, which for a
	// certificate is its serial number. oddKeys holds the key of each row
	// whose Serial is not its key: a key that is not a serial number is
	// kept bounded for showing, and may be shortened. Nearly always empty.
	bySerial map[string]*Certificate
	oddKeys  map[*Certificate]string
	revoked  map[string]*Revocation
	window   time.Duration
}

// Certificate returns the summary kept under a key of the CA's database:
// for a certificate, its serial number in decimal. Nil if the inventory
// has no such row.
func (s *Snapshot) Certificate(key string) *Certificate { return s.bySerial[key] }

// Key is the key of a summary's row in the CA's database: what
// Certificate finds it by. For a certificate that is its serial number. A
// row that is not a certificate can have any key, and its Serial is that
// key made fit to show, which is not always the key itself.
func (s *Snapshot) Key(c *Certificate) string {
	if key, odd := s.oddKeys[c]; odd {
		return key
	}
	return c.Serial
}

// oddKeysOf finds the rows whose Serial is not their key.
func oddKeysOf(certs map[string]*Certificate) map[*Certificate]string {
	var odd map[*Certificate]string
	for key, c := range certs {
		if key == c.Serial {
			continue
		}
		if odd == nil {
			odd = map[*Certificate]string{}
		}
		odd[c] = key
	}
	return odd
}

// Revocation returns the revocation recorded for a serial, nil if none.
func (s *Snapshot) Revocation(serial string) *Revocation { return s.revoked[serial] }

// Status says what a certificate's status is at now.
func (s *Snapshot) Status(c *Certificate, now time.Time) Status {
	switch {
	case c.Problem != "":
		return StatusUnreadable
	case s.revoked[c.Serial] != nil:
		return StatusRevoked
	case !now.Before(c.NotAfter):
		return StatusExpired
	case now.Before(c.NotBefore):
		return StatusNotYetValid
	case !s.State.RevocationsKnown:
		return StatusUnknown
	}
	// Expiring: inside the window, or, for a certificate whose whole life
	// is short, inside its last third. A one-day certificate is not
	// "expiring" from the moment it is issued.
	window := min(s.window, c.NotAfter.Sub(c.NotBefore)/3)
	if c.NotAfter.Sub(now) <= window {
		return StatusExpiring
	}
	return StatusValid
}

// Counts tallies the certificates by status at now.
func (s *Snapshot) Counts(now time.Time) map[Status]int {
	counts := map[Status]int{}
	for _, c := range s.Certificates {
		counts[s.Status(c, now)]++
	}
	return counts
}

// Inventory holds the summaries and keeps them current. It is safe for
// concurrent use.
type Inventory struct {
	src    Source
	window time.Duration
	now    func() time.Time

	// refreshing serialises refreshes: whoever has put a value into it is
	// the one reading. A channel and not a mutex, so that waiting for a
	// turn can be given up. mu guards the fields below it.
	refreshing chan struct{}
	mu         sync.RWMutex
	certs      map[string]*Certificate
	current    *Snapshot
}

// New returns an empty inventory over src. Nothing is read until Refresh.
func New(src Source) *Inventory {
	inv := &Inventory{src: src, window: DefaultExpiringWindow, now: time.Now, certs: map[string]*Certificate{}, refreshing: make(chan struct{}, 1)}
	inv.current = &Snapshot{State: State{Source: src.Describe()}, revoked: map[string]*Revocation{}, window: inv.window}
	return inv
}

// SetClock replaces the clock the inventory stamps its reads with. For
// tests; call it before the first Refresh.
func (inv *Inventory) SetClock(now func() time.Time) { inv.now = now }

// Snapshot returns the inventory as last read.
func (inv *Inventory) Snapshot() *Snapshot {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return inv.current
}

// Run refreshes the inventory now and then every interval until ctx ends.
// report, if not nil, is told the outcome of every refresh, nil for one
// that worked, so that the caller can log a failure when it starts and a
// recovery when it comes, not one line per round.
func (inv *Inventory) Run(ctx context.Context, interval time.Duration, report func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := inv.Refresh(ctx); ctx.Err() == nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh reads what has changed: the list of serials, the certificates
// not seen before (a certificate never changes once issued, so nothing is
// read twice), and the whole revocation table. If any part fails the
// inventory keeps what it had, and says so in its State.
//
// One refresh runs at a time; another waits its turn, for as long as its
// context lasts. A refresh that is given up, while waiting or while
// reading, says nothing about the database, so it leaves the State as it
// was: it must not replace the result of a read that worked with "the
// caller stopped waiting". Running out of time while reading is different:
// the database did not answer in the time allowed, and the State says so.
func (inv *Inventory) Refresh(ctx context.Context) error {
	select {
	case inv.refreshing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-inv.refreshing }()
	// Both may have been ready at once; the context is the one that counts.
	if err := ctx.Err(); err != nil {
		return err
	}

	attempted := inv.now()
	certs, revoked, orphans, err := inv.read(ctx)
	if err != nil && errors.Is(ctx.Err(), context.Canceled) {
		return err
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()
	state := inv.current.State
	state.AttemptedAt = attempted
	if err != nil {
		// Keep the picture that was read before, and its age.
		state.Problem = clip(err.Error())
		prev := *inv.current
		prev.State = state
		inv.current = &prev
		return err
	}
	state.LoadedAt, state.Problem, state.RevocationsKnown, state.OrphanRevocations = attempted, "", true, orphans
	inv.certs = certs
	inv.current = &Snapshot{State: state, Certificates: sorted(certs), bySerial: certs, oddKeys: oddKeysOf(certs), revoked: revoked, window: inv.window}
	return nil
}

// Errors of DER.
var (
	// ErrNotFound: the inventory has no certificate with that serial.
	ErrNotFound = errors.New("no such certificate in the inventory")
	// ErrUnreadable: there is a row with that serial, but what is stored
	// in it is not a certificate, or not that certificate.
	ErrUnreadable = errors.New("the stored value is not that certificate")
)

// DER returns a certificate as the CA stored it, for showing it in full
// and for downloading. Only certificates of the inventory can be asked
// for: the serial has to be one the last read listed. What comes back is
// checked again, since it is fetched again: it must parse and carry the
// serial it was asked for by.
func (inv *Inventory) DER(ctx context.Context, serial string) ([]byte, error) {
	known := inv.Snapshot().Certificate(serial)
	if known == nil {
		return nil, ErrNotFound
	}
	if known.Problem != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnreadable, known.Problem)
	}
	rows, err := inv.src.Certificates(ctx, []string{serial})
	if err != nil {
		return nil, fmt.Errorf("reading the certificate: %w", err)
	}
	for _, row := range rows {
		if row.Serial != serial {
			continue
		}
		cert, err := x509.ParseCertificate(row.DER)
		if err != nil || cert.SerialNumber == nil || cert.SerialNumber.String() != serial {
			return nil, ErrUnreadable
		}
		return row.DER, nil
	}
	// Listed a moment ago, gone now.
	return nil, ErrNotFound
}

// read builds the next picture from the Source and the summaries already
// held. It changes nothing in inv.
func (inv *Inventory) read(ctx context.Context) (map[string]*Certificate, map[string]*Revocation, int, error) {
	serials, err := inv.src.Serials(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("listing certificates: %w", err)
	}
	inv.mu.RLock()
	known := inv.certs
	inv.mu.RUnlock()

	// Summaries already held are carried over; the rest are fetched.
	certs := make(map[string]*Certificate, len(serials))
	var missing []string
	for _, serial := range serials {
		if c, ok := known[serial]; ok {
			certs[serial] = c
		} else if _, dup := certs[serial]; !dup {
			certs[serial] = nil
			missing = append(missing, serial)
		}
	}
	if err := inv.fetch(ctx, missing, certs); err != nil {
		return nil, nil, 0, fmt.Errorf("reading certificates: %w", err)
	}

	rows, err := inv.src.Revocations(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("reading revocations: %w", err)
	}
	revoked := make(map[string]*Revocation, len(rows))
	orphans := 0
	for _, row := range rows {
		revoked[row.Serial] = readRevocation(row)
		if _, issued := certs[row.Serial]; !issued {
			orphans++
		}
	}
	return certs, revoked, orphans, nil
}

// fetch reads the rows for the serials in missing, in batches, and puts
// their summaries into certs, where each of them is waiting as a nil
// entry. A serial that was listed but whose row was gone a moment later
// (the CA does not delete, but nothing here depends on that) is removed.
func (inv *Inventory) fetch(ctx context.Context, missing []string, certs map[string]*Certificate) error {
	for start := 0; start < len(missing); start += fetchBatch {
		rows, err := inv.src.Certificates(ctx, missing[start:min(start+fetchBatch, len(missing))])
		if err != nil {
			return err
		}
		for _, row := range rows {
			if c, wanted := certs[row.Serial]; wanted && c == nil {
				certs[row.Serial] = summarise(row)
			}
		}
	}
	for _, serial := range missing {
		if certs[serial] == nil {
			delete(certs, serial)
		}
	}
	return nil
}

// sorted orders certificates by the end of their validity, latest first,
// with unreadable rows last, and by serial where that is equal.
func sorted(certs map[string]*Certificate) []*Certificate {
	list := make([]*Certificate, 0, len(certs))
	for _, c := range certs {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.Problem == "") != (b.Problem == "") {
			return a.Problem == ""
		}
		if !a.NotAfter.Equal(b.NotAfter) {
			return a.NotAfter.After(b.NotAfter)
		}
		return a.Serial < b.Serial
	})
	return list
}

// summarise turns a row into the summary kept in memory. A row that is not
// what it should be becomes a Certificate with a Problem.
func summarise(row RawCertificate) *Certificate {
	c := &Certificate{Serial: clipSerial(row.Serial), Provisioner: provisionerOf(row.Data)}
	// An unreadable row can still be found by its key.
	c.haystack = strings.ToLower(c.Serial)
	problem := func(format string, args ...any) *Certificate {
		c.Problem = clip(fmt.Sprintf(format, args...))
		return c
	}
	if !decimal(row.Serial) {
		return problem("the row's key is not a serial number")
	}
	if row.TooLarge {
		return problem("the stored value is too large to be a certificate")
	}
	cert, err := x509.ParseCertificate(row.DER)
	if err != nil {
		return problem("the stored value is not a certificate: %v", err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.String() != row.Serial {
		return problem("the row's key is not the serial number of the certificate stored under it")
	}

	c.SerialHex = cert.SerialNumber.Text(16)
	c.Subject = clip(cert.Subject.CommonName)
	if c.Subject == "" {
		c.Subject = clip(cert.Subject.String())
	}
	c.NotBefore, c.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	c.Names, c.MoreNames = namesOf(cert)
	c.haystack = haystackOf(c, cert)
	return c
}

// haystackOf builds what a certificate is searched in: see
// Certificate.haystack.
func haystackOf(c *Certificate, cert *x509.Certificate) string {
	var b strings.Builder
	line := func(s string) {
		b.WriteString(strings.ToLower(strings.ToValidUTF8(s, string(utf8.RuneError))))
		b.WriteByte('\n')
	}
	line(c.Serial)
	line(c.SerialHex)
	line(c.Subject)
	for _, name := range cert.DNSNames {
		line(name)
	}
	for _, ip := range cert.IPAddresses {
		line(ip.String())
	}
	for _, email := range cert.EmailAddresses {
		line(email)
	}
	for _, uri := range cert.URIs {
		line(uri.String())
	}
	return b.String()
}

// provisionerOf reads who issued a certificate out of the record the CA
// stored beside it. The record is a help, not a condition: a certificate
// with a missing or unreadable record is still a certificate, with no
// provisioner known.
func provisionerOf(data []byte) Provisioner {
	var record struct {
		Provisioner *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"provisioner"`
	}
	if len(data) == 0 || json.Unmarshal(data, &record) != nil || record.Provisioner == nil {
		return Provisioner{}
	}
	return Provisioner{ID: clip(record.Provisioner.ID), Name: clip(record.Provisioner.Name), Type: clip(record.Provisioner.Type)}
}

// namesOf lists a certificate's subject alternative names, the first
// maxNames of them, and counts the rest.
func namesOf(cert *x509.Certificate) (names []Name, more int) {
	add := func(kind NameKind, value string) {
		if len(names) < maxNames {
			names = append(names, Name{Kind: kind, Value: clip(value)})
		} else {
			more++
		}
	}
	for _, name := range cert.DNSNames {
		add(DNS, name)
	}
	for _, ip := range cert.IPAddresses {
		add(IP, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		add(Email, email)
	}
	for _, uri := range cert.URIs {
		add(URI, uri.String())
	}
	return names, more
}

// readRevocation reads a row of the revocation table. The fields are the
// Go names step-ca writes (docs/PLAN.md, section 3).
func readRevocation(row RawRevocation) *Revocation {
	var in struct {
		ProvisionerID string
		ReasonCode    int
		Reason        string
		RevokedAt     time.Time
		MTLS, ACME    bool
	}
	if err := json.Unmarshal(row.JSON, &in); err != nil {
		return &Revocation{Problem: clip("the revocation record could not be read: " + err.Error())}
	}
	return &Revocation{
		ReasonCode:    in.ReasonCode,
		Reason:        clip(in.Reason),
		RevokedAt:     in.RevokedAt.UTC(),
		ProvisionerID: clip(in.ProvisionerID),
		ACME:          in.ACME,
		MTLS:          in.MTLS,
	}
}

// decimal reports whether s is a plausible serial number in decimal.
func decimal(s string) bool {
	if s == "" || len(s) > maxSerial {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// clipSerial bounds a row key for keeping and showing, whatever it holds.
func clipSerial(s string) string { return clipTo(s, maxSerial) }

// clip bounds a string taken from a certificate or a row.
func clip(s string) string { return clipTo(s, maxText) }

func clipTo(s string, limit int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}
