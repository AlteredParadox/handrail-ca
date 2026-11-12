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
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
)

const (
	// statusMaxAge is how long one reading of the CA is reused, so that
	// reloading the page does not turn into requests to the CA.
	statusMaxAge = 15 * time.Second
	// statusTimeout bounds one reading.
	statusTimeout = 15 * time.Second
)

// caSnapshot is one reading of the CA, already in the words the page uses.
// Each part carries its own problem: one failed question does not hide the
// answers to the others, and a part that failed is shown as not known,
// never as a default.
type caSnapshot struct {
	CheckedAt string // UTC time of day
	Address   string

	Reachable      bool
	HealthProblem  string
	Version        string
	VersionProblem string

	// RootFingerprint is the fingerprint handrail-ca was configured with,
	// shown whether or not the root could be fetched.
	RootFingerprint string
	// Root is the certificate with that fingerprint, nil until it has been
	// fetched from the CA; RootProblem says why it could not be.
	Root        *certView
	RootProblem string
	// RootsProblem is set when the CA's own list of roots could not be
	// read; Root.Listed means nothing then.
	RootsProblem string

	Intermediates        []certView
	IntermediatesProblem string

	Provisioners        []provisionerView
	ProvisionersProblem string
	// listed is the same list as the CA sent it, for the pages that need
	// more of a provisioner than the status page shows.
	listed []ca.Provisioner

	CRL        ca.CRL
	CRLNext    string
	CRLProblem string

	Acting actingView
}

// actingView is whether handrail-ca can change anything on the CA.
type actingView struct {
	// ReadOnly means no provisioner was configured; the rest is then empty.
	ReadOnly bool
	// Provisioner is the name of the provisioner handrail-ca acts through.
	Provisioner string
	// Ready means its key is open; KeyID is set with it. Otherwise Problem
	// is why the key could not be opened.
	Ready   bool
	KeyID   string
	Problem string
}

type certView struct {
	Subject     string
	Expires     string
	Expired     bool
	Fingerprint string
	// Listed says whether the CA itself publishes this root (roots only).
	Listed bool
}

type provisionerView struct {
	Name, Type, Default, Longest string
}

func newCertView(cert *x509.Certificate, now time.Time) certView {
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}
	return certView{
		Subject:     subject,
		Expires:     expiry(cert.NotAfter, now),
		Expired:     !cert.NotAfter.After(now),
		Fingerprint: grouped(ca.Fingerprint(cert)),
	}
}

// statusCache holds the latest reading.
type statusCache struct {
	mu   sync.Mutex
	at   time.Time
	snap *caSnapshot
}

// get returns a reading no older than statusMaxAge, taking a new one if
// needed. Concurrent callers wait for the one reading in progress.
func (c *statusCache) get(ctx context.Context, client CA, now func() time.Time) *caSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap != nil && now().Sub(c.at) < statusMaxAge {
		return c.snap
	}
	// Not tied to the request that happened to trigger it: the reading is
	// shared, and a visitor closing the tab must not turn it into errors
	// for everyone else.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusTimeout)
	defer cancel()
	c.snap = readCA(ctx, client, now())
	c.at = now()
	return c.snap
}

// readCA asks the CA everything the status page shows, in parallel.
func readCA(ctx context.Context, client CA, now time.Time) *caSnapshot {
	snap := &caSnapshot{
		CheckedAt:       now.UTC().Format("15:04:05 UTC"),
		Address:         client.URL(),
		RootFingerprint: grouped(client.RootFingerprint()),
	}
	var (
		wg            sync.WaitGroup
		root          *x509.Certificate
		roots, inters []*x509.Certificate
		provisioners  []ca.Provisioner
	)
	ask := func(question func() error, problem *string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := question(); err != nil {
				*problem = err.Error()
			}
		}()
	}
	ask(func() error { return client.Health(ctx) }, &snap.HealthProblem)
	ask(func() (err error) { root, err = client.Root(ctx); return }, &snap.RootProblem)
	ask(func() (err error) { snap.Version, err = client.Version(ctx); return }, &snap.VersionProblem)
	ask(func() (err error) { roots, err = client.Roots(ctx); return }, &snap.RootsProblem)
	ask(func() (err error) { inters, err = client.Intermediates(ctx); return }, &snap.IntermediatesProblem)
	ask(func() (err error) { provisioners, err = client.Provisioners(ctx); return }, &snap.ProvisionersProblem)
	ask(func() (err error) { snap.CRL, err = client.CRL(ctx); return }, &snap.CRLProblem)
	// Opening the provisioner's key, if it is not open yet, is how its
	// current problem is learned.
	if client.ProvisionerState().Configured {
		ask(func() error { return client.Unlock(ctx) }, &snap.Acting.Problem)
	}
	wg.Wait()

	acting := client.ProvisionerState()
	snap.Acting.ReadOnly = !acting.Configured
	snap.Acting.Provisioner, snap.Acting.Ready, snap.Acting.KeyID = acting.Name, acting.Ready, acting.KeyID

	snap.Reachable = snap.HealthProblem == ""
	if root != nil {
		v := newCertView(root, now)
		for _, published := range roots {
			v.Listed = v.Listed || published.Equal(root)
		}
		snap.Root = &v
	}
	for _, cert := range inters {
		snap.Intermediates = append(snap.Intermediates, newCertView(cert, now))
	}
	snap.listed = provisioners
	for _, p := range provisioners {
		snap.Provisioners = append(snap.Provisioners, provisionerView{
			Name: p.Name, Type: p.Type,
			Default: validity(p.Claims.DefaultTLSCertDuration),
			Longest: validity(p.Claims.MaxTLSCertDuration),
		})
	}
	if snap.CRL.Published && !snap.CRL.NextUpdate.IsZero() {
		snap.CRLNext = expiry(snap.CRL.NextUpdate, now)
	}
	return snap
}

// statusData is what the status page shows: the reading of the CA, which
// is reused for a while, and the inventory's state, which is always as of
// this moment.
type statusData struct {
	*caSnapshot
	Inventory inventoryView
}

// inventoryView is the inventory's state in the words the page uses.
type inventoryView struct {
	Source string
	// Read says whether there is a picture at all; Current, whether the
	// last attempt to bring it up to date worked.
	Read, Current bool
	LastRead      string // how long ago, and when
	Every         string
	Total         int
	Breakdown     string
	Problem       string
	// Orphans counts revocations recorded for serials that were never
	// among the certificates.
	Orphans int
}

func newInventoryView(snap *inventory.Snapshot, now time.Time) inventoryView {
	st := snap.State
	v := inventoryView{
		Source:  st.Source,
		Read:    !st.LoadedAt.IsZero(),
		Current: !st.LoadedAt.IsZero() && st.Problem == "",
		Every:   span(InventoryRefresh),
		Total:   len(snap.Certificates),
		Problem: st.Problem,
		Orphans: st.OrphanRevocations,
	}
	if v.Read {
		v.LastRead = span(now.Sub(st.LoadedAt)) + " ago, at " + st.LoadedAt.UTC().Format("15:04:05 UTC")
	}
	// Every status that occurs, most numerous concern last: what works
	// first, then what does not.
	counts := snap.Counts(now)
	var parts []string
	for _, status := range []inventory.Status{
		inventory.StatusValid, inventory.StatusExpiring, inventory.StatusNotYetValid, inventory.StatusExpired,
		inventory.StatusRevoked, inventory.StatusUnknown, inventory.StatusUnreadable,
	} {
		if n := counts[status]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, status))
		}
	}
	v.Breakdown = strings.Join(parts, ", ")
	return v
}

func (s *server) statusPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "status.html", "CA status", statusData{
		caSnapshot: s.status.get(r.Context(), s.opts.CA, s.opts.Now),
		Inventory:  newInventoryView(s.opts.Inventory.Snapshot(), s.opts.Now()),
	})
}
