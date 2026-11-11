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
	"net/http"
	"sync"
	"time"

	"handrail-ca/internal/ca"
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

	CRL        ca.CRL
	CRLNext    string
	CRLProblem string
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
	wg.Wait()

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

func (s *server) statusPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "status.html", "CA status", s.status.get(r.Context(), s.opts.CA, s.opts.Now))
}
