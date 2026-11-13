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
	"net/http"
	"sync"
	"time"
)

const (
	// maxPageBuilds is how many pages that go through the whole inventory
	// are built at once.
	maxPageBuilds = 4
	// maxWaitingBuilds bounds how many more requests wait for their turn,
	// and buildWait how long each of them waits.
	maxWaitingBuilds = 32
	buildWait        = 10 * time.Second
	// retryBuild is the Retry-After, in seconds, of a request that was
	// turned away because too many builds were waiting.
	retryBuild = "5"
)

// buildGate bounds the building of pages that go through every certificate
// in the inventory: the list and the names in use. Each such build holds
// memory that grows with the inventory, megabytes to tens of megabytes on a
// large one, for as long as it runs, and anyone signed in can ask for as
// many at once as they have connections. Unbounded, one account could make
// the process everyone shares hold as much as it liked. A build's memory
// is held while it runs and not while its page is being sent, so a slot is
// given back as soon as the page is ready to write: a visitor who reads
// slowly holds a finished page, not a place in line.
type buildGate struct {
	slots chan struct{}
	mu    sync.Mutex
	// waiting is how many requests are in line.
	waiting int
	// wait is buildWait, shortened by the tests.
	wait time.Duration
}

func newBuildGate() *buildGate {
	return &buildGate{slots: make(chan struct{}, maxPageBuilds), wait: buildWait}
}

// take waits for a slot and returns the function that gives it back, which
// may be called more than once. ok is false when the line was full, the
// wait ran out or the visitor left.
func (g *buildGate) take(ctx context.Context) (release func(), ok bool) {
	give := func() func() {
		var once sync.Once
		return func() { once.Do(func() { <-g.slots }) }
	}
	select {
	case g.slots <- struct{}{}:
		return give(), true
	default:
	}
	g.mu.Lock()
	if g.waiting >= maxWaitingBuilds {
		g.mu.Unlock()
		return nil, false
	}
	g.waiting++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.waiting--
		g.mu.Unlock()
	}()
	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return give(), true
	case <-timer.C:
	case <-ctx.Done():
	}
	return nil, false
}

// wholeInventory wraps a handler whose page is built from every
// certificate in the inventory (see buildGate).
func (s *server) wholeInventory(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		release, ok := s.builds.take(r.Context())
		if !ok {
			if r.Context().Err() != nil {
				return // nobody is there to be told
			}
			w.Header().Set("Retry-After", retryBuild)
			s.errorPage(w, r, http.StatusServiceUnavailable, "handrail-ca is busy building this page for other requests. Try again in a moment.")
			return
		}
		defer release()
		next(&builtPage{ResponseWriter: w, built: release}, r)
	}
}

// builtPage gives the build's slot back when the page starts to be
// written, which is when it has been built: render runs the template into
// a buffer first.
type builtPage struct {
	http.ResponseWriter
	built func()
}

func (p *builtPage) WriteHeader(status int) {
	p.built()
	p.ResponseWriter.WriteHeader(status)
}

func (p *builtPage) Write(b []byte) (int, error) {
	p.built()
	return p.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (p *builtPage) Unwrap() http.ResponseWriter { return p.ResponseWriter }
