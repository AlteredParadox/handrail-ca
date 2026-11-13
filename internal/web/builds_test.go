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
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// soon waits for something another goroutine is about to do.
func soon(t *testing.T, what string, done func() bool) {
	t.Helper()
	for range 5000 {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("still waiting for %s", what)
}

func (g *buildGate) inLine() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.waiting
}

// However many ask at once, only so many pages are built from the whole
// inventory at a time; the rest wait their turn, a bounded number of them,
// each for a bounded time.
func TestOnlySoManyPagesAreBuiltFromTheWholeInventoryAtOnce(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.builds.wait = time.Minute
	var building, most atomic.Int32
	hold := make(chan struct{})
	page := s.server.wholeInventory(func(w http.ResponseWriter, r *http.Request) {
		n := building.Add(1)
		for {
			if m := most.Load(); n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		<-hold
		building.Add(-1)
		w.WriteHeader(http.StatusOK)
	})
	const asking = maxPageBuilds + maxWaitingBuilds
	codes := make(chan int, asking+1)
	var wg sync.WaitGroup
	for range asking {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			page(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			codes <- rec.Code
		}()
	}
	soon(t, "the builds to start and the line to fill", func() bool {
		return building.Load() == maxPageBuilds && s.server.builds.inLine() == maxWaitingBuilds
	})

	// One more finds the line full, and is told so at once.
	rec := httptest.NewRecorder()
	page(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "busy building this page") {
		t.Errorf("a request past the line: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}

	close(hold)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Errorf("a request that waited its turn was answered %d", code)
		}
	}
	if got := most.Load(); got != maxPageBuilds {
		t.Errorf("%d pages were being built at once, want %d", got, maxPageBuilds)
	}
	if n := len(s.server.builds.slots); n != 0 || s.server.builds.inLine() != 0 {
		t.Errorf("afterwards %d slots are taken and %d are in line", n, s.server.builds.inLine())
	}
}

func TestAWaitForAPageBuildEnds(t *testing.T) {
	g := newBuildGate()
	g.wait = 30 * time.Millisecond
	var held []func()
	for range maxPageBuilds {
		release, ok := g.take(context.Background())
		if !ok {
			t.Fatal("a free slot was refused")
		}
		held = append(held, release)
	}
	began := time.Now()
	if _, ok := g.take(context.Background()); ok {
		t.Fatal("a slot was given with every one taken")
	}
	if took := time.Since(began); took < g.wait {
		t.Errorf("gave up after %v, before the limit of %v", took, g.wait)
	}
	// The visitor leaving ends the wait too.
	g.wait = time.Minute
	gone, leave := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		_, ok := g.take(gone)
		done <- ok
	}()
	soon(t, "the request to stand in line", func() bool { return g.inLine() == 1 })
	leave()
	if <-done {
		t.Error("a slot was given to a visitor who had left")
	}
	// Giving a slot back twice gives back one.
	held[0]()
	held[0]()
	if n := len(g.slots); n != maxPageBuilds-1 || g.inLine() != 0 {
		t.Errorf("%d slots taken and %d in line, want %d and 0", n, g.inLine(), maxPageBuilds-1)
	}
}

// A slot is held while the page is built, not while it is sent: a visitor
// who reads slowly holds a finished page and nobody's place.
func TestAPageBuildSlotIsGivenBackBeforeThePageIsSent(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	written, sent := make(chan struct{}), make(chan struct{})
	page := s.server.wholeInventory(func(w http.ResponseWriter, r *http.Request) {
		if n := len(s.server.builds.slots); n != 1 {
			t.Errorf("%d slots taken while the page is built, want 1", n)
		}
		w.WriteHeader(http.StatusOK)
		close(written)
		<-sent // the visitor is still reading
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		page(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-written
	if n := len(s.server.builds.slots); n != 0 {
		t.Errorf("%d slots are still taken while the page is being sent", n)
	}
	close(sent)
	<-done
}

// The list and the names page go through the gate; nothing else does.
func TestWhichPagesWaitForABuildSlot(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.server.builds.wait = 20 * time.Millisecond
	var held []func()
	for range maxPageBuilds {
		release, ok := s.server.builds.take(context.Background())
		if !ok {
			t.Fatal("a free slot was refused")
		}
		held = append(held, release)
	}
	for _, path := range []string{"/", "/names", "/names?view=all", "/?view=all"} {
		rec := b.get(path)
		wantStatus(t, rec, http.StatusServiceUnavailable)
		wantBody(t, rec, "busy building this page")
	}
	for _, path := range []string{"/status", "/history", "/certificates/101", "/certificates/101/revoke", "/issue", "/account"} {
		wantStatus(t, b.get(path), http.StatusOK)
	}
	for _, release := range held {
		release()
	}
	wantStatus(t, b.get("/"), http.StatusOK)
	wantStatus(t, b.get("/names"), http.StatusOK)
}

// A request that the browser says another origin started is answered as
// if nobody were signed in: a page on a neighbouring host name could
// otherwise tell from the answers whether its visitor has a session, as
// what, and what state a certificate is in.
func TestARequestStartedByAnotherOriginHasNoSession(t *testing.T) {
	s := newSite(t, "https://handrail.internal.example")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	paths := []string{"/", "/status", "/certificates/101", "/certificates/101/pem", "/certificates/101/revoke", "/certificates/103/revoke", "/issue", "/history"}

	for _, from := range []string{"same-site", "cross-site"} {
		b.fetchSite = from
		for _, path := range paths {
			rec := b.get(path)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sign-in" {
				t.Errorf("%s asked from %s by a signed-in operator: %d to %q, want what a stranger gets", path, from, rec.Code, rec.Header().Get("Location"))
			}
		}
		// The sign-in page does not give the session away either.
		wantStatus(t, b.get("/sign-in"), http.StatusOK)
	}
	// From its own pages, typed into the address bar, or from a client
	// that does not say: as before.
	for _, from := range []string{"same-origin", "none", ""} {
		b.fetchSite = from
		wantStatus(t, b.get("/"), http.StatusOK)
		wantStatus(t, b.get("/certificates/101/revoke"), http.StatusOK)
		wantRedirect(t, b.get("/sign-in"), "/")
	}
}
