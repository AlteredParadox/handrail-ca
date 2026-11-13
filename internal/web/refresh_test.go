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
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// reads is how many reads of the CA's database have begun.
func (f *fakeRows) reads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listings
}

// However many presses of "Read again now", from however many people, the
// CA's database is read on request once per refreshGap at most, and each
// press is answered by a read begun after it.
func TestReadsAskedForFromThePageAreSpaced(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	const gap = 300 * time.Millisecond
	s.server.refreshGap = gap
	b := signedIn(t, s)
	token := tokenIn(t, b.get("/"))
	press := func(n int) time.Duration {
		start := time.Now()
		var wg sync.WaitGroup
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if rec := b.do(http.MethodPost, "/refresh", url.Values{"form_token": {token}}); rec.Code != http.StatusSeeOther {
					t.Errorf("a press: %d", rec.Code)
				}
			}()
		}
		wg.Wait()
		return time.Since(start)
	}

	// The bound: the read that starts at once, one that answers the
	// presses made while it ran, and one more for each gap waited.
	most := func(took time.Duration) int { return 2 + int(took/gap) }
	before := s.rows.reads()
	took := press(16)
	if n := s.rows.reads() - before; n < 1 || n > most(took) {
		t.Fatalf("16 presses at once, over %s: %d reads, want 1 to %d", took, n, most(took))
	}

	// Pressed again at once: they wait out the gap, and one read answers
	// them, which sees what the CA stored meanwhile.
	s.rows.mu.Lock()
	s.rows.certs = append(s.rows.certs, leafRow(t, 302, "late.internal.example", t0, t0.Add(24*time.Hour)))
	s.rows.mu.Unlock()
	before = s.rows.reads()
	if took := press(16); took < gap-50*time.Millisecond {
		t.Errorf("presses right after a read took %s, want the gap of %s", took, gap)
	}
	if n := s.rows.reads() - before; n != 1 {
		t.Errorf("16 presses after the gap: %d reads, want 1", n)
	}
	wantBody(t, b.get("/?view=all"), "late.internal.example")
}

// Codex's case: a read that takes longer than the gap, and presses that
// keep arriving while it runs. The next read still begins a gap after the
// one before it ended, not straight after it.
func TestTheGapHoldsAfterASlowRead(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	const gap, slow = 200 * time.Millisecond, 300 * time.Millisecond
	s.server.refreshGap = gap
	b := signedIn(t, s)
	token := tokenIn(t, b.get("/"))
	s.rows.mu.Lock()
	s.rows.slow = slow
	from := len(s.rows.starts)
	s.rows.mu.Unlock()

	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 100 * time.Millisecond) // one every 100 ms
			b.do(http.MethodPost, "/refresh", url.Values{"form_token": {token}})
		}()
	}
	wg.Wait()
	s.rows.mu.Lock()
	starts, ends := s.rows.starts[from:], s.rows.ends[from:]
	s.rows.mu.Unlock()
	if len(starts) < 2 {
		t.Fatalf("%d reads for presses over half a second of reads taking %s", len(starts), slow)
	}
	for i := 1; i < len(starts); i++ {
		if rest := starts[i].Sub(ends[i-1]); rest < gap-20*time.Millisecond {
			t.Errorf("read %d began %s after read %d ended, want at least %s", i, rest, i-1, gap)
		}
	}
}
