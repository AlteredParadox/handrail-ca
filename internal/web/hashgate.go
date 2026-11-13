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
	"errors"
	"sync"
	"time"
)

const (
	// maxWaitingForHash bounds each of the two lines for a hashing slot.
	// A request waiting in one holds a connection and its form.
	maxWaitingForHash = 16
	// strangerWait is how long a request that has shown nothing waits for
	// a hashing slot before it is told to come back.
	strangerWait = 5 * time.Second
)

// errBusy is a request turned away because too many are already waiting
// for a password to be checked. Nothing was hashed and nothing counted.
var errBusy = errors.New("too many sign-ins are waiting to be checked")

// hashGate bounds password hashing, which takes 64 MiB and a good part of
// a second each time, to a fixed number at once.
//
// Whoever can reach the sign-in page can ask for a hash, so the slots are
// what an anonymous sender can keep busy. Two things keep that from
// shutting everyone else out. Requests wait in two lines, and the line of
// those who have shown something is served first: a sign-in from a browser
// the account has signed in from before (see knownDevice), and a change of
// password, which comes with a session. They wait for a running hash to
// end and no longer, however many strangers are queued. And the strangers'
// line is short, and nobody stands in it for long: past maxWaitingForHash,
// or after strangerWait, a request is answered errBusy, so that posts for
// made-up names cannot be parked here without limit, each holding a
// connection.
type hashGate struct {
	mu        sync.Mutex
	free      int
	proven    []chan struct{}
	strangers []chan struct{}
	// wait is strangerWait, shortened by the tests.
	wait time.Duration
}

func newHashGate(slots int) *hashGate {
	return &hashGate{free: slots, wait: strangerWait}
}

// take waits for a hashing slot and returns the function that gives it
// back. proven says the caller has shown something (see hashGate). The
// error is errBusy, or the context's when the browser went away first.
func (g *hashGate) take(ctx context.Context, proven bool) (release func(), err error) {
	g.mu.Lock()
	if g.free > 0 {
		g.free--
		g.mu.Unlock()
		return g.release, nil
	}
	line := &g.strangers
	if proven {
		line = &g.proven
	}
	if len(*line) >= maxWaitingForHash {
		g.mu.Unlock()
		return nil, errBusy
	}
	turn := make(chan struct{})
	*line = append(*line, turn)
	g.mu.Unlock()

	var deadline <-chan time.Time
	if !proven {
		timer := time.NewTimer(g.wait)
		defer timer.Stop()
		deadline = timer.C
	}
	select {
	case <-turn:
		return g.release, nil
	case <-deadline:
		err = errBusy
	case <-ctx.Done():
		err = ctx.Err()
	}
	g.mu.Lock()
	left := g.leave(line, turn)
	g.mu.Unlock()
	if !left {
		// Its turn came at the same moment: the slot is already this
		// request's, and goes to the next in line.
		g.release()
	}
	return nil, err
}

// leave takes turn out of its line, and reports whether it was still there.
func (g *hashGate) leave(line *[]chan struct{}, turn chan struct{}) bool {
	for i, waiting := range *line {
		if waiting == turn {
			*line = append((*line)[:i], (*line)[i+1:]...)
			return true
		}
	}
	return false
}

// release hands the slot to whoever is first in line, those who have shown
// something before the others, or frees it.
func (g *hashGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, line := range []*[]chan struct{}{&g.proven, &g.strangers} {
		if len(*line) > 0 {
			turn := (*line)[0]
			*line = (*line)[1:]
			close(turn)
			return
		}
	}
	g.free++
}
