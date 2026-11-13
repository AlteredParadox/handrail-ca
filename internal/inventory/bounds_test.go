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
	"errors"
	"strings"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

// A key is kept in memory as its row's identity. A key that is no serial
// number is kept, its row shown as unreadable (TestRowsAreFoundByTheirKey),
// up to maxKey; past that the read fails, whatever the Source, the picture
// read before is kept, and the error does not repeat the key.
func TestAKeyPastTheBoundIsNotTakenIn(t *testing.T) {
	f, src := loadFixture(t)
	now := f.Captured
	inv := newInventory(src, &now)
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(inv.Snapshot().Certificates)
	long := strings.Repeat("7", 1<<20)

	src.add(RawCertificate{Serial: long, DER: []byte("x")})
	now = now.Add(time.Minute)
	err := inv.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "a key of more than") || len(err.Error()) > 200 {
		t.Fatalf("a certificate row with a 1 MiB key: %.200v", err)
	}
	snap := inv.Snapshot()
	if len(snap.Certificates) != before || snap.Certificate(long) != nil || !strings.Contains(snap.State.Problem, "a key of more than") {
		t.Errorf("after the refused read: %d certificates (want %d), problem %q", len(snap.Certificates), before, snap.State.Problem)
	}
	src.mu.Lock()
	delete(src.certs, long)
	src.revocations = append(src.revocations, RawRevocation{Serial: long, JSON: []byte(`{}`)})
	src.mu.Unlock()
	if err := inv.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "reading revocations") {
		t.Errorf("a revocation row with a 1 MiB key: %.200v", err)
	}
	if snap := inv.Snapshot(); snap.Revocation(long) != nil {
		t.Error("the long revocation key was taken in")
	}

	// A key of the longest length allowed is still taken, as a row that
	// is not a certificate.
	src.mu.Lock()
	src.revocations = src.revocations[:len(src.revocations)-1]
	src.mu.Unlock()
	edge := strings.Repeat("7", maxKey)
	src.add(RawCertificate{Serial: edge, DER: []byte("x")})
	if err := inv.Refresh(context.Background()); err != nil {
		t.Fatalf("a key of %d bytes: %v", maxKey, err)
	}
	if c := inv.Snapshot().Certificate(edge); c == nil || c.Problem == "" {
		t.Errorf("a key of %d bytes: %+v", maxKey, c)
	}
}

// Refresh presses from the page: however many arrive while a read runs,
// the next read answers them all, and it is one begun after each of them
// was made, so a press never gets a picture from before it. Refresh itself
// always reads.
func TestRefreshesAskedForTogetherAreOneRead(t *testing.T) {
	_, src := loadFixture(t)
	gate := &gatedSource{fakeSource: src, entered: make(chan struct{}, 64), release: make(chan struct{})}
	inv := New(gate)
	const callers = 16
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

	// A read is under way when the presses come.
	first := make(chan error, 1)
	go func() { first <- inv.Refresh(context.Background()) }()
	<-gate.entered
	done := make(chan error, callers)
	for range callers {
		go func() { done <- inv.RefreshSince(context.Background(), inv.Ticket()) }()
	}
	time.Sleep(50 * time.Millisecond) // for them all to be waiting
	close(gate.release)
	if err := within("the read under way", first); err != nil {
		t.Fatal(err)
	}
	for range callers {
		if err := within("a press", done); err != nil {
			t.Fatal(err)
		}
	}
	// The read under way began before they asked; one more answered them.
	if n := len(gate.entered); n != 1 {
		t.Fatalf("%d presses during a read made %d more reads, want 1", callers, n)
	}
	<-gate.entered

	// A press after that read ended gets a read of its own.
	if err := inv.RefreshSince(context.Background(), inv.Ticket()); err != nil || len(gate.entered) != 1 {
		t.Fatalf("a later press: %d reads, %v", len(gate.entered), err)
	}
	<-gate.entered
	// Refresh, which the checks after an issue or a revocation use, always
	// reads.
	if err := inv.Refresh(context.Background()); err != nil || len(gate.entered) != 1 {
		t.Fatalf("Refresh: %d reads, %v", len(gate.entered), err)
	}
	<-gate.entered

	// Presses answered by a read that failed get its error.
	held := &gatedSource{fakeSource: src, entered: make(chan struct{}, 64), release: make(chan struct{})}
	inv.src = held
	src.mu.Lock()
	src.serialsErr = errBoom
	src.mu.Unlock()
	go func() { first <- inv.Refresh(context.Background()) }()
	<-held.entered
	for range 2 {
		go func() { done <- inv.RefreshSince(context.Background(), inv.Ticket()) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(held.release)
	_ = within("the failing read under way", first)
	for range 2 {
		if err := within("a press", done); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("a press answered by a failed read: %v", err)
		}
	}
	if n := len(held.entered); n != 1 {
		t.Errorf("two presses during a read made %d more reads, want 1", n)
	}
}

func TestKeyFrom(t *testing.T) {
	if got, err := keyFrom("x509_certs", []byte("1234"), false); got != "1234" || err != nil {
		t.Errorf("a serial: %q, %v", got, err)
	}
	for name, tc := range map[string]struct {
		key     []byte
		tooLong bool
	}{
		"flagged by the query":  {nil, true},
		"longer than the bound": {[]byte(strings.Repeat("9", maxKey+1)), false},
	} {
		got, err := keyFrom("revoked_x509_certs", tc.key, tc.tooLong)
		if got != "" || err == nil || !strings.Contains(err.Error(), "revoked_x509_certs has a key of more than") || strings.Contains(err.Error(), "999") {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}
