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

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func deviceToken(n byte) TokenHash { return HashToken([]byte{'d', 'e', 'v', n}) }

func TestDevices(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, err := s.AddUser(ctx, "alice", "hash-a", RoleOperator, t0)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.AddUser(ctx, "bob", "hash-b", RoleViewer, t0)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing is known to begin with.
	if _, err := s.DeviceUser(ctx, deviceToken(1), t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown device: %v", err)
	}
	// A device is remembered only for the password that was just checked.
	if err := s.RememberDevice(ctx, alice.ID, "an older hash", deviceToken(1), t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("remembered against a hash the account no longer has: %v", err)
	}
	if err := s.RememberDevice(ctx, 999, "hash-a", deviceToken(1), t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("remembered for an account that does not exist: %v", err)
	}
	if _, err := s.DeviceUser(ctx, deviceToken(1), t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a refused device is known")
	}

	if err := s.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(1), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RememberDevice(ctx, bob.ID, "hash-b", deviceToken(2), t0); err != nil {
		t.Fatal(err)
	}
	for token, want := range map[TokenHash]string{deviceToken(1): "alice", deviceToken(2): "bob"} {
		if got, err := s.DeviceUser(ctx, token, t0.Add(time.Hour)); err != nil || got != want {
			t.Errorf("DeviceUser = %q, %v; want %q", got, err, want)
		}
	}
	// The same token cannot be remembered twice: tokens are random, and a
	// second account must not be able to take over a device.
	if err := s.RememberDevice(ctx, bob.ID, "hash-b", deviceToken(1), t0); err == nil {
		t.Error("another account took a device's token")
	}

	// Unused for the lifetime, it is forgotten; used, it is kept.
	last := t0.Add(DeviceLifetime)
	if _, err := s.DeviceUser(ctx, deviceToken(1), last); !errors.Is(err, ErrNotFound) {
		t.Errorf("a device unused for its lifetime is still known: %v", err)
	}
	if _, err := s.DeviceUser(ctx, deviceToken(1), last.Add(-time.Second)); err != nil {
		t.Errorf("a device a second short of its lifetime: %v", err)
	}
	if err := s.TouchDevice(ctx, deviceToken(1), last.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceUser(ctx, deviceToken(1), last.Add(24*time.Hour)); err != nil {
		t.Errorf("a device used again was forgotten: %v", err)
	}
	// The sweep removes what is past use and nothing else.
	if n, err := s.DeleteUnusedDevices(ctx, t0); err != nil || n != 1 {
		t.Errorf("swept %d devices, %v; want bob's, unused since the start", n, err)
	}
	if _, err := s.DeviceUser(ctx, deviceToken(1), last); err != nil {
		t.Errorf("the sweep took a device in use: %v", err)
	}
}

// An account keeps its most recently used devices and no more.
func TestDevicesAreBoundedPerAccount(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice, _ := s.AddUser(ctx, "alice", "hash-a", RoleOperator, t0)
	bob, _ := s.AddUser(ctx, "bob", "hash-b", RoleViewer, t0)
	if err := s.RememberDevice(ctx, bob.ID, "hash-b", deviceToken(200), t0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxDevices; i++ {
		if err := s.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(byte(i)), t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// The oldest is used again, so it is no longer the one to go.
	if err := s.TouchDevice(ctx, deviceToken(0), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(100), t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(3 * time.Hour)
	known := 0
	for i := 0; i < MaxDevices; i++ {
		_, err := s.DeviceUser(ctx, deviceToken(byte(i)), now)
		switch {
		case err == nil:
			known++
		case i != 1:
			t.Errorf("device %d was forgotten, want the least recently used (1) to go: %v", i, err)
		}
	}
	if known != MaxDevices-1 {
		t.Errorf("%d of the first devices are known, want %d", known, MaxDevices-1)
	}
	if _, err := s.DeviceUser(ctx, deviceToken(100), now); err != nil {
		t.Errorf("the newest device: %v", err)
	}
	// Another account's devices are not counted, nor touched.
	if _, err := s.DeviceUser(ctx, deviceToken(200), now); err != nil {
		t.Errorf("another account's device went with them: %v", err)
	}
}

// Whoever had the old password does not keep a sign-in allowance of their
// own; and an account's devices go with the account.
func TestDevicesAreForgottenWithThePassword(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(s *Store, u User) error{
		"changed by the user":       func(s *Store, u User) error { return s.ChangePassword(ctx, u.ID, "hash-a", "hash-new", t0) },
		"set from the command line": func(s *Store, u User) error { return s.SetPassword(ctx, "alice", "hash-new", t0) },
		"the account is removed":    func(s *Store, u User) error { return s.RemoveUser(ctx, "alice") },
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			alice, _ := s.AddUser(ctx, "alice", "hash-a", RoleOperator, t0)
			bob, _ := s.AddUser(ctx, "bob", "hash-b", RoleViewer, t0)
			if err := s.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(1), t0); err != nil {
				t.Fatal(err)
			}
			if err := s.RememberDevice(ctx, bob.ID, "hash-b", deviceToken(2), t0); err != nil {
				t.Fatal(err)
			}
			if err := change(s, alice); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DeviceUser(ctx, deviceToken(1), t0); !errors.Is(err, ErrNotFound) {
				t.Errorf("the device is still known: %v", err)
			}
			if _, err := s.DeviceUser(ctx, deviceToken(2), t0); err != nil {
				t.Errorf("another account's device was forgotten: %v", err)
			}
		})
	}
}

// A store from before devices gains the table when it is opened, and
// keeps what it had.
func TestOpenAddsDevicesToAnOlderStore(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	dir := t.TempDir()
	ctx := context.Background()

	migrations = saved[:2]
	old := open(t, dir)
	alice, err := old.AddUser(ctx, "alice", "hash-a", RoleOperator, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.SetNote(ctx, Note{Serial: "1", Text: "kept", UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := old.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(1), t0); err == nil {
		t.Fatal("the older schema took a device")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	migrations = saved
	s := open(t, dir)
	if n, err := s.Note(ctx, "1"); err != nil || n.Text != "kept" {
		t.Errorf("the note after the upgrade: %+v, %v", n, err)
	}
	if err := s.RememberDevice(ctx, alice.ID, "hash-a", deviceToken(1), t0); err != nil {
		t.Errorf("a device after the upgrade: %v", err)
	}
}
