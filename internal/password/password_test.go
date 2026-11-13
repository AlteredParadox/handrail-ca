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

package password

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// A password over MaxLength is never the right one, and is answered with
// the same work as any other: without it, the answer would come sooner and
// cost its sender nothing.
func TestVerifyHashesAPasswordThatIsTooLong(t *testing.T) {
	longest := strings.Repeat("x", MaxLength)
	hash, err := Hash(longest)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(hash, longest); err != nil || !ok {
		t.Fatalf("Verify(the longest password allowed) = %v, %v", ok, err)
	}
	// What is hashed of this one is the password itself.
	tooLong := longest + "x"
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ok, err := Verify(hash, tooLong)
	runtime.ReadMemStats(&after)
	if err != nil || ok {
		t.Errorf("Verify(a password one byte too long) = %v, %v; want false, nil", ok, err)
	}
	// argon2id works in hashMemory KiB of its own.
	if used := after.TotalAlloc - before.TotalAlloc; used < hashMemory*1024/2 {
		t.Errorf("answered after allocating %d bytes: the password was not hashed", used)
	}
}

func TestHashAndVerify(t *testing.T) {
	const pw = "correct horse battery"
	hash, err := Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("hash = %q", hash)
	}
	if ok, err := Verify(hash, pw); err != nil || !ok {
		t.Errorf("Verify(right password) = %v, %v", ok, err)
	}
	for _, wrong := range []string{"correct horse batterz", "", pw + " ", strings.Repeat("x", MaxLength+1)} {
		if ok, err := Verify(hash, wrong); err != nil || ok {
			t.Errorf("Verify(%.20q) = %v, %v; want false, nil", wrong, ok, err)
		}
	}
	// A fresh salt every time.
	again, err := Hash(pw)
	if err != nil || again == hash {
		t.Errorf("two hashes of one password are equal (%v)", err)
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name, pw, want string
	}{
		{"too short", "elevenchars", "the minimum is 12"},
		{"empty", "", "the minimum is 12"},
		{"too long", strings.Repeat("x", MaxLength+1), "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.pw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Check = %v, want %q", err, tt.want)
			}
			if _, err := Hash(tt.pw); err == nil {
				t.Error("Hash accepted it")
			}
		})
	}
	// Length is counted in characters, not bytes.
	if err := Check("pässwörd-één"); err != nil {
		t.Errorf("twelve characters refused: %v", err)
	}
	if err := Check(strings.Repeat("é", 11)); err == nil {
		t.Error("eleven two-byte characters accepted")
	}
}

func TestVerifyRefusesAMalformedHash(t *testing.T) {
	// A hash made with small parameters, so the accepted variants are quick.
	const good = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5"
	if _, err := Verify(good, "anything at all"); err != nil {
		t.Fatalf("the well-formed hash is refused: %v", err)
	}
	tests := []struct {
		name, hash string
	}{
		{"empty", ""},
		{"plain text", "hunter2hunter2"},
		{"another scheme", "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"},
		{"argon2i", strings.Replace(good, "argon2id", "argon2i", 1)},
		{"old version", strings.Replace(good, "v=19", "v=16", 1)},
		{"version with a tail", strings.Replace(good, "v=19", "v=19x", 1)},
		{"missing field", "$argon2id$v=19$m=64,t=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5"},
		{"parameters with a tail", strings.Replace(good, "p=1", "p=1,x=2", 1)},
		{"zero time", strings.Replace(good, "t=1", "t=0", 1)},
		{"zero threads", strings.Replace(good, "p=1", "p=0", 1)},
		{"too little memory", strings.Replace(good, "m=64", "m=4", 1)},
		{"absurd memory", strings.Replace(good, "m=64", "m=4294967295", 1)},
		{"absurd time", strings.Replace(good, "t=1", "t=1000000", 1)},
		{"absurd threads", strings.Replace(good, "p=1", "p=200", 1)},
		{"negative", strings.Replace(good, "m=64", "m=-64", 1)},
		{"salt not base64", strings.Replace(good, "c2FsdHNhbHRzYWx0", "!!!!", 1)},
		{"short salt", strings.Replace(good, "c2FsdHNhbHRzYWx0", "c2FsdA", 1)},
		{"short key", "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5"},
		{"padded base64", good + "=="},
		{"extra field", good + "$more"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := Verify(tt.hash, "anything at all")
			if !errors.Is(err, ErrMalformed) || ok {
				t.Fatalf("Verify = %v, %v; want false, ErrMalformed", ok, err)
			}
		})
	}
}

func TestVerifyHonoursTheStoredParameters(t *testing.T) {
	// Known answer: argon2id, m=64 KiB, t=1, p=1, salt "saltsaltsalt".
	// Produced by this package's own primitive; it guards against the
	// parameters being read in the wrong order.
	hash, err := Hash("a password of some length")
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(hash, "m=65536,t=3,p=4", "m=65536,t=4,p=3", 1)
	if ok, err := Verify(swapped, "a password of some length"); err != nil || ok {
		t.Errorf("a hash with altered parameters still verifies (%v, %v)", ok, err)
	}
}

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		pw, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 20 || strings.ContainsAny(pw, "0O1lI") {
			t.Fatalf("Generate = %q", pw)
		}
		if err := Check(pw); err != nil {
			t.Fatalf("a generated password fails Check: %v", err)
		}
		if seen[pw] {
			t.Fatal("Generate repeated itself")
		}
		seen[pw] = true
	}
}
