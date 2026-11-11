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

// Package password hashes and checks account passwords with argon2id.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The cost of a new hash: the second recommended option of RFC 9106,
// section 4, for hosts without gigabytes to spare. Each hash carries its own
// parameters, so raising these later leaves existing hashes checkable.
const (
	hashTime    = 3
	hashMemory  = 64 * 1024 // KiB
	hashThreads = 4
	saltLen     = 16
	keyLen      = 32
)

// Limits on a password being set, and on a hash being checked: a stored
// hash asking for more than this is refused, not computed.
const (
	MinLength = 12
	MaxLength = 1024

	maxTime    = 16
	maxMemory  = 1 << 20 // KiB: 1 GiB
	maxThreads = 16
	maxField   = 128 // decoded salt and key bytes
)

// ErrMalformed is returned for a stored hash that is not one of ours.
var ErrMalformed = errors.New("stored password hash is malformed")

// Check says whether a password may be set: long enough to resist guessing,
// short enough to bound the work of hashing it.
func Check(pw string) error {
	if n := len([]rune(pw)); n < MinLength {
		return fmt.Errorf("password has %d characters; the minimum is %d", n, MinLength)
	}
	if len(pw) > MaxLength {
		return fmt.Errorf("password is longer than %d bytes", MaxLength)
	}
	return nil
}

// Hash returns the argon2id hash of pw in the PHC string format,
// $argon2id$v=19$m=...,t=...,p=...$salt$key.
func Hash(pw string) (string, error) {
	if err := Check(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, hashTime, hashMemory, hashThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, hashMemory, hashTime, hashThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether pw is the password behind hash. A wrong password
// is (false, nil); an error means the hash itself could not be used.
func Verify(hash, pw string) (bool, error) {
	p, err := parse(hash)
	if err != nil {
		return false, err
	}
	if len(pw) > MaxLength {
		return false, nil
	}
	key := argon2.IDKey([]byte(pw), p.salt, p.time, p.memory, p.threads, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

type params struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parse(hash string) (params, error) {
	var p params
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, ErrMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, ErrMalformed
	}
	var threads uint32
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &threads); err != nil || n != 3 {
		return p, ErrMalformed
	}
	// Sscanf stops at the first character it cannot use; only the exact
	// form is accepted.
	if parts[2] != fmt.Sprintf("v=%d", version) || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", p.memory, p.time, threads) {
		return p, ErrMalformed
	}
	// argon2 needs at least 8 KiB per thread; x/crypto panics on zero time
	// or threads.
	if p.time < 1 || p.time > maxTime || threads < 1 || threads > maxThreads ||
		p.memory < 8*threads || p.memory > maxMemory {
		return p, ErrMalformed
	}
	p.threads = uint8(threads)
	var err error
	if p.salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil || len(p.salt) < 8 || len(p.salt) > maxField {
		return p, ErrMalformed
	}
	if p.key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil || len(p.key) < 16 || len(p.key) > maxField {
		return p, ErrMalformed
	}
	return p, nil
}

// Generate returns a random password of 20 characters from an alphabet
// without look-alikes (no 0/O, 1/l/I), about 116 bits.
func Generate() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 20
	// Rejection sampling keeps every character equally likely.
	limit := byte(256 - 256%len(alphabet))
	out := make([]byte, 0, length)
	buf := make([]byte, 2*length)
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < limit && len(out) < length {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
