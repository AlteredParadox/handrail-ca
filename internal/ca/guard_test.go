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

package ca

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The fetch of the CA's root by its fingerprint is the one place where the
// usual certificate check is switched off (rootfetch.go says why, and what
// is checked instead). The exceptions made for it, in AGENTS.md and for
// SonarCloud, are scoped to that file. This test is the automatic check
// for everything else: it fails if any other Go file in the repository
// switches verification off, and if rootfetch.go does so more than once.
func TestOnlyTheRootFetchSkipsVerification(t *testing.T) {
	const repo = "../.."
	allowed := filepath.Join("internal", "ca", "rootfetch.go")
	self := filepath.Join("internal", "ca", "guard_test.go")
	// The field being set, in a struct literal or by assignment. Reading it,
	// as the tests do to assert it is false, is not a match.
	setting := regexp.MustCompile(`InsecureSkipVerify\s*(:|=[^=])`)

	inAllowed, scanned := 0, 0
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(repo, path)
		if err != nil {
			return err
		}
		if rel == self {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(data), "\n") {
			if !setting.MatchString(line) {
				continue
			}
			if rel == allowed {
				inAllowed++
				continue
			}
			t.Errorf("%s:%d sets InsecureSkipVerify. The fetch of the CA's root in %s is the only place that may; see AGENTS.md", rel, i+1, allowed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 5 {
		t.Fatalf("only %d Go files were looked at: the walk did not find the repository", scanned)
	}
	if inAllowed != 1 {
		t.Errorf("%s sets InsecureSkipVerify %d times, want exactly once", allowed, inAllowed)
	}
}

// The file that holds the exception holds nothing else: one function. More
// code there would sit outside what SonarCloud checks for certificate
// verification.
func TestRootFetchFileHoldsOnlyTheFetch(t *testing.T) {
	data, err := os.ReadFile("rootfetch.go")
	if err != nil {
		t.Fatal(err)
	}
	funcs := regexp.MustCompile(`(?m)^func .*`).FindAllString(string(data), -1)
	if len(funcs) != 1 || !strings.HasPrefix(funcs[0], "func (c *Client) fetchRoot(") {
		t.Errorf("rootfetch.go declares %q; it must hold fetchRoot and nothing else", funcs)
	}
}
