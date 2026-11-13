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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `make build` stamps the binary with the name of the nearest git tag. A
// tag's name is whatever its author wrote, and tags arrive with any remote
// that is fetched. The name must reach the build as data: pasted into the
// recipe, the shell would run what a name such as v1.0-$(...) holds.
func TestMakeBuildDoesNotRunWhatATagIsCalled(t *testing.T) {
	for _, tool := range []string{"make", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s here", tool)
		}
	}
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), makefile, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		// A repository of its own, whatever the one around the test is.
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.org", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.org")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, args := range [][]string{
		{"init", "-q"}, {"add", "Makefile"}, {"commit", "-q", "-m", "a fixture"},
		// What a tag may be called: this one would leave a file behind.
		{"tag", "v0.0.0-$(touch${IFS}MARKER)"},
	} {
		if out, err := run("git", args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if out, _ := run("git", "describe", "--tags", "--always"); !strings.Contains(out, "$(touch") {
		t.Fatalf("the fixture's version is %q: this test would prove nothing", out)
	}
	// -o notices: the fixture has nothing to list; only the stamp matters.
	out, err := run("make", "-o", "notices", "build")
	if _, statErr := os.Stat(filepath.Join(dir, "MARKER")); statErr == nil {
		t.Errorf("make build ran what the tag is called:\n%s", out)
	}
	if err == nil || !strings.Contains(out, "refusing it") {
		t.Errorf("make build did not refuse the stamp (%v):\n%s", err, out)
	}

	// An ordinary tag is stamped as it is. The fixture has no Go to build,
	// so the build then fails at the compiler, having passed the check.
	for _, args := range [][]string{{"tag", "-d", "v0.0.0-$(touch${IFS}MARKER)"}, {"tag", "v0.1.0"}} {
		if out, err := run("git", args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	out, _ = run("make", "-n", "-o", "notices", "build")
	if !strings.Contains(out, `-X main.version=$HANDRAIL_VERSION`) || strings.Contains(out, "v0.1.0\"") {
		t.Errorf("the recipe does not take the stamp from the environment:\n%s", out)
	}
	if out, _ := run("make", "-o", "notices", "build"); strings.Contains(out, "refusing it") {
		t.Errorf("make build refused the stamp v0.1.0:\n%s", out)
	}
}
