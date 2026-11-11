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
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler() http.Handler {
	return New(Options{
		Version:            "v1.2.3",
		License:            []byte("LICENSE TEXT"),
		ThirdPartyLicenses: []byte("NOTICES TEXT"),
	})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestRoutes(t *testing.T) {
	h := newTestHandler()
	tests := []struct {
		path     string
		status   int
		contains string
	}{
		{"/healthz", http.StatusOK, `"version":"v1.2.3"`},
		{"/license", http.StatusOK, "LICENSE TEXT"},
		{"/third-party-licenses", http.StatusOK, "NOTICES TEXT"},
		{"/", http.StatusOK, "handrail-ca"},
		{"/no-such-page", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := get(t, h, tt.path)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if !strings.Contains(rec.Body.String(), tt.contains) {
				t.Errorf("body %q does not contain %q", rec.Body.String(), tt.contains)
			}
		})
	}
}

func TestSourceRedirect(t *testing.T) {
	rec := get(t, newTestHandler(), "/source")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got, want := rec.Header().Get("Location"), repoURL+"/tree/v1.2.3"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestSecurityHeaders(t *testing.T) {
	for _, path := range []string{"/", "/healthz", "/license", "/no-such-page"} {
		rec := get(t, newTestHandler(), path)
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("%s: Content-Security-Policy = %q", path, csp)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", path, got)
		}
	}
}

func TestNonGetRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestSourceURL(t *testing.T) {
	tests := []struct{ version, want string }{
		{"v0.1.0", repoURL + "/tree/v0.1.0"},
		{"v0.1.0-3-gabc1234", repoURL + "/tree/abc1234"},
		{"v0.1.0-3-gabc1234-dirty", repoURL + "/tree/abc1234"},
		{"abc1234", repoURL + "/tree/abc1234"},
		{"abc1234-dirty", repoURL + "/tree/abc1234"},
		{"dev", repoURL},
		{"ci", repoURL},
		{"", repoURL},
		{"v1.2.3-rc1", repoURL},
	}
	for _, tt := range tests {
		if got := SourceURL(tt.version); got != tt.want {
			t.Errorf("SourceURL(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}
