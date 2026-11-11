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

// Package web is the HTTP surface: the embedded front-end, a health probe,
// and the legal pages the AGPL requires every network user to be able to
// reach (license, third-party notices, corresponding source).
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"regexp"
)

//go:embed static
var staticFS embed.FS

// repoURL is where the corresponding source lives (AGPL section 13).
const repoURL = "https://github.com/AlteredParadox/handrail-ca"

// Options carries what main hands the server.
type Options struct {
	// Version is the stamped build version (a tag, a git description or
	// "dev").
	Version string
	// License and ThirdPartyLicenses are the embedded legal texts.
	License            []byte
	ThirdPartyLicenses []byte
}

// New returns the handler for the whole site.
func New(opts Options) http.Handler {
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // the embedded tree always has static/
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": opts.Version})
	})
	mux.HandleFunc("GET /license", text(opts.License))
	mux.HandleFunc("GET /third-party-licenses", text(opts.ThirdPartyLicenses))
	mux.HandleFunc("GET /source", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, SourceURL(opts.Version), http.StatusFound)
	})
	mux.Handle("GET /", http.FileServerFS(static))
	return securityHeaders(mux)
}

func text(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	}
}

// securityHeaders sets the baseline every response carries. The UI is
// same-origin only: no inline script, no framing, no third-party loads.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

var (
	releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	// `git describe --tags --always --dirty`: v1.2.3-4-gabc1234[-dirty] or a
	// bare abbreviated hash.
	describeHash = regexp.MustCompile(`^(?:.*-g)?([0-9a-f]{7,40})(?:-dirty)?$`)
)

// SourceURL is the source tree a build was made from: the tag for a release,
// the commit for a build between tags, the repository itself when the
// version names neither (a plain `go build` reports "dev").
func SourceURL(version string) string {
	if releaseTag.MatchString(version) {
		return repoURL + "/tree/" + version
	}
	if m := describeHash.FindStringSubmatch(version); m != nil {
		return repoURL + "/tree/" + m[1]
	}
	return repoURL
}
