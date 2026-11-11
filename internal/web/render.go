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
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"handrail-ca/internal/store"
)

//go:embed templates
var templateFS embed.FS

// pages are the parsed templates, one set per page: the shared layout plus
// that page's content.
type pages map[string]*template.Template

var pageNames = []string{"signin.html", "status.html", "error.html"}

func loadPages() (pages, error) {
	set := pages{}
	for _, name := range pageNames {
		t, err := template.New("layout.html").ParseFS(templateFS, "templates/layout.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("web: template %s: %w", name, err)
		}
		set[name] = t
	}
	return set, nil
}

// view is what every page's template is given.
type view struct {
	Title string
	// Base is the path prefix for every link: "" or "/prefix".
	Base string
	// User is the signed-in account, nil on the sign-in page and on error
	// pages shown to nobody in particular.
	User *store.User
	// FormToken goes into every form of a signed-in page.
	FormToken string
	// CAHost is the CA's host name, shown beside the user.
	CAHost string
	// HistoryBroken is set while history cannot be written.
	HistoryBroken bool
	// Page is the template's own name, for marking the current nav item.
	Page string
	Data any
}

// render writes a page. The template runs into a buffer first, so a
// failure becomes a plain 500 and never half a page.
func (s *server) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	v := view{Title: title, Base: s.base, HistoryBroken: s.historyBroken.Load(), Page: page, Data: data}
	if u, err := url.Parse(s.opts.CA.URL()); err == nil {
		v.CAHost = u.Hostname()
	}
	if u := currentUser(r); u != nil {
		v.User = &u.user
		v.FormToken = formToken(u.token)
	}
	var buf bytes.Buffer
	if err := s.pages[page].Execute(&buf, v); err != nil {
		s.log.Error("rendering a page", "page", page, "err", err)
		http.Error(w, "handrail-ca could not build this page. The log has the details.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

type errorData struct {
	Status  int
	Heading string
	Message string
}

// errorPage writes an error in the site's own shell.
func (s *server) errorPage(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	heading := http.StatusText(status)
	s.render(w, r, status, "error.html", heading, errorData{Status: status, Heading: heading, Message: message})
}

// The helpers below turn times and durations into the words the pages use.
// They take the current time as an argument: templates do no clock reads.

// span says a duration in its largest sensible unit: "20 seconds",
// "3 days", "8 years". It rounds down.
func span(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	const day = 24 * time.Hour
	switch {
	case d < time.Minute:
		return count(int(d/time.Second), "second")
	case d < time.Hour:
		return count(int(d/time.Minute), "minute")
	case d < 2*day:
		return count(int(d/time.Hour), "hour")
	case d < 60*day:
		return count(int(d/day), "day")
	case d < 730*day:
		return count(int(d/(30*day)), "month")
	}
	return count(int(d/(365*day)), "year")
}

func count(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// expiry says when a certificate ends, relative to now: "2035-06-01, in 8
// years" or "2024-01-05, expired 10 months ago".
func expiry(notAfter, now time.Time) string {
	day := notAfter.UTC().Format("2006-01-02")
	if !notAfter.After(now) {
		return day + ", expired " + span(now.Sub(notAfter)) + " ago"
	}
	return day + ", in " + span(notAfter.Sub(now))
}

// validity says a provisioner's limit: "90 days", "24 hours", "5 minutes",
// or Go's own form for anything that is not a whole number of those.
func validity(d time.Duration) string {
	switch {
	case d <= 0:
		return "CA default"
	case d%(24*time.Hour) == 0:
		return count(int(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return count(int(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return count(int(d/time.Minute), "minute")
	}
	return d.String()
}

// grouped breaks a hex fingerprint into blocks of eight for reading aloud.
func grouped(hex string) string {
	var b strings.Builder
	for i := 0; i < len(hex); i += 8 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(hex[i:min(i+8, len(hex))])
	}
	return b.String()
}
