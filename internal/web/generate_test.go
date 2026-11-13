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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/store"
)

var onceField = regexp.MustCompile(`name="once" value="([0-9a-f]{96})"`)

// generateFormOf loads the form and returns it filled in.
func (b *browser) generateForm(commonName, names, key string) url.Values {
	b.s.t.Helper()
	page := b.get("/issue/generate")
	wantStatus(b.s.t, page, http.StatusOK)
	m := onceField.FindStringSubmatch(page.Body.String())
	if m == nil {
		b.s.t.Fatal("the form has no mark of its own")
	}
	return url.Values{"form_token": {tokenIn(b.s.t, page)}, "once": {m[1]}, "common_name": {commonName}, "names": {names}, "key": {key}, "validity": {"default"}}
}

var pemOnPage = regexp.MustCompile(`-----BEGIN [A-Z ]+-----[^<]*?-----END [A-Z ]+-----`)

// pemBlocks are the PEM blocks on a page, in order.
func pemBlocks(t *testing.T, body string) []*pem.Block {
	t.Helper()
	var blocks []*pem.Block
	for _, text := range pemOnPage.FindAllString(html.UnescapeString(body), -1) {
		block, _ := pem.Decode([]byte(text))
		if block == nil {
			t.Fatalf("a PEM block on the page does not decode: %.80s", text)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func TestGenerate(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	// The CSR page leads here, and this page says what it costs.
	wantBody(t, b.get("/issue"), `<a class="button on" href="/issue" aria-current="true">I have a CSR</a>`, `<a class="button" href="/issue/generate">Generate a key for me</a>`)
	page := b.get("/issue/generate")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, `<a class="button on" href="/issue/generate" aria-current="true">Generate a key for me</a>`,
		"The private key is created on this server, shown to you once on the next page, and never stored or logged.",
		"that is the safer path", `<option value="p256" selected>ECDSA P-256</option>`, `<option value="p384">ECDSA P-384</option>`,
		`<option value="ed25519">Ed25519</option>`, `<option value="rsa3072">RSA 3072</option>`, "Generate key and sign", "Provisioner limits")

	s.clock.advance(time.Minute)
	form := b.generateForm(" git.internal.example ", "git.internal.example\r\ngit, 10.20.0.14\n\ngit.internal.example", "p256")
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the page with the key may be kept by the browser: Cache-Control %q", got)
	}
	// Nor is it to be held in a proxy's buffer, which spills to a file, or
	// handed to a browser's translation service.
	if got := rec.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("the page with the key may be buffered by the proxy: X-Accel-Buffering %q", got)
	}
	wantBody(t, rec, `<section class="card notranslate" translate="no">`)
	wantBody(t, rec, "The certificate and its private key", "Save the private key now. This page is the only place it is.",
		"<dt>Subject</dt><dd>CN=git.internal.example</dd>", "<dt>Key</dt><dd>ECDSA P-256, not encrypted</dd>", `href="/certificates/5001"`)
	for _, absent := range []string{"Generate key and sign", `name="once"`, "Not as asked"} {
		if strings.Contains(rec.Body.String(), absent) {
			t.Errorf("the page with the key has %q", absent)
		}
	}

	// The key on the page is the certificate's, and the certificate is
	// what was typed: each name once, each as its kind.
	blocks := pemBlocks(t, rec.Body.String())
	if len(blocks) != 4 || blocks[0].Type != "PRIVATE KEY" || blocks[1].Type != "CERTIFICATE" {
		t.Fatalf("%d PEM blocks on the page, want the key, the certificate, and the certificate with its chain", len(blocks))
	}
	key, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	private, isECDSA := key.(*ecdsa.PrivateKey)
	if !isECDSA || !private.PublicKey.Equal(cert.PublicKey) {
		t.Error("the key on the page is not the certificate's")
	}
	if cert.Subject.CommonName != "git.internal.example" || !reflect.DeepEqual(cert.DNSNames, []string{"git.internal.example", "git"}) || len(cert.IPAddresses) != 1 {
		t.Errorf("the certificate: %s %v %v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}

	// The key is nowhere but on that page.
	secret := pem.EncodeToMemory(blocks[0])
	middle := string(secret[40:80])
	if strings.Contains(s.log.String(), middle) {
		t.Error("the private key is in the log")
	}
	for _, e := range s.history() {
		if strings.Contains(e.Detail, middle) || strings.Contains(e.Subject, middle) {
			t.Error("the private key is in the history")
		}
	}
	if strings.Contains(b.get("/certificates/5001").Body.String(), "PRIVATE KEY") {
		t.Error("the certificate's own page has a private key on it")
	}

	events := s.issueEvents()
	const asked = "names: git.internal.example, git, 10.20.0.14; validity: the provisioner's default; key made by handrail-ca (ECDSA P-256)"
	if len(events) != 2 || events[0].Outcome != store.OutcomeAttempt || events[0].Detail != asked ||
		events[1].Outcome != store.OutcomeOK || events[1].Serial != "5001" || events[1].Detail != asked+"; issued, valid until 2026-11-12 12:01 UTC" {
		t.Errorf("history: %+v", events)
	}

	// The same form again, as a reload of that page sends it: no second
	// key, no second certificate, and no key shown.
	again := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, again, http.StatusConflict)
	wantBody(t, again, "This form cannot be taken: it was already sent once", "handrail-ca does not keep it")
	if strings.Contains(again.Body.String(), "PRIVATE KEY") || len(s.ca.signings()) != 1 {
		t.Error("a form sent twice made a second key or certificate")
	}
}

func TestGenerateEachKindOfKey(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	for value, is := range map[string]func(any) bool{
		"p256":    func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve.Params().BitSize == 256 },
		"p384":    func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve.Params().BitSize == 384 },
		"ed25519": func(k any) bool { _, ok := k.(ed25519.PrivateKey); return ok },
		"rsa3072": func(k any) bool { key, ok := k.(*rsa.PrivateKey); return ok && key.N.BitLen() == 3072 },
	} {
		rec := b.do(http.MethodPost, "/issue/generate", b.generateForm(value+".internal.example", "", value))
		wantStatus(t, rec, http.StatusOK)
		blocks := pemBlocks(t, rec.Body.String())
		if len(blocks) < 2 {
			t.Fatalf("%s: no key and certificate on the page", value)
		}
		key, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
		if err != nil || !is(key) {
			t.Errorf("%s: the key on the page is a %T, %v", value, key, err)
		}
		cert, err := x509.ParseCertificate(blocks[1].Bytes)
		if err != nil {
			t.Fatal(err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok || !reflect.DeepEqual(signer.Public(), cert.PublicKey) {
			t.Errorf("%s: the key on the page is not the certificate's", value)
		}
		// With a common name and no names, the certificate carries the
		// common name as its one name.
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != value+".internal.example" {
			t.Errorf("%s: names %v", value, cert.DNSNames)
		}
	}
}

// Nothing is made or sent for a form that does not say what to issue, and
// nobody but an operator gets as far.
func TestGenerateRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	for name, tt := range map[string]struct {
		change func(url.Values)
		want   string
	}{
		"nothing typed":                     {func(v url.Values) { v.Set("common_name", " "); v.Set("names", "\n") }, "Nothing was made or sent: give a common name, or at least one name or address."},
		"no kind of key":                    {func(v url.Values) { v.Del("key") }, "choose a kind of key from the list"},
		"a kind that is not offered":        {func(v url.Values) { v.Set("key", "rsa1024") }, "choose a kind of key from the list"},
		"a validity not offered":            {func(v url.Values) { v.Set("validity", "8760h0m0s") }, "choose a validity from the list"},
		"longer than allowed":               {func(v url.Values) { v.Set("validity", "custom"); v.Set("custom_n", "91"); v.Set("custom_unit", "days") }, "longest validity is 90 days"},
		"a name that does not print":        {func(v url.Values) { v.Set("names", "a\x00b.internal.example") }, "a name has a character in it that does not print"},
		"a common name that does not print": {func(v url.Values) { v.Set("common_name", "a\x07b") }, "the common name has a character in it that does not print"},
		"too many names": {func(v url.Values) {
			v.Set("names", strings.Repeat("h.internal.example x.internal.example ", 1)+manyNames(101))
		}, "more than the 100"},
		"a name too long": {func(v url.Values) { v.Set("names", strings.Repeat("a", 600)) }, "a name longer than"},
	} {
		t.Run(name, func(t *testing.T) {
			form := b.generateForm("git.internal.example", "git.internal.example", "p384")
			tt.change(form)
			rec := b.do(http.MethodPost, "/issue/generate", form)
			wantStatus(t, rec, http.StatusUnprocessableEntity)
			wantBody(t, rec, tt.want, "Generate key and sign")
			if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
				t.Error("a key is on the page")
			}
			// The form comes back to be corrected, good for one more go.
			if m := onceField.FindStringSubmatch(rec.Body.String()); m == nil || m[1] == form.Get("once") {
				t.Error("the form that came back cannot be sent")
			}
		})
	}
	// What was typed comes back with it.
	form := b.generateForm("git.internal.example", "git\n10.20.0.14", "p384")
	form.Set("key", "nope")
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantBody(t, rec, `value="git.internal.example"`, "git\n10.20.0.14</textarea>")

	form = b.generateForm("git.internal.example", "", "p256")

	// Viewers, and everyone who is not signed in.
	viewer := s.browser()
	wantRedirect(t, viewer.signIn("bob", bobPassword), "/")
	wantStatus(t, viewer.get("/issue/generate"), http.StatusForbidden)
	form.Set("form_token", tokenIn(t, viewer.get("/")))
	wantStatus(t, viewer.do(http.MethodPost, "/issue/generate", form), http.StatusForbidden)
	wantRedirect(t, s.browser().get("/issue/generate"), "/sign-in")

	if n := len(s.ca.signings()); n != 0 {
		t.Errorf("the CA was asked to sign %d times", n)
	}
	if events := s.issueEvents(); len(events) != 0 {
		t.Errorf("history has issuances nobody made: %+v", events)
	}
}

func manyNames(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("h")
		b.WriteString(strings.Repeat("0", i%5))
		b.WriteByte(byte('a' + i%26))
		b.WriteString(strings.Repeat("z", i/26))
		b.WriteString(".internal.example\n")
	}
	return b.String()
}

// Only a mark this running handrail-ca gave out is taken. One made up, and
// one from before a restart, make nothing: the memory of which marks were
// taken went with the old process, and a reload of the page that showed a
// key must not make a second key and certificate.
func TestGenerateFormMarks(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	for name, mark := range map[string]string{
		"made up":        strings.Repeat("ab", 48),
		"too short":      strings.Repeat("ab", 16),
		"not hex at all": strings.Repeat("zz", 48),
		"none":           "",
	} {
		form := b.generateForm("git.internal.example", "", "p256")
		form.Set("once", mark)
		rec := b.do(http.MethodPost, "/issue/generate", form)
		if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Errorf("a mark %s: %d", name, rec.Code)
		}
	}

	// A mark that was taken is taken in any spelling: hexadecimal reads
	// the same in either case, and the other case must not pass for a
	// mark never seen.
	taken := b.generateForm("git.internal.example", "", "p256")
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", taken), http.StatusOK)
	respelled := strings.ToUpper(taken.Get("once"))
	if respelled == taken.Get("once") {
		t.Fatal("the mark has no letter to respell")
	}
	taken.Set("once", respelled)
	rec := b.do(http.MethodPost, "/issue/generate", taken)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("a taken mark in capitals: %d", rec.Code)
	}
	if n := len(s.ca.signings()); n != 1 {
		t.Fatalf("the CA was asked to sign %d times", n)
	}

	// A form taken, and its page reloaded after a restart: sessions are in
	// the store and carry on, the process's secret and memory are new.
	form := b.generateForm("git.internal.example", "", "p256")
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", form), http.StatusOK)
	s.server.formKey = []byte("the key of another process, 32 b")
	s.server.onces = usedForms{}
	rec = b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusConflict)
	wantBody(t, rec, "This form cannot be taken", "from before handrail-ca was last restarted")
	if n := len(s.ca.signings()); n != 2 {
		t.Errorf("the CA was asked to sign %d times, want once for each form that was taken", n)
	}
	// A form from the new process is taken.
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", b.generateForm("git.internal.example", "", "p256")), http.StatusOK)
}

// What a certificate's page says about a discarded key comes from what
// happened, not from the address.
func TestKeylessNoticeIsNotForTheAsking(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	// A certificate issued in the ordinary way, with its key handed over.
	rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("git.internal.example", "", "p256"))
	wantStatus(t, rec, http.StatusOK)
	for _, made := range []string{"keyless", "1", "again"} {
		body := b.get("/certificates/5001?issued=" + made).Body.String()
		if strings.Contains(body, "never handed over") || strings.Contains(body, "Revoke it below") {
			t.Errorf("?issued=%s makes a good certificate's page say nobody has its key", made)
		}
	}
	// And one nothing here led to.
	if body := b.get("/certificates/101?issued=keyless").Body.String(); strings.Contains(body, "never handed over") {
		t.Error("?issued=keyless makes any certificate's page say nobody has its key")
	}
}

// Switched off, the path is not offered and not open; on a read-only
// handrail-ca neither way of issuing is.
func TestGenerateSwitchedOff(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.server.opts.NoKeyGeneration = true
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page := b.get("/issue")
	wantStatus(t, page, http.StatusOK)
	if strings.Contains(page.Body.String(), "/issue/generate") || strings.Contains(page.Body.String(), "Generate a key") {
		t.Error("the page offers generating a key although that is switched off")
	}
	rec := b.get("/issue/generate")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "Generating keys is switched off on this handrail-ca.")
	form := url.Values{"form_token": {tokenIn(t, page)}, "once": {strings.Repeat("a", 96)}, "common_name": {"git.internal.example"}, "key": {"p256"}}
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", form), http.StatusForbidden)
	// Issuing for a CSR is as before.
	_, csrForm := b.readCSR(gitCSR(t))
	wantRedirect(t, b.do(http.MethodPost, "/issue", csrForm), "/certificates/5001?issued=1")
	if len(s.ca.signings()) != 1 {
		t.Error("a key was generated although that is switched off")
	}

	ro := newSite(t, "http://127.0.0.1:8080")
	ro.ca.readOnly = true
	rb := ro.browser()
	wantRedirect(t, rb.signIn("alice", alicePassword), "/")
	rec = rb.get("/issue/generate")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "started read-only")
}

// When no certificate comes back, no key is shown, and the page says what
// became of the one that was made.
func TestGenerateOutcomes(t *testing.T) {
	lost := errors.New(`Post "https://ca.internal.example:9000/1.0/sign": context deadline exceeded`)

	t.Run("refused", func(t *testing.T) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		s.ca.sign = func(context.Context, *ca.Request, time.Duration) (*ca.Issued, error) {
			return nil, &ca.StatusError{Status: 403, Message: `dns name "git.internal.example" not allowed`}
		}
		form := b.generateForm("git.internal.example", "", "p256")
		rec := b.do(http.MethodPost, "/issue/generate", form)
		wantStatus(t, rec, http.StatusBadGateway)
		wantBody(t, rec, "No certificate was issued", "The CA refused the request", "not allowed",
			"The key handrail-ca made for this request has been discarded. Sending the form again makes a new one.",
			// The form, with what was typed, good for another go.
			`value="git.internal.example"`, "Generate key and sign")
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Error("a key is on the page")
		}
		if events := s.issueEvents(); len(events) != 2 || events[1].Outcome != store.OutcomeFailed {
			t.Errorf("history: %+v", events)
		}
		// And it can be sent again.
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			issued := s.caSigns(r, d)
			s.caStores(issued.Certificate)
			return issued, nil
		}
		form.Set("once", onceField.FindStringSubmatch(rec.Body.String())[1])
		wantStatus(t, b.do(http.MethodPost, "/issue/generate", form), http.StatusOK)
	})

	t.Run("no answer", func(t *testing.T) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		s.ca.sign = func(context.Context, *ca.Request, time.Duration) (*ca.Issued, error) { return nil, lost }
		rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("git.internal.example", "", "p256"))
		wantStatus(t, rec, http.StatusBadGateway)
		wantBody(t, rec, "It is not known yet whether a certificate was issued",
			"The key handrail-ca made for this request has been discarded. If a certificate does turn up, it is for that key, which nobody has: revoke it.")
		if events := s.issueEvents(); len(events) != 2 || events[1].Outcome != store.OutcomeUnknown {
			t.Errorf("history: %+v", events)
		}
	})

	// The CA issued, its answer was lost, and the certificate is in its
	// database: a certificate whose key nobody has. Not a success.
	t.Run("the answer was lost, and the certificate is there", func(t *testing.T) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			s.caStores(s.caSigns(r, d).Certificate)
			return nil, lost
		}
		rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("git.internal.example", "", "p256"))
		wantRedirect(t, rec, "/certificates/5001?issued=1")
		page := b.get("/certificates/5001?issued=1")
		wantBody(t, page, "issued for a key that handrail-ca had made and never handed over", "Nobody has it, and the certificate is of no use. Revoke it below",
			`href="/certificates/5001/revoke"`)
		events := s.issueEvents()
		if len(events) != 2 || events[1].Outcome != store.OutcomeFailed || events[1].Serial != "5001" ||
			!strings.HasSuffix(events[1].Detail, "the key was not handed over and is gone, so the certificate is of no use to anyone") {
			t.Errorf("history: %+v", events)
		}
	})

	// The certificate is issued and the CA's database cannot be read: the
	// key and the certificate are on the page all the same.
	t.Run("issued, and the database cannot be read", func(t *testing.T) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			issued := s.caSigns(r, d)
			s.rows.fail(errors.New("connection refused"))
			return issued, nil
		}
		rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("git.internal.example", "", "p256"))
		wantStatus(t, rec, http.StatusOK)
		wantBody(t, rec, "Save the private key now.", "The certificate will be in the list once the CA's database has been read again.")
		if blocks := pemBlocks(t, rec.Body.String()); len(blocks) != 4 || blocks[0].Type != "PRIVATE KEY" {
			t.Errorf("%d PEM blocks on the page", len(blocks))
		}
		if strings.Contains(rec.Body.String(), `href="/certificates/5001"`) {
			t.Error("the page links to a certificate page that does not exist yet")
		}
	})
}

// An attempt whose outcome was not learned is accounted for before the
// same certificate is tried again. If it was given a certificate after
// all, that one is for a key nobody has, and the operator is taken to it
// before a second is made.
func TestGenerateAgainAfterAnUnknownOutcome(t *testing.T) {
	lost := errors.New(`Post "https://ca.internal.example:9000/1.0/sign": context deadline exceeded`)
	start := func(t *testing.T) (*site, *browser, url.Values, **ca.Issued) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		var pending *ca.Issued
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			pending = s.caSigns(r, d)
			return nil, lost
		}
		form := b.generateForm("git.internal.example", "git\n10.20.0.14", "p256")
		rec := b.do(http.MethodPost, "/issue/generate", form)
		wantStatus(t, rec, http.StatusBadGateway)
		wantBody(t, rec, "It is not known yet whether a certificate was issued")
		// The form that came back, with what was typed, good for another go.
		form.Set("once", onceField.FindStringSubmatch(rec.Body.String())[1])
		return s, b, form, &pending
	}
	issues := func(s *site) {
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			issued := s.caSigns(r, d)
			s.caStores(issued.Certificate)
			return issued, nil
		}
	}

	t.Run("too soon to know", func(t *testing.T) {
		s, b, form, _ := start(t)
		issues(s)
		rec := b.do(http.MethodPost, "/issue/generate", form)
		wantStatus(t, rec, http.StatusConflict)
		wantBody(t, rec, "an earlier attempt to issue this certificate has an outcome that is not known yet", "Nothing was made or sent")
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") || len(s.ca.signings()) != 1 {
			t.Errorf("a second key or certificate was made: %d signings", len(s.ca.signings()))
		}
	})

	t.Run("the first certificate has turned up", func(t *testing.T) {
		s, b, form, pending := start(t)
		issues(s)
		s.caStores((*pending).Certificate)
		s.clock.advance(time.Minute)
		rec := b.do(http.MethodPost, "/issue/generate", form)
		wantRedirect(t, rec, "/certificates/5001?issued=1")
		wantBody(t, b.get("/certificates/5001?issued=1"), "issued for a key that handrail-ca had made and never handed over", "Revoke it below", `href="/certificates/5001/revoke"`)
		if n := len(s.ca.signings()); n != 1 {
			t.Fatalf("the CA was asked to sign %d times", n)
		}
		events := s.issueEvents()
		if last := events[len(events)-1]; last.Outcome != store.OutcomeFailed || last.Serial != "5001" || !strings.Contains(last.Detail, "Its key was made by handrail-ca and discarded then") {
			t.Errorf("history: %+v", last)
		}
		// With the first accounted for, the same form makes a new one.
		rec = b.do(http.MethodPost, "/issue/generate", form)
		wantStatus(t, rec, http.StatusOK)
		wantBody(t, rec, "Save the private key now.")
		if n := len(s.ca.signings()); n != 2 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
	})

	t.Run("nothing was issued, as far as can be known", func(t *testing.T) {
		s, b, form, _ := start(t)
		issues(s)
		s.clock.advance(issueSettles)
		rec := b.do(http.MethodPost, "/issue/generate", form)
		wantStatus(t, rec, http.StatusOK)
		wantBody(t, rec, "Save the private key now.")
	})

	// Another certificate, or the same names asked for by someone else, is
	// not held up by it.
	t.Run("another certificate is not held up", func(t *testing.T) {
		s, b, _, _ := start(t)
		issues(s)
		rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("other.internal.example", "", "p256"))
		wantStatus(t, rec, http.StatusOK)
	})
}

var fileLinkOnPage = regexp.MustCompile(`<button type="button" class="secondary" hidden data-save-name="([^"]*)" data-save-type="application/x-p(?:em-file|kcs12)" data-save-body="([^"]+)">([^<]*)</button>`)

// filesOn are the files a page carries to be saved, by name.
func filesOn(t *testing.T, body string) (names []string, files map[string]string) {
	t.Helper()
	files = map[string]string{}
	for _, m := range fileLinkOnPage.FindAllStringSubmatch(body, -1) {
		// As the page's script reads the attribute: the page's escaping
		// undone, and what is left is the file in base64.
		text, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[2]))
		if err != nil {
			t.Fatalf("the file %s on the page does not decode: %v", m[1], err)
		}
		names = append(names, m[1])
		files[m[1]] = string(text)
	}
	// No file is ever its own address: a browser keeps the addresses of
	// its downloads, and a private key was found kept that way.
	if strings.Contains(body, "data:") {
		t.Error("the page has a data: address in it")
	}
	return names, files
}

// The page that hands the key over also carries it, and the certificate,
// as files to save: inside the page itself, so that saving one asks
// handrail-ca for nothing and the key is still in that one answer only.
func TestGenerateOffersTheFilesToSave(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	rec := b.do(http.MethodPost, "/issue/generate", b.generateForm("Git <server> 01", "git.internal.example", "p256"))
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if strings.Contains(body, "ZgotmplZ") {
		t.Fatal("a link on the page was blanked by the template's own escaping")
	}
	names, files := filesOn(t, body)
	// Named after the certificate, safely, like the downloads on its page.
	if want := []string{"git-server-01.key", "git-server-01.pem", "git-server-01-chain.pem", "git-server-01-key-and-chain.pem"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("files offered: %v, want %v", names, want)
	}
	wantBody(t, rec, ">Download key</button>", ">Download certificate</button>", ">Download chain</button>", ">Key and chain in one file</button>", "saving one fetches nothing from handrail-ca")
	// The buttons are worked by the page's script, which is the only one
	// and comes from handrail-ca itself. Until it has run they are hidden
	// and the page says what to do without them.
	wantBody(t, rec, `<script src="/static/save.js" defer></script>`, `<p class="sub" data-save-on hidden>`,
		`<p class="sub" data-save-off>The buttons that save these as files need JavaScript, which is not running on this page. Copy the key and the certificate from below instead.</p>`)
	if strings.Count(body, "<script") != 1 {
		t.Errorf("%d scripts on the page", strings.Count(body, "<script"))
	}
	if strings.Contains(b.get("/issue/generate").Body.String(), "<script") {
		t.Error("the form has a script on it")
	}

	// The files are what the page shows, to the byte.
	shown := pemOnPage.FindAllString(html.UnescapeString(regexp.MustCompile(`(?s)<h3>Private key</h3>.*`).FindString(body)), -1)
	if len(shown) != 4 {
		t.Fatalf("%d PEM blocks shown", len(shown))
	}
	key, cert, chain := shown[0]+"\n", shown[1]+"\n", shown[2]+"\n"+shown[3]+"\n"
	for name, want := range map[string]string{
		"git-server-01.key": key, "git-server-01.pem": cert, "git-server-01-chain.pem": chain, "git-server-01-key-and-chain.pem": key + chain,
	} {
		if files[name] != want {
			t.Errorf("the file %s is not what the page shows:\n%s", name, files[name])
		}
	}
	// Nothing on the page fetches the key from the server: there is no
	// address for it.
	if strings.Contains(body, `href="/issue/generate/`) || strings.Contains(body, `/key"`) {
		t.Error("the page links to an address for the key")
	}
}

// With a password, the key is handed over encrypted with it, and the
// password is nowhere afterwards.
func TestGenerateWithAPasswordOnTheKey(t *testing.T) {
	const secret = "a password for one key only"
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	wantBody(t, b.get("/issue/generate"), `name="key_password" type="password" autocomplete="new-password"`, `name="key_password_again" type="password"`,
		"handrail-ca does not keep the password or show it again")

	form := b.generateForm("git.internal.example", "", "p256")
	form.Set("key_password", secret)
	form.Set("key_password_again", secret)
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	wantBody(t, rec, "<dt>Key</dt><dd>ECDSA P-256, encrypted with the password you gave</dd>", "handrail-ca has not kept the password and cannot show it again")
	blocks := pemBlocks(t, body)
	if len(blocks) != 4 || blocks[0].Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("the key on the page is a %q block", blocks[0].Type)
	}
	if _, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes); err == nil {
		t.Fatal("the key on the page reads without the password")
	}
	_, files := filesOn(t, body)
	for name, text := range files {
		if strings.Contains(text, "-----BEGIN PRIVATE KEY-----") {
			t.Errorf("the file %s carries the key unencrypted", name)
		}
	}
	if !strings.Contains(files["git.internal.example.key"], "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		t.Error("the key file is not the encrypted key")
	}

	// The password is not on the page, in the log or in the history.
	if strings.Contains(body, secret) || strings.Contains(html.UnescapeString(body), secret) {
		t.Error("the password is on the page")
	}
	if strings.Contains(s.log.String(), secret) {
		t.Error("the password is in the log")
	}
	events := s.issueEvents()
	for _, e := range events {
		if strings.Contains(e.Detail, secret) {
			t.Error("the password is in the history")
		}
	}
	if !strings.Contains(events[1].Detail, "key made by handrail-ca (ECDSA P-256), encrypted with a password") {
		t.Errorf("history: %q", events[1].Detail)
	}

	// With openssl to hand: the password opens the key, and the key is
	// the certificate's.
	if openssl, err := exec.LookPath("openssl"); err == nil {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "k.key")
		if err := os.WriteFile(keyFile, []byte(files["git.internal.example.key"]), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(openssl, "pkey", "-in", keyFile, "-passin", "env:GENERATE_TEST_PASSWORD", "-pubout", "-outform", "DER")
		cmd.Env = append(os.Environ(), "GENERATE_TEST_PASSWORD="+secret)
		public, err := cmd.Output()
		if err != nil {
			t.Fatalf("openssl does not open the key with the password: %v", err)
		}
		cert, err := x509.ParseCertificate(blocks[1].Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
			t.Error("the key that the password opens is not the certificate's")
		}
	}
}

// As a PFX file: one file with the key, the certificate and its chain,
// opened with the password. The key is then nowhere on the page as text.
func TestGenerateAsAPFXFile(t *testing.T) {
	const secret = "a password for one file only"
	for name, tt := range map[string]struct {
		format, key string
		says        []string
		history     string
	}{
		"AES-256":           {"pfx", "p256", []string{"It is protected with AES-256", "Windows 10 and Windows Server 2019 or newer", "can try passwords against it about four times as fast as against a PEM key from here"}, "handed over in a PFX file"},
		"for older devices": {"pfx-legacy", "rsa3072", []string{"It is the kind for older devices", "Triple DES and SHA-1. That is weak, and a password a person chose can be found from the file quickly"}, "handed over in a PFX file for older devices"},
		"an Ed25519 key":    {"pfx", "ed25519", []string{"It is protected with AES-256"}, "handed over in a PFX file"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			form := b.generateForm("git.internal.example", "git.internal.example\n10.20.0.14", tt.key)
			form.Set("format", tt.format)
			form.Set("key_password", secret)
			form.Set("key_password_again", secret)
			rec := b.do(http.MethodPost, "/issue/generate", form)
			wantStatus(t, rec, http.StatusOK)
			body := rec.Body.String()
			wantBody(t, rec, "Save the PFX file now. This page is the only place it is.", "inside a PFX file that opens with the password you gave", ">Download PFX file</button>")
			wantBody(t, rec, tt.says...)
			if strings.Contains(body, "ZgotmplZ") {
				t.Fatal("a link on the page was blanked by the template's own escaping")
			}
			// The key is not on the page as text, in any form.
			if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, secret) {
				t.Error("the key, or the password, is on the page as text")
			}
			names, files := filesOn(t, body)
			if want := []string{"git.internal.example.pfx", "git.internal.example.pem", "git.internal.example-chain.pem"}; !reflect.DeepEqual(names, want) {
				t.Fatalf("files offered: %v, want %v", names, want)
			}
			if !strings.Contains(body, `data-save-name="git.internal.example.pfx" data-save-type="application/x-pkcs12" data-save-body="`) {
				t.Error("the PFX file is not offered as one")
			}
			// For a browser that does not run the script, the file is on
			// the page as base64 text, with how to turn it back; it is
			// the same file.
			wantBody(t, rec, "The PFX file is below as text instead", "<h3>PFX file, as base64 text</h3>", "base64 -d pfx.txt &gt; git.internal.example.pfx", "certutil -decode pfx.txt git.internal.example.pfx")
			text := regexp.MustCompile(`(?s)<h3>PFX file, as base64 text</h3>\s*<pre class="pem key">([^<]+)</pre>`).FindStringSubmatch(body)
			if text == nil {
				t.Fatal("the PFX file is not on the page as text")
			}
			asText, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(html.UnescapeString(text[1]), "\n", ""))
			if err != nil || string(asText) != files["git.internal.example.pfx"] {
				t.Errorf("the PFX file as text is not the file the button saves (%v)", err)
			}

			// The file opens with the password, and holds the certificate's
			// key, the certificate and its chain.
			pfx := []byte(files["git.internal.example.pfx"])
			key, cert, chain, err := pkcs12.DecodeChain(pfx, secret)
			if err != nil {
				t.Fatalf("the PFX file does not open with the password: %v", err)
			}
			signer, ok := key.(crypto.Signer)
			if !ok || !reflect.DeepEqual(signer.Public(), cert.PublicKey) {
				t.Error("the key in the file is not the certificate's")
			}
			if cert.Subject.CommonName != "git.internal.example" || len(chain) != 1 || !chain[0].Equal(s.signer.cert) {
				t.Errorf("the file holds %s and %d more certificates", cert.Subject, len(chain))
			}
			if _, _, _, err := pkcs12.DecodeChain(pfx, "another password"); err == nil {
				t.Error("the file opens with another password")
			}
			// The file stretches its password as many times as is meant
			// for its kind, in each of the three places it is used (the
			// key, the certificates and the check on the whole), and says
			// so in itself.
			rounds := map[string]int{"pfx": pfxIterations, "pfx-legacy": olderPFXIterations}[tt.format]
			count, err := asn1.Marshal(rounds)
			if err != nil {
				t.Fatal(err)
			}
			if n := bytes.Count(pfx, count); n != 3 {
				t.Errorf("the file names %d rounds %d times, want 3 times", rounds, n)
			}
			// It is the certificate the page shows.
			if shown := pemBlocks(t, body); len(shown) != 3 || !bytes.Equal(shown[0].Bytes, cert.Raw) {
				t.Errorf("%d PEM blocks shown, or the first is not the certificate in the file", len(shown))
			}
			if events := s.issueEvents(); !strings.Contains(events[1].Detail, tt.history+";") || strings.Contains(events[1].Detail, secret) {
				t.Errorf("history: %q", events[1].Detail)
			}
			if strings.Contains(s.log.String(), secret) {
				t.Error("the password is in the log")
			}

			// With openssl to hand, it reads the file too.
			if openssl, err := exec.LookPath("openssl"); err == nil {
				file := filepath.Join(t.TempDir(), "x.pfx")
				if err := os.WriteFile(file, pfx, 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(openssl, "pkcs12", "-in", file, "-passin", "env:GENERATE_TEST_PASSWORD", "-nokeys")
				cmd.Env = append(os.Environ(), "GENERATE_TEST_PASSWORD="+secret)
				if out, err := cmd.CombinedOutput(); err != nil || bytes.Count(out, []byte("BEGIN CERTIFICATE")) != 2 {
					t.Errorf("openssl does not read the file: %v\n%.300s", err, out)
				}
			}
		})
	}
}

// A PFX file is opened with its password, so there has to be one; and
// only the forms that are offered are taken.
func TestGenerateKeyFormRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	wantBody(t, b.get("/issue/generate"), `<option value="pem" selected>PEM files</option>`, `<option value="pfx">One PFX file, AES-256</option>`,
		`<option value="pfx-legacy">One PFX file for older devices, Triple DES</option>`)
	for name, tt := range map[string]struct {
		format, password, want string
	}{
		"a PFX file with no password":      {"pfx", "", "a PFX file needs a password: it is what the file is opened with"},
		"the older kind with no password":  {"pfx-legacy", "", "a PFX file needs a password"},
		"a PFX file with a short password": {"pfx", "hunter2", "the minimum is 12"},
		"a form that is not offered":       {"jks", "a password for one file", "choose how the key is handed over from the list"},
	} {
		t.Run(name, func(t *testing.T) {
			form := b.generateForm("git.internal.example", "", "p256")
			form.Set("format", tt.format)
			form.Set("key_password", tt.password)
			form.Set("key_password_again", tt.password)
			rec := b.do(http.MethodPost, "/issue/generate", form)
			wantStatus(t, rec, http.StatusUnprocessableEntity)
			wantBody(t, rec, tt.want)
			// The choice comes back as it was left, where it was one.
			if tt.format != "jks" && !strings.Contains(rec.Body.String(), `<option value="`+tt.format+`" selected>`) {
				t.Error("the chosen form was not kept")
			}
		})
	}
	if n := len(s.ca.signings()); n != 0 {
		t.Errorf("the CA was asked to sign %d times", n)
	}
}

// If the PFX file cannot be made once the certificate exists, the key
// still reaches the operator: as PEM, encrypted with the same password.
func TestGenerateWhenThePFXFileCannotBeMade(t *testing.T) {
	const secret = "a password for one file only"
	saved := keyForms[1].pfx
	// An encoder that refuses any password, standing in for one that fails.
	keyForms[1].pfx = pkcs12.Passwordless
	t.Cleanup(func() { keyForms[1].pfx = saved })

	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	form := b.generateForm("git.internal.example", "", "p256")
	form.Set("format", "pfx")
	form.Set("key_password", secret)
	form.Set("key_password_again", secret)
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "The PFX file that was asked for could not be made", "The key is handed over below as PEM instead, encrypted with the same password.",
		"Save the private key now.", ">Download key</button>")
	blocks := pemBlocks(t, rec.Body.String())
	if len(blocks) != 4 || blocks[0].Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("%d PEM blocks, the first a %q", len(blocks), blocks[0].Type)
	}
	if names, _ := filesOn(t, rec.Body.String()); len(names) != 4 || names[0] != "git.internal.example.key" {
		t.Errorf("files offered: %v", names)
	}
}

// A password that would leave a key nobody can open, or one too short to
// protect it, makes nothing; and no password is ever sent back.
func TestGenerateKeyPasswordRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	for name, tt := range map[string]struct {
		first, again, want string
	}{
		"typed differently the second time": {"a password for one key", "a password for one kez", "the two passwords for the key are not the same"},
		"typed once only":                   {"a password for one key", "", "the two passwords for the key are not the same"},
		"only the second box":               {"", "a password for one key", "the two passwords for the key are not the same"},
		"too short":                         {"hunter2", "hunter2", "the key&#39;s password has 7 characters; the minimum is 12"},
		"too long":                          {strings.Repeat("x", 1025), strings.Repeat("x", 1025), "the key&#39;s password is longer than 1024 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			form := b.generateForm("git.internal.example", "", "p256")
			form.Set("key_password", tt.first)
			form.Set("key_password_again", tt.again)
			rec := b.do(http.MethodPost, "/issue/generate", form)
			wantStatus(t, rec, http.StatusUnprocessableEntity)
			wantBody(t, rec, tt.want, "Generate key and sign")
			for _, typed := range []string{tt.first, tt.again} {
				if typed != "" && strings.Contains(rec.Body.String(), typed) {
					t.Error("a password was sent back to the browser")
				}
			}
			if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
				t.Error("a key was made")
			}
		})
	}
	if n := len(s.ca.signings()); n != 0 {
		t.Errorf("the CA was asked to sign %d times", n)
	}
}

// madePassword is the password a page shows as made for the key.
var madePassword = regexp.MustCompile(`<span class="mono made">([^<]+)</span>`)

// A password can be made here instead of typed: it is shown on the one
// page that carries the key, opens what is handed over, and is in no
// record.
func TestGenerateWithAMadePassword(t *testing.T) {
	for name, format := range map[string]string{"PEM files": "pem", "a PFX file": "pfx", "a PFX file for older devices": "pfx-legacy"} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			wantBody(t, b.get("/issue/generate"), `<input id="make_password" name="make_password" type="checkbox" value="1">`, "A password made here is 20 random characters")
			form := b.generateForm("git.internal.example", "", "p256")
			form.Set("format", format)
			form.Set("make_password", "1")
			rec := b.do(http.MethodPost, "/issue/generate", form)
			wantStatus(t, rec, http.StatusOK)
			body := rec.Body.String()
			shown := madePassword.FindAllStringSubmatch(body, -1)
			if len(shown) != 1 || len(shown[0][1]) != 20 {
				t.Fatalf("passwords shown: %v", shown)
			}
			made := shown[0][1]
			if strings.Count(body, made) != 1 {
				t.Errorf("the password is on the page %d times", strings.Count(body, made))
			}
			wantBody(t, rec, "and its password now. This page is the only place they are.", "shown here once and kept nowhere")
			_, files := filesOn(t, body)
			if format == "pem" {
				wantBody(t, rec, "encrypted with the password below", "encrypted with the password above (PBKDF2 and AES-256)")
				blocks := pemBlocks(t, body)
				if blocks[0].Type != "ENCRYPTED PRIVATE KEY" {
					t.Fatalf("the key on the page is a %q block", blocks[0].Type)
				}
				if _, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes); err == nil {
					t.Fatal("the key on the page reads without the password")
				}
				// With openssl to hand: the password shown opens the key,
				// and the key is the certificate's.
				if openssl, err := exec.LookPath("openssl"); err == nil {
					keyFile := filepath.Join(t.TempDir(), "k.key")
					if err := os.WriteFile(keyFile, []byte(files["git.internal.example.key"]), 0o600); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(openssl, "pkey", "-in", keyFile, "-passin", "env:GENERATE_TEST_PASSWORD", "-pubout", "-outform", "DER")
					cmd.Env = append(os.Environ(), "GENERATE_TEST_PASSWORD="+made)
					public, err := cmd.Output()
					if err != nil {
						t.Fatalf("openssl does not open the key with the password shown: %v", err)
					}
					cert, err := x509.ParseCertificate(blocks[1].Bytes)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
						t.Error("the key that the password opens is not the certificate's")
					}
				}
			} else {
				wantBody(t, rec, "inside a PFX file that opens with the password below", "opens with the password above")
				// What is said of a password a person chose is not said of this one.
				if format == "pfx" {
					wantBody(t, rec, "Delete the file once it has been imported.")
				}
				if strings.Contains(body, "try passwords against it") || strings.Contains(body, "a password a person chose") {
					t.Error("the page warns about a chosen password, and this one was made")
				}
				if strings.Contains(body, "your password") || strings.Contains(body, "you gave") {
					t.Error("the page speaks of a password the operator gave")
				}
				key, cert, _, err := pkcs12.DecodeChain([]byte(files["git.internal.example.pfx"]), made)
				if err != nil {
					t.Fatalf("the password shown does not open the file: %v", err)
				}
				if signer, ok := key.(crypto.Signer); !ok || !reflect.DeepEqual(signer.Public(), cert.PublicKey) {
					t.Error("the key in the file is not the certificate's")
				}
			}
			// It is in the history only as having been made, and not in the log.
			events := s.issueEvents()
			for _, e := range events {
				if strings.Contains(e.Detail, made) {
					t.Error("the password is in the history")
				}
			}
			if want := map[string]string{
				"pem":        "), encrypted with a password that handrail-ca made;",
				"pfx":        "), handed over in a PFX file, opened with a password that handrail-ca made;",
				"pfx-legacy": "), handed over in a PFX file for older devices, opened with a password that handrail-ca made;",
			}[format]; !strings.Contains(events[1].Detail, want) {
				t.Errorf("history: %q, want %q in it", events[1].Detail, want)
			}
			if strings.Contains(s.log.String(), made) {
				t.Error("the password is in the log")
			}
			// Another one is another password.
			if format != "pem" {
				return
			}
			again := b.generateForm("git.internal.example", "", "p256")
			again.Set("format", format)
			again.Set("make_password", "1")
			rec = b.do(http.MethodPost, "/issue/generate", again)
			wantStatus(t, rec, http.StatusOK)
			if next := madePassword.FindStringSubmatch(rec.Body.String()); next == nil || next[1] == made {
				t.Errorf("the second password: %v", next)
			}
		})
	}
}

// A password typed and a password made cannot both be meant; and a page
// that refuses shows no password, and keeps the box as it was left.
func TestGenerateMadePasswordRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	form := b.generateForm("git.internal.example", "", "p256")
	form.Set("key_password", "a password for one key")
	form.Set("key_password_again", "a password for one key")
	form.Set("make_password", "1")
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "either type a password for the key or have one made, not both", `name="make_password" type="checkbox" value="1" checked>`)
	if madePassword.MatchString(rec.Body.String()) || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("a refused form was answered with a password or a key")
	}

	// Refused for another reason, with the box ticked: no password either.
	form = b.generateForm("", "", "p256")
	form.Set("make_password", "1")
	rec = b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	if madePassword.MatchString(rec.Body.String()) {
		t.Error("a refused form was answered with a password")
	}
	if n := len(s.ca.signings()); n != 0 {
		t.Errorf("the CA was asked to sign %d times", n)
	}

	// When the CA refuses, the key is gone and the password with it.
	s.ca.sign = func(context.Context, *ca.Request, time.Duration) (*ca.Issued, error) {
		return nil, &ca.StatusError{Status: http.StatusForbidden, Message: "not allowed"}
	}
	form = b.generateForm("git.internal.example", "", "p256")
	form.Set("make_password", "1")
	rec = b.do(http.MethodPost, "/issue/generate", form)
	if rec.Code == http.StatusOK || madePassword.MatchString(rec.Body.String()) {
		t.Errorf("answered %d, or with a password for a key that was thrown away", rec.Code)
	}
}

// The script that saves the files is served by handrail-ca as a script,
// and neither it nor any page makes a file its own address: a browser
// keeps the addresses of its downloads in its history, and Chromium was
// found to keep a whole private key that way.
func TestNoFileIsItsOwnAddress(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	rec := s.browser().get("/static/save.js")
	wantStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/javascript") {
		t.Errorf("the script is served as %q", got)
	}
	script := rec.Body.String()
	for _, want := range []string{"URL.createObjectURL(new Blob(", "URL.revokeObjectURL(address)", `button.getAttribute("data-save-body")`} {
		if !strings.Contains(script, want) {
			t.Errorf("the script does not have %q in it", want)
		}
	}
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{"static/save.js": strings.Join(regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`).Split(script, -1), "")}
	for _, e := range entries {
		text, err := fs.ReadFile(templateFS, "templates/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sources["templates/"+e.Name()] = string(text)
	}
	if len(sources) < 5 {
		t.Fatalf("only %d sources read", len(sources))
	}
	for name, text := range sources {
		if strings.Contains(text, "data:") {
			t.Errorf("%s has a data: address in it", name)
		}
	}
	// And nothing in the package can mark an address as safe to put on a
	// page unescaped, which is what a data: link needed.
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) < 10 {
		t.Fatalf("%d Go files found: %v", len(files), err)
	}
	for _, name := range files {
		text, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(name, "_test.go") && strings.Contains(string(text), "template.URL") {
			t.Errorf("%s uses template.URL", name)
		}
	}
}

func TestTypedNames(t *testing.T) {
	got, err := typedNames(" a.internal.example,b.internal.example\r\n\n10.20.0.1  a.internal.example\tspiffe://x/y ")
	want := []string{"a.internal.example", "b.internal.example", "10.20.0.1", "spiffe://x/y"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("typedNames = %v, %v; want %v", got, err, want)
	}
	if got, err := typedNames(""); err != nil || len(got) != 0 {
		t.Errorf("nothing typed: %v, %v", got, err)
	}
	if _, err := typedNames(strings.Repeat("a ", maxTypedNames)); err == nil {
		t.Error("an enormous box of names was taken")
	}
}

// A form is taken once, and the memory of taken forms is bounded.
func TestUsedForms(t *testing.T) {
	var u usedForms
	if !u.take("a", t0) || u.take("a", t0.Add(time.Hour)) {
		t.Error("a form was taken twice, or not at all")
	}
	if !u.take("b", t0) {
		t.Error("another form was refused")
	}
	// Long after, the memory of it has gone; by then its session has too.
	if !u.take("a", t0.Add(onceLifetime+time.Hour)) {
		t.Error("a form is remembered for ever")
	}
	if len(u.used) != 1 {
		t.Errorf("%d forms remembered, want the one just taken", len(u.used))
	}
}
