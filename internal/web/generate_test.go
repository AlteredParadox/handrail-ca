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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"html"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

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

	// A form taken, and its page reloaded after a restart: sessions are in
	// the store and carry on, the process's secret and memory are new.
	form := b.generateForm("git.internal.example", "", "p256")
	wantStatus(t, b.do(http.MethodPost, "/issue/generate", form), http.StatusOK)
	s.server.formKey = []byte("the key of another process, 32 b")
	s.server.onces = usedForms{}
	rec := b.do(http.MethodPost, "/issue/generate", form)
	wantStatus(t, rec, http.StatusConflict)
	wantBody(t, rec, "This form cannot be taken", "from before handrail-ca was last restarted")
	// And so is one that was never sent before the restart.
	if n := len(s.ca.signings()); n != 1 {
		t.Errorf("the CA was asked to sign %d times, want the once", n)
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
