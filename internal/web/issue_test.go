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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/store"
)

// newCSR is a certificate signing request in PEM, with a new P-256 key.
func newCSR(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func gitCSR(t *testing.T) string {
	return newCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "git.internal.example"}, DNSNames: []string{"git.internal.example", "git"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.14")},
	})
}

var checkedField = regexp.MustCompile(`name="checked" value="([0-9a-f]{64})"`)

// read posts a request for reading and returns the page with what was
// read, and the form to sign it with.
func (b *browser) readCSR(csr string) (page string, form url.Values) {
	b.s.t.Helper()
	first := b.get("/issue")
	wantStatus(b.s.t, first, http.StatusOK)
	token := tokenIn(b.s.t, first)
	rec := b.do(http.MethodPost, "/issue", url.Values{"form_token": {token}, "csr": {csr}, "step": {"read"}})
	wantStatus(b.s.t, rec, http.StatusOK)
	m := checkedField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		b.s.t.Fatalf("the page that read the request has no fingerprint of it:\n%.600s", rec.Body.String())
	}
	return rec.Body.String(), url.Values{"form_token": {token}, "csr": {csr}, "step": {"sign"}, "checked": {m[1]}, "validity": {"default"}}
}

// issueEvents are the history's issuance rows, oldest first.
func (s *site) issueEvents() []store.Event {
	s.t.Helper()
	var events []store.Event
	for _, e := range s.history() {
		if e.Action == store.ActionIssue {
			events = append([]store.Event{e}, events...)
		}
	}
	return events
}

func TestIssue(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")

	// The way to it is in the navigation, and the page starts with the
	// one thing to do.
	first := b.get("/issue")
	wantStatus(t, first, http.StatusOK)
	wantBody(t, first, `<a href="/issue" aria-current="page">Issue</a>`, "Signed by the CA through the", ">handrail</span> provisioner",
		"1. Paste the certificate signing request", `<button type="submit" name="step" value="read" class="secondary">Read request</button>`,
		// The provisioner's limits, as the CA lists them.
		"Provisioner limits", "<dt>Longest</dt><dd>90 days</dd>", `<dt>Shortest</dt><dd><span class="muted">The CA's own</span></dd>`,
		"Making a CSR", "step certificate create", "openssl req -new")
	for _, absent := range []string{"2. Check what will be signed", "Sign certificate", `name="checked"`, "Not read"} {
		if strings.Contains(first.Body.String(), absent) {
			t.Errorf("the page has %q before a request was read", absent)
		}
	}

	csr := gitCSR(t)
	page, form := b.readCSR(csr)
	for _, want := range []string{
		"2. Check what will be signed", "<dt>Common name</dt><dd>git.internal.example</dd>",
		`<dt>DNS names</dt><dd><ul class="names"><li class="mono small">git.internal.example</li><li class="mono small">git</li></ul></dd>`,
		`<dt>IP addresses</dt><dd><ul class="names"><li class="mono small">10.20.0.14</li></ul></dd>`,
		"<dt>Public key</dt><dd>ECDSA P-256</dd>", `<dd class="good">Valid</dd>`,
		"What the request asks for beyond its names is not copied.",
		"3. Choose how long it is valid",
		`<option value="default" selected>The provisioner&#39;s default</option>`, `<option value="24h0m0s">1 day</option>`, `<option value="168h0m0s">7 days</option>`,
		`<option value="720h0m0s">30 days</option>`, `<option value="2160h0m0s">90 days (the longest this provisioner allows)</option>`, `<option value="custom">Another length</option>`,
		`<button type="submit" name="step" value="sign" class="primary wide">Sign certificate</button>`,
		// The request is still there, to be sent again with the signing.
		"-----BEGIN CERTIFICATE REQUEST-----",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, absent := range []string{"365 days", "8760h", "taken from the names", "lists no names", "Only the common name of the subject is kept", "certificate template of its own"} {
		if strings.Contains(page, absent) {
			t.Errorf("the page says %q", absent)
		}
	}
	if len(s.ca.signings()) != 0 || len(s.issueEvents()) != 0 {
		t.Fatal("reading a request sent or recorded something")
	}

	// Signed, for ninety days.
	s.clock.advance(time.Minute)
	form.Set("validity", "2160h0m0s")
	rec := b.do(http.MethodPost, "/issue", form)
	wantRedirect(t, rec, "/certificates/5001?issued=1")
	asked := s.ca.signings()
	if len(asked) != 1 || asked[0].validity != 2160*time.Hour || asked[0].request.CommonName != "git.internal.example" || asked[0].request.PEM != csr {
		t.Fatalf("the CA was asked for %+v", asked)
	}

	// Its page, read back from the CA's database, with the certificate to
	// download; and it is in the list without waiting for a timed read.
	cert := b.get("/certificates/5001?issued=1")
	wantStatus(t, cert, http.StatusOK)
	wantBody(t, cert, "<h1>git.internal.example</h1>", "Issued. This is the certificate the CA signed for the request.", "/certificates/5001/pem", "-----BEGIN CERTIFICATE-----")
	wantBody(t, b.get("/?q=git.internal.example"), `href="/certificates/5001"`)
	// The plain page says nothing about a request.
	if strings.Contains(b.get("/certificates/5001").Body.String(), "Issued. This is") {
		t.Error("a page not reached from the issue page says a request was signed")
	}

	events := s.issueEvents()
	if len(events) != 2 {
		t.Fatalf("history: %+v", events)
	}
	const askedFor = "names: git.internal.example, git, 10.20.0.14; validity: 90 days"
	if e := events[0]; e.Actor != "alice" || e.Outcome != store.OutcomeAttempt || e.Subject != "git.internal.example" || e.Serial != "" || e.Detail != askedFor || e.Remote != "10.20.0.5" {
		t.Errorf("the attempt: %+v", e)
	}
	if e := events[1]; e.Outcome != store.OutcomeOK || e.Serial != "5001" || e.Subject != "git.internal.example" || e.Detail != askedFor+"; issued, valid until 2027-02-09 12:01 UTC" {
		t.Errorf("the outcome: %+v", e)
	}
	// The certificate's page has its issuance in its history.
	wantBody(t, cert, `<span class="strong">alice</span> Issue <span class="badge ok">Done</span>`)

	// The same form sent again gives the same certificate, not a second.
	rec = b.do(http.MethodPost, "/issue", form)
	wantRedirect(t, rec, "/certificates/5001?issued=again")
	wantBody(t, b.get("/certificates/5001?issued=again"), "This request had already been signed a moment ago", "It was not signed a second time.")
	if len(s.ca.signings()) != 1 || len(s.issueEvents()) != 2 {
		t.Error("a request sent twice was signed twice")
	}
	// Later, it is a new request to sign like any other.
	s.clock.advance(justIssued)
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5002?issued=1")
}

// What the page says the certificate will carry, for each shape of
// request.
func TestIssueShowsWhatWillBeSigned(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	uri, _ := url.Parse("spiffe://internal.example/app")

	for name, tt := range map[string]struct {
		tmpl   x509.CertificateRequest
		want   []string
		absent []string
	}{
		"names and no common name": {
			x509.CertificateRequest{DNSNames: []string{"a.internal.example"}, IPAddresses: []net.IP{net.ParseIP("10.20.0.1")}},
			[]string{`<dt>Common name</dt><dd>a.internal.example <span class="sub">taken from the names: the request has no common name, and the CA wants one</span></dd>`},
			[]string{"lists no names", "Only the common name of the subject"},
		},
		"a common name and no names": {
			x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}},
			[]string{"<dt>Common name</dt><dd>a.internal.example</dd>", "The request lists no names of its own. The certificate will carry its common name as its one name.",
				`<dt>DNS names</dt><dd><ul class="names"><li class="mono small">a.internal.example</li></ul></dd>`},
			[]string{"taken from the names"},
		},
		"a common name not among the names": {
			x509.CertificateRequest{Subject: pkix.Name{CommonName: "Build <server>"}, DNSNames: []string{"ci.internal.example"}},
			[]string{"<dt>Common name</dt><dd>Build &lt;server&gt;</dd>", `<li class="mono small">ci.internal.example</li>`,
				"The common name is not one of the request's names.", "it has to be a name the policy allows, or be allowed by itself"},
			[]string{"taken from the names", "lists no names", "<server>"},
		},
		"a common name among the names": {
			x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example"}, DNSNames: []string{"b.internal.example", "a.internal.example"}},
			[]string{"<dt>Common name</dt><dd>a.internal.example</dd>"},
			[]string{"The common name is not one of the request's names"},
		},
		"more in the subject than a common name": {
			x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example", Organization: []string{"Example"}, Country: []string{"DE"}}, DNSNames: []string{"a.internal.example"}},
			[]string{"Only the common name of the subject is kept.", `<span class="mono">CN=a.internal.example,O=Example,C=DE</span>`, "has to give this provisioner a template"},
			nil,
		},
		"every kind of name": {
			x509.CertificateRequest{Subject: pkix.Name{CommonName: "app"}, DNSNames: []string{"app.internal.example"}, IPAddresses: []net.IP{net.ParseIP("2001:db8::1")},
				EmailAddresses: []string{"ops@internal.example"}, URIs: []*url.URL{uri}},
			[]string{"<dt>DNS names</dt>", "<dt>IP addresses</dt>", "2001:db8::1", "<dt>Email addresses</dt>", "ops@internal.example", "<dt>URIs</dt>", "spiffe://internal.example/app"},
			nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			page, _ := b.readCSR(newCSR(t, &tt.tmpl))
			for _, want := range tt.want {
				if !strings.Contains(page, want) {
					t.Errorf("the page lacks %q", want)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(page, absent) {
					t.Errorf("the page says %q", absent)
				}
			}
		})
	}
}

// With a certificate template on the provisioner, step-ca's defaults no
// longer describe the certificate, and the page stops claiming them.
func TestIssueWithATemplateOnTheProvisioner(t *testing.T) {
	const template = `{"subject": {{ toJson .Insecure.CR.Subject }}, "sans": {{ toJson .SANs }}}`
	s := newSite(t, "http://127.0.0.1:8080")
	s.ca.provs[0].Template = template
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	csr := newCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.internal.example", Organization: []string{"Example <Org>"}}, DNSNames: []string{"a.internal.example"}})
	page, form := b.readCSR(csr)
	for _, want := range []string{
		"This provisioner has a certificate template of its own on the CA.", "The template decides the certificate's subject",
		`<dt>Request's subject</dt><dd>CN=a.internal.example,O=Example \&lt;Org\&gt;</dd>`,
		"The template, as the CA publishes it", "{{ toJson .Insecure.CR.Subject }}",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, absent := range []string{"Only the common name of the subject is kept", "What the request asks for beyond its names is not copied", "<Org>"} {
		if strings.Contains(page, absent) {
			t.Errorf("the page says %q", absent)
		}
	}
	// The CA, with such a template, puts the organisation in. That is the
	// template at work, not a difference to warn about.
	s.ca.sign = func(_ context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
		issued := s.caSigns(r, validity)
		issued.Certificate.Subject.Organization = []string{"Example <Org>"}
		s.caStores(issued.Certificate)
		return issued, nil
	}
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")

	// A template whose text the CA does not publish is still said to be one.
	s2 := newSite(t, "http://127.0.0.1:8080")
	s2.ca.provs[0].TemplateFile = "templates/leaf.tpl"
	b2 := s2.browser()
	wantRedirect(t, b2.signIn("alice", alicePassword), "/")
	page, _ = b2.readCSR(csr)
	if !strings.Contains(page, "certificate template of its own") || !strings.Contains(page, "templates/leaf.tpl") || !strings.Contains(page, "the CA does not publish its text") {
		t.Error("a template kept in a file on the CA is not mentioned")
	}
}

// A certificate that does not carry the names asked for is not passed off
// as what was asked.
func TestIssueSaysWhenTheCertificateDiffers(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	s.ca.sign = func(_ context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
		other := *r
		other.DNSNames = []string{"git.internal.example"}
		other.CommonName = "something else"
		issued := s.caSigns(&other, validity)
		s.caStores(issued.Certificate)
		return issued, nil
	}
	_, form := b.readCSR(gitCSR(t))
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
	page := b.get("/certificates/5001?issued=1")
	wantBody(t, page, "Issued, but the certificate does not carry exactly what was asked for.",
		"the certificate&#39;s DNS names are [git.internal.example], not the [git.internal.example, git] asked for",
		"the certificate&#39;s subject is &#34;CN=something else&#34;, not the common name &#34;git.internal.example&#34; asked for")
	if strings.Contains(page.Body.String(), "Issued. This is the certificate") {
		t.Error("the page says the certificate is what was asked for")
	}
}

// Nothing is sent, and nothing recorded as attempted, unless an operator
// asked for the request that was shown, with a validity that was offered.
func TestIssueRefusals(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	token := tokenIn(t, b.get("/issue"))
	csr := gitCSR(t)
	_, form := b.readCSR(csr)
	with := func(change func(url.Values)) url.Values {
		copied := url.Values{}
		for k, v := range form {
			copied[k] = append([]string{}, v...)
		}
		change(copied)
		return copied
	}

	// What is not a request is said to be so, and stays in the box to be
	// corrected.
	rec := b.do(http.MethodPost, "/issue", url.Values{"form_token": {token}, "csr": {"git.internal.example"}, "step": {"read"}})
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "Not read: this is not a certificate signing request in PEM", ">git.internal.example</textarea>")
	// Except a private key, which is not sent back a second time.
	key := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSECRETSECRETSECRET\n-----END PRIVATE KEY-----\n"
	rec = b.do(http.MethodPost, "/issue", url.Values{"form_token": {token}, "csr": {key}, "step": {"read"}})
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "this is a private key, not a certificate signing request", "treat it as exposed")
	if strings.Contains(rec.Body.String(), "SECRETSECRET") {
		t.Error("a pasted private key was sent back to the browser")
	}
	if strings.Contains(s.log.String(), "SECRETSECRET") {
		t.Error("a pasted private key is in the log")
	}
	// The same for a key in a paste too large to be a request: the size
	// is not what is said, and nothing of it is sent back.
	rec = b.do(http.MethodPost, "/issue", url.Values{"form_token": {token}, "csr": {csr + strings.Repeat("x", 40<<10) + key}, "step": {"read"}})
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "this is a private key, not a certificate signing request")
	if strings.Contains(rec.Body.String(), "SECRETSECRET") || strings.Contains(rec.Body.String(), "xxxxxxxx") {
		t.Error("an oversized paste holding a private key was sent back to the browser")
	}

	for name, tt := range map[string]struct {
		form url.Values
		code int
		want string
	}{
		"signing without having read":       {with(func(v url.Values) { v.Del("checked") }), 422, "the request is not one this page has read and shown"},
		"another request than the one read": {with(func(v url.Values) { v.Set("csr", gitCSR(t)) }), 422, "the request is not one this page has read and shown"},
		"a validity that was not offered":   {with(func(v url.Values) { v.Set("validity", "8760h0m0s") }), 422, "Not signed: choose a validity from the list."},
		"a validity that is no length":      {with(func(v url.Values) { v.Set("validity", "forever") }), 422, "choose a validity from the list"},
		"another length, not given":         {with(func(v url.Values) { v.Set("validity", "custom") }), 422, "give the validity as a whole number of hours or days"},
		"another length of nothing":         {with(func(v url.Values) { v.Set("validity", "custom"); v.Set("custom_n", "0"); v.Set("custom_unit", "days") }), 422, "whole number of hours or days"},
		"another length in no unit":         {with(func(v url.Values) { v.Set("validity", "custom"); v.Set("custom_n", "3"); v.Set("custom_unit", "weeks") }), 422, "whole number of hours or days"},
		"another length beyond all reason": {with(func(v url.Values) {
			v.Set("validity", "custom")
			v.Set("custom_n", "99999999999")
			v.Set("custom_unit", "days")
		}), 422, "whole number of hours or days"},
		"longer than the provisioner allows": {with(func(v url.Values) { v.Set("validity", "custom"); v.Set("custom_n", "91"); v.Set("custom_unit", "days") }), 422, "Not signed: the provisioner&#39;s longest validity is 90 days."},
		"without the session's form token":   {with(func(v url.Values) { v.Set("form_token", "") }), 403, "not sent from a page of your current session"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := b.do(http.MethodPost, "/issue", tt.form)
			wantStatus(t, rec, tt.code)
			wantBody(t, rec, tt.want)
		})
	}
	// A form larger than the page takes is said to be that.
	rec = b.do(http.MethodPost, "/issue", url.Values{"form_token": {token}, "csr": {strings.Repeat("A", maxIssueForm)}, "step": {"read"}})
	wantStatus(t, rec, http.StatusRequestEntityTooLarge)
	// From another origin it is not looked at.
	other := s.browser()
	other.cookies = b.cookies
	other.origin = "https://evil.example"
	wantStatus(t, other.do(http.MethodPost, "/issue", form), http.StatusForbidden)

	// A viewer cannot issue, and is not shown the way to it.
	viewer := s.browser()
	wantRedirect(t, viewer.signIn("bob", bobPassword), "/")
	if strings.Contains(viewer.get("/").Body.String(), `href="/issue"`) {
		t.Error("a viewer's pages lead to issuing")
	}
	rec = viewer.get("/issue")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "Only operators can issue a certificate.")
	viewerForm := with(func(v url.Values) { v.Set("form_token", tokenIn(t, viewer.get("/"))) })
	wantStatus(t, viewer.do(http.MethodPost, "/issue", viewerForm), http.StatusForbidden)
	wantRedirect(t, s.browser().get("/issue"), "/sign-in")

	if n := len(s.ca.signings()); n != 0 {
		t.Errorf("the CA was asked to sign %d times", n)
	}
	if events := s.issueEvents(); len(events) != 0 {
		t.Errorf("history has issuances nobody made: %+v", events)
	}

	// Another length inside the limits is taken.
	ok := with(func(v url.Values) {
		v.Set("validity", "custom")
		v.Set("custom_n", "36")
		v.Set("custom_unit", "hours")
	})
	wantRedirect(t, b.do(http.MethodPost, "/issue", ok), "/certificates/5001?issued=1")
	if asked := s.ca.signings(); len(asked) != 1 || asked[0].validity != 36*time.Hour {
		t.Errorf("the CA was asked for %+v", asked)
	}
}

func TestIssueReadOnly(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.ca.readOnly = true
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	home := b.get("/")
	if strings.Contains(home.Body.String(), `href="/issue"`) {
		t.Error("a read-only handrail-ca's pages lead to issuing")
	}
	rec := b.get("/issue")
	wantStatus(t, rec, http.StatusForbidden)
	wantBody(t, rec, "handrail-ca was started read-only, so nothing can be issued from here.")
	rec = b.do(http.MethodPost, "/issue", url.Values{"form_token": {tokenIn(t, home)}, "csr": {gitCSR(t)}, "step": {"read"}})
	wantStatus(t, rec, http.StatusForbidden)
	if len(s.ca.signings()) != 0 {
		t.Error("a read-only handrail-ca asked the CA to sign")
	}
}

// What the page and the history say when no certificate came back.
func TestIssueOutcomes(t *testing.T) {
	refused := &ca.StatusError{Status: 403, Message: `The request was forbidden by the certificate authority: dns name "git.internal.example" not allowed`}
	unauthorized := &ca.StatusError{Status: 401, Message: "The request lacked necessary authorization to be completed.", ClockDifference: -3 * time.Minute}
	lost := errors.New(`Post "https://ca.internal.example:9000/1.0/sign": context deadline exceeded`)
	gateway := &ca.StatusError{Status: 502}
	unsent := &ca.NotSentError{Err: errors.New("dial tcp 10.20.0.2:9000: connect: connection refused")}
	down := errors.New("connection refused")
	const askedFor = "names: git.internal.example, git, 10.20.0.14; validity: the provisioner's default; "

	tests := []struct {
		name string
		// ca is what the CA does: what it stores, and what it answers.
		ca     func(s *site, r *ca.Request) (*ca.Issued, error)
		dbDown bool

		status   int
		redirect string
		page     []string
		absent   []string
		outcome  string
		serial   string
		detail   string
	}{
		{
			name:   "refused by the CA's name policy",
			ca:     func(*site, *ca.Request) (*ca.Issued, error) { return nil, refused },
			status: http.StatusBadGateway,
			page: []string{"No certificate was issued", "The CA refused the request: the CA answered 403", "dns name &#34;git.internal.example&#34; not allowed",
				// The form is there, with the request, to correct and send again.
				"-----BEGIN CERTIFICATE REQUEST-----", "2. Check what will be signed"},
			absent:  []string{"It is not known", "could not be sent"},
			outcome: store.OutcomeFailed,
			detail:  `not issued: the CA answered 403: The request was forbidden by the certificate authority: dns name "git.internal.example" not allowed`,
		},
		{
			name:    "refused, and the clocks differ",
			ca:      func(*site, *ca.Request) (*ca.Issued, error) { return nil, unauthorized },
			status:  http.StatusBadGateway,
			page:    []string{"No certificate was issued", "The CA&#39;s clock is 3 minutes behind this machine&#39;s.", "within a minute of its own time"},
			outcome: store.OutcomeFailed,
			detail:  "not issued: the CA answered 401: The request lacked necessary authorization to be completed.",
		},
		{
			name:    "never sent, and the database cannot be read",
			ca:      func(*site, *ca.Request) (*ca.Issued, error) { return nil, unsent },
			dbDown:  true,
			status:  http.StatusBadGateway,
			page:    []string{"No certificate was issued", "The request could not be sent to the CA: dial tcp 10.20.0.2:9000: connect: connection refused", "Nothing was changed."},
			absent:  []string{"It is not known", "The CA refused"},
			outcome: store.OutcomeFailed,
			detail:  "not issued: the request could not be sent: dial tcp 10.20.0.2:9000: connect: connection refused",
		},
		{
			name:   "no answer, and no new certificate yet",
			ca:     func(*site, *ca.Request) (*ca.Issued, error) { return nil, lost },
			status: http.StatusBadGateway,
			page: []string{"It is not known yet whether a certificate was issued", "no certificate came back: Post &#34;https://ca.internal.example:9000/1.0/sign&#34;: context deadline exceeded",
				"held no new certificate for this request's key when it was read just afterwards. That does not settle it", `<a href="/?sort=issued">newest certificates</a>`},
			absent:  []string{"No certificate was issued", "Nothing was changed", "The CA refused"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the CA's database held no new certificate for the request's key when read just afterwards, which does not settle it",
		},
		{
			name:    "a gateway's error, and no new certificate yet",
			ca:      func(*site, *ca.Request) (*ca.Issued, error) { return nil, gateway },
			status:  http.StatusBadGateway,
			page:    []string{"It is not known yet whether a certificate was issued", "the CA answered 502"},
			absent:  []string{"No certificate was issued"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: the CA answered 502; the CA's database held no new certificate for the request's key when read just afterwards, which does not settle it",
		},
		{
			name:   "no answer, and the database cannot be read",
			ca:     func(*site, *ca.Request) (*ca.Issued, error) { return nil, lost },
			dbDown: true,
			status: http.StatusBadGateway,
			page: []string{"It is not known whether a certificate was issued", "could not be read to see whether one was issued all the same: listing certificates: connection refused",
				"Signing again would give a second certificate if the first was issued."},
			absent:  []string{"No certificate was issued", "not known yet"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the CA's database could not be read to check: listing certificates: connection refused",
		},
		{
			// The answer was lost, and the certificate is in the database:
			// found by the request's key among what is new there.
			name: "the answer was lost, and the certificate is there",
			ca: func(s *site, r *ca.Request) (*ca.Issued, error) {
				// Another certificate lands at the same time, for another key.
				s.caStores(s.caSigns(mustReadCSR(s.t, gitCSR(s.t)), 0).Certificate)
				s.caStores(s.caSigns(r, 0).Certificate)
				return nil, lost
			},
			redirect: "/certificates/5002?issued=1",
			outcome:  store.OutcomeOK,
			serial:   "5002",
			detail:   "the CA's answer was not a certificate (" + lost.Error() + "), but its database holds one for the request's key and names, issued since",
		},
		{
			// A certificate that is new to the inventory is not thereby new.
			// One for the same key, issued an hour ago and only now seen, is
			// not this request's: the outcome stays unknown.
			name: "the answer was lost, and an older certificate for the same key turns up",
			ca: func(s *site, r *ca.Request) (*ca.Issued, error) {
				s.clock.advance(-time.Hour)
				older := s.caSigns(r, 0).Certificate
				s.clock.advance(time.Hour)
				s.caStores(older)
				return nil, lost
			},
			status:  http.StatusBadGateway,
			page:    []string{"It is not known yet whether a certificate was issued"},
			absent:  []string{"No certificate was issued"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the CA's database held no new certificate for the request's key when read just afterwards, which does not settle it",
		},
		{
			// The certificate is there, and cannot be read to be recognised:
			// unknown, and recorded as a search that was not complete.
			name: "the answer was lost, and the new certificate cannot be read",
			ca: func(s *site, r *ca.Request) (*ca.Issued, error) {
				s.caStores(s.caSigns(r, 0).Certificate)
				s.server.opts.Inventory = &unreadable{Inventory: s.inv, serial: "5001"}
				return nil, lost
			},
			status:  http.StatusBadGateway,
			page:    []string{"It is not known yet whether a certificate was issued", "could not all be read to look for one with this request's key. So one may be there."},
			absent:  []string{"No certificate was issued", "held no new certificate"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the certificates new to the CA's database could not all be read to look for it",
		},
		{
			// Nor is a new certificate for the same key with other names.
			name: "the answer was lost, and a new certificate for the same key has other names",
			ca: func(s *site, r *ca.Request) (*ca.Issued, error) {
				other := *r
				other.DNSNames = []string{"something-else.internal.example"}
				s.caStores(s.caSigns(&other, 0).Certificate)
				return nil, lost
			},
			status:  http.StatusBadGateway,
			page:    []string{"It is not known yet whether a certificate was issued"},
			outcome: store.OutcomeUnknown,
			detail:  "not confirmed: " + lost.Error() + "; the CA's database held no new certificate for the request's key when read just afterwards, which does not settle it",
		},
		{
			name: "issued, and the database cannot be read",
			ca: func(s *site, r *ca.Request) (*ca.Issued, error) {
				issued := s.caSigns(r, 0)
				s.caStores(issued.Certificate)
				return issued, nil
			},
			dbDown: true,
			status: http.StatusOK,
			page: []string{"The CA issued the certificate", "<dt>Subject</dt><dd>CN=git.internal.example</dd>", `<dd class="mono small">5001</dd>`,
				"Copy it from this page.", "The CA's database could not be read afterwards (listing certificates: connection refused)",
				"<h3>Certificate</h3>", "<h3>Certificate and chain</h3>", "-----BEGIN CERTIFICATE-----"},
			absent:  []string{"1. Paste the certificate signing request", "No certificate was issued", "-----BEGIN CERTIFICATE REQUEST-----"},
			outcome: store.OutcomeOK,
			serial:  "5001",
			detail:  "issued, valid until 2026-11-12 12:00 UTC",
		},
		{
			name:    "issued, and the database does not show it",
			ca:      func(s *site, r *ca.Request) (*ca.Issued, error) { return s.caSigns(r, 0), nil },
			status:  http.StatusOK,
			page:    []string{"The CA issued the certificate", "Copy it from this page.", "The CA's database did not show it when it was read just afterwards", "-----BEGIN CERTIFICATE-----"},
			absent:  []string{"could not be read"},
			outcome: store.OutcomeOK,
			serial:  "5001",
			detail:  "issued, valid until 2026-11-12 12:00 UTC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			_, form := b.readCSR(gitCSR(t))
			s.ca.sign = func(_ context.Context, r *ca.Request, _ time.Duration) (*ca.Issued, error) {
				issued, err := tt.ca(s, r)
				if tt.dbDown {
					s.rows.fail(down)
				}
				return issued, err
			}
			rec := b.do(http.MethodPost, "/issue", form)
			if tt.redirect != "" {
				wantRedirect(t, rec, tt.redirect)
			} else {
				wantStatus(t, rec, tt.status)
				wantBody(t, rec, tt.page...)
				for _, absent := range tt.absent {
					if strings.Contains(rec.Body.String(), absent) {
						t.Errorf("the page says %q", absent)
					}
				}
			}
			if n := len(s.ca.signings()); n != 1 {
				t.Errorf("the CA was asked %d times", n)
			}
			events := s.issueEvents()
			if len(events) != 2 || events[0].Outcome != store.OutcomeAttempt {
				t.Fatalf("history: %+v", events)
			}
			if got := events[1]; got.Outcome != tt.outcome || got.Serial != tt.serial || got.Detail != askedFor+tt.detail {
				t.Errorf("history says %q, serial %q, %q\nwant %q, serial %q, %q", got.Outcome, got.Serial, got.Detail, tt.outcome, tt.serial, askedFor+tt.detail)
			}
		})
	}
}

// unreadable is an inventory whose picture is whole but one of whose
// certificates cannot be read from the database when asked for.
type unreadable struct {
	Inventory
	serial string
}

func (u *unreadable) DER(ctx context.Context, serial string) ([]byte, error) {
	if serial == u.serial {
		return nil, errors.New("connection reset by peer")
	}
	return u.Inventory.DER(ctx, serial)
}

func mustReadCSR(t *testing.T, text string) *ca.Request {
	t.Helper()
	r, err := ca.ReadRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// step-ca answers a bare error 500 when its name policy cannot read a
// request's common name as a name. The page says what is known about that
// answer, for such a common name and for no other.
func TestIssueExplainsTheErrorForACommonNameThatIsNoName(t *testing.T) {
	bare := &ca.StatusError{Status: 500, Message: "error creating certificate"}
	const hint = "One cause is known."
	for name, tt := range map[string]struct {
		cn   string
		err  error
		want bool
	}{
		"a space in it":         {"HP LaserJet 400", bare, true},
		"an underscore in it":   {"host_name", bare, true},
		"markup in it":          {"Build <server>", bare, true},
		"a name like any other": {"printer.internal.example", bare, false},
		"an address":            {"10.20.0.14", bare, false},
		"a space in it, but a refusal with a reason": {"HP LaserJet 400", &ca.StatusError{Status: 403, Message: `cn name "x" not allowed`}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			s.ca.sign = func(context.Context, *ca.Request, time.Duration) (*ca.Issued, error) { return nil, tt.err }
			_, form := b.readCSR(newCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: tt.cn}, DNSNames: []string{"printer.internal.example"}}))
			rec := b.do(http.MethodPost, "/issue", form)
			wantStatus(t, rec, http.StatusBadGateway)
			wantBody(t, rec, "No certificate was issued", "The CA refused the request")
			if got := strings.Contains(rec.Body.String(), hint); got != tt.want {
				t.Errorf("the page explains the common name: %v, want %v", got, tt.want)
			}
			if strings.Contains(rec.Body.String(), "<server>") {
				t.Error("the common name is on the page unescaped")
			}
		})
	}
}

// The certificate found after a lost answer is said to be that, and a
// request that failed can be sent again.
func TestIssueAfterALostAnswer(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	_, form := b.readCSR(gitCSR(t))
	calls := 0
	s.ca.sign = func(_ context.Context, r *ca.Request, _ time.Duration) (*ca.Issued, error) {
		calls++
		if calls == 1 {
			return nil, &ca.StatusError{Status: 403, Message: "not allowed"}
		}
		s.caStores(s.caSigns(r, 0).Certificate)
		return nil, errors.New("connection reset by peer")
	}
	// Refused: nothing is remembered as signed, so the same request can
	// be sent again once whatever was wrong is put right.
	wantStatus(t, b.do(http.MethodPost, "/issue", form), http.StatusBadGateway)
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
	wantBody(t, b.get("/certificates/5001?issued=1"), "The CA's answer to the request did not arrive, but its database holds this certificate for the request's key")
	// And now it is remembered: a third send signs nothing.
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=again")
	if calls != 2 {
		t.Errorf("the CA was asked %d times", calls)
	}
}

// Two forms for one request at the same moment give one certificate.
func TestIssueTwiceAtOnce(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	_, form := b.readCSR(gitCSR(t))
	started, finish := make(chan struct{}), make(chan struct{})
	s.ca.sign = func(_ context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
		close(started)
		<-finish
		issued := s.caSigns(r, validity)
		s.caStores(issued.Certificate)
		return issued, nil
	}
	first := make(chan int, 1)
	go func() { first <- b.do(http.MethodPost, "/issue", form).Code }()
	<-started
	second := s.browser()
	second.cookies = b.cookies
	rec := second.do(http.MethodPost, "/issue", form)
	wantStatus(t, rec, http.StatusConflict)
	wantBody(t, rec, "this request is being signed right now")
	close(finish)
	if code := <-first; code != http.StatusSeeOther {
		t.Errorf("the first form: %d", code)
	}
	if n := len(s.ca.signings()); n != 1 {
		t.Errorf("the CA was asked %d times", n)
	}
}

// Once sent, a signing request is seen through and recorded although the
// browser has gone away.
func TestIssueIsSeenThroughWhenTheBrowserLeaves(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	_, form := b.readCSR(gitCSR(t))
	gone, leave := context.WithCancel(context.Background())
	s.ca.sign = func(ctx context.Context, r *ca.Request, validity time.Duration) (*ca.Issued, error) {
		leave()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		issued := s.caSigns(r, validity)
		s.caStores(issued.Certificate)
		return issued, nil
	}
	b.ctx = gone
	b.do(http.MethodPost, "/issue", form)
	if events := s.issueEvents(); len(events) != 2 || events[1].Outcome != store.OutcomeOK || events[1].Serial != "5001" {
		t.Errorf("history: %+v", events)
	}
	if s.inv.Snapshot().Certificate("5001") == nil {
		t.Error("the CA's database was not read afterwards")
	}
}

// When the provisioner's limits cannot be read, the page says so, offers
// every length, and leaves the refusing to the CA.
func TestIssueWhenTheLimitsAreNotKnown(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.ca.provsErr = errors.New("the CA answered 503")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	page, form := b.readCSR(gitCSR(t))
	for _, want := range []string{"The provisioner's limits could not be read from the CA: the CA answered 503", `<option value="8760h0m0s">365 days</option>`, `<option value="2160h0m0s">90 days</option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "the longest this provisioner allows") || strings.Contains(page, "<dt>Longest</dt>") {
		t.Error("the page states limits it could not read")
	}
	form.Set("validity", "8760h0m0s")
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
}

func TestValidityOptions(t *testing.T) {
	values := func(options []validityOption) string {
		var out []string
		for _, o := range options {
			v := o.Value
			if o.Selected {
				v += "*"
			}
			out = append(out, v)
		}
		return strings.Join(out, " ")
	}
	for name, tt := range map[string]struct {
		claims ca.Claims
		chosen string
		want   string
	}{
		"no limits of its own":   {ca.Claims{}, "", "default* 24h0m0s 168h0m0s 720h0m0s 2160h0m0s 8760h0m0s custom"},
		"a longest of 90 days":   {ca.Claims{MaxTLSCertDuration: 90 * day}, "720h0m0s", "default 24h0m0s 168h0m0s 720h0m0s* 2160h0m0s custom"},
		"a longest of 45 days":   {ca.Claims{MaxTLSCertDuration: 45 * day}, "1080h0m0s", "default 24h0m0s 168h0m0s 720h0m0s 1080h0m0s* custom"},
		"a shortest of two days": {ca.Claims{MinTLSCertDuration: 2 * day, MaxTLSCertDuration: 30 * day}, "custom", "default 168h0m0s 720h0m0s custom*"},
		"a longest of an hour":   {ca.Claims{MaxTLSCertDuration: time.Hour}, "24h0m0s", "default* 1h0m0s custom"},
		"what was never offered": {ca.Claims{MaxTLSCertDuration: 90 * day}, "8760h0m0s", "default* 24h0m0s 168h0m0s 720h0m0s 2160h0m0s custom"},
	} {
		if got := values(validityOptions(tt.claims, tt.chosen)); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tt.want)
		}
	}
	if label := validityOptions(ca.Claims{DefaultTLSCertDuration: 12 * time.Hour}, "")[0].Label; label != "The provisioner's default (12 hours)" {
		t.Errorf("default label = %q", label)
	}
}

// What a certificate's page says about the request that led to it comes
// from what handrail-ca saw happen, not from the address: anyone can write
// an address, and a page that told an operator a good certificate was
// faulty would have them revoke it.
func TestIssuedNoticesComeFromWhatHappenedNotFromTheAddress(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	notices := []string{"Issued. This is", "Issued, but", "did not arrive", "already been signed", "never handed over", "Revoke it below"}
	says := func(path string) (said []string) {
		body := b.get(path).Body.String()
		for _, n := range notices {
			if strings.Contains(body, n) {
				said = append(said, n)
			}
		}
		return said
	}
	// Nothing through handrail-ca led to this certificate: whatever the
	// address says, the page says nothing.
	for _, made := range []string{"1", "now", "differs", "found", "again", "before", "keyless"} {
		if said := says("/certificates/101?issued=" + made); len(said) != 0 {
			t.Errorf("?issued=%s on a certificate nobody asked for here: the page says %q", made, said)
		}
	}
	// One that a request was just given, as asked for: the page says that
	// and only that, whatever the address would have it say.
	_, form := b.readCSR(gitCSR(t))
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
	for _, made := range []string{"1", "now", "differs", "found", "keyless", "anything"} {
		if said := says("/certificates/5001?issued=" + made); len(said) != 1 || said[0] != "Issued. This is" {
			t.Errorf("?issued=%s on a certificate issued as asked: the page says %q", made, said)
		}
	}
	// "again" is the one thing the address chooses, and it is true: the
	// request was signed a moment ago.
	if said := says("/certificates/5001?issued=again"); len(said) != 1 || said[0] != "already been signed" {
		t.Errorf("?issued=again: the page says %q", said)
	}
	// Without the asking, nothing; and after a while, nothing.
	if said := says("/certificates/5001"); len(said) != 0 {
		t.Errorf("the plain page says %q", said)
	}
	s.clock.advance(justIssued)
	if said := says("/certificates/5001?issued=1"); len(said) != 0 {
		t.Errorf("ten minutes on, the page says %q", said)
	}
}

// An attempt whose outcome was not learned is not forgotten. The same form
// sent again does not go to the CA until the earlier attempt is accounted
// for: a browser retrying a lost response must not get a second
// certificate.
func TestIssueAgainAfterAnUnknownOutcome(t *testing.T) {
	lost := errors.New(`Post "https://ca.internal.example:9000/1.0/sign": context deadline exceeded`)
	// start signs in, reads a request and sends it to a CA that issues a
	// certificate but does not answer and has not stored it yet.
	start := func(t *testing.T) (*site, *browser, url.Values, **ca.Issued) {
		s := newSite(t, "http://127.0.0.1:8080")
		b := s.browser()
		wantRedirect(t, b.signIn("alice", alicePassword), "/")
		_, form := b.readCSR(gitCSR(t))
		var pending *ca.Issued
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			pending = s.caSigns(r, d)
			return nil, lost
		}
		rec := b.do(http.MethodPost, "/issue", form)
		wantStatus(t, rec, http.StatusBadGateway)
		wantBody(t, rec, "It is not known yet whether a certificate was issued")
		return s, b, form, &pending
	}

	t.Run("the certificate has turned up since", func(t *testing.T) {
		s, b, form, pending := start(t)
		// The CA finished after all; the next read shows its certificate.
		s.caStores((*pending).Certificate)
		rec := b.do(http.MethodPost, "/issue", form)
		wantRedirect(t, rec, "/certificates/5001?issued=1")
		wantBody(t, b.get("/certificates/5001?issued=1"), "The CA's answer to the request did not arrive, but its database holds this certificate")
		if n := len(s.ca.signings()); n != 1 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
		events := s.issueEvents()
		if len(events) != 3 || events[1].Outcome != store.OutcomeUnknown || events[2].Outcome != store.OutcomeOK || events[2].Serial != "5001" ||
			!strings.Contains(events[2].Detail, "the earlier attempt, whose outcome was not known, was given this certificate") {
			t.Errorf("history: %+v", events)
		}
		// And from then on it is a request that was signed.
		wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=again")
	})

	t.Run("the database cannot be read to find out", func(t *testing.T) {
		s, b, form, _ := start(t)
		s.clock.advance(5 * time.Minute)
		s.rows.fail(errors.New("connection refused"))
		rec := b.do(http.MethodPost, "/issue", form)
		wantStatus(t, rec, http.StatusConflict)
		wantBody(t, rec, "an earlier attempt to sign this request has an outcome that is not known yet", "the CA&#39;s database cannot be read to find out", "It was not sent again")
		if n := len(s.ca.signings()); n != 1 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
	})

	t.Run("too soon to know", func(t *testing.T) {
		s, b, form, _ := start(t)
		s.clock.advance(20 * time.Second)
		rec := b.do(http.MethodPost, "/issue", form)
		wantStatus(t, rec, http.StatusConflict)
		wantBody(t, rec, "it was made less than a minute ago and the CA may still be at it", "It was not sent again")
		if n := len(s.ca.signings()); n != 1 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
		// Still remembered: asking twice does not wear it down.
		wantStatus(t, b.do(http.MethodPost, "/issue", form), http.StatusConflict)
	})

	// The database is read, but the one certificate that could be the
	// earlier attempt's cannot be: finding nothing is then not knowing.
	t.Run("the search could not be completed", func(t *testing.T) {
		s, b, form, pending := start(t)
		s.caStores((*pending).Certificate)
		s.clock.advance(5 * time.Minute)
		s.server.opts.Inventory = &unreadable{Inventory: s.inv, serial: "5001"}
		rec := b.do(http.MethodPost, "/issue", form)
		wantStatus(t, rec, http.StatusConflict)
		wantBody(t, rec, "could not all be read to look for it", "It was not sent again")
		if n := len(s.ca.signings()); n != 1 {
			t.Fatalf("the CA was asked to sign %d times, although its first certificate is in the database", n)
		}
		// Readable again, the first certificate is found and nothing is sent.
		s.server.opts.Inventory = s.inv
		wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
		if n := len(s.ca.signings()); n != 1 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
	})

	// More new certificates than are searched: the same.
	t.Run("more new certificates than are looked through", func(t *testing.T) {
		s, b, form, _ := start(t)
		s.rows.mu.Lock()
		for i := 0; i <= maxNewToSearch; i++ {
			s.rows.certs = append(s.rows.certs, leafRow(t, int64(9000+i), "other.internal.example", s.clock.Now().Add(-time.Minute), s.clock.Now().Add(time.Hour)))
		}
		s.rows.mu.Unlock()
		s.clock.advance(3 * time.Minute)
		rec := b.do(http.MethodPost, "/issue", form)
		wantStatus(t, rec, http.StatusConflict)
		wantBody(t, rec, "could not all be read to look for it")
		if n := len(s.ca.signings()); n != 1 {
			t.Errorf("the CA was asked to sign %d times", n)
		}
	})

	t.Run("nothing was issued, as far as can be known", func(t *testing.T) {
		s, b, form, _ := start(t)
		// Long enough for the CA to have finished, the database read, and
		// no certificate for this request in it: now it may be sent again.
		s.clock.advance(2 * time.Minute)
		s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
			issued := s.caSigns(r, d)
			s.caStores(issued.Certificate)
			return issued, nil
		}
		rec := b.do(http.MethodPost, "/issue", form)
		wantRedirect(t, rec, "/certificates/5002?issued=1")
		if n := len(s.ca.signings()); n != 2 {
			t.Errorf("the CA was asked to sign %d times, want the second, wanted, time", n)
		}
	})
}

// A request signed while the CA's database could not be read has no page
// to go to. The form sent again (the first answer may never have reached
// the browser) gets the same certificate again, and the CA is not asked a
// second time. Once the inventory has it, the form leads to its page.
func TestIssueAgainWhileTheCertificateHasNoPage(t *testing.T) {
	for name, dbDown := range map[string]bool{"the database cannot be read": true, "the database does not show it": false} {
		t.Run(name, func(t *testing.T) {
			s := newSite(t, "http://127.0.0.1:8080")
			b := s.browser()
			wantRedirect(t, b.signIn("alice", alicePassword), "/")
			_, form := b.readCSR(gitCSR(t))
			var issued *ca.Issued
			s.ca.sign = func(_ context.Context, r *ca.Request, d time.Duration) (*ca.Issued, error) {
				issued = s.caSigns(r, d)
				if dbDown {
					s.caStores(issued.Certificate)
					s.rows.fail(errors.New("connection refused"))
				}
				return issued, nil
			}
			first := b.do(http.MethodPost, "/issue", form)
			wantStatus(t, first, http.StatusOK)
			wantBody(t, first, "The CA issued the certificate", "Copy it from this page.")
			// The certificate as that page has it.
			certificate := regexp.MustCompile(`(?s)<h3>Certificate</h3>\s*<pre class="pem">.*?</pre>`).FindString(first.Body.String())
			if !strings.Contains(certificate, "BEGIN CERTIFICATE") {
				t.Fatal("no certificate on the first page")
			}

			again := b.do(http.MethodPost, "/issue", form)
			wantStatus(t, again, http.StatusOK)
			wantBody(t, again, "This request was signed a moment ago, and this is the certificate it was given. It was not signed a second time.",
				"The certificate list does not have it yet", certificate, `<dd class="mono small">5001</dd>`)
			if n := len(s.ca.signings()); n != 1 {
				t.Fatalf("the CA was asked to sign %d times", n)
			}
			if events := s.issueEvents(); len(events) != 2 {
				t.Errorf("history has %d rows for one issuance", len(events))
			}

			// The database is read again and has it: now the form leads to
			// the certificate's page.
			if !dbDown {
				s.caStores(issued.Certificate)
			}
			s.rows.fail(nil)
			if err := s.inv.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=again")
			if n := len(s.ca.signings()); n != 1 {
				t.Errorf("the CA was asked to sign %d times", n)
			}
		})
	}
}

// A signing form from before handrail-ca was restarted confirms nothing:
// the memory of what was just signed went with the old process, so the
// request is shown again and not signed unasked.
func TestIssueFormFromBeforeARestart(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	b := s.browser()
	wantRedirect(t, b.signIn("alice", alicePassword), "/")
	_, form := b.readCSR(gitCSR(t))
	// As a restart leaves things: sessions are in the store and carry on,
	// the process's own secret and memory are new.
	s.server.formKey = []byte("the key of another process, 32 b")
	s.server.issues = recentIssues{}
	rec := b.do(http.MethodPost, "/issue", form)
	wantStatus(t, rec, http.StatusUnprocessableEntity)
	wantBody(t, rec, "the request is not one this page has read and shown", "or handrail-ca was restarted in between", "2. Check what will be signed")
	if len(s.ca.signings()) != 0 {
		t.Fatal("a form from before a restart was signed")
	}
	// Shown again, it can be confirmed again.
	form.Set("checked", checkedField.FindStringSubmatch(rec.Body.String())[1])
	wantRedirect(t, b.do(http.MethodPost, "/issue", form), "/certificates/5001?issued=1")
}
