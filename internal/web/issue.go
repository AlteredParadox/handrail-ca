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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/store"
)

const (
	// maxIssueForm bounds the form a certificate request is posted in:
	// the request in PEM, which a browser sends with a good part of it
	// percent-encoded, twice over on the confirming step's worst day.
	maxIssueForm = 96 << 10
	// issueTimeout bounds one issuance: the request to the CA and the
	// reading of its database afterwards. Like a revocation's, it is not
	// the browser's to cut short.
	issueTimeout = 45 * time.Second
	// justIssued is how long a request that was signed is remembered, so
	// that the same form sent twice gives one certificate.
	justIssued = 10 * time.Minute
	// maxNewToSearch bounds how many certificates new to the inventory are
	// read when one is looked for by its key.
	maxNewToSearch = 200
	// maxCustomDays bounds a validity typed by hand, before the
	// provisioner's own limits are applied.
	maxCustomDays = 3660
	day           = 24 * time.Hour
	// arrived is what the address of a certificate's page carries when a
	// request has just led there: it asks the page to say what happened.
	arrived = "?issued=1"
	// issueSettles is how long after a signing request went out the CA
	// may still act on it: the token it carried is good for a minute.
	// After that, a database that shows no certificate for it means none
	// was issued.
	issueSettles = tokenGood + 30*time.Second
	tokenGood    = time.Minute
	// issuedWithin is how far a certificate's start may lie from the
	// moment a request was sent and still be taken for that request's:
	// the CA dates a certificate a minute back, by its own clock.
	issuedWithin = 5 * time.Minute
)

// offeredValidities are the lengths the page offers, where the
// provisioner allows them.
var offeredValidities = []time.Duration{24 * time.Hour, 7 * day, 30 * day, 90 * day, 365 * day}

type issueData struct {
	Provisioner string
	// CSR is what was pasted, shown back.
	CSR string
	// Problem is why the form was not accepted; nothing was sent.
	Problem string
	// Request is what was read from the CSR, nil until one has been.
	Request *requestView
	// Checked is the fingerprint of the request that was read and shown:
	// only that request is signed.
	Checked string

	Validities             []validityOption
	CustomN, CustomUnit    string
	Limits                 limitsView
	Template, TemplateFile string

	Failure *issueFailure
	// Unlisted is set when the CA issued a certificate that the inventory
	// does not have yet: the page then hands it over itself.
	Unlisted *unlistedView
}

type requestView struct {
	CommonName         string
	CommonNameFromName bool
	// CommonNameApart says the common name is not one of the request's
	// names: a CA with a name policy holds it to the policy by itself.
	CommonNameApart bool
	Names           []nameGroup
	NameAdded       bool
	// SubjectNotCopied is the request's whole subject, when it holds more
	// than a common name and the CA's default template will drop the rest.
	SubjectNotCopied string
	// RequestSubject is the request's whole subject, shown when the
	// provisioner has a template of its own that may use it.
	RequestSubject string
	PublicKey      string
}

type validityOption struct {
	Value, Label string
	Selected     bool
}

// limitsView is the provisioner's validity limits in the words the page
// uses. Empty strings are limits the provisioner does not set itself.
type limitsView struct {
	Shortest, Default, Longest string
	// Problem is why the limits could not be read from the CA.
	Problem string
}

// issueFailure describes a signing request that did not come back with a
// certificate. The fields mean what revokeFailure's do.
type issueFailure struct {
	// Incomplete is set with Unknown when the CA's database was read but
	// the certificates new to it could not all be looked at.
	Incomplete          bool
	NotSent, Unknown    bool
	CA, Clock, Database string
	// OddCommonName is the request's common name, set when the CA
	// answered with an error that gives no reason and the common name is
	// one a name policy cannot read as a name: the one cause of that
	// answer that is known (docs/ca-setup.md, section 2).
	OddCommonName string
}

type unlistedView struct {
	Subject, Serial, Expires string
	PEM, Chain               string
	// Again is set when this is the certificate of a request signed a
	// moment ago, handed over a second time and not signed a second time.
	Again bool
	// Database is why the CA's database could not be read, empty if it
	// was read and did not show the certificate.
	Database string
}

// recentIssues keeps one form sent twice from becoming two certificates:
// a request being signed is not signed again at the same time, and one
// that was signed a moment ago leads to the certificate it got. It is
// also what a certificate's page goes by when it says something about the
// request that led to it: what handrail-ca itself saw happen, not what an
// address claims.
type recentIssues struct {
	mu       sync.Mutex
	inFlight map[string]bool
	done     map[string]issuedAt
}

// issuedAt is what is remembered of a request that was given a
// certificate.
type issuedAt struct {
	serial string
	// how is what happened, in the words the certificate's page keys its
	// notice on: "now", "differs", "found".
	how string
	// issued is the certificate and its chain as the CA sent them, kept
	// for as long as the entry so that they can be handed over again
	// while the inventory has no page for the certificate. Nil when the
	// certificate was found in the inventory and never came in an answer.
	issued *ca.Issued
	at     time.Time

	// uncertain is set, with no serial, for an attempt whose outcome was
	// not learned: sent, no certificate back, and nothing to say the CA
	// made none. before and sentAt are what a later look needs to tell
	// that attempt's certificate from any other: the inventory as it was,
	// and the moment the request went out.
	uncertain bool
	before    *inventory.Snapshot
	sentAt    time.Time
}

// maxRememberedIssues bounds the requests remembered as just signed.
const maxRememberedIssues = 1000

// forget drops what is older than justIssued. The caller holds the lock.
func (ri *recentIssues) forget(now time.Time) {
	for k, d := range ri.done {
		if now.Sub(d.at) >= justIssued {
			delete(ri.done, k)
		}
	}
}

// begin claims a request for signing. It returns what is remembered of
// the request from a moment ago. An entry with a serial means it was
// given that certificate, and nothing is claimed. An uncertain entry
// means an earlier attempt's outcome is not known: the request is claimed,
// for the caller to settle that attempt before anything is sent again.
// busy means another signing of the same request is under way.
func (ri *recentIssues) begin(fingerprint string, now time.Time) (already issuedAt, busy bool) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.forget(now)
	if ri.inFlight[fingerprint] {
		return issuedAt{}, true
	}
	if d, ok := ri.done[fingerprint]; ok && !d.uncertain {
		return d, false
	}
	already = ri.done[fingerprint]
	if ri.inFlight == nil {
		ri.inFlight = map[string]bool{}
	}
	ri.inFlight[fingerprint] = true
	return already, false
}

// end releases a request. An entry with a serial, or an uncertain one, is
// remembered in place of whatever was; any other clears it: the request
// was refused or never sent, and may be sent again.
func (ri *recentIssues) end(fingerprint string, entry issuedAt) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	delete(ri.inFlight, fingerprint)
	if entry.serial == "" && !entry.uncertain {
		delete(ri.done, fingerprint)
		return
	}
	if _, replacing := ri.done[fingerprint]; !replacing && len(ri.done) >= maxRememberedIssues {
		return
	}
	if ri.done == nil {
		ri.done = map[string]issuedAt{}
	}
	ri.done[fingerprint] = entry
}

// about returns how the certificate with this serial came to be, if a
// request through handrail-ca was given it within the last justIssued.
func (ri *recentIssues) about(serial string, now time.Time) (how string, ok bool) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.forget(now)
	for _, d := range ri.done {
		if d.serial == serial {
			return d.how, true
		}
	}
	return "", false
}

// mayIssue refuses whoever may not issue, and says why.
func (s *server) mayIssue(w http.ResponseWriter, r *http.Request) bool {
	if !s.opts.CA.ProvisionerState().Configured {
		s.errorPage(w, r, http.StatusForbidden, "handrail-ca was started read-only, so nothing can be issued from here.")
		return false
	}
	if currentUser(r).user.Role != store.RoleOperator {
		s.errorPage(w, r, http.StatusForbidden, "Only operators can issue a certificate.")
		return false
	}
	return true
}

// actingProvisioner is the provisioner handrail-ca acts through, as the
// CA lists it: its limits and its template. problem is why it is not
// known.
func (s *server) actingProvisioner(r *http.Request) (p ca.Provisioner, problem string) {
	status := s.status.get(r.Context(), s.opts.CA, s.opts.Now)
	if status.ProvisionersProblem != "" {
		return p, status.ProvisionersProblem
	}
	name := s.opts.CA.ProvisionerState().Name
	for _, listed := range status.listed {
		if listed.Name == name && listed.Type == "JWK" {
			return listed, ""
		}
	}
	return p, "the CA does not list a JWK provisioner named " + name
}

func (s *server) newIssueData(r *http.Request, csr string, chosen string) (issueData, ca.Provisioner) {
	p, problem := s.actingProvisioner(r)
	data := issueData{
		Provisioner: s.opts.CA.ProvisionerState().Name, CSR: csr,
		CustomN: r.PostForm.Get("custom_n"), CustomUnit: r.PostForm.Get("custom_unit"),
		Template: p.Template, TemplateFile: p.TemplateFile,
		Limits: limitsView{Problem: problem},
	}
	if d := p.Claims.MinTLSCertDuration; d > 0 {
		data.Limits.Shortest = validity(d)
	}
	if d := p.Claims.DefaultTLSCertDuration; d > 0 {
		data.Limits.Default = validity(d)
	}
	if d := p.Claims.MaxTLSCertDuration; d > 0 {
		data.Limits.Longest = validity(d)
	}
	data.Validities = validityOptions(p.Claims, chosen)
	return data, p
}

// validityOptions are the choices of validity for a provisioner with
// these limits, with the chosen one marked.
func validityOptions(claims ca.Claims, chosen string) []validityOption {
	label := "The provisioner's default"
	if d := claims.DefaultTLSCertDuration; d > 0 {
		label += " (" + validity(d) + ")"
	}
	options := []validityOption{{Value: "default", Label: label}}
	lengths := map[time.Duration]bool{}
	for _, d := range offeredValidities {
		if within(d, claims) == nil {
			lengths[d] = true
		}
	}
	if longest := claims.MaxTLSCertDuration; longest > 0 {
		lengths[longest] = true
	}
	var sorted []time.Duration
	for d := range lengths {
		sorted = append(sorted, d)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for _, d := range sorted {
		label := validity(d)
		if d == claims.MaxTLSCertDuration {
			label += " (the longest this provisioner allows)"
		}
		options = append(options, validityOption{Value: d.String(), Label: label})
	}
	options = append(options, validityOption{Value: "custom", Label: "Another length"})
	found := false
	for i := range options {
		options[i].Selected = options[i].Value == chosen
		found = found || options[i].Selected
	}
	if !found {
		options[0].Selected = true
	}
	return options
}

// within checks a validity against the limits the provisioner sets
// itself. A limit it does not set is the CA's own, which handrail-ca
// cannot read: the CA then decides.
func within(d time.Duration, claims ca.Claims) error {
	if shortest := claims.MinTLSCertDuration; shortest > 0 && d < shortest {
		return fmt.Errorf("the provisioner's shortest validity is %s", validity(shortest))
	}
	if longest := claims.MaxTLSCertDuration; longest > 0 && d > longest {
		return fmt.Errorf("the provisioner's longest validity is %s", validity(longest))
	}
	return nil
}

// chosenValidity reads the validity the form asks for; zero is the
// provisioner's default. Only what the page offered is taken, and a
// length typed by hand is held to the provisioner's limits before
// anything is sent.
func chosenValidity(r *http.Request, claims ca.Claims) (time.Duration, error) {
	chosen := r.PostForm.Get("validity")
	switch chosen {
	case "", "default":
		return 0, nil
	case "custom":
		n, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("custom_n")))
		unit := map[string]time.Duration{"hours": time.Hour, "days": day}[r.PostForm.Get("custom_unit")]
		if err != nil || n <= 0 || unit == 0 || time.Duration(n) > maxCustomDays*day/unit {
			return 0, errors.New("give the validity as a whole number of hours or days")
		}
		d := time.Duration(n) * unit
		return d, within(d, claims)
	}
	for _, o := range validityOptions(claims, chosen) {
		if o.Value == chosen && o.Selected {
			d, err := time.ParseDuration(chosen)
			if err != nil {
				break
			}
			return d, nil
		}
	}
	return 0, errors.New("choose a validity from the list")
}

func newRequestView(req *ca.Request, hasTemplate bool) *requestView {
	v := &requestView{
		CommonName: req.CommonName, CommonNameFromName: req.CommonNameFromName, NameAdded: req.NameAdded,
		PublicKey: keyWords(req.CSR.PublicKey),
	}
	for _, g := range []nameGroup{
		{Label: "DNS names", Values: req.DNSNames}, {Label: "IP addresses", Values: req.IPAddresses},
		{Label: "Email addresses", Values: req.EmailAddresses}, {Label: "URIs", Values: req.URIs},
	} {
		if len(g.Values) > 0 {
			v.Names = append(v.Names, g)
		}
	}
	v.CommonNameApart = !req.CommonNameFromName && !req.NameAdded && !contains(requestNamesOf(req), req.CommonName)
	if hasTemplate {
		v.RequestSubject = req.CSR.Subject.String()
	} else {
		v.SubjectNotCopied = req.SubjectNotCopied
	}
	return v
}

// shown is what the signing form carries to say which request was read
// and shown: the request's fingerprint, keyed with a secret this process
// made when it started. A form can therefore only confirm a request that
// this running handrail-ca showed. One from before a restart confirms
// nothing, and the request is shown again: the memory of what was signed
// a moment ago does not outlive a restart, and without this the same form
// would be signed a second time unasked.
func (s *server) shown(req *ca.Request) string {
	mac := hmac.New(sha256.New, s.formKey)
	mac.Write([]byte("issue " + requestFingerprint(req)))
	return hex.EncodeToString(mac.Sum(nil))
}

func requestFingerprint(req *ca.Request) string {
	sum := sha256.Sum256(req.CSR.Raw)
	return hex.EncodeToString(sum[:])
}

func (s *server) renderIssue(w http.ResponseWriter, r *http.Request, code int, data issueData) {
	s.render(w, r, code, "issue.html", "Issue a certificate", data)
}

func (s *server) issueForm(w http.ResponseWriter, r *http.Request) {
	if !s.mayIssue(w, r) {
		return
	}
	data, _ := s.newIssueData(r, "", "")
	s.renderIssue(w, r, http.StatusOK, data)
}

// issue reads a pasted request and, on the second step, has the CA sign
// it. The first step only shows what was read. The second signs the
// request that was shown and no other: the form carries its fingerprint.
//
// Signing follows the order a revocation does: the attempt goes into the
// history, the request goes to the CA once, the CA's database is read
// again, and what is said afterwards comes from both.
func (s *server) issue(w http.ResponseWriter, r *http.Request) {
	if !s.mayIssue(w, r) {
		return
	}
	pasted := r.PostForm.Get("csr")
	data, provisioner := s.newIssueData(r, pasted, r.PostForm.Get("validity"))
	refuse := func(code int, problem string) {
		data.Problem = problem
		s.renderIssue(w, r, code, data)
	}
	req, err := ca.ReadRequest(pasted)
	if err != nil {
		if errors.Is(err, ca.ErrPrivateKey) {
			// Not sent back to the browser a second time.
			data.CSR = ""
		}
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}
	data.Request, data.Checked = newRequestView(req, provisioner.HasTemplate()), s.shown(req)
	if r.PostForm.Get("step") != "sign" {
		s.renderIssue(w, r, http.StatusOK, data)
		return
	}
	if r.PostForm.Get("checked") != data.Checked {
		refuse(http.StatusUnprocessableEntity, "the request is not one this page has read and shown: it was changed since, or handrail-ca was restarted in between. Check what it says now, below, and sign again")
		return
	}
	length, err := chosenValidity(r, provisioner.Claims)
	if err != nil {
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}

	now := s.opts.Now()
	fingerprint := requestFingerprint(req)
	already, busy := s.issues.begin(fingerprint, now)
	switch {
	case busy:
		refuse(http.StatusConflict, "this request is being signed right now, by a form sent a moment ago. Wait for that one")
		return
	case already.serial != "":
		s.issuedAlready(w, r, data, already)
		return
	}
	// What is remembered of this request when the handler is done. It
	// starts as what was: an earlier attempt of unknown outcome stays
	// remembered unless this one settles it.
	done := already
	defer func() { s.issues.end(fingerprint, done) }()
	if already.uncertain {
		// Not sent again until the earlier attempt is accounted for.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), issueTimeout)
		serial, wait := s.settleEarlier(ctx, req, already)
		cancel()
		switch {
		case serial != "":
			done = issuedAt{serial: serial, how: "found", at: now}
			s.record(r, store.Event{Actor: currentUser(r).user.Username, Action: store.ActionIssue, Outcome: store.OutcomeOK, Serial: serial, Subject: req.CommonName,
				Detail: "the earlier attempt, whose outcome was not known, was given this certificate: the CA's database holds it now. Not signed again"})
			http.Redirect(w, r, s.certificateURL(serial)+arrived, http.StatusSeeOther)
			return
		case wait != "":
			refuse(http.StatusConflict, "an earlier attempt to sign this request has an outcome that is not known yet, and "+wait+". It was not sent again: that could give a second certificate")
			return
		}
	}
	done = issuedAt{at: now}

	u := currentUser(r)
	asked := "names: " + strings.Join(requestNamesOf(req), ", ") + "; validity: " + validityWords(length)
	event := store.Event{Actor: u.user.Username, Action: store.ActionIssue, Subject: req.CommonName}
	attempt := event
	attempt.Outcome, attempt.Detail = store.OutcomeAttempt, asked
	s.record(r, attempt)

	// Not the request's context: once sent, a signing request is seen
	// through and recorded whether or not the browser is still there.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), issueTimeout)
	defer cancel()
	before := s.opts.Inventory.Snapshot()
	sentAt := s.opts.Now()
	issued, sendErr := s.opts.CA.Sign(ctx, req, length)
	readErr := s.opts.Inventory.Refresh(ctx)
	after := s.opts.Inventory.Snapshot()

	if sendErr == nil {
		serial := issued.Certificate.SerialNumber.String()
		differs := differences(req, issued.Certificate, provisioner.HasTemplate())
		event.Serial, event.Subject = serial, issued.Certificate.Subject.CommonName
		event.Outcome, event.Detail = store.OutcomeOK, asked+"; issued, valid until "+issued.Certificate.NotAfter.UTC().Format(stamp)
		for _, d := range differs {
			event.Detail += "; " + d
		}
		s.record(r, event)
		// Remembered with the certificate itself, so that it can be handed
		// over again if this answer does not reach the browser.
		done.serial, done.how, done.issued = serial, "now", issued
		if len(differs) > 0 {
			done.how = "differs"
		}
		if after.Certificate(serial) == nil {
			// Issued, and not in the inventory to be looked at: handed over
			// here, since this answer is the only place it is.
			data.Request, data.Unlisted = nil, newUnlistedView(issued, readErr, now)
			s.renderIssue(w, r, http.StatusOK, data)
			return
		}
		http.Redirect(w, r, s.certificateURL(serial)+arrived, http.StatusSeeOther)
		return
	}

	outcome := s.issueOutcome(ctx, sendErr, readErr, before, after, req, sentAt)
	event.Serial, event.Outcome, event.Detail = outcome.serial, outcome.outcome, asked+"; "+outcome.detail
	s.record(r, event)
	if outcome.serial != "" {
		done.serial, done.how = outcome.serial, "found"
		http.Redirect(w, r, s.certificateURL(outcome.serial)+arrived, http.StatusSeeOther)
		return
	}
	if outcome.outcome == store.OutcomeUnknown {
		// Remembered as that: the same form sent again settles this
		// attempt first, and is not simply signed a second time.
		done.uncertain, done.before, done.sentAt = true, before, sentAt
	}
	data.Failure = outcome.failure
	s.renderIssue(w, r, http.StatusBadGateway, data)
}

// settleEarlier accounts for an earlier attempt to sign this request
// whose outcome was not learned, before the request is sent again. The
// CA's database is read now. If it holds the certificate that attempt was
// given, its serial is returned and nothing more is sent. If it cannot be
// read, or not all of it that matters could be, or the attempt is too
// recent to have finished for certain, wait says why the request is not
// sent again yet. With neither, the earlier
// attempt issued nothing, as far as can be known, and the request may go
// out again.
func (s *server) settleEarlier(ctx context.Context, req *ca.Request, earlier issuedAt) (serial, wait string) {
	if err := s.opts.Inventory.Refresh(ctx); err != nil {
		return "", "the CA's database cannot be read to find out: " + err.Error()
	}
	serial, complete := s.issuedFor(ctx, earlier.before, s.opts.Inventory.Snapshot(), req, earlier.sentAt)
	if serial != "" {
		return serial, ""
	}
	if !complete {
		// Nothing found is not nothing there: not all of what might be
		// that attempt's certificate could be looked at.
		return "", "the certificates that have appeared in the CA's database since could not all be read to look for it"
	}
	if s.opts.Now().Sub(earlier.sentAt) < issueSettles {
		return "", "it was made less than a minute ago and the CA may still be at it. Try again in a minute"
	}
	return "", ""
}

// issuedAlready answers a form for a request that was signed a moment
// ago. It is not signed again. If the certificate has a page, the visitor
// is sent there. If it has none yet, because the CA's database has not
// shown it, the certificate that was kept from the CA's answer is handed
// over again: a first answer that never reached the browser must not have
// been the only chance to have it.
func (s *server) issuedAlready(w http.ResponseWriter, r *http.Request, data issueData, already issuedAt) {
	if s.opts.Inventory.Snapshot().Certificate(already.serial) != nil {
		http.Redirect(w, r, s.certificateURL(already.serial)+"?issued=again", http.StatusSeeOther)
		return
	}
	if already.issued == nil {
		s.errorPage(w, r, http.StatusConflict, "This request was signed a moment ago, and the certificate it was given (serial "+already.serial+") is not in the certificate list as handrail-ca has it now. It was not signed again. Look for it in the list once the CA's database is being read.")
		return
	}
	data.Request, data.Unlisted = nil, newUnlistedView(already.issued, nil, s.opts.Now())
	data.Unlisted.Again = true
	s.renderIssue(w, r, http.StatusOK, data)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// notAName reports whether a common name has something in it that no DNS
// name, address, email address or URI has, a space or an underscore for
// instance. step-ca's name policy cannot read such a common name, and
// answers a request that carries one with an error and no reason (seen on
// step-ca 0.30.2; its log says "cannot parse cn domain").
func notAName(cn string) bool {
	for _, r := range cn {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-.:@*/[]%+=?&#~", r):
		default:
			return true
		}
	}
	return false
}

func requestNamesOf(req *ca.Request) []string {
	var names []string
	for _, kind := range [][]string{req.DNSNames, req.IPAddresses, req.EmailAddresses, req.URIs} {
		names = append(names, kind...)
	}
	return names
}

func validityWords(d time.Duration) string {
	if d == 0 {
		return "the provisioner's default"
	}
	return validity(d)
}

// differences says where a certificate does not carry what was asked for.
// Its names are compared kind by kind. Its subject is compared with the
// common name asked for, unless the provisioner has a template of its
// own: a template may well put more in the subject, and that is then
// reported as what the subject is, not as a difference.
func differences(req *ca.Request, cert *x509.Certificate, hasTemplate bool) []string {
	out := nameDifferences(req, cert)
	if !hasTemplate && cert.Subject.String() != "CN="+req.CommonName && cert.Subject.CommonName != req.CommonName {
		out = append(out, fmt.Sprintf("the certificate's subject is %q, not the common name %q asked for", cert.Subject.String(), req.CommonName))
	}
	return out
}

// nameDifferences says where a certificate's names are not the names a
// request was read as, kind by kind.
func nameDifferences(req *ca.Request, cert *x509.Certificate) []string {
	var out []string
	var ips, uris []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	for _, kind := range []struct {
		what      string
		got, want []string
	}{
		{"DNS names", cert.DNSNames, req.DNSNames}, {"IP addresses", ips, req.IPAddresses},
		{"email addresses", cert.EmailAddresses, req.EmailAddresses}, {"URIs", uris, req.URIs},
	} {
		if !sameSet(kind.got, kind.want) {
			out = append(out, fmt.Sprintf("the certificate's %s are [%s], not the [%s] asked for", kind.what, strings.Join(kind.got, ", "), strings.Join(kind.want, ", ")))
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func newUnlistedView(issued *ca.Issued, readErr error, now time.Time) *unlistedView {
	cert := issued.Certificate
	v := &unlistedView{Subject: cert.Subject.String(), Serial: cert.SerialNumber.String(), Expires: expiry(cert.NotAfter, now)}
	var chain bytes.Buffer
	for _, c := range append([]*x509.Certificate{cert}, issued.Intermediates...) {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	v.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	v.Chain = chain.String()
	if readErr != nil {
		v.Database = readErr.Error()
	}
	return v
}

// signed is what became of a signing request that did not come back with
// a certificate.
type signed struct {
	outcome, detail string
	// serial is set when the CA's database holds a certificate for the
	// request's key that was not there before: it was issued after all.
	serial  string
	failure *issueFailure
}

// issueOutcome works out what became of a signing request that failed,
// from the error (sendErr), whether the CA's database could be read
// afterwards (readErr), and the certificates that are in it now and were
// not before.
func (s *server) issueOutcome(ctx context.Context, sendErr, readErr error, before, after *inventory.Snapshot, req *ca.Request, sentAt time.Time) signed {
	failure := &issueFailure{CA: sendErr.Error()}
	var refused *ca.StatusError
	answered := errors.As(sendErr, &refused)
	if answered && refused.ClockDifference != 0 {
		failure.Clock = clockWords(refused.ClockDifference)
	}
	var notSent *ca.NotSentError
	if errors.As(sendErr, &notSent) {
		failure.NotSent = true
		return signed{outcome: store.OutcomeFailed, failure: failure, detail: "not issued: the request could not be sent: " + sendErr.Error()}
	}
	if answered && !fromInBetween(refused.Status) {
		if refused.Status == http.StatusInternalServerError && notAName(req.CommonName) {
			failure.OddCommonName = req.CommonName
		}
		return signed{outcome: store.OutcomeFailed, failure: failure, detail: "not issued: " + sendErr.Error()}
	}
	// No certificate came back, and nothing says the CA did not make one.
	if readErr != nil {
		failure.Unknown, failure.Database = true, readErr.Error()
		return signed{outcome: store.OutcomeUnknown, failure: failure,
			detail: "not confirmed: " + sendErr.Error() + "; the CA's database could not be read to check: " + readErr.Error()}
	}
	serial, complete := s.issuedFor(ctx, before, after, req, sentAt)
	if serial != "" {
		return signed{outcome: store.OutcomeOK, serial: serial,
			detail: "the CA's answer was not a certificate (" + sendErr.Error() + "), but its database holds one for the request's key and names, issued since"}
	}
	failure.Unknown = true
	if !complete {
		failure.Incomplete = true
		return signed{outcome: store.OutcomeUnknown, failure: failure,
			detail: "not confirmed: " + sendErr.Error() + "; the certificates new to the CA's database could not all be read to look for it"}
	}
	return signed{outcome: store.OutcomeUnknown, failure: failure,
		detail: "not confirmed: " + sendErr.Error() + "; the CA's database held no new certificate for the request's key when read just afterwards, which does not settle it"}
}

// issuedFor looks among the certificates that are new to the inventory
// for the one this request was given, and returns its serial. New to the
// inventory is not new: a stale inventory catching up shows certificates
// that were issued long ago, and a key may have been used before. So the
// certificate must carry the request's key, start within issuedWithin of
// the moment the request was sent, and carry the names that were asked
// for. Anything less is not taken for this request's.
//
// complete says whether every candidate was looked at. It is false when
// one could not be read, or there were more than are searched: finding
// nothing then does not mean there is nothing, and the caller must not
// take it to.
func (s *server) issuedFor(ctx context.Context, before, after *inventory.Snapshot, req *ca.Request, sentAt time.Time) (serial string, complete bool) {
	looked := 0
	complete = true
	for _, c := range after.Certificates {
		if c.Problem != "" || before.Certificate(c.Serial) != nil {
			continue
		}
		if c.NotBefore.Before(sentAt.Add(-issuedWithin)) || c.NotBefore.After(sentAt.Add(issuedWithin)) {
			continue
		}
		if looked++; looked > maxNewToSearch {
			return "", false
		}
		der, err := s.opts.Inventory.DER(ctx, c.Serial)
		if err != nil {
			complete = false
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			complete = false
			continue
		}
		if !bytes.Equal(cert.RawSubjectPublicKeyInfo, req.CSR.RawSubjectPublicKeyInfo) {
			continue
		}
		if len(nameDifferences(req, cert)) == 0 {
			return c.Serial, true
		}
	}
	return "", complete
}
