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
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"handrail-ca/internal/ca"
	"handrail-ca/internal/inventory"
	"handrail-ca/internal/keyfile"
	"handrail-ca/internal/password"
	"handrail-ca/internal/store"
)

// The second way to issue (docs/PLAN.md, D3): handrail-ca makes the key
// pair and the request itself. The private key exists in this process for
// the length of one request. It goes into the page that answers that
// request and nowhere else: not into the store, not into the log, and not
// into anything that outlives the answer.

const (
	// maxTypedNames bounds the box the names are typed in.
	maxTypedNames = 8 << 10
	// onceLifetime is how long a used form is remembered, so that sending
	// it again does not make a second key. It is longer than a session.
	onceLifetime = 13 * time.Hour
	// maxOnces bounds the forms remembered as used.
	maxOnces = 10000
)

// keyKinds are the keys handrail-ca makes, in the order offered.
var keyKinds = []struct {
	value, label string
	make         func() (crypto.Signer, error)
}{
	{"p256", "ECDSA P-256", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
	{"p384", "ECDSA P-384", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
	{"ed25519", "Ed25519", func() (crypto.Signer, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}},
	{"rsa3072", "RSA 3072", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }},
}

// keyForms are the forms a generated key is handed over in, in the order
// offered. The PFX kinds are one file holding the key, the certificate
// and its chain, opened with a password; pfx names the encoder for them,
// and older says it is the kind for older devices.
var keyForms = []struct {
	value, label string
	pfx          *pkcs12.Encoder
	older        bool
}{
	{"pem", "PEM files", nil, false},
	// AES-256 with PBKDF2 over SHA-256, as OpenSSL 3 writes by default,
	// but with the password stretched pfxIterations times and not the
	// library's 2,048, which the library says itself is no protection for
	// a password a person would choose.
	{"pfx", "One PFX file, AES-256", pkcs12.Modern2023.WithIterations(pfxIterations), false},
	// Triple DES and SHA-1: weak, and what older devices can read. The
	// counts are the ones OpenSSL writes with -legacy, 2,048 throughout,
	// which is what such devices have long been given; the library alone
	// would stretch the password once for the check on the whole file,
	// and that check is where a password is guessed fastest.
	{"pfx-legacy", "One PFX file for older devices, Triple DES", pkcs12.LegacyDES.WithIterations(olderPFXIterations), true},
}

// olderPFXIterations is the count in a PFX file for older devices.
const olderPFXIterations = 2048

// pfxIterations is how many rounds of PBKDF2 stretch the password of an
// AES-256 PFX file, in each of the three places the file uses it (the key,
// the certificates and the check on the whole).
//
// A PFX file is read by other people's software, some of which refuses a
// file that asks for too much work. As published on 2026-11-12, and not
// tried here: Windows refuses a count above 600,000; .NET 9 and newer
// refuse one above 300,000, or a file whose counts add up to more than
// 1,000,000; and .NET Framework, where no password is passed to it,
// refuses a file whose three counts add up to more than 600,000. 150,000
// each, 450,000 together, is inside all of them, and a quarter of what a
// PEM key from here gets.
const pfxIterations = 150_000

// generateView is the form for a certificate whose key handrail-ca makes.
type generateView struct {
	CommonName, Names string
	Kinds             []validityOption
	// Forms are the forms the key can be handed over in.
	Forms []validityOption
	// MakePassword says the box for having a password made was ticked.
	MakePassword bool
	// Once marks this showing of the form: it is taken once.
	Once string
}

// generatedView is the one answer that carries a private key.
type generatedView struct {
	Subject, Serial, Expires, Kind string
	KeyPEM, PEM, Chain             string
	// Encrypted says the key is encrypted with the password that was
	// given with the form.
	Encrypted bool
	// PFX says the key was handed over inside a PFX file, with the
	// certificate and chain, and not as text; OlderPFX, that the file is
	// the kind for older devices. PFXProblem is why a PFX file that was
	// asked for could not be made: the key is then handed over as PEM.
	PFX, OlderPFX bool
	PFXProblem    string
	// MadePassword is the password handrail-ca made for the key, when it
	// was asked to: shown on this page, once, and kept nowhere.
	MadePassword string
	// Files are the same things as files to save. Each is carried
	// within this page and saved from it by the page's script: nothing is
	// fetched to save it, so the key is still in this one answer and
	// nowhere else. PFXText is the PFX file in base64, in lines, for a
	// browser that does not run the script.
	Files   []fileLink
	PFXText string
	// URL is the certificate's page, when the inventory has it.
	URL string
	// Differs says where the certificate does not carry what was asked.
	Differs []string
}

// fileLink is a file carried inside the page, to be saved from it: its
// name, its media type and its contents in base64.
//
// The contents are never an address. A file that is its own address (a
// data: link) is saved without asking the server for anything, which is
// what is wanted, but a browser keeps the address of each download in its
// history: Chromium was found to keep the whole of a private key that way
// (2026-11-12). The page's script (static/save.js) saves the file from
// the page under a blob: address instead, which names nothing.
type fileLink struct {
	Label, Name, Type, Body string
}

// carried makes a file for the page to carry.
func carried(label, name, mediaType string, body []byte) fileLink {
	return fileLink{Label: label, Name: name, Type: mediaType, Body: base64.StdEncoding.EncodeToString(body)}
}

func pemFile(label, name, text string) fileLink {
	return carried(label, name, "application/x-pem-file", []byte(text))
}

// usedForms remembers the forms that have been taken, so that a form sent
// a second time (a reload of the page that showed the key) is refused and
// does not quietly make another key and another certificate.
type usedForms struct {
	mu   sync.Mutex
	used map[string]time.Time
}

// take reports whether a form is taken now for the first time.
func (u *usedForms) take(once string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for k, at := range u.used {
		if now.Sub(at) >= onceLifetime {
			delete(u.used, k)
		}
	}
	if _, ok := u.used[once]; ok || len(u.used) >= maxOnces {
		return false
	}
	if u.used == nil {
		u.used = map[string]time.Time{}
	}
	u.used[once] = now
	return true
}

// A form's mark is a random number and a code over it, keyed with the
// secret this process made when it started. Only a mark this running
// handrail-ca gave out is taken, and each only once. The memory of which
// were taken is the process's own and goes with it, and that is why the
// key does too: after a restart every mark from before is refused, where
// one remembered nowhere would be taken a second time and make a second
// key and certificate.
const onceRandom = 16

func (s *server) newOnce() (string, error) {
	b := make([]byte, onceRandom)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b) + hex.EncodeToString(s.onceCode(b)), nil
}

func (s *server) onceCode(random []byte) []byte {
	mac := hmac.New(sha256.New, s.formKey)
	mac.Write([]byte("once "))
	mac.Write(random)
	return mac.Sum(nil)
}

// ourOnce reports whether a mark is one this process gave out.
func (s *server) ourOnce(once string) bool {
	raw, err := hex.DecodeString(once)
	if err != nil || len(raw) != onceRandom+sha256.Size {
		return false
	}
	// As it was given out and in no other spelling. Hexadecimal reads the
	// same in either case, and a mark is remembered as taken by its text:
	// one letter in the other case would be a mark never seen before.
	if hex.EncodeToString(raw) != once {
		return false
	}
	return hmac.Equal(raw[onceRandom:], s.onceCode(raw[:onceRandom]))
}

// mayGenerate refuses whoever may not issue, and everyone when the path is
// switched off.
func (s *server) mayGenerate(w http.ResponseWriter, r *http.Request) bool {
	if !s.mayIssue(w, r) {
		return false
	}
	if s.opts.NoKeyGeneration {
		s.errorPage(w, r, http.StatusForbidden, "Generating keys is switched off on this handrail-ca. Make the key and a certificate signing request on the machine that will use the certificate, and issue from that.")
		return false
	}
	return true
}

func (s *server) newGenerateData(r *http.Request, w http.ResponseWriter) (issueData, ca.Provisioner, bool) {
	data, provisioner := s.newIssueData(r, "", r.PostForm.Get("validity"))
	once, err := s.newOnce()
	if err != nil {
		s.log.Error("no randomness for a form", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not prepare the form.")
		return data, provisioner, false
	}
	data.Generate = &generateView{CommonName: r.PostForm.Get("common_name"), Names: r.PostForm.Get("names"), Once: once, MakePassword: r.PostForm.Get("make_password") != ""}
	chosen := r.PostForm.Get("key")
	for i, k := range keyKinds {
		data.Generate.Kinds = append(data.Generate.Kinds, validityOption{Value: k.value, Label: k.label, Selected: k.value == chosen || (chosen == "" && i == 0)})
	}
	form := r.PostForm.Get("format")
	for i, f := range keyForms {
		data.Generate.Forms = append(data.Generate.Forms, validityOption{Value: f.value, Label: f.label, Selected: f.value == form || (form == "" && i == 0)})
	}
	return data, provisioner, true
}

func (s *server) generateForm(w http.ResponseWriter, r *http.Request) {
	if !s.mayGenerate(w, r) {
		return
	}
	data, _, ok := s.newGenerateData(r, w)
	if !ok {
		return
	}
	s.renderIssue(w, r, http.StatusOK, data)
}

// typedNames reads the names box: one name to a line, or separated by
// commas or spaces.
func typedNames(typed string) ([]string, error) {
	if len(typed) > maxTypedNames {
		return nil, errors.New("the names are more than this form takes")
	}
	names := strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		for _, r := range n {
			if !unicode.IsPrint(r) {
				return nil, errors.New("a name has a character in it that does not print")
			}
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// earlierGenerateSettled accounts for an earlier attempt at the same
// certificate whose outcome was not learned. It reports whether the new
// attempt may go ahead. When it may not, the answer has been written: the
// operator was taken to the certificate the earlier attempt turned out to
// have been given, or told why nothing is made yet. left is what stays
// remembered of the earlier attempt.
func (s *server) earlierGenerateSettled(w http.ResponseWriter, r *http.Request, data issueData, earlier issuedAt, left *issuedAt) bool {
	u := currentUser(r)
	settle, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), issueTimeout)
	orphan, wait := s.settleEarlier(settle, earlier.req, earlier)
	cancel()
	if orphan != "" {
		*left = issuedAt{}
		s.record(r, store.Event{Actor: u.user.Username, Action: store.ActionIssue, Outcome: store.OutcomeFailed, Serial: orphan, Subject: earlier.req.CommonName,
			Detail: "the earlier attempt, whose outcome was not known, was given this certificate: the CA's database holds it now. Its key was made by handrail-ca and discarded then, so the certificate is of no use to anyone"})
		s.issues.remember(issuedAt{serial: orphan, how: "keyless", at: s.opts.Now()})
		http.Redirect(w, r, s.certificateURL(orphan)+arrived, http.StatusSeeOther)
		return false
	}
	if wait != "" {
		data.Problem = "an earlier attempt to issue this certificate has an outcome that is not known yet, and " + wait + ". Nothing was made or sent: a second certificate would leave the first, if there is one, with a key nobody has and nobody looking for it"
		s.renderIssue(w, r, http.StatusConflict, data)
		return false
	}
	return true
}

// generateKey is what an attempt to issue a certificate with a generated
// key is remembered under while its outcome is not known: who asked, and
// for what common name and names.
func generateKey(username, commonName string, names []string) string {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(username + "\x00" + commonName + "\x00" + strings.Join(sorted, "\x00")))
	return "generate " + hex.EncodeToString(sum[:])
}

// generateAsk is what a key-generating form asks for, checked.
type generateAsk struct {
	commonName string
	names      []string
	makeKey    func() (crypto.Signer, error)
	kind       string
	length     time.Duration
	// password encrypts the key that is handed over, if it is not empty;
	// madePassword says handrail-ca made it, and so has to show it.
	password     string
	madePassword bool
	// pfx is the encoder for the PFX file the key is handed over in, nil
	// for PEM; older says it is the kind for older devices.
	pfx   *pkcs12.Encoder
	older bool
}

// generateAsked reads and checks the form. Nothing is made here.
func generateAsked(r *http.Request, claims ca.Claims) (generateAsk, error) {
	var want generateAsk
	want.commonName = strings.TrimSpace(r.PostForm.Get("common_name"))
	for _, c := range want.commonName {
		if !unicode.IsPrint(c) {
			return want, errors.New("the common name has a character in it that does not print")
		}
	}
	names, err := typedNames(r.PostForm.Get("names"))
	if err != nil {
		return want, err
	}
	want.names = names
	if want.commonName == "" && len(names) == 0 {
		return want, errors.New("give a common name, or at least one name or address")
	}
	for _, k := range keyKinds {
		if k.value == r.PostForm.Get("key") {
			want.makeKey, want.kind = k.make, k.label
		}
	}
	if want.makeKey == nil {
		return want, errors.New("choose a kind of key from the list")
	}
	if want.length, err = chosenValidity(r, claims); err != nil {
		return want, err
	}
	if err := want.handover(r); err != nil {
		return want, err
	}
	return want, nil
}

// handover reads how the key is to be handed over: with what password,
// and in what form.
func (want *generateAsk) handover(r *http.Request) error {
	// A password for the key is optional. One that is given is typed
	// twice, since a slip would leave a key nobody can open, and is held
	// to the length asked of every password here.
	want.password = r.PostForm.Get("key_password")
	if want.password != r.PostForm.Get("key_password_again") {
		return errors.New("the two passwords for the key are not the same")
	}
	if want.password != "" {
		if err := password.Check(want.password); err != nil {
			return errors.New("the key's " + err.Error())
		}
	}
	// Or one is made here, long and random: what a file that other
	// software has to be able to open needs more than anything else.
	if r.PostForm.Get("make_password") != "" {
		if want.password != "" {
			return errors.New("either type a password for the key or have one made, not both")
		}
		made, err := password.Generate()
		if err != nil {
			return errors.New("handrail-ca could not make a password")
		}
		want.password, want.madePassword = made, true
	}
	form, known := r.PostForm.Get("format"), false
	if form == "" {
		form = keyForms[0].value
	}
	for _, f := range keyForms {
		if f.value == form {
			want.pfx, want.older, known = f.pfx, f.older, true
		}
	}
	if !known {
		return errors.New("choose how the key is handed over from the list")
	}
	if want.pfx != nil && want.password == "" {
		return errors.New("a PFX file needs a password: it is what the file is opened with")
	}
	return nil
}

// words says how the key is handed over, for the history. The password
// itself is in no record.
func (want generateAsk) words() string {
	var words string
	switch {
	case want.pfx != nil && want.older:
		words = ", handed over in a PFX file for older devices"
	case want.pfx != nil:
		words = ", handed over in a PFX file"
	case want.password != "":
		words = ", encrypted with a password"
	}
	if want.madePassword {
		words += " that handrail-ca made"
	}
	return words
}

// keyPEM writes a private key as it is handed over: PKCS #8 in PEM,
// encrypted with the password if there is one.
func keyPEM(key crypto.Signer, pw string) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	defer clear(der)
	if pw == "" {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
	}
	out, err := keyfile.Encrypt(der, pw)
	return string(out), err
}

// handOver puts on the answer page what the operator takes away: the
// chain, the files to save, and the password if handrail-ca made it.
func (s *server) handOver(view *generatedView, want generateAsk, key crypto.Signer, commonName string, issued *ca.Issued) {
	cert := issued.Certificate
	if want.madePassword {
		view.MadePassword = want.password
	}
	var chain bytes.Buffer
	for _, c := range append([]*x509.Certificate{cert}, issued.Intermediates...) {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	view.Chain = chain.String()
	// Named like the downloads on a certificate's own page.
	named := &inventory.Certificate{Subject: commonName, SerialHex: cert.SerialNumber.Text(16)}
	certificates := []fileLink{
		pemFile("Download certificate", fileName(named, ".pem"), view.PEM),
		pemFile("Download chain", fileName(named, "-chain.pem"), view.Chain),
	}
	view.Files = append([]fileLink{pemFile("Download key", fileName(named, ".key"), view.KeyPEM)}, certificates...)
	view.Files = append(view.Files, pemFile("Key and chain in one file", fileName(named, "-key-and-chain.pem"), view.KeyPEM+view.Chain))
	if want.pfx == nil {
		return
	}
	pfx, err := want.pfx.Encode(key, cert, issued.Intermediates, want.password)
	if err != nil {
		// The certificate exists; its key must still reach the operator.
		// It is handed over as PEM, encrypted with the same password,
		// which was made ready before the CA was asked.
		s.log.Error("making a PFX file", "err", err)
		view.PFXProblem = err.Error()
		return
	}
	view.PFX, view.OlderPFX, view.KeyPEM = true, want.older, ""
	view.PFXText = inLines(base64.StdEncoding.EncodeToString(pfx), 64)
	view.Files = append([]fileLink{carried("Download PFX file", fileName(named, ".pfx"), "application/x-pkcs12", pfx)}, certificates...)
}

// inLines breaks text into lines of the given width.
func inLines(text string, width int) string {
	var b strings.Builder
	for len(text) > width {
		b.WriteString(text[:width])
		b.WriteByte('\n')
		text = text[width:]
	}
	b.WriteString(text)
	return b.String()
}

// generate makes a key and a request for what was typed, has the CA sign
// it, and answers with the key, once.
func (s *server) generate(w http.ResponseWriter, r *http.Request) {
	if !s.mayGenerate(w, r) {
		return
	}
	data, provisioner, ok := s.newGenerateData(r, w)
	if !ok {
		return
	}
	refuse := func(code int, problem string) {
		data.Problem = problem
		s.renderIssue(w, r, code, data)
	}
	want, err := generateAsked(r, provisioner.Claims)
	if err != nil {
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}
	commonName, names, makeKey, kind, length := want.commonName, want.names, want.makeKey, want.kind, want.length
	// An earlier attempt at the same certificate, by the same operator,
	// whose outcome was not learned is accounted for before another is
	// made. If it was given a certificate after all, that certificate is
	// for a key nobody has: the operator is taken to it, to revoke it,
	// before a second one joins it.
	u := currentUser(r)
	pending := generateKey(u.user.Username, commonName, names)
	earlier, busy := s.issues.begin(pending, s.opts.Now())
	if busy {
		refuse(http.StatusConflict, "this certificate is being issued right now, by a form sent a moment ago. Wait for that one")
		return
	}
	// What is remembered of this certificate when the handler is done: an
	// earlier attempt of unknown outcome, unless this request settles it.
	left := earlier
	defer func() { s.issues.end(pending, left) }()
	if earlier.uncertain && !s.earlierGenerateSettled(w, r, data, earlier, &left) {
		return
	}
	left = issuedAt{}

	// Everything typed has been checked. From here a key is made, so the
	// form is taken: sent again, it makes nothing.
	once := r.PostForm.Get("once")
	if !s.ourOnce(once) || !s.onces.take(once, s.opts.Now()) {
		s.errorPage(w, r, http.StatusConflict, "This form cannot be taken: it was already sent once, or it is from before handrail-ca was last restarted. If it made a key, that key was shown then and is gone: handrail-ca does not keep it. Start again from the Issue page for a new one.")
		return
	}

	key, err := makeKey()
	if err != nil {
		s.log.Error("making a key", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not make a key. Nothing was sent to the CA.")
		return
	}
	req, err := ca.NewRequest(key, commonName, names)
	if err != nil {
		// The form is given back with a new mark: nothing was sent.
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}
	// The key in the form it will be handed over in, before the CA is
	// asked for anything: a certificate must not come to exist for a key
	// that then cannot be written out.
	handover, err := keyPEM(key, want.password)
	if err != nil {
		s.log.Error("writing out a generated key", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not write out the key it made. Nothing was sent to the CA.")
		return
	}

	asked := "names: " + strings.Join(requestNamesOf(req), ", ") + "; validity: " + validityWords(length) + "; key made by handrail-ca (" + kind + ")" + want.words()
	event := store.Event{Actor: u.user.Username, Action: store.ActionIssue, Subject: req.CommonName}
	attempt := event
	attempt.Outcome, attempt.Detail = store.OutcomeAttempt, asked
	s.record(r, attempt)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), issueTimeout)
	defer cancel()
	before := s.opts.Inventory.Snapshot()
	sentAt := s.opts.Now()
	issued, sendErr := s.opts.CA.Sign(ctx, req, length)
	readErr := s.opts.Inventory.Refresh(ctx)
	after := s.opts.Inventory.Snapshot()

	if sendErr != nil {
		outcome := s.issueOutcome(ctx, sendErr, readErr, before, after, req, sentAt)
		event.Serial, event.Outcome, event.Detail = outcome.serial, outcome.outcome, asked+"; "+outcome.detail
		if outcome.serial != "" {
			// A certificate exists for a key that is about to be gone:
			// nobody was given it, since no answer brought the certificate.
			event.Outcome = store.OutcomeFailed
			event.Detail += "; the key was not handed over and is gone, so the certificate is of no use to anyone"
			s.record(r, event)
			// Remembered as that, so that its page can say so from what
			// happened here and not from an address.
			s.issues.remember(issuedAt{serial: outcome.serial, how: "keyless", at: s.opts.Now()})
			http.Redirect(w, r, s.certificateURL(outcome.serial)+arrived, http.StatusSeeOther)
			return
		}
		if outcome.outcome == store.OutcomeUnknown {
			// Remembered, with the request (which holds the public key and
			// the names, and nothing secret): the next attempt at this
			// certificate looks for what became of this one first.
			left = issuedAt{uncertain: true, before: before, sentAt: sentAt, req: req, at: s.opts.Now()}
		}
		s.record(r, event)
		data.Failure = outcome.failure
		data.Failure.KeyDiscarded = true
		s.renderIssue(w, r, http.StatusBadGateway, data)
		return
	}

	cert := issued.Certificate
	serial := cert.SerialNumber.String()
	differs := differences(req, cert, provisioner.HasTemplate())
	event.Serial, event.Subject = serial, cert.Subject.CommonName
	event.Outcome, event.Detail = store.OutcomeOK, asked+"; issued, valid until "+cert.NotAfter.UTC().Format(stamp)
	for _, d := range differs {
		event.Detail += "; " + d
	}
	s.record(r, event)

	view := &generatedView{
		Subject: cert.Subject.String(), Serial: serial, Expires: expiry(cert.NotAfter, s.opts.Now()), Kind: kind, Differs: differs,
		KeyPEM: handover, Encrypted: want.password != "",
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	s.handOver(view, want, key, req.CommonName, issued)
	if after.Certificate(serial) != nil {
		view.URL = s.certificateURL(serial)
	}
	data.Generate, data.Generated = nil, view
	s.renderIssue(w, r, http.StatusOK, data)
}
