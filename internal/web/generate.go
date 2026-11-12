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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"handrail-ca/internal/ca"
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

// generateView is the form for a certificate whose key handrail-ca makes.
type generateView struct {
	CommonName, Names string
	Kinds             []validityOption
	// Once marks this showing of the form: it is taken once.
	Once string
}

// generatedView is the one answer that carries a private key.
type generatedView struct {
	Subject, Serial, Expires, Kind string
	KeyPEM, PEM, Chain             string
	// URL is the certificate's page, when the inventory has it.
	URL string
	// Differs says where the certificate does not carry what was asked.
	Differs []string
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
	data.Generate = &generateView{CommonName: r.PostForm.Get("common_name"), Names: r.PostForm.Get("names"), Once: once}
	chosen := r.PostForm.Get("key")
	for i, k := range keyKinds {
		data.Generate.Kinds = append(data.Generate.Kinds, validityOption{Value: k.value, Label: k.label, Selected: k.value == chosen || (chosen == "" && i == 0)})
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
	commonName := strings.TrimSpace(r.PostForm.Get("common_name"))
	for _, c := range commonName {
		if !unicode.IsPrint(c) {
			refuse(http.StatusUnprocessableEntity, "the common name has a character in it that does not print")
			return
		}
	}
	names, err := typedNames(r.PostForm.Get("names"))
	if err != nil {
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}
	if commonName == "" && len(names) == 0 {
		refuse(http.StatusUnprocessableEntity, "give a common name, or at least one name or address")
		return
	}
	var makeKey func() (crypto.Signer, error)
	kind := ""
	for _, k := range keyKinds {
		if k.value == r.PostForm.Get("key") {
			makeKey, kind = k.make, k.label
		}
	}
	if makeKey == nil {
		refuse(http.StatusUnprocessableEntity, "choose a kind of key from the list")
		return
	}
	length, err := chosenValidity(r, provisioner.Claims)
	if err != nil {
		refuse(http.StatusUnprocessableEntity, err.Error())
		return
	}
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

	u := currentUser(r)
	asked := "names: " + strings.Join(requestNamesOf(req), ", ") + "; validity: " + validityWords(length) + "; key made by handrail-ca (" + kind + ")"
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
			http.Redirect(w, r, s.certificateURL(outcome.serial)+"?issued=1", http.StatusSeeOther)
			return
		}
		s.record(r, event)
		data.Failure = outcome.failure
		data.Failure.KeyDiscarded = true
		s.renderIssue(w, r, http.StatusBadGateway, data)
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		// The certificate exists and its key cannot be written out.
		s.log.Error("encoding a generated key", "err", err)
		event.Serial, event.Outcome = issued.Certificate.SerialNumber.String(), store.OutcomeFailed
		event.Detail = asked + "; issued, but the key could not be encoded to hand over, so the certificate is of no use to anyone"
		s.record(r, event)
		s.errorPage(w, r, http.StatusInternalServerError, "The CA issued a certificate, but handrail-ca could not write out its key, which is now gone. Revoke the certificate from its page and start again.")
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
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	clear(keyDER)
	var chain bytes.Buffer
	for _, c := range append([]*x509.Certificate{cert}, issued.Intermediates...) {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	view.Chain = chain.String()
	if after.Certificate(serial) != nil {
		view.URL = s.certificateURL(serial)
	}
	data.Generate, data.Generated = nil, view
	s.renderIssue(w, r, http.StatusOK, data)
}
