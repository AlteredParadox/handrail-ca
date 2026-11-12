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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"handrail-ca/internal/inventory"
	"handrail-ca/internal/store"
)

// maxShownNames is how many names of each kind the detail page lists.
const maxShownNames = 200

// stamp is how the detail page writes a moment.
const stamp = "2006-01-02 15:04 UTC"

// detailData is what a certificate's page shows.
type detailData struct {
	Serial      string // decimal: the certificate's address in handrail-ca
	Title       string // the subject
	Badge       string
	StatusLabel string
	Summary     string

	// Problem is set for a row that is not a certificate; nothing below
	// it is filled in then.
	Problem string

	CommonName string
	Subject    string // the whole subject
	Names      []nameGroup

	NotBefore, NotAfter string
	Lifetime            string
	// Used and Total are the lifetime's progress, in seconds, for a bar.
	Used, Total int64

	Provisioner     string
	ProvisionerType string
	Issuer          string
	SerialHex       string
	SerialDecimal   string

	PublicKey     string
	Signature     string
	KeyUsage      string
	ExtendedUsage string
	Authority     string // "Yes" or "No": may it sign other certificates
	SHA256        string
	Extensions    []extensionView

	Revocation *revocationView
	// RevocationsKnown is false when no revocation table has been read.
	RevocationsKnown bool
	LastRead         string
	// Stale is why the last attempt to read the CA's database failed,
	// empty if it did not. With it set, everything here is as it was at
	// LastRead: a revocation since then is not on the page.
	Stale string

	PEM string

	// Note is what handrail-ca's users have recorded about the
	// certificate. Nil for a row that is not a certificate.
	Note *noteView

	// History is what was done to the certificate through handrail-ca.
	// Nil for a row that is not a certificate.
	History *certificateEvents

	// CanRevoke is set for an operator looking at a certificate that has
	// no revocation record, on a handrail-ca that can act on the CA.
	// ReadOnly is set when the same operator cannot because handrail-ca
	// was started read-only.
	CanRevoke, ReadOnly bool
	// JustRevoked says how the visitor got here from the revoke page:
	// "now" when their request revoked the certificate, "before" when it
	// found it revoked already. Only looked at beside a revocation record.
	JustRevoked string
}

// noteView is the note and labels of a certificate, and the form for
// changing them.
type noteView struct {
	Text   string
	Labels []string
	// Updated says when and by whom it was last changed; empty if never.
	Updated string
	// CanEdit is true for operators, who get the form. Typed and
	// TypedLabels are what the form holds: the saved note, or what was
	// just submitted and refused.
	CanEdit            bool
	Typed, TypedLabels string
	MaxNote            int
	// Saved is set on the page shown right after a save; Problem is why
	// what was submitted was not saved; Unread is set when the note could
	// not be read from the store, and is then not shown as "no note".
	Saved   bool
	Problem string
	Unread  bool
}

type nameGroup struct {
	Label  string
	Values []string
	More   int
}

type extensionView struct {
	OID, Name string
	Critical  bool
}

type revocationView struct {
	When, Reason, Detail, How, By string
	Problem                       string
}

// found is the certificate a request is about.
type found struct {
	snap    *inventory.Snapshot
	summary *inventory.Certificate
	// cert is nil for a row that is not a certificate.
	cert *x509.Certificate
}

// certificateFor finds the certificate a request is about: its summary in
// the inventory, and the certificate itself, read again from the CA's
// database. It writes the error page and returns ok false when there is
// none to show.
func (s *server) certificateFor(w http.ResponseWriter, r *http.Request) (f found, ok bool) {
	serial := r.PathValue("serial")
	f.snap = s.opts.Inventory.Snapshot()
	f.summary = f.snap.Certificate(serial)
	if f.summary == nil {
		s.errorPage(w, r, http.StatusNotFound, "The CA's database has no certificate with that serial number, as far as handrail-ca has read it.")
		return f, false
	}
	if f.summary.Problem != "" {
		return f, true
	}
	der, err := s.opts.Inventory.DER(r.Context(), serial)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "That certificate was in the CA's database a moment ago and is not any more.")
		return f, false
	case errors.Is(err, inventory.ErrUnreadable):
		s.errorPage(w, r, http.StatusBadGateway, "What the CA's database now holds under that serial number is not the certificate that was listed.")
		return f, false
	case err != nil:
		s.log.Warn("reading a certificate", "serial", serial, "err", err)
		s.errorPage(w, r, http.StatusBadGateway, "The certificate could not be read from the CA's database just now. The CA status page says what is wrong.")
		return f, false
	}
	f.cert, err = x509.ParseCertificate(der)
	if err != nil {
		// The inventory parsed it before handing it over.
		s.errorPage(w, r, http.StatusBadGateway, "The certificate could not be read.")
		return f, false
	}
	return f, true
}

func (s *server) detailPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.certificateFor(w, r)
	if !ok {
		return
	}
	note := s.noteFor(r, f.summary.Serial)
	note.Saved = note.CanEdit && r.URL.Query().Get("saved") == "note"
	s.renderDetail(w, r, http.StatusOK, f, note)
}

// noteFor reads a certificate's note from the store, for the signed-in
// user. A store that cannot be read costs the note, not the page.
func (s *server) noteFor(r *http.Request, serial string) *noteView {
	view := &noteView{CanEdit: currentUser(r).user.Role == store.RoleOperator, MaxNote: store.MaxNote}
	note, err := s.opts.Store.Note(r.Context(), serial)
	if err != nil {
		s.log.Error("reading a certificate's note", "serial", serial, "err", err)
		view.Unread, view.CanEdit = true, false
		return view
	}
	view.Text, view.Labels = note.Text, note.Labels
	view.Typed, view.TypedLabels = note.Text, strings.Join(note.Labels, ", ")
	if !note.UpdatedAt.IsZero() {
		view.Updated = note.UpdatedAt.UTC().Format(stamp) + " by " + note.UpdatedBy
	}
	return view
}

// renderDetail writes a certificate's page.
func (s *server) renderDetail(w http.ResponseWriter, r *http.Request, code int, f found, note *noteView) {
	now := s.opts.Now()
	snap, summary, cert := f.snap, f.summary, f.cert
	status := snap.Status(summary, now)
	look := statusLook[status]
	data := detailData{
		Serial: summary.Serial, Title: summary.Subject, Badge: look.badge, StatusLabel: look.label,
		Provisioner: summary.Provisioner.Name, ProvisionerType: summary.Provisioner.Type,
		RevocationsKnown: snap.State.RevocationsKnown, Stale: snap.State.Problem,
	}
	if !snap.State.LoadedAt.IsZero() {
		data.LastRead = span(now.Sub(snap.State.LoadedAt)) + " ago"
	}
	if rev := snap.Revocation(summary.Serial); rev != nil {
		data.Revocation = newRevocationView(rev, snap.Provisioners())
	}
	if cert == nil {
		data.Title = "Serial " + shortSerial(summary.Serial)
		data.Problem = summary.Problem
		s.render(w, r, code, "detail.html", data.Title, data)
		return
	}
	fillCertificate(&data, cert, now)
	data.Summary = summarySentence(status, summary, snap.Revocation(summary.Serial), now)
	data.Note = note
	data.History = s.certificateEvents(r, summary.Serial)
	if u := currentUser(r); u.user.Role == store.RoleOperator && data.Revocation == nil {
		acting := s.opts.CA.ProvisionerState().Configured
		data.CanRevoke, data.ReadOnly = acting, !acting
	}
	if said := r.URL.Query().Get("revoked"); data.Revocation != nil && (said == "now" || said == "before") {
		data.JustRevoked = said
	}
	s.render(w, r, code, "detail.html", data.Title, data)
}

// saveNote replaces a certificate's note and labels. It changes only
// handrail-ca's own store, nothing at the CA, and only an operator may: a
// note is read by everyone who signs in, as a statement about a
// certificate. The change goes into the history, without the text.
func (s *server) saveNote(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u.user.Role != store.RoleOperator {
		s.errorPage(w, r, http.StatusForbidden, "Only operators can change a certificate's note and labels.")
		return
	}
	f, ok := s.certificateFor(w, r)
	if !ok {
		return
	}
	if f.cert == nil {
		s.errorPage(w, r, http.StatusNotFound, "That row of the CA's database is not a certificate, so there is nothing to keep a note about.")
		return
	}
	serial := f.summary.Serial
	typed, typedLabels := r.PostForm.Get("note"), r.PostForm.Get("labels")
	text, err := store.CleanNote(typed)
	var labels []string
	if err == nil {
		labels, err = store.ParseLabels(typedLabels)
	}
	if err == nil {
		err = s.opts.Store.SetNote(r.Context(), store.Note{Serial: serial, Text: text, Labels: labels, UpdatedAt: s.opts.Now(), UpdatedBy: u.user.Username})
	}
	if errors.Is(err, store.ErrInvalidNote) {
		// Back to the page with what was typed, and why it was not kept.
		note := s.noteFor(r, serial)
		note.Typed, note.TypedLabels = typed, typedLabels
		note.Problem = strings.TrimPrefix(err.Error(), store.ErrInvalidNote.Error()+": ")
		s.renderDetail(w, r, http.StatusUnprocessableEntity, f, note)
		return
	}
	if err != nil {
		s.log.Error("saving a certificate's note", "serial", serial, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "handrail-ca could not save the note in its store, so nothing was changed. The log has the details.")
		return
	}
	detail := "note and labels changed"
	if text == "" && len(labels) == 0 {
		detail = "note and labels removed"
	}
	s.record(r, store.Event{Actor: u.user.Username, Action: store.ActionNote, Outcome: store.OutcomeOK, Serial: serial, Subject: f.summary.Subject, Detail: detail})
	http.Redirect(w, r, s.base+"/certificates/"+url.PathEscape(serial)+"?saved=note#note", http.StatusSeeOther)
}

// fillCertificate puts what the certificate itself says into data.
func fillCertificate(data *detailData, cert *x509.Certificate, now time.Time) {
	data.CommonName = cert.Subject.CommonName
	data.Subject = cert.Subject.String()
	data.Issuer = cert.Issuer.CommonName
	if data.Issuer == "" {
		data.Issuer = cert.Issuer.String()
	}
	data.Names = nameGroups(cert)

	data.NotBefore, data.NotAfter = cert.NotBefore.UTC().Format(stamp), cert.NotAfter.UTC().Format(stamp)
	total := cert.NotAfter.Sub(cert.NotBefore)
	used := min(max(now.Sub(cert.NotBefore), 0), total)
	data.Total, data.Used = int64(total/time.Second), int64(used/time.Second)
	data.Lifetime = span(total)
	switch {
	case now.Before(cert.NotBefore):
		data.Lifetime += ", not started"
	case used >= total:
		data.Lifetime += ", all used"
	default:
		data.Lifetime += ", " + span(used) + " used"
	}

	data.SerialHex = groupedBy(cert.SerialNumber.Text(16), 4)
	data.SerialDecimal = cert.SerialNumber.String()
	data.PublicKey = publicKeyWords(cert)
	data.Signature = cert.SignatureAlgorithm.String()
	data.KeyUsage = strings.Join(keyUsageWords(cert.KeyUsage), ", ")
	data.ExtendedUsage = strings.Join(extendedUsageWords(cert), ", ")
	data.Authority = "No"
	if cert.IsCA {
		data.Authority = "Yes: this certificate can sign others"
	}
	sum256 := sha256.Sum256(cert.Raw)
	data.SHA256 = grouped(hex.EncodeToString(sum256[:]))
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		data.Extensions = append(data.Extensions, extensionView{OID: oid, Name: extensionNames[oid], Critical: ext.Critical})
	}
	data.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// nameGroups lists a certificate's subject alternative names by kind, the
// kinds it has none of left out.
func nameGroups(cert *x509.Certificate) []nameGroup {
	var groups []nameGroup
	add := func(label string, values []string) {
		if len(values) == 0 {
			return
		}
		g := nameGroup{Label: label, Values: values}
		if len(values) > maxShownNames {
			g.Values, g.More = values[:maxShownNames], len(values)-maxShownNames
		}
		groups = append(groups, g)
	}
	add("DNS names", cert.DNSNames)
	var ips, uris []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	add("IP addresses", ips)
	add("Email addresses", cert.EmailAddresses)
	add("URIs", uris)
	return groups
}

// summarySentence says in a line where the certificate stands.
func summarySentence(status inventory.Status, c *inventory.Certificate, rev *inventory.Revocation, now time.Time) string {
	const day, clock = "2006-01-02", "15:04 UTC"
	end := c.NotAfter.UTC()
	var s string
	switch status {
	case inventory.StatusRevoked:
		s = "Revoked"
		if rev != nil && !rev.RevokedAt.IsZero() {
			s += " on " + rev.RevokedAt.UTC().Format(day)
		}
		s += ". It would have expired on " + end.Format(day) + "."
	case inventory.StatusExpired:
		s = "Expired " + span(now.Sub(end)) + " ago, on " + end.Format(day) + " at " + end.Format(clock) + "."
	case inventory.StatusNotYetValid:
		s = "Not valid until " + c.NotBefore.UTC().Format(day) + " at " + c.NotBefore.UTC().Format(clock) + "."
	case inventory.StatusUnknown:
		s = "In date until " + end.Format(day) + ", but whether it has been revoked is not known: the CA's revocation records have not been read."
	default:
		s = "Expires in " + span(end.Sub(now)) + ", on " + end.Format(day) + " at " + end.Format(clock) + "."
	}
	if c.Provisioner.Name != "" {
		s += " Issued by the " + c.Provisioner.Name + " provisioner."
	}
	return s
}

// revocationReasons are the reason codes of RFC 5280, section 5.3.1.
var revocationReasons = map[int]string{
	0: "Unspecified", 1: "Key compromise", 2: "CA compromise", 3: "Affiliation changed", 4: "Superseded",
	5: "Cessation of operation", 6: "Certificate hold", 8: "Remove from CRL", 9: "Privilege withdrawn", 10: "AA compromise",
}

// newRevocationView puts a revocation record into words. The CA records
// the provisioner by its ID; where a certificate in the inventory names
// that provisioner, its name is shown instead.
func newRevocationView(rev *inventory.Revocation, known []inventory.ProvisionerCount) *revocationView {
	if rev.Problem != "" {
		return &revocationView{Problem: rev.Problem}
	}
	v := &revocationView{Detail: rev.Reason, By: rev.ProvisionerID}
	for _, p := range known {
		if p.ID != "" && p.ID == rev.ProvisionerID {
			v.By = p.Name
		}
	}
	if !rev.RevokedAt.IsZero() {
		v.When = rev.RevokedAt.UTC().Format(stamp)
	}
	v.Reason = revocationReasons[rev.ReasonCode]
	if v.Reason == "" {
		v.Reason = fmt.Sprintf("Reason code %d", rev.ReasonCode)
	}
	switch {
	// What step-ca records and no more (authority.RevokeOptions, 0.30.2).
	// An ACME revocation may have been asked for by an account or signed
	// with the certificate's own key; the record does not say which.
	case rev.ACME:
		v.How = "Through ACME"
	case rev.MTLS:
		v.How = "By the certificate itself, over mutual TLS"
	default:
		v.How = "With a provisioner's token"
	}
	return v
}

func publicKeyWords(cert *x509.Certificate) string {
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + key.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", key.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return cert.PublicKeyAlgorithm.String()
}

func keyUsageWords(usage x509.KeyUsage) []string {
	var words []string
	for _, u := range []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital signature"}, {x509.KeyUsageContentCommitment, "Content commitment"},
		{x509.KeyUsageKeyEncipherment, "Key encipherment"}, {x509.KeyUsageDataEncipherment, "Data encipherment"},
		{x509.KeyUsageKeyAgreement, "Key agreement"}, {x509.KeyUsageCertSign, "Certificate signing"},
		{x509.KeyUsageCRLSign, "CRL signing"}, {x509.KeyUsageEncipherOnly, "Encipher only"}, {x509.KeyUsageDecipherOnly, "Decipher only"},
	} {
		if usage&u.bit != 0 {
			words = append(words, u.name)
		}
	}
	return words
}

func extendedUsageWords(cert *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny: "Any", x509.ExtKeyUsageServerAuth: "Server authentication", x509.ExtKeyUsageClientAuth: "Client authentication",
		x509.ExtKeyUsageCodeSigning: "Code signing", x509.ExtKeyUsageEmailProtection: "Email protection",
		x509.ExtKeyUsageTimeStamping: "Time stamping", x509.ExtKeyUsageOCSPSigning: "OCSP signing",
	}
	var words []string
	for _, u := range cert.ExtKeyUsage {
		if name := names[u]; name != "" {
			words = append(words, name)
		} else {
			words = append(words, fmt.Sprintf("Usage %d", int(u)))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		words = append(words, oid.String())
	}
	return words
}

// extensionNames are the extensions step-ca's certificates carry, and the
// common ones besides.
var extensionNames = map[string]string{
	"2.5.29.14": "Subject key identifier", "2.5.29.15": "Key usage", "2.5.29.17": "Subject alternative name",
	"2.5.29.19": "Basic constraints", "2.5.29.30": "Name constraints", "2.5.29.31": "CRL distribution points",
	"2.5.29.32": "Certificate policies", "2.5.29.35": "Authority key identifier", "2.5.29.37": "Extended key usage",
	"1.3.6.1.5.5.7.1.1":           "Authority information access",
	"1.3.6.1.4.1.37476.9000.64.1": "step-ca provisioner",
	"1.3.6.1.4.1.11129.2.4.2":     "Signed certificate timestamps",
}

// groupedBy breaks a string into blocks of n characters, from the left.
func groupedBy(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+n, len(s))])
	}
	return b.String()
}

var unsafeInFileName = regexp.MustCompile(`[^a-z0-9.-]+`)

// fileName is a safe name for a downloaded certificate: from its subject
// if that leaves anything, else from its serial.
func fileName(c *inventory.Certificate, ext string) string {
	base := strings.Trim(unsafeInFileName.ReplaceAllString(strings.ToLower(c.Subject), "-"), "-.")
	if len(base) > 64 {
		base = strings.Trim(base[:64], "-.")
	}
	if base == "" {
		base = "certificate-" + c.SerialHex
	}
	return base + ext
}

// download writes a certificate file as an attachment.
func download(w http.ResponseWriter, name, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", fmt.Sprint(len(body)))
	_, _ = w.Write(body)
}

// certificateFile serves the certificate itself: PEM, DER, or PEM with the
// CA's intermediate after it.
func (s *server) certificateFile(w http.ResponseWriter, r *http.Request) {
	f, ok := s.certificateFor(w, r)
	if !ok {
		return
	}
	summary, cert := f.summary, f.cert
	if cert == nil {
		s.errorPage(w, r, http.StatusNotFound, "That row of the CA's database is not a certificate, so there is nothing to download.")
		return
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	switch r.PathValue("form") {
	case "pem":
		download(w, fileName(summary, ".pem"), "application/x-pem-file", leaf)
	case "der":
		download(w, fileName(summary, ".der"), "application/pkix-cert", cert.Raw)
	case "chain":
		// The intermediate comes from the CA, and only one that really
		// signed this certificate is put after it: a chain file that does
		// not verify is worse than none.
		intermediates, err := s.opts.CA.Intermediates(r.Context())
		if err != nil {
			s.log.Warn("reading the CA's intermediates", "err", err)
			s.errorPage(w, r, http.StatusBadGateway, "The CA could not be asked for its intermediate certificate just now, so the chain cannot be put together. The certificate alone can still be downloaded.")
			return
		}
		var chain bytes.Buffer
		chain.Write(leaf)
		found := false
		for _, inter := range intermediates {
			if cert.CheckSignatureFrom(inter) == nil {
				chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}))
				found = true
				break
			}
		}
		if !found {
			s.errorPage(w, r, http.StatusConflict, "None of the CA's current intermediate certificates signed this certificate, so handrail-ca cannot put its chain together. It may have been issued under an earlier intermediate.")
			return
		}
		download(w, fileName(summary, "-chain.pem"), "application/x-pem-file", chain.Bytes())
	default:
		s.errorPage(w, r, http.StatusNotFound, "There is no such page.")
	}
}
