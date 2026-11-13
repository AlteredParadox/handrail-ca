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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"handrail-ca/internal/inventory"
)

// unshownCertificate is a certificate holding what Go's parser does not
// hand over: an other name (a user principal name) and a directory name
// beside a DNS name, and a subject of two common names.
func unshownCertificate(t *testing.T, serial int64) []byte {
	t.Helper()
	mustMarshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	upn := mustMarshal(asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: append(
		mustMarshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
		mustMarshal(asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: mustMarshal("zz-upn@corp.invalid")})...)})
	dirName := mustMarshal(asn1.RawValue{Tag: 4, Class: asn1.ClassContextSpecific, IsCompound: true,
		Bytes: mustMarshal(pkix.Name{CommonName: "zz-directory"}.ToRDNSequence())})
	dns := mustMarshal(asn1.RawValue{Tag: 2, Class: asn1.ClassContextSpecific, Bytes: []byte("shown.internal.example")})
	san := mustMarshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(append(upn, dirName...), dns...)})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "zz-first-cn"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "last-cn.internal.example"},
		}},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}},
		NotBefore:       t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// N-20 of the security review: a certificate's page says when the
// certificate holds names it does not show, and the names page says that
// it lists only the names handrail-ca can read.
func TestACertificatesPageSaysWhatItDoesNotShow(t *testing.T) {
	s := newSite(t, "http://127.0.0.1:8080")
	s.addRows(
		inventory.RawCertificate{Serial: "5151", DER: unshownCertificate(t, 5151), Data: []byte(`{"provisioner":{"id":"p1","name":"handrail","type":"JWK"}}`)},
		leafRow(t, 5152, "plain.internal.example", t0.Add(-time.Hour), t0.Add(24*time.Hour)),
	)
	b := signedIn(t, s)

	page := b.get("/certificates/5151")
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "shown.internal.example",
		"The subject has 2 common names", "zz-first-cn", "last-cn.internal.example",
		"also hold 1 directory name, 1 other name, which handrail-ca does not show")
	if strings.Contains(page.Body.String(), "zz-upn@corp.invalid") {
		t.Error("the page shows the other name after all: the note is wrong")
	}

	// A certificate with only the four kinds and one common name has no
	// such notes.
	plain := b.get("/certificates/5152")
	wantStatus(t, plain, http.StatusOK)
	for _, unwanted := range []string{"common names.", "also hold"} {
		if strings.Contains(plain.Body.String(), unwanted) {
			t.Errorf("a plain certificate's page says %q", unwanted)
		}
	}

	wantBody(t, b.get("/names"), "Every name handrail-ca can read in", "a certificate's own page says when it holds any")
}

// The counting itself: every kind of GeneralName, and a SAN extension that
// cannot be read.
func TestUnshownNames(t *testing.T) {
	general := func(tag int, compound bool) asn1.RawValue {
		return asn1.RawValue{Tag: tag, Class: asn1.ClassContextSpecific, IsCompound: compound, Bytes: []byte{0x30, 0}}
	}
	var body []byte
	for _, n := range []asn1.RawValue{
		general(0, true), general(0, true), general(1, false), general(2, false), general(3, true),
		general(4, true), general(5, true), general(6, false), general(7, false), general(8, false), general(9, false),
		{Tag: asn1.TagUTF8String, Class: asn1.ClassUniversal, Bytes: []byte("x")},
	} {
		b, err := asn1.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, b...)
	}
	san, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}}
	got := strings.Join(unshownNames(cert), "; ")
	want := "1 EDI party name; 1 X.400 address; 1 directory name; 1 registered ID; 2 names of an unknown kind; 2 other names"
	if got != want {
		t.Errorf("unshownNames = %q, want %q", got, want)
	}

	for name, value := range map[string][]byte{"not DER": {0xff}, "trailing bytes": append(san, 0), "not a sequence": {0x04, 0}, "a broken entry": {0x30, 2, 0x82, 5}} {
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}}}
		if got := unshownNames(cert); len(got) != 1 || !strings.Contains(got[0], "could not be read") {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := unshownNames(&x509.Certificate{}); got != nil {
		t.Errorf("no SAN extension: %q", got)
	}
}
