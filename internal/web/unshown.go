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
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sort"
)

// What Go's certificate parser does not hand over (security review N-20):
// subject alternative names of kinds other than DNS name, IP address, email
// address and URI, and every common name of a subject but the last. The
// pages show neither, so a certificate's page says when it has them rather
// than presenting what is left as the whole.

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCommonName     = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// generalNameKinds names, singular and plural, the GeneralName choices
// (RFC 5280, 4.2.1.6) that the pages do not show; 1, 2, 6 and 7 are the
// four they do.
var generalNameKinds = map[int][2]string{
	0: {"other name", "other names"},
	3: {"X.400 address", "X.400 addresses"},
	4: {"directory name", "directory names"},
	5: {"EDI party name", "EDI party names"},
	8: {"registered ID", "registered IDs"},
}

var unknownKind = [2]string{"name of an unknown kind", "names of an unknown kind"}

// unshownNames counts, by kind, the subject alternative names that the
// pages do not show, as sentences' worth of words ("2 other names"). A SAN
// extension that cannot be read is said so: the parser would have refused
// the certificate, so it does not happen for a certificate shown here, but
// it is not silently taken for "none".
func unshownNames(cert *x509.Certificate) []string {
	counts := map[[2]string]int{}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) > 0 || seq.Tag != asn1.TagSequence {
			return []string{"subject alternative names that could not be read"}
		}
		for rest := seq.Bytes; len(rest) > 0; {
			var name asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &name); err != nil {
				return []string{"subject alternative names that could not be read"}
			}
			if kind := kindOf(name); kind[0] != "" {
				counts[kind]++
			}
		}
	}
	var out []string
	for kind, n := range counts {
		if n == 1 {
			out = append(out, "1 "+kind[0])
		} else {
			out = append(out, fmt.Sprintf("%d %s", n, kind[1]))
		}
	}
	sort.Strings(out)
	return out
}

// kindOf is the words for a GeneralName that the pages do not show, or
// the zero value for one they do.
func kindOf(name asn1.RawValue) [2]string {
	if name.Class != asn1.ClassContextSpecific {
		return unknownKind
	}
	switch name.Tag {
	case 1, 2, 6, 7:
		return [2]string{}
	}
	if kind, ok := generalNameKinds[name.Tag]; ok {
		return kind
	}
	return unknownKind
}

// commonNames is every common name in the subject, in order, when there is
// more than one; Go's parser keeps only the last of them.
func commonNames(cert *x509.Certificate) []string {
	var cns []string
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidCommonName) {
			cns = append(cns, fmt.Sprint(atv.Value))
		}
	}
	if len(cns) < 2 {
		return nil
	}
	if len(cns) > maxShownNames {
		cns = cns[:maxShownNames]
	}
	return cns
}
