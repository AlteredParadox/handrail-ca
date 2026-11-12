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

package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	// maxCRL bounds the revocation list that is read to describe it.
	maxCRL = 16 << 20
	// maxCertificates bounds the root and intermediate lists.
	maxCertificates = 64
	// provisionerPage is the page size asked for; maxProvisionerPages stops
	// a CA that never ends its list.
	provisionerPage     = 100
	maxProvisionerPages = 50
)

// Health asks the CA whether it is up. nil means it said "ok".
func (c *Client) Health(ctx context.Context) error {
	var answer struct {
		Status string `json:"status"`
	}
	if err := c.getJSON(ctx, "/health", nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("the CA reports status %q", clip(answer.Status))
	}
	return nil
}

// Version is the step-ca version the CA reports.
func (c *Client) Version(ctx context.Context) (string, error) {
	var answer struct {
		Version string `json:"version"`
	}
	if err := c.getJSON(ctx, "/version", nil, &answer); err != nil {
		return "", err
	}
	if answer.Version == "" {
		return "", errors.New("/version: the CA reported no version")
	}
	return clip(answer.Version), nil
}

// Roots are the root certificates the CA publishes. The pinned root is
// normally one of them; a CA in the middle of a root rotation lists more.
func (c *Client) Roots(ctx context.Context) ([]*x509.Certificate, error) {
	return c.certificates(ctx, "/roots")
}

// Intermediates are the CA's intermediate certificates. step-ca versions
// before the endpoint existed answer 404, which comes back as a StatusError.
func (c *Client) Intermediates(ctx context.Context) ([]*x509.Certificate, error) {
	return c.certificates(ctx, "/intermediates")
}

func (c *Client) certificates(ctx context.Context, path string) ([]*x509.Certificate, error) {
	var answer struct {
		Certs []string `json:"crts"`
	}
	if err := c.getJSON(ctx, path, nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Certs) > maxCertificates {
		return nil, fmt.Errorf("%s: %d certificates, more than the %d this client reads", path, len(answer.Certs), maxCertificates)
	}
	certs := make([]*x509.Certificate, 0, len(answer.Certs))
	for i, s := range answer.Certs {
		cert, err := onePEMCertificate(s)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d: %w", path, i+1, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Provisioner is one of the CA's provisioners, as far as handrail-ca uses it.
type Provisioner struct {
	// Type is step-ca's name for the kind: "JWK", "ACME", "OIDC" and so on.
	Type string
	Name string
	// KeyID is the key ID of a JWK provisioner, empty for other types.
	KeyID  string
	Claims Claims
	// Template is the provisioner's own X.509 certificate template, if it
	// has one: with it, what a certificate carries is the template's
	// doing and not step-ca's default. TemplateFile is set instead when
	// the template is a file on the CA's host, whose text is not
	// published.
	Template     string
	TemplateFile string
}

// HasTemplate reports whether the provisioner replaces step-ca's default
// certificate template with one of its own.
func (p Provisioner) HasTemplate() bool { return p.Template != "" || p.TemplateFile != "" }

// maxTemplate bounds a template that is kept for showing.
const maxTemplate = 8 << 10

// Claims are a provisioner's own X.509 validity limits. A zero duration
// means the provisioner does not set that limit and the CA's default
// applies. The answer carries more claims (renewal, SSH); they are left
// unread until something uses them, and the renewal ones are optional
// booleans whose absence means "as the CA is configured", not false.
type Claims struct {
	MinTLSCertDuration     time.Duration
	MaxTLSCertDuration     time.Duration
	DefaultTLSCertDuration time.Duration
}

// Provisioners lists every provisioner on the CA, following its paging.
func (c *Client) Provisioners(ctx context.Context) ([]Provisioner, error) {
	var all []Provisioner
	err := c.eachProvisioner(ctx, func(raw json.RawMessage) error {
		p, err := parseProvisioner(raw)
		if err != nil {
			return err
		}
		all = append(all, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// eachProvisioner hands every entry of the CA's provisioner list to visit,
// following the list's paging, and stops at the first error.
func (c *Client) eachProvisioner(ctx context.Context, visit func(json.RawMessage) error) error {
	cursor := ""
	for page := 0; page < maxProvisionerPages; page++ {
		query := url.Values{"limit": {fmt.Sprint(provisionerPage)}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		var answer struct {
			Provisioners []json.RawMessage `json:"provisioners"`
			NextCursor   string            `json:"nextCursor"`
		}
		if err := c.getJSON(ctx, "/provisioners", query, &answer); err != nil {
			return err
		}
		for _, raw := range answer.Provisioners {
			if err := visit(raw); err != nil {
				return err
			}
		}
		if answer.NextCursor == "" {
			return nil
		}
		if answer.NextCursor == cursor {
			return errors.New("/provisioners: the CA repeated a page cursor")
		}
		cursor = answer.NextCursor
	}
	return fmt.Errorf("/provisioners: more than %d pages", maxProvisionerPages)
}

func parseProvisioner(raw json.RawMessage) (Provisioner, error) {
	var in struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Key  *struct {
			KeyID string `json:"kid"`
		} `json:"key"`
		Claims *struct {
			Min     string `json:"minTLSCertDuration"`
			Max     string `json:"maxTLSCertDuration"`
			Default string `json:"defaultTLSCertDuration"`
		} `json:"claims"`
		Options *struct {
			X509 *struct {
				Template     string `json:"template"`
				TemplateFile string `json:"templateFile"`
			} `json:"x509"`
		} `json:"options"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return Provisioner{}, fmt.Errorf("/provisioners: an entry is not the expected JSON: %w", err)
	}
	if in.Type == "" || in.Name == "" {
		return Provisioner{}, errors.New("/provisioners: an entry has no type or no name")
	}
	p := Provisioner{Type: clip(in.Type), Name: clip(in.Name)}
	if in.Key != nil {
		p.KeyID = clip(in.Key.KeyID)
	}
	if in.Options != nil && in.Options.X509 != nil {
		p.Template, p.TemplateFile = in.Options.X509.Template, clip(in.Options.X509.TemplateFile)
		if len(p.Template) > maxTemplate {
			p.Template = p.Template[:maxTemplate] + "\n… (the rest is not shown)"
		}
	}
	if in.Claims == nil {
		return p, nil
	}
	for _, d := range []struct {
		field string
		text  string
		into  *time.Duration
	}{
		{"minTLSCertDuration", in.Claims.Min, &p.Claims.MinTLSCertDuration},
		{"maxTLSCertDuration", in.Claims.Max, &p.Claims.MaxTLSCertDuration},
		{"defaultTLSCertDuration", in.Claims.Default, &p.Claims.DefaultTLSCertDuration},
	} {
		if d.text == "" {
			continue
		}
		v, err := time.ParseDuration(d.text)
		if err != nil || v <= 0 {
			return Provisioner{}, fmt.Errorf("/provisioners: provisioner %q: %s %q is not a duration", p.Name, d.field, clip(d.text))
		}
		*d.into = v
	}
	return p, nil
}

// CRL says whether the CA publishes a certificate revocation list, which is
// the only way a relying party learns of a revocation (step-ca has no OCSP
// responder).
type CRL struct {
	// Published is false when the CA answers 404: the list is switched off.
	Published bool
	// The rest describes the published list.
	Issuer     string
	ThisUpdate time.Time
	NextUpdate time.Time
	// Entries is the number of revoked certificates on the list.
	Entries int
}

// CRL fetches the CA's revocation list to see whether there is one. An
// error means the question could not be answered, which is neither
// "published" nor "not published".
func (c *Client) CRL(ctx context.Context) (CRL, error) {
	body, err := c.get(ctx, "/1.0/crl", nil, maxCRL)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return CRL{}, nil
		}
		return CRL{}, err
	}
	// step-ca sends DER; `?pem=true` and some proxies give PEM.
	der := body
	if block, _ := pem.Decode(body); block != nil && block.Type == "X509 CRL" {
		der = block.Bytes
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return CRL{}, fmt.Errorf("/1.0/crl: the CA answered, but not with a revocation list: %w", err)
	}
	return CRL{
		Published:  true,
		Issuer:     list.Issuer.String(),
		ThisUpdate: list.ThisUpdate,
		NextUpdate: list.NextUpdate,
		Entries:    len(list.RevokedCertificateEntries),
	}, nil
}

// clip bounds a string from the CA that is kept or shown.
func clip(s string) string {
	const limit = 256
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}
