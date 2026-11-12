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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The tests in this file run against the development CA (deploy/dev), a real
// step-ca, and are skipped without it. `make dev-test` sets the two
// variables from the running Compose project: the CA's address and the
// fingerprint of its root certificate.
func devCA(t *testing.T) (url, fingerprint string) {
	t.Helper()
	url, fingerprint = os.Getenv("HANDRAIL_DEV_CA_URL"), os.Getenv("HANDRAIL_DEV_CA_FINGERPRINT")
	if url == "" || fingerprint == "" {
		t.Skip("no development CA: run `make dev-up` and `make dev-test`")
	}
	return url, fingerprint
}

func devContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestIntegrationReadSide(t *testing.T) {
	url, fingerprint := devCA(t)
	c, err := New(Config{URL: url, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)

	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	version, err := c.Version(ctx)
	if err != nil || !regexp.MustCompile(`^\d+\.\d+\.\d+`).MatchString(version) {
		t.Errorf("Version = %q, %v", version, err)
	}

	// The root that was fetched is the one configured, and the CA lists it.
	pinned, err := c.Root(ctx)
	if err != nil || Fingerprint(pinned) != fingerprint {
		t.Fatalf("Root: %v", err)
	}
	roots, err := c.Roots(ctx)
	if err != nil || len(roots) != 1 || !roots[0].Equal(pinned) {
		t.Fatalf("Roots = %d certificates, %v; want the pinned root alone", len(roots), err)
	}
	inters, err := c.Intermediates(ctx)
	if err != nil || len(inters) != 1 {
		t.Fatalf("Intermediates = %d certificates, %v", len(inters), err)
	}
	if err := inters[0].CheckSignatureFrom(pinned); err != nil {
		t.Errorf("the intermediate is not signed by the pinned root: %v", err)
	}

	provisioners, err := c.Provisioners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Provisioner{}
	for _, p := range provisioners {
		byName[p.Name] = p
	}
	// What deploy/dev/seed.sh creates, and the image's own admin provisioner.
	if p := byName["handrail"]; p.Type != "JWK" || p.KeyID == "" || p.Claims.MaxTLSCertDuration != 2160*time.Hour {
		t.Errorf("handrail provisioner = %+v", p)
	}
	if p := byName["acme"]; p.Type != "ACME" || p.KeyID != "" {
		t.Errorf("acme provisioner = %+v", p)
	}
	if p := byName["Admin JWK"]; p.Type != "JWK" || p.Claims.DefaultTLSCertDuration != 5*time.Minute {
		t.Errorf("Admin JWK provisioner = %+v", p)
	}

	// The development CA has no CRL switched on.
	crl, err := c.CRL(ctx)
	if err != nil || crl.Published {
		t.Errorf("CRL = %+v, %v; want not published", crl, err)
	}
}

// A client configured with a fingerprint that is not this CA's root must
// not pin anything, nor talk to it.
func TestIntegrationRefusesAnotherFingerprint(t *testing.T) {
	url, _ := devCA(t)
	c, err := New(Config{URL: url, Fingerprint: Fingerprint(newTestPKI(t).root)})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Health(devContext(t))
	if err == nil || !strings.Contains(err.Error(), "has no root with fingerprint") {
		t.Fatalf("err = %v, want a refusal to pin", err)
	}
	if c.pinned != nil {
		t.Error("a root was pinned")
	}
}

// The development CA's certificate names localhost, not 127.0.0.1: reached
// by address it must be refused, even with the right fingerprint. This is
// the check that the server handing out the root is itself of that CA,
// under the configured name.
func TestIntegrationRefusesAnotherName(t *testing.T) {
	url, fingerprint := devCA(t)
	if !strings.Contains(url, "//localhost:") {
		t.Skip("the development CA is not at localhost")
	}
	c, err := New(Config{URL: strings.Replace(url, "//localhost:", "//127.0.0.1:", 1), Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	var wrongName x509.HostnameError
	if err := c.Health(devContext(t)); !errors.As(err, &wrongName) {
		t.Fatalf("err = %v, want a host-name error", err)
	}
	if c.pinned != nil {
		t.Error("a root was pinned for a server under the wrong name")
	}
}

// devProvisioner is the development CA's handrail provisioner (seed.sh):
// its password, read from the file `make dev-test` names.
func devProvisioner(t *testing.T) *ProvisionerConfig {
	t.Helper()
	path := os.Getenv("HANDRAIL_DEV_PROVISIONER_PASSWORD_FILE")
	if path == "" {
		t.Skip("no provisioner password: run `make dev-test`")
	}
	pw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &ProvisionerConfig{Name: "handrail", Password: strings.TrimSpace(string(pw))}
}

// The write side against a real step-ca: the key the CA publishes opens
// with the provisioner's password, and a token signed with it, with the
// claims and the request body this client builds, revokes a certificate.
// This is the check that those shapes, first read from step-ca's source,
// are what a running CA accepts.
func TestIntegrationRevoke(t *testing.T) {
	url, fingerprint := devCA(t)
	acting := devProvisioner(t)
	serial := os.Getenv("HANDRAIL_DEV_REVOKE_SERIAL")
	if serial == "" {
		t.Skip("no certificate to revoke: run `make dev-test`")
	}
	c, err := New(Config{URL: url, Fingerprint: fingerprint, Provisioner: acting})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)

	if err := c.Unlock(ctx); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	provisioners, err := c.Provisioners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := c.ProvisionerState()
	for _, p := range provisioners {
		if p.Name == "handrail" && (!st.Ready || st.KeyID != p.KeyID) {
			t.Errorf("state = %+v, want the key the CA lists (%s) open", st, p.KeyID)
		}
	}

	if err := c.Revoke(ctx, Revocation{Serial: serial, ReasonCode: 4, Reason: "handrail-ca integration test"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The CA holds the revocation: asked again, it says so. The inventory's
	// integration tests read the record itself from the database.
	err = c.Revoke(ctx, Revocation{Serial: serial, ReasonCode: 4})
	var refused *StatusError
	if !errors.As(err, &refused) || refused.Status != 400 || !strings.Contains(refused.Message, "is already revoked") {
		t.Errorf("a second revocation: %v, want the CA's refusal of a certificate already revoked", err)
	}
	if refused != nil && refused.ClockDifference != 0 {
		t.Errorf("clock difference of %s reported between this machine and a CA on it", refused.ClockDifference)
	}
}

func TestIntegrationProvisionerKeyRefusals(t *testing.T) {
	url, fingerprint := devCA(t)
	acting := devProvisioner(t)
	ctx := devContext(t)
	for name, tt := range map[string]struct {
		cfg  ProvisionerConfig
		want string
	}{
		"a wrong password":              {ProvisionerConfig{Name: "handrail", Password: acting.Password + "x"}, "does not open its key"},
		"a provisioner of another type": {ProvisionerConfig{Name: "acme", Password: acting.Password}, "is of type ACME"},
		"no such provisioner":           {ProvisionerConfig{Name: "nobody", Password: acting.Password}, `no provisioner named "nobody"`},
		// The CA's own admin provisioner is a JWK provisioner with an
		// encrypted key too; handrail's password is not its password.
		"another provisioner's key": {ProvisionerConfig{Name: "Admin JWK", Password: acting.Password}, "does not open its key"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(Config{URL: url, Fingerprint: fingerprint, Provisioner: &tt.cfg})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Unlock(ctx); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Unlock: %v, want an error containing %q", err, tt.want)
			}
			if err := c.Revoke(ctx, Revocation{Serial: "1"}); err == nil {
				t.Error("a revocation was sent without a key")
			}
		})
	}
}

// A machine whose clock is ten minutes behind the CA's dates its tokens in
// the past, and the CA refuses them without saying why. The error carries
// the difference between the clocks, which is the reason.
func TestIntegrationAClockThatIsOffIsReported(t *testing.T) {
	url, fingerprint := devCA(t)
	c, err := New(Config{
		URL: url, Fingerprint: fingerprint, Provisioner: devProvisioner(t),
		Now: func() time.Time { return time.Now().Add(-10 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// A serial that was never issued: the token is refused before the CA
	// looks at it, and nothing is stored.
	err = c.Revoke(devContext(t), Revocation{Serial: "1"})
	var refused *StatusError
	if !errors.As(err, &refused) || refused.Status != 401 {
		t.Fatalf("err = %v, want the CA's 401", err)
	}
	t.Logf("the CA's refusal of an expired token: %v", refused)
	if d := refused.ClockDifference; d < 9*time.Minute || d > 11*time.Minute {
		t.Errorf("clock difference = %s, want about ten minutes", d)
	}
}

// devRequest is a certificate signing request as ReadRequest reads it.
func devRequest(t *testing.T, tmpl *x509.CertificateRequest) *Request {
	t.Helper()
	text, _ := csrPEM(t, "P-256", tmpl)
	r, err := ReadRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Signing against a real step-ca. The certificate that comes back carries
// what ReadRequest said it would, for each shape of request: this is the
// check that the working-out in ReadRequest is step-ca's own, and that the
// token claims and request body, first read from step-ca's source, are
// what a running CA accepts. Sign itself checks every certificate for the
// request's key and a chain to the pinned root.
func TestIntegrationSign(t *testing.T) {
	caURL, fingerprint := devCA(t)
	c, err := New(Config{URL: caURL, Fingerprint: fingerprint, Provisioner: devProvisioner(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)
	// Names inside the development CA's policy (seed.sh): one label under
	// handrail.test, and addresses in 10.20.0.0/16.
	tests := []struct {
		name string
		tmpl x509.CertificateRequest
	}{
		{"a common name among its names", x509.CertificateRequest{Subject: pkix.Name{CommonName: "issue1.handrail.test"}, DNSNames: []string{"issue1.handrail.test"}, IPAddresses: []net.IP{net.ParseIP("10.20.3.1")}}},
		{"names and no common name", x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.20.3.2")}, DNSNames: []string{"issue2.handrail.test", "issue2b.handrail.test"}}},
		{"a common name that is not among the names", x509.CertificateRequest{Subject: pkix.Name{CommonName: "issue3.handrail.test"}, DNSNames: []string{"issue3b.handrail.test"}}},
		{"a common name and no names", x509.CertificateRequest{Subject: pkix.Name{CommonName: "issue4.handrail.test"}}},
		{"an address for a common name and no names", x509.CertificateRequest{Subject: pkix.Name{CommonName: "10.20.3.5"}}},
		{"more in the subject than a common name", x509.CertificateRequest{Subject: pkix.Name{CommonName: "issue6.handrail.test", Organization: []string{"Example"}, Country: []string{"DE"}}, DNSNames: []string{"issue6.handrail.test"}}},
		// The request asks to be a CA. step-ca's template does not copy
		// extensions from the request.
		{"a request that asks for more than a leaf", x509.CertificateRequest{Subject: pkix.Name{CommonName: "issue7.handrail.test"}, DNSNames: []string{"issue7.handrail.test"},
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := devRequest(t, &tt.tmpl)
			issued, err := c.Sign(ctx, req, 0)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			cert := issued.Certificate
			// The subject is the common name ReadRequest named, and nothing
			// else of the request's subject.
			if got := cert.Subject.String(); got != "CN="+req.CommonName {
				t.Errorf("subject = %q, want CN=%s alone", got, req.CommonName)
			}
			var ips, uris []string
			for _, ip := range cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			for _, u := range cert.URIs {
				uris = append(uris, u.String())
			}
			for kind, pair := range map[string][2][]string{
				"DNS names": {cert.DNSNames, req.DNSNames}, "IP addresses": {ips, req.IPAddresses},
				"email addresses": {cert.EmailAddresses, req.EmailAddresses}, "URIs": {uris, req.URIs},
			} {
				if strings.Join(pair[0], " ") != strings.Join(pair[1], " ") {
					t.Errorf("%s = %v, want %v as the request was read", kind, pair[0], pair[1])
				}
			}
			if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
				t.Error("the certificate may sign others")
			}
			// The provisioner's default validity, dated a minute back.
			if d := cert.NotAfter.Sub(cert.NotBefore); d != 24*time.Hour+time.Minute {
				t.Errorf("validity = %s, want the default 24 hours and the CA's minute of backdating", d)
			}
			if len(issued.Intermediates) != 1 {
				t.Errorf("%d intermediates came with it", len(issued.Intermediates))
			}
		})
	}
}

func TestIntegrationSignLimits(t *testing.T) {
	caURL, fingerprint := devCA(t)
	c, err := New(Config{URL: caURL, Fingerprint: fingerprint, Provisioner: devProvisioner(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)
	request := func(name string) *Request {
		return devRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}})
	}
	refused := func(err error, status int, says string) bool {
		var se *StatusError
		return errors.As(err, &se) && se.Status == status && strings.Contains(se.Message, says)
	}

	// A validity is a length the CA counts from its own clock, and the
	// certificate is that long plus the minute it is dated back.
	issued, err := c.Sign(ctx, request("limit1.handrail.test"), 2160*time.Hour)
	if err != nil {
		t.Fatalf("the provisioner's longest validity: %v", err)
	}
	if d := issued.Certificate.NotAfter.Sub(issued.Certificate.NotBefore); d != 2160*time.Hour+time.Minute {
		t.Errorf("validity = %s, want 90 days and a minute", d)
	}
	if _, err := c.Sign(ctx, request("limit2.handrail.test"), 2161*time.Hour); !refused(err, 403, "more than the authorized maximum certificate duration") {
		t.Errorf("an hour over the provisioner's longest: %v", err)
	}
	if _, err := c.Sign(ctx, request("limit3.handrail.test"), time.Minute); !refused(err, 403, "less than the authorized minimum certificate duration") {
		t.Errorf("under the CA's shortest: %v", err)
	}
	// The CA's name policy, and its words for it.
	if _, err := c.Sign(ctx, request("outside.example.org"), 0); !refused(err, 403, `dns name "outside.example.org" not allowed`) {
		t.Errorf("a name outside the policy: %v", err)
	}

	// A token is good for the one request it was made for.
	mine, another := request("bound.handrail.test"), request("bound.handrail.test")
	body, err := c.signRequest(ctx, mine, 0)
	if err != nil {
		t.Fatal(err)
	}
	sent := body.(map[string]string)
	sent["csr"] = another.PEM
	if _, err := c.postJSON(ctx, signPath, sent, maxSigned); !refused(err, 403, "certificate request fingerprint does not match") {
		t.Errorf("another request sent with this request's token: %v", err)
	}
}

// The development CA's second provisioner has the certificate template
// from docs/ca-setup.md, section 6, which takes the subject whole from the
// request. Through it, the same client gets certificates that carry more
// than a common name; and the client can tell which provisioner has a
// template, since the CA publishes it.
func TestIntegrationSignUnderATemplate(t *testing.T) {
	caURL, fingerprint := devCA(t)
	acting := devProvisioner(t)
	acting.Name = "handrail-template"
	c, err := New(Config{URL: caURL, Fingerprint: fingerprint, Provisioner: acting})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)

	provisioners, err := c.Provisioners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range provisioners {
		switch p.Name {
		case "handrail-template":
			if !p.HasTemplate() || !strings.Contains(p.Template, ".Insecure.CR.Subject") {
				t.Errorf("handrail-template is listed with the template %q", p.Template)
			}
		case "handrail", "acme", "Admin JWK":
			if p.HasTemplate() {
				t.Errorf("%s is listed with a template: %q", p.Name, p.Template)
			}
		}
	}

	// The whole subject of the request, and its names as before.
	req := devRequest(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "tpl1.handrail.test", Organization: []string{"Example Org"}, OrganizationalUnit: []string{"Ops"}, Country: []string{"DE"}},
		DNSNames: []string{"tpl1.handrail.test"}, IPAddresses: []net.IP{net.ParseIP("10.20.5.1")},
	})
	issued, err := c.Sign(ctx, req, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert := issued.Certificate
	if got := cert.Subject.String(); got != "CN=tpl1.handrail.test,OU=Ops,O=Example Org,C=DE" {
		t.Errorf("subject = %q, want the request's whole subject", got)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "tpl1.handrail.test" || len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.20.5.1" {
		t.Errorf("names = %v %v", cert.DNSNames, cert.IPAddresses)
	}

	// A request with no subject: the template has none to copy, so the
	// certificate's subject is empty, where the default template would
	// have made a common name of the first name.
	req = devRequest(t, &x509.CertificateRequest{DNSNames: []string{"tpl2.handrail.test"}})
	issued, err = c.Sign(ctx, req, 0)
	if err != nil {
		t.Fatalf("Sign, a request with names only: %v", err)
	}
	if got := issued.Certificate.Subject.String(); got != "" {
		t.Errorf("subject = %q, want none", got)
	}
	if names := issued.Certificate.DNSNames; len(names) != 1 || names[0] != "tpl2.handrail.test" {
		t.Errorf("names = %v", names)
	}

	// The name policy holds under a template.
	_, err = c.Sign(ctx, devRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "outside.example.org", Organization: []string{"Example Org"}}, DNSNames: []string{"outside.example.org"}}), 0)
	var refused *StatusError
	if !errors.As(err, &refused) || refused.Status != 403 || !strings.Contains(refused.Message, "not allowed") {
		t.Errorf("a name outside the policy, under the template: %v", err)
	}
}

// The development CA has a name policy, and a policy holds the common name
// to its rules as a name of its own. What the CA answers differs with the
// common name, and the Issue page's explanation of the second answer rests
// on this.
func TestIntegrationSignCommonNamesUnderThePolicy(t *testing.T) {
	caURL, fingerprint := devCA(t)
	c, err := New(Config{URL: caURL, Fingerprint: fingerprint, Provisioner: devProvisioner(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := devContext(t)
	sign := func(cn string) error {
		_, err := c.Sign(ctx, devRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"cn-test.handrail.test"}}), 0)
		return err
	}
	if err := sign("cn-other.handrail.test"); err != nil {
		t.Errorf("a common name that is an allowed name, not among the names: %v", err)
	}
	var refused *StatusError
	if err := sign("printer"); !errors.As(err, &refused) || refused.Status != 403 || !strings.Contains(refused.Message, `cn name "printer" not allowed`) {
		t.Errorf("a common name that reads as a name and is not allowed: %v", err)
	}
	if err := sign("HP LaserJet 400"); !errors.As(err, &refused) || refused.Status != 500 || !strings.Contains(refused.Message, "error creating certificate") || strings.Contains(refused.Message, "LaserJet") {
		t.Errorf("a common name that is no name: %v, want a 500 that gives no reason", err)
	}
}
