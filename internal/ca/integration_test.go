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
	"errors"
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
