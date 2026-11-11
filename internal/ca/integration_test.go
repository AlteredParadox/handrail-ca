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
