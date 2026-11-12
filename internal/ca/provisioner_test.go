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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testPassword = "correct horse battery staple"

// testProvisioner is a JWK provisioner as the CA lists it: a public key
// with a key ID, and the private key encrypted with a password.
type testProvisioner struct {
	name      string
	public    jose.JSONWebKey
	encrypted string
}

func newKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch kind {
	case "P-256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "Ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "RSA":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("no such kind of key: %s", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// encryptKey is what `step ca provisioner add --create` does with the
// private key: a PBES2 JWE of its JWK. The iteration count is low to keep
// the tests quick.
func encryptKey(t *testing.T, private jose.JSONWebKey, password string) string {
	t.Helper()
	plain, err := json.Marshal(private)
	if err != nil {
		t.Fatal(err)
	}
	return encryptBytes(t, plain, password)
}

func encryptBytes(t *testing.T, plain []byte, password string) string {
	t.Helper()
	enc, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{Algorithm: jose.PBES2_HS256_A128KW, Key: []byte(password), PBES2Count: 1000},
		(&jose.EncrypterOptions{}).WithContentType("jwk+json"))
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := enc.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// newTestProvisioner makes a provisioner named "handrail" with a key of
// the given kind; alg is the "alg" its JWK names, which may be empty.
func newTestProvisioner(t *testing.T, kind, alg string) testProvisioner {
	t.Helper()
	key := newKey(t, kind)
	private := jose.JSONWebKey{Key: key, Algorithm: alg, Use: "sig"}
	sum, err := private.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	private.KeyID = base64.RawURLEncoding.EncodeToString(sum)
	return testProvisioner{name: "handrail", public: private.Public(), encrypted: encryptKey(t, private, testPassword)}
}

func (p testProvisioner) entry() map[string]any {
	e := map[string]any{"type": "JWK", "name": p.name, "key": p.public}
	if p.encrypted != "" {
		e["encryptedKey"] = p.encrypted
	}
	return e
}

// lists makes the fake CA answer /provisioners with these entries, beside
// an ACME provisioner as every real list has other entries.
func (f *fakeCA) lists(entries ...map[string]any) {
	all := append([]map[string]any{{"type": "ACME", "name": "acme"}}, entries...)
	f.mux.HandleFunc("GET /provisioners", jsonRoute(http.StatusOK, map[string]any{"provisioners": all}))
}

// acting is a client for the fake CA that acts through "handrail".
func (f *fakeCA) acting(t *testing.T, password string, now func() time.Time) *Client {
	t.Helper()
	c, err := New(Config{
		URL: f.srv.URL, Fingerprint: Fingerprint(f.pki.root), Timeout: 5 * time.Second,
		Provisioner: &ProvisionerConfig{Name: "handrail", Password: password}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// revocations records what the fake CA's /1.0/revoke was sent, and answers
// as told.
type revocations struct {
	mu     sync.Mutex
	bodies []map[string]any
	status int
	answer any
	date   string // a Date header to send, if set
}

func (f *fakeCA) revocations() *revocations {
	rec := &revocations{status: http.StatusOK, answer: map[string]string{"status": "ok"}}
	f.mux.HandleFunc("POST /1.0/revoke", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, body)
		status, answer, date := rec.status, rec.answer, rec.date
		rec.mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			status, answer = http.StatusBadRequest, map[string]any{"status": 400, "message": "not JSON"}
		}
		if date != "" {
			w.Header().Set("Date", date)
		}
		writeJSON(w, status, answer)
	})
	return rec
}

func (rec *revocations) sent(t *testing.T, n int) []map[string]any {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.bodies) != n {
		t.Fatalf("the CA was sent %d revocations, want %d", len(rec.bodies), n)
	}
	return rec.bodies
}

// claimsOf checks a token's signature with the provisioner's public key
// and returns its header and claims.
func claimsOf(t *testing.T, token string, p testProvisioner, alg jose.SignatureAlgorithm) (jose.Header, map[string]any) {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("the token does not parse as a JWS signed with %s: %v", alg, err)
	}
	payload, err := jws.Verify(p.public.Key)
	if err != nil {
		t.Fatalf("the token's signature does not verify with the provisioner's public key: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return jws.Signatures[0].Protected, claims
}

func TestRevoke(t *testing.T) {
	f := newFakeCA(t)
	p := newTestProvisioner(t, "P-256", "ES256")
	f.lists(p.entry())
	rec := f.revocations()
	now := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	c := f.acting(t, testPassword, func() time.Time { return now })
	ctx := context.Background()

	if st := c.ProvisionerState(); !st.Configured || st.Ready || st.Name != "handrail" {
		t.Fatalf("before anything is asked: %+v", st)
	}
	if err := c.Revoke(ctx, Revocation{Serial: "28772997619311", ReasonCode: 1, Reason: "laptop stolen"}); err != nil {
		t.Fatal(err)
	}
	if st := c.ProvisionerState(); !st.Ready || st.KeyID != p.public.KeyID {
		t.Errorf("after a revocation: %+v", st)
	}
	if c.provisioner.password != nil {
		t.Error("the password was kept after the key was opened")
	}

	body := rec.sent(t, 1)[0]
	token, _ := body["ott"].(string)
	delete(body, "ott")
	want := map[string]any{"serial": "28772997619311", "reasonCode": float64(1), "reason": "laptop stolen", "passive": true}
	if len(body) != len(want) {
		t.Errorf("request = %v, want %v and a token", body, want)
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("request %s = %v, want %v", k, body[k], v)
		}
	}

	header, claims := claimsOf(t, token, p, jose.ES256)
	if header.KeyID != p.public.KeyID || header.ExtraHeaders["typ"] != "JWT" {
		t.Errorf("token header: kid %q typ %v", header.KeyID, header.ExtraHeaders["typ"])
	}
	for k, v := range map[string]any{
		"iss": "handrail",
		"sub": "28772997619311",
		"aud": f.srv.URL + "/1.0/revoke",
		"iat": float64(now.Unix()),
		"nbf": float64(now.Unix()),
		"exp": float64(now.Add(time.Minute).Unix()),
	} {
		if claims[k] != v {
			t.Errorf("token claim %s = %v, want %v", k, claims[k], v)
		}
	}
	id, _ := claims["jti"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) {
		t.Errorf("token id = %q, want 32 random bytes in hex", id)
	}
	if len(claims) != 7 {
		t.Errorf("token claims = %v, want the seven above and no more", claims)
	}

	// A second revocation: a new token, and the key is not fetched again.
	listed := f.hits.Load()
	if err := c.Revoke(ctx, Revocation{Serial: "5"}); err != nil {
		t.Fatal(err)
	}
	if got := f.hits.Load() - listed; got != 1 {
		t.Errorf("the second revocation made %d requests, want the one", got)
	}
	_, second := claimsOf(t, rec.sent(t, 2)[1]["ott"].(string), p, jose.ES256)
	if second["jti"] == id || second["sub"] != "5" {
		t.Errorf("second token: id reused or wrong subject: %v", second)
	}
}

func TestRevokeSendsOnlyPlainDecimalSerials(t *testing.T) {
	f := newFakeCA(t)
	p := newTestProvisioner(t, "P-256", "")
	f.lists(p.entry())
	rec := f.revocations()
	c := f.acting(t, testPassword, nil)
	ctx := context.Background()

	for _, serial := range []string{"", "0x1f", "-5", "12a", "1 2", "١٢", strings.Repeat("9", 81)} {
		if err := c.Revoke(ctx, Revocation{Serial: serial}); err == nil || !strings.Contains(err.Error(), "serial number") {
			t.Errorf("serial %q: err = %v, want a refusal", serial, err)
		}
	}
	for _, code := range []int{-1, 11} {
		wantErr(t, c.Revoke(ctx, Revocation{Serial: "5", ReasonCode: code}), "reason code")
	}
	rec.sent(t, 0)
	if f.hits.Load() != 0 {
		t.Errorf("%d requests were made for revocations that were refused here", f.hits.Load())
	}

	// step-ca would read a leading zero as octal. What is sent, and what
	// the token is for, is the number in plain decimal.
	if err := c.Revoke(ctx, Revocation{Serial: "0010"}); err != nil {
		t.Fatal(err)
	}
	body := rec.sent(t, 1)[0]
	_, claims := claimsOf(t, body["ott"].(string), p, jose.ES256)
	if body["serial"] != "10" || claims["sub"] != "10" {
		t.Errorf("sent serial %v with a token for %v, want 10 and 10", body["serial"], claims["sub"])
	}
}

func TestRevokeWithoutAProvisioner(t *testing.T) {
	f := newFakeCA(t)
	c := f.client(t)
	if st := c.ProvisionerState(); st.Configured {
		t.Errorf("state = %+v", st)
	}
	if err := c.Revoke(context.Background(), Revocation{Serial: "5"}); !errors.Is(err, ErrNoProvisioner) {
		t.Errorf("Revoke: %v", err)
	}
	if err := c.Unlock(context.Background()); !errors.Is(err, ErrNoProvisioner) {
		t.Errorf("Unlock: %v", err)
	}
	if f.hits.Load()+f.rootFetches.Load() != 0 {
		t.Error("the CA was asked something")
	}
	for _, cfg := range []ProvisionerConfig{{Name: "", Password: "x"}, {Name: "handrail", Password: ""}} {
		if _, err := New(Config{URL: f.srv.URL, Fingerprint: Fingerprint(f.pki.root), Provisioner: &cfg}); err == nil {
			t.Errorf("New accepted provisioner %+v", cfg)
		}
	}
}

// What the CA says about a revocation it did not make is passed on, the
// request is not repeated, and the token appears in no error.
func TestRevokeFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		answer any
		want   string
	}{
		{"already revoked", 400, map[string]any{"status": 400, "message": "certificate with serial number '5' is already revoked"}, "already revoked"},
		{"token refused", 401, map[string]any{"status": 401, "message": "The request lacked necessary authorization to be completed."}, "the CA answered 401"},
		{"the CA failed", 500, "boom", "the CA answered 500"},
		{"success that is not a confirmation", 200, map[string]any{"status": "pending"}, "not with the confirmation"},
		{"success with no body to speak of", 200, []int{}, "not with the confirmation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCA(t)
			f.lists(newTestProvisioner(t, "P-256", "").entry())
			rec := f.revocations()
			rec.status, rec.answer = tt.status, tt.answer
			err := f.acting(t, testPassword, nil).Revoke(context.Background(), Revocation{Serial: "5"})
			wantErr(t, err, tt.want)
			token := rec.sent(t, 1)[0]["ott"].(string)
			if strings.Contains(err.Error(), token) {
				t.Error("the error carries the token")
			}
			var se *StatusError
			if tt.status != 200 && (!errors.As(err, &se) || se.Status != tt.status) {
				t.Errorf("err = %#v, want a StatusError with %d", err, tt.status)
			}
		})
	}

	t.Run("no answer", func(t *testing.T) {
		f := newFakeCA(t)
		f.lists(newTestProvisioner(t, "P-256", "").entry())
		c := f.acting(t, testPassword, nil)
		if err := c.Unlock(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.srv.Close()
		err := c.Revoke(context.Background(), Revocation{Serial: "5"})
		var se *StatusError
		if err == nil || errors.As(err, &se) {
			t.Errorf("err = %v, want a failure that is not an answer", err)
		}
	})
}

// A token is dated here and checked by the CA's clock. When the CA refuses
// and its clock is far from ours, the error says by how much.
func TestRevokeReportsAClockDifference(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		caClock time.Time
		want    time.Duration
	}{
		{now.Add(5 * time.Minute), 5 * time.Minute},
		{now.Add(-90 * time.Second), -90 * time.Second},
		{now.Add(20 * time.Second), 0},
		{now, 0},
	}
	for _, tt := range tests {
		f := newFakeCA(t)
		f.lists(newTestProvisioner(t, "P-256", "").entry())
		rec := f.revocations()
		rec.status, rec.answer = 401, map[string]any{"status": 401, "message": "no"}
		rec.date = tt.caClock.Format(http.TimeFormat)
		err := f.acting(t, testPassword, func() time.Time { return now }).Revoke(context.Background(), Revocation{Serial: "5"})
		var se *StatusError
		if !errors.As(err, &se) || se.ClockDifference != tt.want {
			t.Errorf("CA clock %s from ours: err = %#v, want a difference of %s", tt.caClock.Sub(now), err, tt.want)
		}
	}
}

func TestUnlockFailsVisibly(t *testing.T) {
	good := newTestProvisioner(t, "P-256", "")
	other := newTestProvisioner(t, "P-256", "")

	swapped := good
	swapped.encrypted = other.encrypted // someone else's private key

	publicOnly := good
	publicOnly.encrypted = encryptKey(t, good.public, testPassword)

	noKey := good
	noKey.encrypted = ""

	garbage := good
	garbage.encrypted = "not.a.jwe"

	notAKey := good
	notAKey.encrypted = encryptBytes(t, []byte(`"hello"`), testPassword)

	huge := good
	huge.encrypted = strings.Repeat("A", maxEncryptedKey+1)

	noKeyID := good
	noKeyID.public.KeyID = ""

	renamed := good
	renamed.name = "someone-else"

	tests := []struct {
		name     string
		entries  []map[string]any
		password string
		want     string
	}{
		{"no such provisioner", []map[string]any{renamed.entry()}, testPassword, `no provisioner named "handrail"`},
		{"not a JWK provisioner", []map[string]any{{"type": "OIDC", "name": "handrail"}}, testPassword, "is of type OIDC"},
		{"two with the name", []map[string]any{good.entry(), other.entry()}, testPassword, "2 JWK provisioners"},
		{"the CA holds no encrypted key", []map[string]any{noKey.entry()}, testPassword, "does not hold its encrypted key"},
		{"wrong password", []map[string]any{good.entry()}, "not the password", "does not open its key"},
		{"another key pair's private key", []map[string]any{swapped.entry()}, testPassword, "not the private half"},
		{"a public key inside", []map[string]any{publicOnly.entry()}, testPassword, "not a private key"},
		{"not a key inside", []map[string]any{notAKey.entry()}, testPassword, "not a private key"},
		{"not a JWE", []map[string]any{garbage.entry()}, testPassword, "not a password-encrypted JWE"},
		{"an enormous key", []map[string]any{huge.entry()}, testPassword, "larger than"},
		{"no key ID", []map[string]any{noKeyID.entry()}, testPassword, "no usable public key"},
		{"a public key that does not parse", []map[string]any{{"type": "JWK", "name": "handrail", "key": map[string]any{"kty": "EC"}}}, testPassword, "does not parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCA(t)
			f.lists(tt.entries...)
			rec := f.revocations()
			c := f.acting(t, tt.password, nil)
			wantErr(t, c.Unlock(context.Background()), tt.want)
			if st := c.ProvisionerState(); st.Ready || st.KeyID != "" {
				t.Errorf("state = %+v", st)
			}
			// Nothing is sent to the CA with a key that could not be opened.
			wantErr(t, c.Revoke(context.Background(), Revocation{Serial: "5"}), tt.want)
			rec.sent(t, 0)
		})
	}
}

// A password that failed on a key is not tried on that key again; when the
// key on the CA changes, it is.
func TestAWrongPasswordIsTriedOncePerKey(t *testing.T) {
	f := newFakeCA(t)
	old := newTestProvisioner(t, "P-256", "")
	old.encrypted = encryptKey(t, jose.JSONWebKey{Key: newKey(t, "P-256")}, "the old password")
	current := old
	var mu sync.Mutex
	f.mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"provisioners": []any{current.entry()}})
	})
	c := f.acting(t, testPassword, nil)
	ctx := context.Background()

	wantErr(t, c.Unlock(ctx), "does not open its key")
	if c.provisioner.failedKey != old.encrypted {
		t.Fatal("the key the password failed on was not remembered")
	}
	// Proof that the second attempt does not decrypt: the remembered error
	// is the one returned, by identity.
	first := c.provisioner.failedErr
	if err := c.Unlock(ctx); err != first {
		t.Errorf("second attempt: %v, want the remembered error", err)
	}

	// The provisioner is given a new key, encrypted with our password.
	replacement := newTestProvisioner(t, "P-256", "")
	mu.Lock()
	current = replacement
	mu.Unlock()
	if err := c.Unlock(ctx); err != nil {
		t.Fatalf("after the key changed: %v", err)
	}
	if st := c.ProvisionerState(); !st.Ready || st.KeyID != replacement.public.KeyID {
		t.Errorf("state = %+v", st)
	}
}

// handrail-ca starts while the CA is down: the password is kept until the
// key has been opened.
func TestUnlockWaitsForTheCA(t *testing.T) {
	f := newFakeCA(t)
	p := newTestProvisioner(t, "P-256", "")
	up := false
	var mu sync.Mutex
	f.mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !up {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": 503, "message": "starting"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"provisioners": []any{p.entry()}})
	})
	c := f.acting(t, testPassword, nil)
	wantErr(t, c.Unlock(context.Background()), "the CA answered 503")
	mu.Lock()
	up = true
	mu.Unlock()
	if err := c.Unlock(context.Background()); err != nil {
		t.Fatalf("once the CA is up: %v", err)
	}
}

func TestTokensAreSignedAsTheKeyAllows(t *testing.T) {
	tests := []struct {
		kind, named string
		want        jose.SignatureAlgorithm
	}{
		{"P-256", "ES256", jose.ES256},
		{"P-256", "", jose.ES256},
		{"P-384", "", jose.ES384},
		{"P-521", "ES512", jose.ES512},
		{"Ed25519", "EdDSA", jose.EdDSA},
		{"RSA", "", jose.RS256},
		{"RSA", "PS256", jose.PS256},
		// An algorithm that does not suit the key is not taken from it.
		{"P-256", "RS256", jose.ES256},
		{"RSA", "none", jose.RS256},
	}
	for _, tt := range tests {
		t.Run(tt.kind+"/"+tt.named, func(t *testing.T) {
			f := newFakeCA(t)
			p := newTestProvisioner(t, tt.kind, tt.named)
			f.lists(p.entry())
			rec := f.revocations()
			if err := f.acting(t, testPassword, nil).Revoke(context.Background(), Revocation{Serial: "5"}); err != nil {
				t.Fatal(err)
			}
			header, _ := claimsOf(t, rec.sent(t, 1)[0]["ott"].(string), p, tt.want)
			if header.Algorithm != string(tt.want) || header.KeyID != p.public.KeyID {
				t.Errorf("header = %+v", header)
			}
		})
	}
}
