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
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// handrail-ca acts on the CA through one JWK provisioner. The CA publishes
// that provisioner's private key encrypted with the provisioner password (a
// PBES2 JWE); handrail-ca is given the password, opens the key, keeps it in
// memory only, and signs a one-time token with it for each request. Shapes
// checked against step-ca 0.30.2 (docs/PLAN.md, section 3).

// tokenLifetime is how long a one-time token is good for. The CA allows a
// minute of clock difference on either side of it.
const tokenLifetime = time.Minute

// ErrNoProvisioner is returned by everything that acts on the CA when the
// client was configured without a provisioner (read-only mode).
var ErrNoProvisioner = errors.New("no provisioner is configured: handrail-ca is read-only")

// ProvisionerConfig names the provisioner handrail-ca acts through.
type ProvisionerConfig struct {
	// Name is the provisioner's name on the CA. It must be a JWK
	// provisioner whose encrypted key the CA holds.
	Name string
	// Password opens that key. It is kept until the key has been opened,
	// since the CA may be down when handrail-ca starts, and then dropped.
	Password string
}

// The key-wrapping and content algorithms accepted for the encrypted key.
// step-ca writes PBES2-HS256+A128KW with A256GCM; the rest of the PBES2
// family is what a key encrypted with other `step crypto` options carries.
var (
	keyWrapAlgorithms = []jose.KeyAlgorithm{jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW}
	contentAlgorithms = []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
)

// maxEncryptedKey bounds the encrypted key that is tried. A P-256 key is
// about 500 bytes, an RSA-4096 key about 5,000.
const maxEncryptedKey = 32 << 10

// provisioner is the configured provisioner and, once opened, its key.
type provisioner struct {
	name string

	// opening is held by the one attempt to open the key that is under
	// way: a slot, not a mutex, so that waiting for it can be given up.
	// The attempt talks to the CA and decrypts, which takes as long as
	// the CA takes; nothing else waits for it.
	opening chan struct{}

	// mu guards the fields below and is never held across a request to
	// the CA or a decryption, so asking for the state never waits.
	mu       sync.Mutex
	password []byte
	signer   jose.Signer
	keyID    string
	// A password that did not open a key is not tried on that key again:
	// each try costs hundreds of thousands of hash rounds.
	failedKey string
	failedErr error
}

func newProvisioner(cfg *ProvisionerConfig) (*provisioner, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Name == "" {
		return nil, errors.New("provisioner: no name")
	}
	if cfg.Password == "" {
		return nil, errors.New("provisioner: no password")
	}
	return &provisioner{name: cfg.Name, password: []byte(cfg.Password), opening: make(chan struct{}, 1)}, nil
}

// ProvisionerState says what handrail-ca can do on the CA right now.
type ProvisionerState struct {
	// Configured is false in read-only mode; the rest is then empty.
	Configured bool
	Name       string
	// Ready means the key has been opened. KeyID is set with it.
	Ready bool
	KeyID string
}

// ProvisionerState reports the provisioner without asking the CA anything
// and without waiting for an attempt to open the key that is under way.
func (c *Client) ProvisionerState() ProvisionerState {
	p := c.provisioner
	if p == nil {
		return ProvisionerState{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return ProvisionerState{Configured: true, Name: p.name, Ready: p.signer != nil, KeyID: p.keyID}
}

// ready is the signer, if the key is open.
func (p *provisioner) ready() jose.Signer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signer
}

// Unlock opens the provisioner's key if that has not been done yet: it
// reads the encrypted key from the CA and decrypts it with the configured
// password. It is called by everything that needs the key, and can be
// called ahead of time to find a wrong name or password early. One attempt
// runs at a time; a caller waiting for another's attempt stops waiting
// when its own context ends.
func (c *Client) Unlock(ctx context.Context) error {
	p := c.provisioner
	if p == nil {
		return ErrNoProvisioner
	}
	if p.ready() != nil {
		return nil
	}
	select {
	case p.opening <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.opening }()
	// The attempt that was waited for may have opened it.
	if p.ready() != nil {
		return nil
	}

	listed, err := c.listedKey(ctx, p.name)
	if err != nil {
		return err
	}
	p.mu.Lock()
	failed := p.failedKey != "" && subtle.ConstantTimeCompare([]byte(p.failedKey), []byte(listed.encrypted)) == 1
	failedErr := p.failedErr
	// Only the attempt holding the slot drops the password, and it is this
	// one: the slice is safe to read without the lock until then.
	password := p.password
	p.mu.Unlock()
	if failed {
		return failedErr
	}

	signer, err := openKey(listed, password)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		err = fmt.Errorf("provisioner %q: %w", p.name, err)
		if errors.Is(err, errWrongPassword) {
			p.failedKey, p.failedErr = listed.encrypted, err
		}
		return err
	}
	p.signer, p.keyID = signer, listed.public.KeyID
	p.failedKey, p.failedErr = "", nil
	clear(p.password)
	p.password = nil
	return nil
}

// listedKey is what the CA publishes about a JWK provisioner's key.
type listedKey struct {
	public    jose.JSONWebKey
	encrypted string
}

// listedKey finds the one JWK provisioner with this name in the CA's list.
func (c *Client) listedKey(ctx context.Context, name string) (listedKey, error) {
	var (
		found   []listedKey
		another string
	)
	err := c.eachProvisioner(ctx, func(raw json.RawMessage) error {
		var in struct {
			Type         string          `json:"type"`
			Name         string          `json:"name"`
			Key          json.RawMessage `json:"key"`
			EncryptedKey string          `json:"encryptedKey"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return fmt.Errorf("/provisioners: an entry is not the expected JSON: %w", err)
		}
		if in.Name != name {
			return nil
		}
		if in.Type != "JWK" {
			another = in.Type
			return nil
		}
		var k listedKey
		if err := json.Unmarshal(in.Key, &k.public); err != nil {
			return fmt.Errorf("provisioner %q: the CA's copy of its public key does not parse: %w", name, err)
		}
		k.encrypted = in.EncryptedKey
		found = append(found, k)
		return nil
	})
	switch {
	case err != nil:
		return listedKey{}, err
	case len(found) == 0 && another != "":
		return listedKey{}, fmt.Errorf("provisioner %q is of type %s on the CA: handrail-ca needs a JWK provisioner", name, clip(another))
	case len(found) == 0:
		return listedKey{}, fmt.Errorf("the CA has no provisioner named %q", name)
	case len(found) > 1:
		return listedKey{}, fmt.Errorf("the CA has %d JWK provisioners named %q: handrail-ca needs the name to mean one", len(found), name)
	}
	k := found[0]
	switch {
	case !k.public.Valid() || !k.public.IsPublic() || k.public.KeyID == "":
		return listedKey{}, fmt.Errorf("provisioner %q: the CA lists no usable public key with a key ID for it", name)
	case k.encrypted == "":
		return listedKey{}, fmt.Errorf("provisioner %q: the CA does not hold its encrypted key (it was created without one, or it was removed), so there is nothing for the password to open", name)
	case len(k.encrypted) > maxEncryptedKey:
		return listedKey{}, fmt.Errorf("provisioner %q: its encrypted key is larger than %d bytes", name, maxEncryptedKey)
	}
	return k, nil
}

// errWrongPassword marks a decryption that failed: the password is wrong,
// or the key is damaged, and trying again will not help.
var errWrongPassword = errors.New("the configured password does not open its key (a wrong password, or a damaged key)")

// openKey decrypts the provisioner's key and returns a signer for it. The
// key must be the private half of the public key the CA lists: a token
// signed with any other key would be refused, and it is better to say so
// here than at the first revocation.
func openKey(listed listedKey, password []byte) (jose.Signer, error) {
	jwe, err := jose.ParseEncryptedCompact(listed.encrypted, keyWrapAlgorithms, contentAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("its encrypted key is not a password-encrypted JWE this version reads: %w", err)
	}
	plain, err := jwe.Decrypt(password)
	if errors.Is(err, jose.ErrCryptoFailure) {
		return nil, errWrongPassword
	}
	if err != nil {
		return nil, fmt.Errorf("its encrypted key could not be decrypted: %w", err)
	}
	defer clear(plain)
	var key jose.JSONWebKey
	if err := json.Unmarshal(plain, &key); err != nil || !key.Valid() || key.IsPublic() {
		return nil, errors.New("its key decrypted, but to something that is not a private key")
	}
	public := key.Public()
	got, err1 := public.Thumbprint(crypto.SHA256)
	want, err2 := listed.public.Thumbprint(crypto.SHA256)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, errors.New("its decrypted key is not the private half of the public key the CA lists")
	}
	alg, err := signatureAlgorithm(key)
	if err != nil {
		return nil, err
	}
	// The token's "kid" is the key ID as the CA lists it: that, with the
	// provisioner's name, is how the CA finds the provisioner for a token.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key.Key, KeyID: listed.public.KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("its key cannot sign tokens: %w", err)
	}
	return signer, nil
}

// signatureAlgorithm is the algorithm tokens are signed with: the one the
// key names for itself, if it suits the key, else the usual one for its
// type, which is what the step CLI does.
func signatureAlgorithm(key jose.JSONWebKey) (jose.SignatureAlgorithm, error) {
	var usual jose.SignatureAlgorithm
	var others []jose.SignatureAlgorithm
	switch k := key.Key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			usual = jose.ES256
		case 384:
			usual = jose.ES384
		case 521:
			usual = jose.ES512
		default:
			return "", errors.New("its key is on an elliptic curve tokens are not signed with")
		}
	case ed25519.PrivateKey:
		usual = jose.EdDSA
	case *rsa.PrivateKey:
		usual = jose.RS256
		others = []jose.SignatureAlgorithm{jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512}
	default:
		return "", errors.New("its key is of a type tokens are not signed with")
	}
	for _, alg := range others {
		if key.Algorithm == string(alg) {
			return alg, nil
		}
	}
	return usual, nil
}

// token signs a one-time token for one request: audience is the endpoint's
// address, subject what the request is about. It is the caller's to send
// once and never to log.
func (c *Client) token(ctx context.Context, path, subject string) (string, error) {
	if err := c.Unlock(ctx); err != nil {
		return "", err
	}
	signer, name := c.provisioner.ready(), c.provisioner.name

	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := c.now()
	audience := *c.base
	audience.Path = path
	claims, err := json.Marshal(map[string]any{
		"iss": name,
		"sub": subject,
		"aud": audience.String(),
		"jti": hex.EncodeToString(id),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(tokenLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("signing a token: %w", err)
	}
	return signed.CompactSerialize()
}
