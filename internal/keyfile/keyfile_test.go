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

package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// decrypt is the reading of an encrypted key that this package does not
// offer: the tests use it to open what Encrypt wrote, and what OpenSSL
// wrote, so that the two are shown to be the same format.
func decrypt(pemText []byte, password string) ([]byte, error) {
	block, rest := pem.Decode(pemText)
	if block == nil || block.Type != PEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not one ENCRYPTED PRIVATE KEY block")
	}
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(block.Bytes, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("not an EncryptedPrivateKeyInfo")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("not PBES2")
	}
	var scheme pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &scheme); err != nil {
		return nil, err
	}
	if !scheme.KeyDerivation.Algorithm.Equal(oidPBKDF2) || !scheme.Encryption.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("not PBKDF2 with AES-256-CBC")
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(scheme.KeyDerivation.Parameters.FullBytes, &kdf); err != nil {
		return nil, err
	}
	if !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) {
		return nil, errors.New("not HMAC-SHA-256")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(scheme.Encryption.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("no IV")
	}
	key, err := pbkdf2.Key(sha256.New, password, kdf.Salt, kdf.Iterations, 32)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, errors.New("not whole blocks")
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(plain, info.Data)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(plain) {
		return nil, errors.New("wrong password")
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errors.New("wrong password")
		}
	}
	return plain[:len(plain)-pad], nil
}

func testKeys(t *testing.T) map[string][]byte {
	t.Helper()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for name, key := range map[string]any{"ECDSA P-256": p256, "ECDSA P-384": p384, "Ed25519": ed, "RSA": rsaKey} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = der
	}
	return out
}

func TestEncrypt(t *testing.T) {
	const password = "correct horse battery staple"
	for name, der := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			out, err := encrypt(der, password, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(out, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")) {
				t.Fatalf("not an encrypted key in PEM: %.60s", out)
			}
			// The key is not in it in the clear, not even a part of it.
			block, _ := pem.Decode(out)
			if bytes.Contains(block.Bytes, der[len(der)/2:len(der)/2+16]) {
				t.Error("part of the key is in the output unencrypted")
			}
			back, err := decrypt(out, password)
			if err != nil || !bytes.Equal(back, der) {
				t.Fatalf("decrypted to something else: %v", err)
			}
			if _, err := x509.ParsePKCS8PrivateKey(back); err != nil {
				t.Errorf("what comes back is not a key: %v", err)
			}
			if back, err := decrypt(out, password+"x"); err == nil && bytes.Equal(back, der) {
				t.Error("another password opens it")
			}
			// A new salt and IV each time: the same key and password never
			// give the same file twice.
			again, err := encrypt(der, password, 1000)
			if err != nil || bytes.Equal(again, out) {
				t.Error("two encryptions of one key are identical")
			}
		})
	}
}

// What is written says how it was made, with the count this package
// promises: a reader needs nothing but the password.
func TestEncryptWritesItsParameters(t *testing.T) {
	der := testKeys(t)["ECDSA P-256"]
	out, err := Encrypt(der, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(out)
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &info); err != nil {
		t.Fatal(err)
	}
	var scheme pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &scheme); err != nil {
		t.Fatal(err)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(scheme.KeyDerivation.Parameters.FullBytes, &kdf); err != nil {
		t.Fatal(err)
	}
	if kdf.Iterations != 600_000 || len(kdf.Salt) != 16 || !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) {
		t.Errorf("key derivation: %d rounds, %d bytes of salt, PRF %v", kdf.Iterations, len(kdf.Salt), kdf.PRF.Algorithm)
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) || !scheme.Encryption.Algorithm.Equal(oidAES256CBC) {
		t.Errorf("scheme: %v with %v", info.Algorithm.Algorithm, scheme.Encryption.Algorithm)
	}
}

func TestEncryptRefusals(t *testing.T) {
	der := testKeys(t)["ECDSA P-256"]
	if _, err := Encrypt(der, ""); err == nil {
		t.Error("encrypted with no password")
	}
	if _, err := Encrypt(nil, "a password"); err == nil {
		t.Error("encrypted no key")
	}
}

// The format is OpenSSL's, shown in both directions with OpenSSL itself:
// it opens what Encrypt wrote and gets the same key, and what it writes
// with the same choices opens with the reading the other tests use.
// Skipped where there is no openssl to ask.
func TestEncryptIsWhatOpenSSLReadsAndWrites(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on this machine")
	}
	const password = "correct horse battery staple"
	dir := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(openssl, args...)
		cmd.Env = append(os.Environ(), "KEYFILE_TEST_PASSWORD="+password)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	for name, der := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			plain := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".key")
			if err := os.WriteFile(plain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}

			// The full count of rounds for one kind of key; fewer for the
			// rest, which differ only in what is inside.
			rounds := 10_000
			if name == "ECDSA P-256" {
				rounds = Iterations
			}
			// Ours, opened by OpenSSL.
			ours, err := encrypt(der, password, rounds)
			if err != nil {
				t.Fatal(err)
			}
			oursFile := plain + ".ours"
			if err := os.WriteFile(oursFile, ours, 0o600); err != nil {
				t.Fatal(err)
			}
			opened := run("pkcs8", "-in", oursFile, "-passin", "env:KEYFILE_TEST_PASSWORD", "-nocrypt", "-topk8", "-outform", "DER")
			if !bytes.Equal(opened, der) {
				t.Error("OpenSSL opened it to another key")
			}
			// And refuses the wrong password.
			wrong := exec.Command(openssl, "pkcs8", "-in", oursFile, "-passin", "pass:not the password", "-nocrypt", "-topk8")
			if wrong.Run() == nil {
				t.Error("OpenSSL opened it with the wrong password")
			}

			// OpenSSL's, with the same choices, opened by the tests' reading.
			theirsFile := plain + ".theirs"
			run("pkcs8", "-topk8", "-in", plain, "-out", theirsFile, "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", strconv.Itoa(rounds), "-passout", "env:KEYFILE_TEST_PASSWORD")
			theirs, err := os.ReadFile(theirsFile)
			if err != nil {
				t.Fatal(err)
			}
			back, err := decrypt(theirs, password)
			if err != nil || !bytes.Equal(back, der) {
				t.Errorf("OpenSSL's file does not open as ours do: %v", err)
			}
		})
	}
}
