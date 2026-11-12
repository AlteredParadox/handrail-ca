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

// Package keyfile writes a private key as a password-encrypted PKCS #8
// file: the "ENCRYPTED PRIVATE KEY" PEM that OpenSSL, the step CLI and
// most servers read.
//
// The encryption is PBES2 from RFC 8018 (PKCS #5 v2.1): the password is
// stretched with PBKDF2 over HMAC-SHA-256, and the key is encrypted with
// AES-256 in CBC mode. Go's standard library has every part of that but
// not the assembly of them into this file, which is what this package is:
// one fixed choice of algorithms, written out, and nothing read back.
package keyfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

// Iterations is how many rounds of PBKDF2 stretch the password. It is the
// count the step CLI uses for its own encrypted keys.
const Iterations = 600_000

// The object identifiers of the pieces, from RFC 8018 and NIST.
var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	PRF        pkix.AlgorithmIdentifier
}

type pbes2Params struct {
	KeyDerivation pkix.AlgorithmIdentifier
	Encryption    pkix.AlgorithmIdentifier
}

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// PEMType is the PEM label of what Encrypt returns.
const PEMType = "ENCRYPTED PRIVATE KEY"

// Encrypt returns a PKCS #8 private key (the DER of an unencrypted
// PrivateKeyInfo, as x509.MarshalPKCS8PrivateKey gives it) encrypted with
// a password, as PEM.
func Encrypt(pkcs8 []byte, password string) ([]byte, error) {
	return encrypt(pkcs8, password, Iterations)
}

func encrypt(pkcs8 []byte, password string, iterations int) ([]byte, error) {
	if len(pkcs8) == 0 {
		return nil, errors.New("keyfile: no key")
	}
	if password == "" {
		return nil, errors.New("keyfile: no password")
	}
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// PKCS #7 padding: always at least one byte, each the count of them.
	pad := aes.BlockSize - len(pkcs8)%aes.BlockSize
	padded := make([]byte, len(pkcs8)+pad)
	copy(padded, pkcs8)
	for i := len(pkcs8); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	defer clear(padded)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	kdf, err := asn1.Marshal(pbkdf2Params{
		Salt: salt, Iterations: iterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return nil, err
	}
	ivValue, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	scheme, err := asn1.Marshal(pbes2Params{
		KeyDerivation: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Encryption:    pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivValue}},
	})
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: scheme}},
		Data:      encrypted,
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: der}), nil
}
