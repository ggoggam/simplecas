// Package seal encrypts small secrets at rest under a versioned set of server
// keys.
//
// It exists for the per-team S3 secrets. SigV4 is symmetric HMAC, so the
// server needs each secret back verbatim to check a signature and cannot store
// a one-way hash of it. Sealing is the next best thing: someone who can read
// the database but not the server's configuration learns nothing usable.
//
// A Keyring holds one or more named keys. The first seals; every key opens what
// was sealed under its name, which is what lets a key be rotated without a
// flag day: add the new key at the end, roll it out, move it to the front, roll
// that out, and drop the old one once nothing is sealed under it any more.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeyBytes is the size of every key: AES-256.
const KeyBytes = 32

// maxKeyIDLen bounds a key's name, which is stored beside every sealed value.
const maxKeyIDLen = 32

// ErrOpen is returned for a sealed value that does not authenticate under the
// key it names, including one moved to a row it was not sealed for.
var ErrOpen = errors.New("seal: value does not authenticate")

// Keyring is a parsed, ordered set of keys. The zero value is not usable;
// build one with Parse.
type Keyring struct {
	current string
	aeads   map[string]cipher.AEAD
}

// Parse builds a Keyring from "id:base64key" entries, the first of which is
// the key new values are sealed under. The key material is standard or URL
// base64 of exactly KeyBytes bytes (`openssl rand -base64 32`). An empty list
// is not a keyring; callers decide whether that is allowed.
func Parse(entries []string) (*Keyring, error) {
	if len(entries) == 0 {
		return nil, errors.New("no keys")
	}
	k := &Keyring{aeads: make(map[string]cipher.AEAD, len(entries))}
	for i, entry := range entries {
		id, material, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			return nil, fmt.Errorf("key %d: want id:base64key", i+1)
		}
		if !validKeyID(id) {
			return nil, fmt.Errorf("key %d: id %q must be 1-%d letters, digits, '-' or '_'", i+1, id, maxKeyIDLen)
		}
		if _, dup := k.aeads[id]; dup {
			return nil, fmt.Errorf("key id %q appears twice", id)
		}
		raw, err := decodeKey(material)
		if err != nil {
			// Deliberately not echoing the material: this error is logged.
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		k.aeads[id] = aead
		if i == 0 {
			k.current = id
		}
	}
	return k, nil
}

// decodeKey accepts the base64 spellings a key is likely to be pasted in.
func decodeKey(material string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		raw, err := enc.DecodeString(material)
		if err != nil {
			continue
		}
		if len(raw) != KeyBytes {
			return nil, fmt.Errorf("decodes to %d bytes, want %d", len(raw), KeyBytes)
		}
		return raw, nil
	}
	return nil, errors.New("is not base64")
}

func validKeyID(id string) bool {
	if id == "" || len(id) > maxKeyIDLen {
		return false
	}
	for _, c := range id {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// Current is the name of the key Seal uses.
func (k *Keyring) Current() string { return k.current }

// Has reports whether the keyring can open values sealed under id.
func (k *Keyring) Has(id string) bool {
	_, ok := k.aeads[id]
	return ok
}

// Seal encrypts plaintext under the current key and returns that key's name
// with the ciphertext (a random nonce followed by the GCM output).
//
// context is authenticated but not stored. Callers pass what the value belongs
// to — for a secret, its row's primary key — so a sealed value copied onto
// another row fails to open rather than lending that row its secret.
func (k *Keyring) Seal(plaintext, context []byte) (keyID string, sealed []byte, err error) {
	aead := k.aeads[k.current]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("seal: nonce: %w", err)
	}
	return k.current, aead.Seal(nonce, nonce, plaintext, context), nil
}

// Open decrypts a value Seal produced under keyID, with the same context.
func (k *Keyring) Open(keyID string, sealed, context []byte) ([]byte, error) {
	aead, ok := k.aeads[keyID]
	if !ok {
		return nil, fmt.Errorf("seal: no key named %q", keyID)
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrOpen
	}
	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, body, context)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}
