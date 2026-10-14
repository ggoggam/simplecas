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
//
// A Keyring can also derive subkeys (Derive), for callers that seal many
// values and want a key per value rather than one key for all of them, as the
// blob store does for stored content.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// KeyBytes is the size of every key: AES-256.
const KeyBytes = 32

// MaxKeyIDLen bounds a key's name, which is stored beside every sealed value.
const MaxKeyIDLen = 32

// ErrOpen is returned for a sealed value that does not authenticate under the
// key it names, including one moved to a row it was not sealed for.
var ErrOpen = errors.New("seal: value does not authenticate")

// Keyring is a parsed, ordered set of keys. The zero value is not usable;
// build one with Parse.
type Keyring struct {
	current string
	aeads   map[string]cipher.AEAD
	// prks are the keys run through HKDF-Extract, which Derive expands.
	prks map[string][]byte
	ids  []string
}

// deriveSalt is the HKDF salt for Derive, fixed so that a subkey depends only
// on the key and what it is derived for.
const deriveSalt = "simplecas seal derive v1"

// Parse builds a Keyring from "id:base64key" entries, the first of which is
// the key new values are sealed under. The key material is standard or URL
// base64 of exactly KeyBytes bytes (`openssl rand -base64 32`). An empty list
// is not a keyring; callers decide whether that is allowed.
func Parse(entries []string) (*Keyring, error) {
	if len(entries) == 0 {
		return nil, errors.New("no keys")
	}
	k := &Keyring{aeads: make(map[string]cipher.AEAD, len(entries)), prks: make(map[string][]byte, len(entries))}
	for i, entry := range entries {
		id, material, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			return nil, fmt.Errorf("key %d: want id:base64key", i+1)
		}
		if !validKeyID(id) {
			return nil, fmt.Errorf("key %d: id %q must be 1-%d letters, digits, '-' or '_'", i+1, id, MaxKeyIDLen)
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
		prk, err := hkdf.Extract(sha256.New, raw, []byte(deriveSalt))
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		k.aeads[id] = aead
		k.prks[id] = prk
		k.ids = append(k.ids, id)
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

// Normalize returns key material in one canonical spelling, so two entries
// can be compared whatever base64 alphabet or padding each was pasted in. It
// returns the material unchanged if it does not decode to a key.
func Normalize(material string) string {
	raw, err := decodeKey(material)
	if err != nil {
		return material
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func validKeyID(id string) bool {
	if id == "" || len(id) > MaxKeyIDLen {
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

// Derive returns an AES-256-GCM AEAD under a subkey of the key keyID, derived
// with HKDF-SHA256 for info. The same key and info always give the same
// subkey, and different info gives unrelated ones. info should start with a
// label for the purpose, so subkeys for different purposes never meet.
//
// A subkey is never the key Seal uses, so one keyring could serve both, but
// each purpose should still have keys of its own: rotating one should not
// mean rotating the other.
func (k *Keyring) Derive(keyID, info string) (cipher.AEAD, error) {
	prk, ok := k.prks[keyID]
	if !ok {
		return nil, fmt.Errorf("seal: no key named %q", keyID)
	}
	sub, err := hkdf.Expand(sha256.New, prk, info, KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("seal: derive: %w", err)
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, fmt.Errorf("seal: derive: %w", err)
	}
	return cipher.NewGCM(block)
}

// fingerprintInfo derives a key's fingerprint, which is never a key.
const fingerprintInfo = "simplecas seal fingerprint v1"

// Fingerprint identifies the key material named keyID without revealing it:
// two keyrings give the same fingerprint for an id exactly when they hold the
// same key under it. Recording it lets instances that share stored data find
// out they were given different keys under one name before either writes
// anything the other cannot open.
func (k *Keyring) Fingerprint(keyID string) (string, error) {
	prk, ok := k.prks[keyID]
	if !ok {
		return "", fmt.Errorf("seal: no key named %q", keyID)
	}
	sum, err := hkdf.Expand(sha256.New, prk, fingerprintInfo, 16)
	if err != nil {
		return "", fmt.Errorf("seal: fingerprint: %w", err)
	}
	return hex.EncodeToString(sum), nil
}

// IDs lists the keyring's key names, the current one first.
func (k *Keyring) IDs() []string { return slices.Clone(k.ids) }
