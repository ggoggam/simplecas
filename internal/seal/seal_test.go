package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func key(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, KeyBytes))
}

func mustParse(t *testing.T, entries ...string) *Keyring {
	t.Helper()
	k, err := Parse(entries)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return k
}

func TestSealRoundTrip(t *testing.T) {
	k := mustParse(t, "v1:"+key(1))
	id, sealed, err := k.Seal([]byte("hunter2"), []byte("SCASKEY1"))
	if err != nil {
		t.Fatal(err)
	}
	if id != "v1" {
		t.Errorf("sealed under %q, want v1", id)
	}
	if bytes.Contains(sealed, []byte("hunter2")) {
		t.Error("the sealed value contains the plaintext")
	}
	got, err := k.Open(id, sealed, []byte("SCASKEY1"))
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

// Two seals of the same secret differ, so equal ciphertexts reveal nothing
// about equal secrets.
func TestSealIsRandomised(t *testing.T) {
	k := mustParse(t, "v1:"+key(1))
	_, a, _ := k.Seal([]byte("same"), nil)
	_, b, _ := k.Seal([]byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext are identical")
	}
}

// A sealed secret copied onto another row must not open there.
func TestOpenRejectsAnotherContext(t *testing.T) {
	k := mustParse(t, "v1:"+key(1))
	id, sealed, _ := k.Seal([]byte("secret"), []byte("SCASKEYA"))
	if _, err := k.Open(id, sealed, []byte("SCASKEYB")); !errors.Is(err, ErrOpen) {
		t.Errorf("open under another context: err = %v, want ErrOpen", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	k := mustParse(t, "v1:"+key(1))
	id, sealed, _ := k.Seal([]byte("secret"), nil)
	sealed[len(sealed)-1] ^= 1
	if _, err := k.Open(id, sealed, nil); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered: err = %v, want ErrOpen", err)
	}
	if _, err := k.Open(id, sealed[:4], nil); !errors.Is(err, ErrOpen) {
		t.Errorf("truncated: err = %v, want ErrOpen", err)
	}
}

// Rotation: the first key seals, and an older key listed after it still opens
// what it sealed.
func TestRotation(t *testing.T) {
	old := mustParse(t, "v1:"+key(1))
	_, sealedOld, _ := old.Seal([]byte("before"), nil)

	rotated := mustParse(t, "v2:"+key(2), "v1:"+key(1))
	if rotated.Current() != "v2" {
		t.Errorf("current = %q, want v2", rotated.Current())
	}
	got, err := rotated.Open("v1", sealedOld, nil)
	if err != nil || string(got) != "before" {
		t.Fatalf("open under the old key = %q, %v", got, err)
	}
	id, _, _ := rotated.Seal([]byte("after"), nil)
	if id != "v2" {
		t.Errorf("new values sealed under %q, want v2", id)
	}

	if _, err := old.Open("v2", sealedOld, nil); err == nil {
		t.Error("a keyring opened a value under a key it does not hold")
	}
	if !rotated.Has("v1") || rotated.Has("v3") {
		t.Error("Has disagrees with the listed keys")
	}
}

// A key pasted from `openssl rand -base64 32` or any other common base64
// spelling is accepted.
func TestParseAcceptsBase64Spellings(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, KeyBytes)
	for _, material := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	} {
		if _, err := Parse([]string{"k:" + material}); err != nil {
			t.Errorf("Parse(%q): %v", material, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string][]string{
		"empty list":     nil,
		"no separator":   {key(1)},
		"empty id":       {":" + key(1)},
		"bad id":         {"v 1:" + key(1)},
		"long id":        {strings.Repeat("a", maxKeyIDLen+1) + ":" + key(1)},
		"duplicate id":   {"v1:" + key(1), "v1:" + key(2)},
		"short key":      {"v1:" + base64.StdEncoding.EncodeToString([]byte("too short"))},
		"not base64":     {"v1:!!!!"},
		"second invalid": {"v1:" + key(1), "v2:nope"},
	}
	for name, entries := range cases {
		if _, err := Parse(entries); err == nil {
			t.Errorf("%s: Parse(%q) succeeded", name, entries)
		}
	}
}

// A parse error is logged at startup, so it must not repeat the key.
func TestParseErrorOmitsKeyMaterial(t *testing.T) {
	material := base64.StdEncoding.EncodeToString([]byte("sixteen byte key"))
	_, err := Parse([]string{"v1:" + material})
	if err == nil {
		t.Fatal("a 16-byte key parsed")
	}
	if strings.Contains(err.Error(), material) {
		t.Errorf("error %q repeats the key material", err)
	}
}
