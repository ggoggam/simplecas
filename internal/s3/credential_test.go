package s3

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/seal"
)

// rotatedKey is a second credential key, for the rotation tests.
const rotatedKey = "next:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

// withKeys returns a gateway over f's database and blobs whose credential
// keys are keys, the way a restart with an edited auth.credential_keys is.
func (f *tenantFixture) withKeys(t *testing.T, keys ...string) *Gateway {
	t.Helper()
	cfg := *f.g.cfg
	cfg.Auth.CredentialKeys = keys
	return New(f.g.db, f.g.blob, f.g.cas, &cfg, slog.New(slog.DiscardHandler))
}

// storedSecret reads key's secret columns straight from the table.
func (f *tenantFixture) storedSecret(t *testing.T, key string) (plaintext, keyID *string, sealed []byte) {
	t.Helper()
	err := f.pool.QueryRow(t.Context(), `
		SELECT secret_access_key, secret_key_id, secret_sealed
		FROM tenant_credentials WHERE access_key_id = $1`, key).Scan(&plaintext, &keyID, &sealed)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return plaintext, keyID, sealed
}

// plantPlaintext writes a key the way a server from before sealing did.
func (f *tenantFixture) plantPlaintext(t *testing.T, tenantID int64, key, secret string) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), `
		INSERT INTO tenant_credentials (access_key_id, secret_access_key, tenant_id)
		VALUES ($1, $2, $3)`, key, secret, tenantID)
	if err != nil {
		t.Fatalf("plant %s: %v", key, err)
	}
}

// A secret at rest is sealed, and nothing in the row is the secret itself.
func TestTeamSecretIsSealedAtRest(t *testing.T) {
	f := newTenantFixture(t)

	plaintext, keyID, sealed := f.storedSecret(t, f.keyA)
	if plaintext != nil {
		t.Fatalf("secret stored in plaintext: %q", *plaintext)
	}
	if keyID == nil || *keyID != "test" {
		t.Errorf("sealed under %v, want the configured key \"test\"", keyID)
	}
	if bytes.Contains(sealed, []byte(f.secretA)) {
		t.Error("the sealed column contains the secret")
	}
}

// A sealed secret moved onto another key's row does not open there. Without
// the access key id as context, copying a known key's ciphertext over another
// row would hand the copier that row's tenant.
func TestSealedSecretIsBoundToItsKey(t *testing.T) {
	f := newTenantFixture(t)

	_, err := f.pool.Exec(t.Context(), `
		UPDATE tenant_credentials b
		SET secret_sealed = a.secret_sealed, secret_key_id = a.secret_key_id
		FROM tenant_credentials a
		WHERE a.access_key_id = $1 AND b.access_key_id = $2`, f.keyA, f.keyB)
	if err != nil {
		t.Fatal(err)
	}

	w := f.signed(t, f.keyB, f.secretA, http.MethodGet, "/ns-b/", "")
	if w.Code == http.StatusOK {
		t.Fatal("key B verified with key A's secret after the ciphertext was copied")
	}
}

func TestExpiredTeamKeyIsDenied(t *testing.T) {
	f := newTenantFixture(t)

	past := time.Now().Add(-time.Second)
	if _, err := f.g.StoreCredential(t.Context(), Credential{
		AccessKeyID: "SCASEXPIRED", Secret: "expired-secret", TenantID: f.tenantA, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if _, err := f.g.StoreCredential(t.Context(), Credential{
		AccessKeyID: "SCASCURRENT", Secret: "current-secret", TenantID: f.tenantA, ExpiresAt: &future,
	}); err != nil {
		t.Fatal(err)
	}

	// Expired reads exactly like a key that never existed.
	mustCode(t, f.signed(t, "SCASEXPIRED", "expired-secret", http.MethodGet, "/ns-a/", ""),
		http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, "SCASCURRENT", "current-secret", http.MethodGet, "/ns-a/", ""),
		http.StatusOK, "")
}

// A verified request records the key's use; a failed one does not.
func TestVerifiedRequestRecordsLastUse(t *testing.T) {
	f := newTenantFixture(t)

	lastUsed := func() *time.Time {
		var at *time.Time
		if err := f.pool.QueryRow(t.Context(),
			"SELECT last_used_at FROM tenant_credentials WHERE access_key_id = $1", f.keyA).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	f.signed(t, f.keyA, "wrong-secret", http.MethodGet, "/ns-a/", "")
	if at := lastUsed(); at != nil {
		t.Fatalf("a request with a bad signature set last_used_at to %v", at)
	}

	mustCode(t, f.asA(t, http.MethodGet, "/ns-a/", ""), http.StatusOK, "")
	if lastUsed() == nil {
		t.Fatal("a verified request did not set last_used_at")
	}
}

// Upgrading: a plaintext row written before sealing is sealed at startup and
// keeps verifying with the secret its holder already has.
func TestStartupSealsPlaintextSecrets(t *testing.T) {
	f := newTenantFixture(t)
	f.plantPlaintext(t, f.tenantA, "SCASLEGACY", "legacy-secret")

	// Before sealing, the plaintext row still verifies.
	mustCode(t, f.signed(t, "SCASLEGACY", "legacy-secret", http.MethodGet, "/ns-a/", ""), http.StatusOK, "")

	if err := f.g.SealStoredCredentials(t.Context()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	plaintext, keyID, _ := f.storedSecret(t, "SCASLEGACY")
	if plaintext != nil || keyID == nil || *keyID != "test" {
		t.Fatalf("after sealing: plaintext = %v, key = %v", plaintext, keyID)
	}
	mustCode(t, f.signed(t, "SCASLEGACY", "legacy-secret", http.MethodGet, "/ns-a/", ""), http.StatusOK, "")

	// Running it again, as every other instance will, is a no-op.
	if err := f.g.SealStoredCredentials(t.Context()); err != nil {
		t.Fatalf("second seal: %v", err)
	}
}

// Rotation: with the new key first and the old one after it, startup reseals
// every secret under the new key, after which the old key can be dropped.
func TestStartupResealsUnderARotatedKey(t *testing.T) {
	f := newTenantFixture(t)

	rotated := f.withKeys(t, rotatedKey, testCredentialKey)
	if err := rotated.SealStoredCredentials(t.Context()); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	for _, key := range []string{f.keyA, f.keyB} {
		if _, keyID, _ := f.storedSecret(t, key); keyID == nil || *keyID != "next" {
			t.Errorf("%s sealed under %v after rotation, want next", key, keyID)
		}
	}

	// The old key is no longer needed.
	f.g = f.withKeys(t, rotatedKey)
	if err := f.g.SealStoredCredentials(t.Context()); err != nil {
		t.Fatalf("start with only the new key: %v", err)
	}
	mustCode(t, f.asA(t, http.MethodGet, "/ns-a/", ""), http.StatusOK, "")
}

// Dropping a key that still has secrets sealed under it would lock those keys
// out, so startup refuses instead.
func TestStartupRefusesAMissingKey(t *testing.T) {
	f := newTenantFixture(t)

	err := f.withKeys(t, rotatedKey).SealStoredCredentials(t.Context())
	if err == nil || !strings.Contains(err.Error(), `"test"`) {
		t.Fatalf("err = %v, want a refusal naming the missing key", err)
	}

	// And with no keys at all.
	err = f.withKeys(t).SealStoredCredentials(t.Context())
	if err == nil || !strings.Contains(err.Error(), "auth.credential_keys") {
		t.Fatalf("err = %v, want a refusal naming auth.credential_keys", err)
	}
}

// Without keys, a server that never sealed anything starts and keeps serving
// its plaintext keys, but cannot mint new ones.
func TestNoKeysLeavesPlaintextAlone(t *testing.T) {
	f := newTenantFixture(t)
	if _, err := f.pool.Exec(t.Context(), "DELETE FROM tenant_credentials"); err != nil {
		t.Fatal(err)
	}
	f.plantPlaintext(t, f.tenantA, "SCASLEGACY", "legacy-secret")

	f.g = f.withKeys(t)
	if err := f.g.SealStoredCredentials(t.Context()); err != nil {
		t.Fatalf("start without keys: %v", err)
	}
	if plaintext, _, _ := f.storedSecret(t, "SCASLEGACY"); plaintext == nil {
		t.Fatal("a server without keys changed a plaintext row")
	}
	mustCode(t, f.signed(t, "SCASLEGACY", "legacy-secret", http.MethodGet, "/ns-a/", ""), http.StatusOK, "")

	_, err := f.g.StoreCredential(t.Context(), Credential{AccessKeyID: "SCASNEW", Secret: "s", TenantID: f.tenantA})
	if err == nil {
		t.Fatal("a key was stored without a credential key to seal it")
	}
}

// Startup sealing must win over a concurrent instance doing the same, and
// leave every row openable.
func TestConcurrentStartupSealing(t *testing.T) {
	f := newTenantFixture(t)
	for i := range 5 {
		f.plantPlaintext(t, f.tenantA, "SCASLEGACY"+string(rune('A'+i)), "legacy-secret")
	}

	errs := make(chan error, 3)
	for range 3 {
		g := f.withKeys(t, testCredentialKey)
		go func() { errs <- g.SealStoredCredentials(context.Background()) }()
	}
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatalf("seal: %v", err)
		}
	}

	keys, err := seal.Parse([]string{testCredentialKey})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		id := "SCASLEGACY" + string(rune('A'+i))
		plaintext, keyID, sealed := f.storedSecret(t, id)
		if plaintext != nil {
			t.Errorf("%s still plaintext", id)
			continue
		}
		got, err := keys.Open(*keyID, sealed, []byte(id))
		if err != nil || string(got) != "legacy-secret" {
			t.Errorf("%s opens to %q, %v", id, got, err)
		}
	}
}

// A misconfigured keyring is a startup error from config.Validate; New
// trusts it and panics rather than serve without the keys it was given.
func TestNewPanicsOnMalformedKeys(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted a malformed credential key")
		}
	}()
	cfg := config.Default()
	cfg.Auth.CredentialKeys = []string{"bad"}
	New(nil, nil, nil, &cfg, slog.New(slog.DiscardHandler))
}
