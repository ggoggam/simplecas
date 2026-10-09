package db

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// sealedFor stands in for the gateway's sealing: this package stores and
// returns the bytes it is given and never interprets them.
func sealedFor(accessKeyID string) []byte { return []byte("sealed:" + accessKeyID) }

// allPermissions is the scope of a key with no limits, which the gateway
// fills in when a key is minted without one.
var allPermissions = S3Scope{Permissions: []string{"read", "list", "write", "delete"}}

func mustCredential(t *testing.T, d *DB, tenantID int64, accessKeyID string) {
	t.Helper()
	err := d.CreateS3Credential(t.Context(), NewS3Credential{
		AccessKeyID: accessKeyID, TenantID: tenantID, KeyID: "k1", Sealed: sealedFor(accessKeyID),
		Scope: allPermissions,
	})
	if err != nil {
		t.Fatalf("create credential %s: %v", accessKeyID, err)
	}
}

func TestS3CredentialRoundTrip(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	owner := mustUser(t, d, "owner@example.com")
	tenantID, err := d.CreateTenant(ctx, "team-a", owner)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := d.CreateS3Credential(ctx, NewS3Credential{
		AccessKeyID: "SCASKEY1", TenantID: tenantID, KeyID: "k1", Sealed: sealedFor("SCASKEY1"),
		Description: "ci", CreatedBy: &owner, Scope: allPermissions,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	cred, ok, err := d.LookupS3Credential(ctx, "SCASKEY1")
	if err != nil || !ok {
		t.Fatalf("lookup: ok = %v, err = %v", ok, err)
	}
	// The sealed bytes have to come back verbatim, under the key that sealed
	// them, or the gateway cannot open them.
	if cred.Secret.Plaintext != nil {
		t.Errorf("a sealed key came back with a plaintext secret %q", *cred.Secret.Plaintext)
	}
	if cred.Secret.KeyID == nil || *cred.Secret.KeyID != "k1" || !bytes.Equal(cred.Secret.Sealed, sealedFor("SCASKEY1")) {
		t.Errorf("secret = %+v, want sealed under k1", cred.Secret)
	}
	if cred.TenantID != tenantID {
		t.Errorf("tenant = %d, want %d", cred.TenantID, tenantID)
	}
	if cred.LastUsedAt != nil {
		t.Errorf("a new key has last_used_at %v", cred.LastUsedAt)
	}

	if _, ok, err := d.LookupS3Credential(ctx, "SCASNOSUCHKEY"); err != nil || ok {
		t.Errorf("unknown key: ok = %v, err = %v", ok, err)
	}

	list, err := d.ListS3Credentials(ctx, tenantID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if list[0].CreatedBy != "owner@example.com" || list[0].Description != "ci" || list[0].ExpiresAt != nil {
		t.Errorf("listed %+v", list[0])
	}
}

// An expired key stops resolving, and is still listed so its owner can see it.
func TestExpiredS3CredentialDoesNotResolve(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for id, expires := range map[string]*time.Time{"SCASPAST": &past, "SCASFUTURE": &future} {
		if err := d.CreateS3Credential(ctx, NewS3Credential{
			AccessKeyID: id, TenantID: tenantID, KeyID: "k1", Sealed: sealedFor(id), ExpiresAt: expires,
			Scope: allPermissions,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, ok, err := d.LookupS3Credential(ctx, "SCASPAST"); err != nil || ok {
		t.Errorf("expired key: ok = %v, err = %v", ok, err)
	}
	if _, ok, err := d.LookupS3Credential(ctx, "SCASFUTURE"); err != nil || !ok {
		t.Errorf("unexpired key: ok = %v, err = %v", ok, err)
	}
	list, err := d.ListS3Credentials(ctx, tenantID)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v; want both keys", list, err)
	}
}

func TestTouchS3Credential(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	mustCredential(t, d, tenantID, "SCASKEY1")

	if err := d.TouchS3Credential(ctx, "SCASKEY1", time.Minute); err != nil {
		t.Fatal(err)
	}
	cred, _, _ := d.LookupS3Credential(ctx, "SCASKEY1")
	if cred.LastUsedAt == nil {
		t.Fatal("touch did not set last_used_at")
	}
	first := *cred.LastUsedAt

	// Within touchAfter the stored time stays put.
	if err := d.TouchS3Credential(ctx, "SCASKEY1", time.Hour); err != nil {
		t.Fatal(err)
	}
	cred, _, _ = d.LookupS3Credential(ctx, "SCASKEY1")
	if !cred.LastUsedAt.Equal(first) {
		t.Errorf("last_used_at moved from %v to %v inside touchAfter", first, *cred.LastUsedAt)
	}
}

// insertPlaintext writes a row the way a server before sealing did.
func insertPlaintext(t *testing.T, d *DB, tenantID int64, accessKeyID, secret string) {
	t.Helper()
	_, err := d.pool.Exec(t.Context(), `
		INSERT INTO tenant_credentials (access_key_id, secret_access_key, tenant_id)
		VALUES ($1, $2, $3)`, accessKeyID, secret, tenantID)
	if err != nil {
		t.Fatalf("insert plaintext %s: %v", accessKeyID, err)
	}
}

func TestResealS3Credential(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	insertPlaintext(t, d, tenantID, "SCASLEGACY", "legacy-secret")
	mustCredential(t, d, tenantID, "SCASOLD")
	if err := d.CreateS3Credential(ctx, NewS3Credential{
		AccessKeyID: "SCASCURRENT", TenantID: tenantID, KeyID: "k2", Sealed: sealedFor("SCASCURRENT"),
		Scope: allPermissions,
	}); err != nil {
		t.Fatal(err)
	}

	plain, sealed, err := d.CountS3CredentialSecrets(ctx)
	if err != nil || plain != 1 || sealed != 2 {
		t.Fatalf("counts = %d plaintext, %d sealed, %v; want 1, 2", plain, sealed, err)
	}

	todo, err := d.S3CredentialsToSeal(ctx, "k2")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range todo {
		ids = append(ids, c.AccessKeyID)
	}
	if !slices.Equal(ids, []string{"SCASLEGACY", "SCASOLD"}) {
		t.Fatalf("to seal = %v, want the plaintext and the k1 row", ids)
	}
	if todo[0].Secret.Plaintext == nil || *todo[0].Secret.Plaintext != "legacy-secret" {
		t.Errorf("legacy secret = %+v", todo[0].Secret)
	}

	for _, c := range todo {
		ok, err := d.ResealS3Credential(ctx, c.AccessKeyID, c.Secret, "k2", sealedFor(c.AccessKeyID+"@k2"))
		if err != nil || !ok {
			t.Fatalf("reseal %s: ok = %v, err = %v", c.AccessKeyID, ok, err)
		}
		// A second instance working from the same stale read changes nothing.
		ok, err = d.ResealS3Credential(ctx, c.AccessKeyID, c.Secret, "k2", []byte("racing instance"))
		if err != nil || ok {
			t.Errorf("stale reseal of %s: ok = %v, err = %v; want a no-op", c.AccessKeyID, ok, err)
		}
	}

	if todo, _ := d.S3CredentialsToSeal(ctx, "k2"); len(todo) != 0 {
		t.Errorf("still to seal after resealing: %v", todo)
	}
	legacy, _, _ := d.LookupS3Credential(ctx, "SCASLEGACY")
	if legacy.Secret.Plaintext != nil || !bytes.Equal(legacy.Secret.Sealed, sealedFor("SCASLEGACY@k2")) {
		t.Errorf("legacy row after reseal = %+v", legacy.Secret)
	}
	if plain, sealed, _ := d.CountS3CredentialSecrets(ctx); plain != 0 || sealed != 3 {
		t.Errorf("counts after reseal = %d plaintext, %d sealed; want 0, 3", plain, sealed)
	}
}

// A row holds its secret in exactly one form.
func TestS3CredentialSecretForm(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for name, stmt := range map[string]string{
		"both":               `INSERT INTO tenant_credentials (access_key_id, tenant_id, secret_access_key, secret_key_id, secret_sealed) VALUES ('SCASX', $1, 's', 'k1', 'x')`,
		"neither":            `INSERT INTO tenant_credentials (access_key_id, tenant_id) VALUES ('SCASX', $1)`,
		"sealed, no key":     `INSERT INTO tenant_credentials (access_key_id, tenant_id, secret_sealed) VALUES ('SCASX', $1, 'x')`,
		"key, no ciphertext": `INSERT INTO tenant_credentials (access_key_id, tenant_id, secret_access_key, secret_key_id) VALUES ('SCASX', $1, 's', 'k1')`,
	} {
		if _, err := d.pool.Exec(ctx, stmt, tenantID); err == nil {
			t.Errorf("%s: the row was accepted", name)
		}
	}
}

// A key's scope comes back as it was stored, from both the gateway's lookup
// and the listing; a key with no namespace list reaches every one.
func TestS3CredentialScopeRoundTrip(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	scoped := S3Scope{Permissions: []string{"read", "list"}, Namespaces: []string{"logs", "photos"}}
	if err := d.CreateS3Credential(ctx, NewS3Credential{
		AccessKeyID: "SCASSCOPED", TenantID: tenantID, KeyID: "k1", Sealed: sealedFor("SCASSCOPED"), Scope: scoped,
	}); err != nil {
		t.Fatal(err)
	}
	mustCredential(t, d, tenantID, "SCASFULL")

	cred, ok, err := d.LookupS3Credential(ctx, "SCASSCOPED")
	if err != nil || !ok {
		t.Fatalf("lookup: ok = %v, err = %v", ok, err)
	}
	if !slices.Equal(cred.Scope.Permissions, scoped.Permissions) || !slices.Equal(cred.Scope.Namespaces, scoped.Namespaces) {
		t.Errorf("looked up scope %+v, want %+v", cred.Scope, scoped)
	}
	full, _, _ := d.LookupS3Credential(ctx, "SCASFULL")
	if full.Scope.Namespaces != nil {
		t.Errorf("a key minted for every namespace came back limited to %q", full.Scope.Namespaces)
	}

	list, err := d.ListS3Credentials(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.AccessKeyID == "SCASSCOPED" &&
			(!slices.Equal(c.Permissions, scoped.Permissions) || !slices.Equal(c.Namespaces, scoped.Namespaces)) {
			t.Errorf("listed scope %q in %q, want %+v", c.Permissions, c.Namespaces, scoped)
		}
	}
}

// A key minted before scopes existed keeps the access it always had.
func TestLegacyS3CredentialHasFullScope(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	insertPlaintext(t, d, tenantID, "SCASLEGACY", "legacy-secret")

	cred, ok, err := d.LookupS3Credential(ctx, "SCASLEGACY")
	if err != nil || !ok {
		t.Fatalf("lookup: ok = %v, err = %v", ok, err)
	}
	if !slices.Equal(cred.Scope.Permissions, allPermissions.Permissions) || cred.Scope.Namespaces != nil {
		t.Errorf("legacy key scope = %+v, want every permission on every namespace", cred.Scope)
	}
}

// The table refuses a scope that grants nothing, names an unknown permission,
// or lists no namespaces, whatever the gateway lets through.
func TestS3CredentialScopeShape(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]S3Scope{
		"no permissions":     {Permissions: []string{}},
		"unknown permission": {Permissions: []string{"read", "admin"}},
		"empty namespaces":   {Permissions: []string{"read"}, Namespaces: []string{}},
	} {
		err := d.CreateS3Credential(ctx, NewS3Credential{
			AccessKeyID: "SCASX", TenantID: tenantID, KeyID: "k1", Sealed: sealedFor("SCASX"), Scope: scope,
		})
		if err == nil {
			t.Errorf("%s: the key was stored", name)
		}
	}
}

func TestListS3CredentialsIsScopedToItsTenant(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	a, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTenant(ctx, "team-b", mustUser(t, d, "b@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tenant int64
		id     string
	}{{a, "SCASA1"}, {a, "SCASA2"}, {b, "SCASB1"}} {
		mustCredential(t, d, c.tenant, c.id)
	}

	listA, err := d.ListS3Credentials(ctx, a)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listA) != 2 {
		t.Fatalf("team A has %d credentials, want 2", len(listA))
	}
	for _, c := range listA {
		if c.AccessKeyID == "SCASB1" {
			t.Error("team A's listing included team B's key")
		}
	}
}

func TestDeleteS3CredentialRequiresTheOwningTenant(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	a, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTenant(ctx, "team-b", mustUser(t, d, "b@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	mustCredential(t, d, a, "SCASA1")

	// Naming team A's key under team B must not revoke it.
	if err := d.DeleteS3Credential(ctx, b, "SCASA1"); !errors.Is(err, apperr.ErrNoSuchCredential) {
		t.Fatalf("cross-tenant delete err = %v, want ErrNoSuchCredential", err)
	}
	if _, ok, _ := d.LookupS3Credential(ctx, "SCASA1"); !ok {
		t.Fatal("the key was revoked by the wrong tenant")
	}

	// Its own tenant can.
	if err := d.DeleteS3Credential(ctx, a, "SCASA1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := d.LookupS3Credential(ctx, "SCASA1"); ok {
		t.Fatal("the key survived its own tenant's revocation")
	}
}

// Deleting a tenant must not leave its keys behind still resolving to a
// tenant id that no longer exists.
func TestDeletingATenantCascadesToItsCredentials(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	mustCredential(t, d, tenantID, "SCASA1")
	if err := d.DeleteTenant(ctx, tenantID); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if _, ok, err := d.LookupS3Credential(ctx, "SCASA1"); err != nil || ok {
		t.Fatalf("credential outlived its tenant: ok = %v, err = %v", ok, err)
	}
}
