package db

import (
	"errors"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
)

func TestS3CredentialRoundTrip(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantID, err := d.CreateTenant(ctx, "team-a", "owner@example.com")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := d.CreateS3Credential(ctx, tenantID, "SCASKEY1", "secret-1", "ci"); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	cred, ok, err := d.LookupS3Credential(ctx, "SCASKEY1")
	if err != nil || !ok {
		t.Fatalf("lookup: ok = %v, err = %v", ok, err)
	}
	// The secret has to come back verbatim: SigV4 re-derives the signing key
	// from it, so any transformation on the way in or out breaks verification.
	if cred.SecretAccessKey != "secret-1" {
		t.Errorf("secret = %q, want secret-1", cred.SecretAccessKey)
	}
	if cred.TenantID != tenantID {
		t.Errorf("tenant = %d, want %d", cred.TenantID, tenantID)
	}

	if _, ok, err := d.LookupS3Credential(ctx, "SCASNOSUCHKEY"); err != nil || ok {
		t.Errorf("unknown key: ok = %v, err = %v", ok, err)
	}
}

func TestListS3CredentialsIsScopedToItsTenant(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	a, err := d.CreateTenant(ctx, "team-a", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTenant(ctx, "team-b", "b@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tenant int64
		id     string
	}{{a, "SCASA1"}, {a, "SCASA2"}, {b, "SCASB1"}} {
		if err := d.CreateS3Credential(ctx, c.tenant, c.id, "s", ""); err != nil {
			t.Fatal(err)
		}
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

	a, err := d.CreateTenant(ctx, "team-a", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTenant(ctx, "team-b", "b@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateS3Credential(ctx, a, "SCASA1", "s", ""); err != nil {
		t.Fatal(err)
	}

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

	tenantID, err := d.CreateTenant(ctx, "team-a", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateS3Credential(ctx, tenantID, "SCASA1", "s", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTenant(ctx, tenantID); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if _, ok, err := d.LookupS3Credential(ctx, "SCASA1"); err != nil || ok {
		t.Fatalf("credential outlived its tenant: ok = %v, err = %v", ok, err)
	}
}
