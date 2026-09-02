package db

import (
	"errors"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
)

func TestCreateTenantSeedsAnOwner(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id, err := d.CreateTenant(ctx, "acme", "boss@example.com")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == 0 {
		t.Error("expected a generated tenant id")
	}

	// A tenant must never exist without an owner.
	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Email != "boss@example.com" || members[0].Role != "owner" {
		t.Fatalf("members = %+v, want a single owner", members)
	}

	if _, err := d.CreateTenant(ctx, "acme", "other@example.com"); !errors.Is(err, apperr.ErrTenantAlreadyExists) {
		t.Errorf("duplicate create = %v, want ErrTenantAlreadyExists", err)
	}
}

func TestTenantLookups(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id, err := d.CreateTenant(ctx, "acme", "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}

	got, err := d.TenantIDByName(ctx, "acme")
	if err != nil || got != id {
		t.Errorf("TenantIDByName = %d, %v; want %d", got, err, id)
	}
	if _, err := d.TenantIDByName(ctx, "nope"); !errors.Is(err, apperr.ErrNoSuchTenant) {
		t.Errorf("missing tenant = %v, want ErrNoSuchTenant", err)
	}

	role, ok, err := d.TenantRole(ctx, id, "boss@example.com")
	if err != nil || !ok || role != "owner" {
		t.Errorf("TenantRole = %q, %v, %v; want owner", role, ok, err)
	}
	_, ok, err = d.TenantRole(ctx, id, "stranger@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a non-member must not have a role")
	}

	memberships, err := d.ListTenantsForEmail(ctx, "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(memberships) != 1 || memberships[0].Name != "acme" || memberships[0].Role != "owner" {
		t.Errorf("memberships = %+v", memberships)
	}

	ids, err := d.TenantIDsForEmail(ctx, "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != id {
		t.Errorf("TenantIDsForEmail = %v, want [%d]", ids, id)
	}

	// Callers feed this straight into `= ANY($1)`, so it must never be nil.
	empty, err := d.TenantIDsForEmail(ctx, "nobody@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if empty == nil {
		t.Error("TenantIDsForEmail must return an empty slice, not nil")
	}
}

func TestAddMemberUpsertsRole(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id, err := d.CreateTenant(ctx, "acme", "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := d.AddMember(ctx, id, "dev@example.com", "member"); err != nil {
		t.Fatal(err)
	}
	// Re-inviting an existing member changes their role rather than failing.
	if err := d.AddMember(ctx, id, "dev@example.com", "owner"); err != nil {
		t.Fatal(err)
	}

	role, ok, err := d.TenantRole(ctx, id, "dev@example.com")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Errorf("role = %q, want owner after re-invite", role)
	}

	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %+v, want 2", members)
	}
	// Email order.
	if members[0].Email != "boss@example.com" || members[1].Email != "dev@example.com" {
		t.Errorf("members are not email-ordered: %+v", members)
	}
}

// A tenant stripped of its last owner would be unmanageable, so that removal
// has to be refused.
func TestRemoveMemberProtectsTheLastOwner(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id, err := d.CreateTenant(ctx, "acme", "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}

	err = d.RemoveMember(ctx, id, "boss@example.com")
	if err == nil {
		t.Fatal("removing the last owner should be refused")
	}
	if e := apperr.From(err); e.Status() != 400 {
		t.Errorf("status = %d, want 400", e.Status())
	}

	// With a second owner, removing the first is fine.
	if err := d.AddMember(ctx, id, "second@example.com", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, "boss@example.com"); err != nil {
		t.Errorf("remove with a co-owner present: %v", err)
	}

	// Removing a plain member is unrestricted, and removing a non-member is a
	// silent success so the call is idempotent.
	if err := d.AddMember(ctx, id, "dev@example.com", "member"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, "dev@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, "dev@example.com"); err != nil {
		t.Errorf("removing a non-member should be idempotent, got %v", err)
	}
}

func TestDeleteTenantRefusesWhenItOwnsNamespaces(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id, err := d.CreateTenant(ctx, "acme", "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mustNamespace(t, d, "owned", &id)

	if err := d.DeleteTenant(ctx, id); !errors.Is(err, apperr.ErrTenantNotEmpty) {
		t.Fatalf("delete = %v, want ErrTenantNotEmpty", err)
	}

	if err := d.DeleteNamespace(ctx, "owned"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTenant(ctx, id); err != nil {
		t.Fatalf("delete after releasing the namespace: %v", err)
	}
	// Membership cascades.
	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Errorf("membership should have cascaded, got %+v", members)
	}
}
