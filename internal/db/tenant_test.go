package db

import (
	"errors"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// mustMember makes userID a member of tenant name with role, the only way a
// membership comes to exist: an invitation to their address, accepted.
func mustMember(t *testing.T, d *DB, tenantID int64, tenant string, inviter, userID int64, email, role string) {
	t.Helper()
	ctx := t.Context()
	if err := d.Invite(ctx, tenantID, email, role, inviter, time.Hour); err != nil {
		t.Fatalf("invite %s: %v", email, err)
	}
	if err := d.AcceptInvitation(ctx, tenant, email, userID); err != nil {
		t.Fatalf("accept %s: %v", email, err)
	}
}

func TestCreateTenantSeedsAnOwner(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
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
	if len(members) != 1 || members[0].UserID != boss || members[0].Role != "owner" ||
		members[0].Email != "boss@example.com" {
		t.Fatalf("members = %+v, want boss as the single owner", members)
	}

	if _, err := d.CreateTenant(ctx, "acme", mustUser(t, d, "other@example.com")); !errors.Is(err, apperr.ErrTenantAlreadyExists) {
		t.Errorf("duplicate create = %v, want ErrTenantAlreadyExists", err)
	}
}

func TestTenantLookups(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	stranger := mustUser(t, d, "stranger@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
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

	role, ok, err := d.TenantRole(ctx, id, boss)
	if err != nil || !ok || role != "owner" {
		t.Errorf("TenantRole = %q, %v, %v; want owner", role, ok, err)
	}
	_, ok, err = d.TenantRole(ctx, id, stranger)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a non-member must not have a role")
	}

	memberships, err := d.ListTenantsForUser(ctx, boss)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberships) != 1 || memberships[0].Name != "acme" || memberships[0].Role != "owner" {
		t.Errorf("memberships = %+v", memberships)
	}

	ids, err := d.TenantIDsForUser(ctx, boss)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != id {
		t.Errorf("TenantIDsForUser = %v, want [%d]", ids, id)
	}

	// Callers feed this straight into `= ANY($1)`, so it must never be nil.
	empty, err := d.TenantIDsForUser(ctx, stranger)
	if err != nil {
		t.Fatal(err)
	}
	if empty == nil {
		t.Error("TenantIDsForUser must return an empty slice, not nil")
	}
}

// Membership follows the account, not the address: a second account that
// presents the same verified email, from another provider, gets nothing.
func TestMembershipIsKeyedOnTheAccountNotTheEmail(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	boss, err := d.ResolveUser(ctx, "https://idp-a.test", "boss", "boss@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := d.ResolveUser(ctx, "https://idp-b.test", "boss", "boss@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if impostor.ID == boss.ID {
		t.Fatal("the same subject at two issuers must be two users")
	}

	id, err := d.CreateTenant(ctx, "acme", boss.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := d.TenantRole(ctx, id, impostor.ID); err != nil || ok {
		t.Errorf("an account sharing the owner's email has role ok=%v, err=%v; want none", ok, err)
	}
	mustNamespace(t, d, "owned", &id)
	if _, err := d.GetNamespaceForMember(ctx, "owned", impostor.ID); !errors.Is(err, apperr.ErrNoSuchNamespace) {
		t.Errorf("namespace via a shared email = %v, want ErrNoSuchNamespace", err)
	}
}

func TestListMembersOrder(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	mustMember(t, d, id, "acme", boss, mustUser(t, d, "dev@example.com"), "dev@example.com", "member")
	mustMember(t, d, id, "acme", boss, mustUser(t, d, "amy@example.com"), "amy@example.com", "member")

	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var emails []string
	for _, m := range members {
		emails = append(emails, m.Email)
	}
	want := []string{"amy@example.com", "boss@example.com", "dev@example.com"}
	if len(emails) != len(want) {
		t.Fatalf("members = %v, want %v", emails, want)
	}
	for i := range want {
		if emails[i] != want[i] {
			t.Fatalf("members = %v, want email order %v", emails, want)
		}
	}
}

func TestSetMemberRole(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	dev := mustUser(t, d, "dev@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	mustMember(t, d, id, "acme", boss, dev, "dev@example.com", "member")

	// Promote, and setting the role a member already has is a no-op.
	for range 2 {
		if err := d.SetMemberRole(ctx, id, dev, "owner"); err != nil {
			t.Fatalf("promote: %v", err)
		}
	}
	if role, _, _ := d.TenantRole(ctx, id, dev); role != "owner" {
		t.Errorf("role after promotion = %q, want owner", role)
	}

	// With two owners either may be demoted, but not both.
	if err := d.SetMemberRole(ctx, id, boss, "member"); err != nil {
		t.Fatalf("demote with a co-owner present: %v", err)
	}
	err = d.SetMemberRole(ctx, id, dev, "member")
	if e := apperr.From(err); err == nil || e.Status() != 400 {
		t.Fatalf("demoting the last owner = %v, want a 400 refusal", err)
	}
	if role, _, _ := d.TenantRole(ctx, id, dev); role != "owner" {
		t.Errorf("the refused demotion changed the role to %q", role)
	}

	if err := d.SetMemberRole(ctx, id, mustUser(t, d, "stranger@example.com"), "owner"); !errors.Is(err, apperr.ErrNoSuchMember) {
		t.Errorf("re-roling a non-member = %v, want ErrNoSuchMember", err)
	}
}

// A tenant stripped of its last owner would be unmanageable, so that removal
// has to be refused.
func TestRemoveMemberProtectsTheLastOwner(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	second := mustUser(t, d, "second@example.com")
	dev := mustUser(t, d, "dev@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	err = d.RemoveMember(ctx, id, boss)
	if err == nil {
		t.Fatal("removing the last owner should be refused")
	}
	if e := apperr.From(err); e.Status() != 400 {
		t.Errorf("status = %d, want 400", e.Status())
	}

	// With a second owner, removing the first is fine.
	mustMember(t, d, id, "acme", boss, second, "second@example.com", "owner")
	if err := d.RemoveMember(ctx, id, boss); err != nil {
		t.Errorf("remove with a co-owner present: %v", err)
	}

	// Removing a plain member is unrestricted, and removing a non-member is a
	// silent success so the call is idempotent.
	mustMember(t, d, id, "acme", second, dev, "dev@example.com", "member")
	if err := d.RemoveMember(ctx, id, dev); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, dev); err != nil {
		t.Errorf("removing a non-member should be idempotent, got %v", err)
	}
}

// Two owners removing each other at once must not both succeed. Each removal
// counts the other owner before deleting its target; under READ COMMITTED, with
// only the target row locked, each would see the other's row (deleted, but not
// yet committed) and go ahead. The tenant lock makes the second wait and count
// what the first left.
//
// The first removal is played out by hand inside a transaction, stopped just
// short of committing, so the interleaving is the bad one every time.
func TestConcurrentOwnerRemovalsKeepAnOwner(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	a := mustUser(t, d, "a@example.com")
	b := mustUser(t, d, "b@example.com")
	id, err := d.CreateTenant(ctx, "acme", a)
	if err != nil {
		t.Fatal(err)
	}
	mustMember(t, d, id, "acme", a, b, "b@example.com", "owner")

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockTenant(ctx, tx, id); err != nil {
		t.Fatal(err)
	}
	if n, err := otherOwners(ctx, tx, id, a); err != nil || n != 1 {
		t.Fatalf("otherOwners = %d, %v; want 1", n, err)
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM tenant_members WHERE tenant_id = $1 AND user_id = $2", id, a); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- d.RemoveMember(ctx, id, b) }()
	select {
	case err := <-done:
		t.Fatalf("the second removal finished (%v) while the first held the tenant", err)
	case <-time.After(200 * time.Millisecond):
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	if e := apperr.From(err); err == nil || e.Status() != 400 {
		t.Fatalf("second removal = %v, want the last-owner refusal", err)
	}

	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].UserID != b || members[0].Role != "owner" {
		t.Errorf("members = %+v, want b left as the owner", members)
	}
}

func TestDeleteTenantRefusesWhenItOwnsNamespaces(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Invite(ctx, id, "dev@example.com", "member", boss, time.Hour); err != nil {
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
	// Membership and invitations cascade.
	members, err := d.ListMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Errorf("membership should have cascaded, got %+v", members)
	}
	pending, err := d.PendingInvitations(ctx, "dev@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("invitations should have cascaded, got %+v", pending)
	}
}
