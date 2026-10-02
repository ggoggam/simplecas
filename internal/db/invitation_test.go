package db

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/testdb"
)

func TestInvitationIsAcceptedOnce(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	dev := mustUser(t, d, "dev@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Invite(ctx, id, "dev@example.com", "owner", boss, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Pending grants nothing.
	if _, ok, _ := d.TenantRole(ctx, id, dev); ok {
		t.Fatal("an unaccepted invitation must not grant membership")
	}

	// Both sides see it, with who sent it and when it lapses.
	for name, list := range map[string]func() ([]Invitation, error){
		"team":    func() ([]Invitation, error) { return d.ListInvitations(ctx, id) },
		"invitee": func() ([]Invitation, error) { return d.PendingInvitations(ctx, "dev@example.com") },
	} {
		got, err := list()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("%s sees %+v, want one invitation", name, got)
		}
		inv := got[0]
		if inv.Tenant != "acme" || inv.Email != "dev@example.com" || inv.Role != "owner" ||
			inv.InvitedBy != "boss@example.com" || inv.ExpiresAt == nil {
			t.Errorf("%s sees %+v", name, inv)
		}
		if until := time.Until(*inv.ExpiresAt); until < 50*time.Minute || until > time.Hour+time.Minute {
			t.Errorf("%s: expires in %v, want about an hour", name, until)
		}
	}

	if err := d.AcceptInvitation(ctx, "acme", "dev@example.com", dev); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if role, ok, _ := d.TenantRole(ctx, id, dev); !ok || role != "owner" {
		t.Errorf("after accepting, role = %q (member %v), want owner", role, ok)
	}

	// Consumed: a second account presenting the same address cannot reuse it.
	other := mustUser(t, d, "dev@example.com-elsewhere")
	if err := d.AcceptInvitation(ctx, "acme", "dev@example.com", other); !errors.Is(err, apperr.ErrNoSuchInvitation) {
		t.Errorf("second accept = %v, want ErrNoSuchInvitation", err)
	}
	if pending, _ := d.ListInvitations(ctx, id); len(pending) != 0 {
		t.Errorf("accepted invitation still listed: %+v", pending)
	}
}

// An invitation adds people; it is not a back door around SetMemberRole's
// last-owner check, so it never changes the role of someone already there.
func TestAcceptingAsAnExistingMemberKeepsTheirRole(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Invite(ctx, id, "boss@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptInvitation(ctx, "acme", "boss@example.com", boss); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if role, _, _ := d.TenantRole(ctx, id, boss); role != "owner" {
		t.Errorf("role = %q, want the owner role kept", role)
	}
	if pending, _ := d.ListInvitations(ctx, id); len(pending) != 0 {
		t.Errorf("the invitation should still be consumed: %+v", pending)
	}
}

func TestReinvitingReplacesTheInvitation(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Invite(ctx, id, "dev@example.com", "member", boss, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := d.Invite(ctx, id, "dev@example.com", "owner", boss, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := d.ListInvitations(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Role != "owner" || time.Until(*got[0].ExpiresAt) < 47*time.Hour {
		t.Errorf("invitations = %+v, want one owner invitation good for 48h", got)
	}
}

func TestExpiredInvitationsAreGone(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	boss := mustUser(t, d, "boss@example.com")
	dev := mustUser(t, d, "dev@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Invite(ctx, id, "dev@example.com", "member", boss, -time.Second); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.ListInvitations(ctx, id); len(got) != 0 {
		t.Errorf("team lists an expired invitation: %+v", got)
	}
	if got, _ := d.PendingInvitations(ctx, "dev@example.com"); len(got) != 0 {
		t.Errorf("invitee sees an expired invitation: %+v", got)
	}
	if err := d.AcceptInvitation(ctx, "acme", "dev@example.com", dev); !errors.Is(err, apperr.ErrNoSuchInvitation) {
		t.Errorf("accepting an expired invitation = %v, want ErrNoSuchInvitation", err)
	}
	if err := d.DeclineInvitation(ctx, "acme", "dev@example.com"); !errors.Is(err, apperr.ErrNoSuchInvitation) {
		t.Errorf("declining an expired invitation = %v, want ErrNoSuchInvitation", err)
	}

	// The next invitation to the team purges it.
	if err := d.Invite(ctx, id, "other@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := d.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM tenant_invitations WHERE email = 'dev@example.com'").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("expired invitation still stored after the next invite")
	}
}

func TestDeclineAndRevoke(t *testing.T) {
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
	if err := d.DeclineInvitation(ctx, "acme", "dev@example.com"); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if err := d.DeclineInvitation(ctx, "acme", "dev@example.com"); !errors.Is(err, apperr.ErrNoSuchInvitation) {
		t.Errorf("second decline = %v, want ErrNoSuchInvitation", err)
	}

	if err := d.Invite(ctx, id, "dev@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if err := d.RevokeInvitation(ctx, id, "dev@example.com"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
	}
	if got, _ := d.PendingInvitations(ctx, "dev@example.com"); len(got) != 0 {
		t.Errorf("revoked invitation still pending: %+v", got)
	}
}

// Migration 0004 cannot attach the old email-keyed memberships to users that do
// not exist yet, so it turns each into a pending invitation that keeps its role
// and never lapses. Nothing is granted until the address's holder signs in and
// accepts.
func TestMigrationCarriesMembershipsOverAsInvitations(t *testing.T) {
	ctx := t.Context()
	url := testdb.URL(t)

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
		    version    BIGINT PRIMARY KEY,
		    name       TEXT NOT NULL,
		    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version >= 4 {
			break
		}
		if _, err := pool.Exec(ctx, m.sql); err != nil {
			t.Fatalf("apply %d: %v", m.version, err)
		}
		if _, err := pool.Exec(ctx,
			"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (name) VALUES ('acme');
		INSERT INTO tenant_members (tenant_id, email, role)
		SELECT id, 'boss@example.com', 'owner' FROM tenants WHERE name = 'acme';
		INSERT INTO tenant_members (tenant_id, email, role)
		SELECT id, 'dev@example.com', 'member' FROM tenants WHERE name = 'acme';`); err != nil {
		t.Fatal(err)
	}

	d, err := Connect(ctx, url, 4)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(d.Close)

	id, err := d.TenantIDByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if members, _ := d.ListMembers(ctx, id); len(members) != 0 {
		t.Errorf("members = %+v, want none until someone accepts", members)
	}
	got, err := d.ListInvitations(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, inv := range got {
		if inv.ExpiresAt != nil {
			t.Errorf("carried-over invitation for %s expires at %v, want never", inv.Email, inv.ExpiresAt)
		}
		roles[inv.Email] = inv.Role
	}
	if len(roles) != 2 || roles["boss@example.com"] != "owner" || roles["dev@example.com"] != "member" {
		t.Errorf("invitations = %+v, want boss as owner and dev as member", got)
	}

	boss := mustUser(t, d, "boss@example.com")
	if err := d.AcceptInvitation(ctx, "acme", "boss@example.com", boss); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if role, _, _ := d.TenantRole(ctx, id, boss); role != "owner" {
		t.Errorf("role after accepting = %q, want owner", role)
	}
}
