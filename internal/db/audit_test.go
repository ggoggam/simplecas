package db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// actingAs attributes the changes made under the returned context to userID.
func actingAs(ctx context.Context, userID int64, email string) context.Context {
	return WithActor(ctx, Actor{UserID: &userID, Email: email, RequestID: "req-" + email})
}

// auditTrail returns tenantID's events, oldest first, as "action target" lines.
func auditTrail(t *testing.T, d *DB, tenantID int64) []string {
	t.Helper()
	events, err := d.ListAuditEvents(t.Context(), tenantID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(events))
	for i, ev := range events {
		out[len(events)-1-i] = ev.Action + " " + ev.Target
	}
	return out
}

func equalTrail(got, want []string) bool {
	return strings.Join(got, "\n") == strings.Join(want, "\n")
}

func TestMembershipChangesAreAudited(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	dev := mustUser(t, d, "dev@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Invite(ctx, id, "dev@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptInvitation(actingAs(t.Context(), dev, "dev@example.com"), "acme", "dev@example.com", dev); err != nil {
		t.Fatal(err)
	}
	if err := d.SetMemberRole(ctx, id, dev, "owner"); err != nil {
		t.Fatal(err)
	}
	// Setting the role someone already has changes nothing, and records
	// nothing.
	if err := d.SetMemberRole(ctx, id, dev, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := d.Invite(ctx, id, "later@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeInvitation(ctx, id, "later@example.com"); err != nil {
		t.Fatal(err)
	}
	// Nor does withdrawing an invitation that is no longer there.
	if err := d.RevokeInvitation(ctx, id, "later@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := d.Invite(ctx, id, "nope@example.com", "member", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.DeclineInvitation(t.Context(), "acme", "nope@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, dev); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMember(ctx, id, dev); err != nil {
		t.Fatal(err)
	}

	devTarget := strconv.FormatInt(dev, 10)
	want := []string{
		"tenant.create acme",
		"invitation.create dev@example.com",
		"invitation.accept dev@example.com",
		"member.role " + devTarget,
		"invitation.create later@example.com",
		"invitation.revoke later@example.com",
		"invitation.create nope@example.com",
		"invitation.decline nope@example.com",
		"member.remove " + devTarget,
	}
	if got := auditTrail(t, d, id); !equalTrail(got, want) {
		t.Fatalf("trail =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	events, err := d.ListAuditEvents(t.Context(), id, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	byAction := map[string]AuditEvent{}
	for _, ev := range events {
		byAction[ev.Action] = ev
	}

	role := byAction[EventMemberRole]
	if role.ActorUserID == nil || *role.ActorUserID != boss || role.ActorEmail != "boss@example.com" ||
		role.RequestID != "req-boss@example.com" {
		t.Errorf("member.role actor = %v %q %q, want boss", role.ActorUserID, role.ActorEmail, role.RequestID)
	}
	if role.Details["from"] != "member" || role.Details["to"] != "owner" || role.Details["email"] != "dev@example.com" {
		t.Errorf("member.role details = %v", role.Details)
	}

	accept := byAction[EventInvitationAccept]
	if accept.ActorUserID == nil || *accept.ActorUserID != dev {
		t.Errorf("invitation.accept actor = %v, want the invitee", accept.ActorUserID)
	}
	if accept.Details["joined"] != true || accept.Details["role"] != "member" {
		t.Errorf("invitation.accept details = %v", accept.Details)
	}

	// No actor on the context is a change through an open plane.
	decline := byAction[EventInvitationDecline]
	if decline.ActorUserID != nil || decline.ActorEmail != "" || decline.ActorAccessKeyID != "" {
		t.Errorf("invitation.decline actor = %+v, want none", decline)
	}

	if remove := byAction[EventMemberRemove]; remove.Details["role"] != "owner" {
		t.Errorf("member.remove details = %v", remove.Details)
	}
}

func TestRefusedChangesAreNotAudited(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetMemberRole(ctx, id, boss, "member"); err == nil {
		t.Fatal("demoting the last owner succeeded")
	}
	if err := d.RemoveMember(ctx, id, boss); err == nil {
		t.Fatal("removing the last owner succeeded")
	}
	mustNamespace(t, d, "photos", &id)
	putObject(t, d, mustNamespace(t, d, "full", &id), "k", hashOf("x"), 1)
	if err := d.DeleteNamespace(ctx, "full"); !errors.Is(err, apperr.ErrNamespaceNotEmpty) {
		t.Fatalf("delete occupied = %v", err)
	}
	if err := d.DeleteTenant(ctx, id); !errors.Is(err, apperr.ErrTenantNotEmpty) {
		t.Fatalf("delete occupied tenant = %v", err)
	}
	if err := d.DeleteS3Credential(ctx, id, "SCASMISSING"); !errors.Is(err, apperr.ErrNoSuchCredential) {
		t.Fatalf("revoke missing = %v", err)
	}

	want := []string{"tenant.create acme", "namespace.create photos", "namespace.create full"}
	if got := auditTrail(t, d, id); !equalTrail(got, want) {
		t.Fatalf("trail = %q, want %q", got, want)
	}
}

func TestCredentialChangesAreAudited(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	err = d.CreateS3Credential(ctx, NewS3Credential{
		AccessKeyID: "SCASKEY1", TenantID: id, KeyID: "k1", Sealed: []byte("sealed"),
		Description: "ci", CreatedBy: &boss,
		Scope: S3Scope{Permissions: []string{"write"}, Namespaces: []string{"photos"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteS3Credential(ctx, id, "SCASKEY1"); err != nil {
		t.Fatal(err)
	}

	want := []string{"tenant.create acme", "credential.create SCASKEY1", "credential.revoke SCASKEY1"}
	if got := auditTrail(t, d, id); !equalTrail(got, want) {
		t.Fatalf("trail = %q, want %q", got, want)
	}
	events, err := d.ListAuditEvents(t.Context(), id, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	// The secret, sealed or not, is never part of the record.
	created := events[1].Details
	if created["description"] != "ci" || created["expires_at"] != nil {
		t.Errorf("credential.create details = %v", created)
	}
	if perms, _ := created["permissions"].([]any); len(perms) != 1 || perms[0] != "write" {
		t.Errorf("permissions = %v", created["permissions"])
	}
	for k := range created {
		if strings.Contains(k, "secret") || strings.Contains(k, "sealed") {
			t.Errorf("credential.create details carry %q", k)
		}
	}
}

func TestATeamsHistoryOutlivesIt(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")

	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	mustNamespace(t, d, "photos", &id)
	if err := d.DeleteNamespace(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTenant(ctx, id); err != nil {
		t.Fatal(err)
	}

	want := []string{"tenant.create acme", "namespace.create photos", "namespace.delete photos", "tenant.delete acme"}
	if got := auditTrail(t, d, id); !equalTrail(got, want) {
		t.Fatalf("trail = %q, want %q", got, want)
	}

	// A team created later under the same name is a new tenant id, and does
	// not inherit the old one's history.
	again, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	if got := auditTrail(t, d, again); !equalTrail(got, []string{"tenant.create acme"}) {
		t.Errorf("new team's trail = %q", got)
	}
}

func TestUnownedNamespaceChangesAreAuditedWithoutATenant(t *testing.T) {
	d := testDB(t)
	ctx := WithActor(t.Context(), Actor{AccessKeyID: "admin"})
	if err := d.CreateNamespace(ctx, "loose", nil); err != nil {
		t.Fatal(err)
	}
	var tenant *int64
	var key string
	err := d.pool.QueryRow(t.Context(),
		"SELECT tenant_id, actor_access_key_id FROM audit_events WHERE action = $1 AND target = 'loose'",
		EventNamespaceCreate).Scan(&tenant, &key)
	if err != nil {
		t.Fatal(err)
	}
	if tenant != nil || key != "admin" {
		t.Errorf("tenant = %v, key = %q", tenant, key)
	}
}

func TestListAuditEventsPages(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateTenant(ctx, "other", boss)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		mustNamespace(t, d, "ns-"+strconv.Itoa(i), &id)
	}
	mustNamespace(t, d, "theirs", &other)

	first, err := d.ListAuditEvents(t.Context(), id, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first[0].Target != "ns-3" || first[2].Target != "ns-1" {
		t.Fatalf("first page = %+v", first)
	}
	rest, err := d.ListAuditEvents(t.Context(), id, first[2].ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 2 || rest[0].Target != "ns-0" || rest[1].Action != EventTenantCreate {
		t.Fatalf("second page = %+v", rest)
	}
}

// Each committed event is one log line whose keys are fixed, under either
// handler; an event that rolled back is never logged.
func TestAuditEventsAreLoggedParseably(t *testing.T) {
	d := testDB(t)
	boss := mustUser(t, d, "boss@example.com")
	ctx := actingAs(t.Context(), boss, "boss@example.com")
	id, err := d.CreateTenant(ctx, "acme", boss)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	d.SetAuditLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := d.Invite(ctx, id, "dev@example.com", "owner", boss, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTenant(ctx, "acme", boss); !errors.Is(err, apperr.ErrTenantAlreadyExists) {
		t.Fatalf("duplicate = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("logged %d lines, want 1:\n%s", len(lines), buf.String())
	}
	var line struct {
		Msg   string `json:"msg"`
		Audit struct {
			ID          int64          `json:"id"`
			Action      string         `json:"action"`
			TenantID    int64          `json:"tenant_id"`
			ActorUserID int64          `json:"actor_user_id"`
			ActorEmail  string         `json:"actor_email"`
			RequestID   string         `json:"request_id"`
			Target      string         `json:"target"`
			Details     map[string]any `json:"details"`
		} `json:"audit"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, lines[0])
	}
	a := line.Audit
	if line.Msg != "audit" || a.Action != EventInvitationCreate || a.TenantID != id || a.ActorUserID != boss ||
		a.ActorEmail != "boss@example.com" || a.RequestID != "req-boss@example.com" ||
		a.Target != "dev@example.com" || a.Details["role"] != "owner" || a.ID == 0 {
		t.Errorf("logged %+v", line)
	}

	// The text handler gives the same keys as key=value pairs, with details
	// as a quoted JSON object.
	buf.Reset()
	d.SetAuditLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	if err := d.RevokeInvitation(ctx, id, "dev@example.com"); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{
		"msg=audit", "audit.action=invitation.revoke", "audit.tenant_id=" + strconv.FormatInt(id, 10),
		"audit.actor_email=boss@example.com", "audit.target=dev@example.com",
		`audit.details="{\"role\":\"owner\"}"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text line lacks %s:\n%s", want, text)
		}
	}
}
