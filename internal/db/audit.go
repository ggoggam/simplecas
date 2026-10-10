package db

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// The audit log records changes to who can reach a team's data: membership,
// invitations, S3 keys, namespaces and the team itself. The methods that make
// those changes record them in their own transaction (see audited), so an event
// exists exactly when its change committed, and a no-op (re-removing a removed
// member, setting the role someone already has) records nothing.
//
// Each committed event is also written to the server log as one structured
// line, for shipping to a log pipeline. Object reads and writes are not
// recorded: they are data, not access, and would dwarf everything else.

// Audited actions. The names are a contract with anything that parses the log
// or the API's listing: add new ones rather than renaming these.
const (
	EventTenantCreate      = "tenant.create"
	EventTenantDelete      = "tenant.delete"
	EventMemberRole        = "member.role"
	EventMemberRemove      = "member.remove"
	EventInvitationCreate  = "invitation.create"
	EventInvitationRevoke  = "invitation.revoke"
	EventInvitationAccept  = "invitation.accept"
	EventInvitationDecline = "invitation.decline"
	EventCredentialCreate  = "credential.create"
	EventCredentialRevoke  = "credential.revoke"
	EventNamespaceCreate   = "namespace.create"
	EventNamespaceDelete   = "namespace.delete"
)

// Actor is who a change is attributed to. At most one of UserID and
// AccessKeyID is set; neither is a change through an open plane (/api with
// sign-in off, or the S3 gateway with auth disabled).
type Actor struct {
	UserID *int64
	// Email is the user's address when they acted, for display.
	Email string
	// AccessKeyID is the S3 key that signed the request: a team key, or the
	// admin credential's id.
	AccessKeyID string
	// RequestID is the router's per-request id.
	RequestID string
}

type actorKey struct{}

// WithActor attributes the changes made under ctx to a. The API and the S3
// gateway set it once per request, after authenticating it.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// actorFrom returns the actor set on ctx, or the zero (anonymous) actor.
func actorFrom(ctx context.Context) Actor {
	a, _ := ctx.Value(actorKey{}).(Actor)
	return a
}

// AuditEvent is one recorded change. Its fields are the audit_events columns;
// the server log and the admin API both name them in snake_case, the same way.
type AuditEvent struct {
	ID       int64
	At       time.Time
	TenantID *int64
	Action   string
	// ActorUserID is nil for a change made with an S3 key or through an open
	// plane, and for one whose user has since been deleted.
	ActorUserID      *int64
	ActorEmail       string
	ActorAccessKeyID string
	RequestID        string
	Target           string
	Details          map[string]any
}

// SetAuditLogger sends each committed audit event to l as well as to the
// table. Call it before serving; with none set, events are only stored.
func (d *DB) SetAuditLogger(l *slog.Logger) {
	d.auditLog = l
}

// recordFunc records one event inside the transaction audited opened. tenantID
// is nil for an unowned namespace; details may be nil.
type recordFunc func(tenantID *int64, action, target string, details map[string]any) error

// audited runs fn in a transaction whose changes fn records through record,
// attributed to ctx's actor. The events reach the server log only after the
// transaction commits, so the log never shows a change that rolled back.
func (d *DB) audited(ctx context.Context, fn func(tx pgx.Tx, record recordFunc) error) error {
	actor := actorFrom(ctx)
	var events []AuditEvent
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		return fn(tx, func(tenantID *int64, action, target string, details map[string]any) error {
			if details == nil {
				details = map[string]any{}
			}
			ev := AuditEvent{
				TenantID: tenantID, Action: action,
				ActorUserID: actor.UserID, ActorEmail: actor.Email, ActorAccessKeyID: actor.AccessKeyID,
				RequestID: actor.RequestID, Target: target, Details: details,
			}
			err := tx.QueryRow(ctx, `
				INSERT INTO audit_events
				    (tenant_id, action, actor_user_id, actor_email, actor_access_key_id, request_id, target, details)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				RETURNING id, at`,
				ev.TenantID, ev.Action, ev.ActorUserID, ev.ActorEmail, ev.ActorAccessKeyID,
				ev.RequestID, ev.Target, ev.Details).Scan(&ev.ID, &ev.At)
			if err != nil {
				return apperr.Internal(err)
			}
			events = append(events, ev)
			return nil
		})
	})
	if err != nil {
		return err
	}
	for _, ev := range events {
		d.logEvent(ctx, ev)
	}
	return nil
}

// logEvent writes ev as one line with a fixed set of keys under "audit": with
// the text handler, audit.action=member.remove audit.target=42 …; with the JSON
// handler, an "audit" object. tenant_id and actor_user_id are left out when
// null. details is always a JSON object, as a string under the text handler.
func (d *DB) logEvent(ctx context.Context, ev AuditEvent) {
	if d.auditLog == nil {
		return
	}
	details, err := json.Marshal(ev.Details)
	if err != nil {
		details = []byte("{}")
	}
	attrs := []any{
		slog.Int64("id", ev.ID),
		slog.Time("at", ev.At),
		slog.String("action", ev.Action),
	}
	if ev.TenantID != nil {
		attrs = append(attrs, slog.Int64("tenant_id", *ev.TenantID))
	}
	if ev.ActorUserID != nil {
		attrs = append(attrs, slog.Int64("actor_user_id", *ev.ActorUserID))
	}
	attrs = append(attrs,
		slog.String("actor_email", ev.ActorEmail),
		slog.String("actor_access_key_id", ev.ActorAccessKeyID),
		slog.String("request_id", ev.RequestID),
		slog.String("target", ev.Target),
		slog.Any("details", json.RawMessage(details)),
	)
	d.auditLog.InfoContext(ctx, "audit", slog.Group("audit", attrs...))
}

// ListAuditEvents returns up to limit of tenantID's events older than the event
// with id before (0 for the newest), newest first.
func (d *DB) ListAuditEvents(ctx context.Context, tenantID, before int64, limit int) ([]AuditEvent, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT id, at, tenant_id, action, actor_user_id, actor_email, actor_access_key_id,
		       request_id, target, details
		FROM audit_events
		WHERE tenant_id = $1 AND ($2 = 0 OR id < $2)
		ORDER BY id DESC
		LIMIT $3`, tenantID, before, limit)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AuditEvent])
	return out, apperr.Internal(err)
}

// userTarget renders a member's user id as an event target.
func userTarget(userID int64) string {
	return strconv.FormatInt(userID, 10)
}
