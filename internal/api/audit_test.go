package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/auth"
)

// auditPage fetches one page of a team's audit log as the current caller.
func auditPage(t *testing.T, f *fixture, target string) (events []map[string]any, nextBefore any) {
	t.Helper()
	w := f.do(t, http.MethodGet, target, "")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)
	raw, ok := body["events"].([]any)
	if !ok {
		t.Fatalf("events = %#v, want an array", body["events"])
	}
	for _, e := range raw {
		events = append(events, e.(map[string]any))
	}
	return events, body["next_before"]
}

func TestAuditLogRecordsWhoDidWhat(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	join(t, f, "team-a", "dev@example.com", "member")
	createNamespaceIn(t, f, "photos", "team-a")
	key := mintCredential(t, f, "team-a", "ci")
	mustStatus(t, f.do(t, http.MethodDelete, "/api/tenants/team-a/credentials/"+key["access_key_id"].(string), ""),
		http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodPatch, memberPath(t, f, "team-a", "dev@example.com"),
		`{"role":"owner"}`, "Content-Type", "application/json"), http.StatusNoContent)

	events, next := auditPage(t, f, "/api/tenants/team-a/audit")
	if next != nil {
		t.Errorf("next_before = %v on the only page", next)
	}
	var actions []string
	for _, e := range events {
		actions = append(actions, e["action"].(string))
	}
	want := []string{
		"member.role", "credential.revoke", "credential.create", "namespace.create",
		"invitation.accept", "invitation.create", "tenant.create",
	}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Fatalf("actions = %v, want %v", actions, want)
	}

	// Every event carries the same keys, so a parser needs no per-action case.
	for _, e := range events {
		for _, k := range []string{
			"id", "at", "action", "actor_user_id", "actor_email", "actor_access_key_id",
			"request_id", "target", "details",
		} {
			if _, ok := e[k]; !ok {
				t.Errorf("%s event lacks %q: %#v", e["action"], k, e)
			}
		}
	}
	if events[0]["actor_email"] != "boss@example.com" || events[0]["details"].(map[string]any)["to"] != "owner" {
		t.Errorf("member.role = %#v", events[0])
	}
	if events[4]["actor_email"] != "dev@example.com" {
		t.Errorf("invitation.accept actor = %v, want the invitee", events[4]["actor_email"])
	}
}

func TestAuditLogPages(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	for i := range 3 {
		createNamespaceIn(t, f, fmt.Sprintf("ns-%d", i), "team-a")
	}

	first, next := auditPage(t, f, "/api/tenants/team-a/audit?limit=2")
	if len(first) != 2 || first[0]["target"] != "ns-2" || next == nil {
		t.Fatalf("first page = %v, next = %v", first, next)
	}
	rest, next := auditPage(t, f, fmt.Sprintf("/api/tenants/team-a/audit?limit=2&before=%v", next))
	if len(rest) != 2 || rest[0]["target"] != "ns-0" || rest[1]["action"] != "tenant.create" || next != nil {
		t.Fatalf("second page = %v, next = %v", rest, next)
	}

	for _, q := range []string{"limit=0", "limit=501", "limit=x", "before=0", "before=-3"} {
		mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/audit?"+q, ""), http.StatusBadRequest)
	}
}

func TestAuditLogIsOwnerOnly(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	join(t, f, "team-a", "dev@example.com", "member")

	f.signIn("dev@example.com")
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/audit", ""), http.StatusForbidden)

	f.signIn("stranger@example.com")
	w := f.do(t, http.MethodGet, "/api/tenants/team-a/audit", "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchTenant" {
		t.Errorf("code = %q", code)
	}

	f.caller = nil
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/audit", ""), http.StatusForbidden)
}

// The request id the router puts on the response is recorded with the change,
// tying the event to the request log.
func TestAuditLogCarriesTheRequestID(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")

	r := httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(`{"name":"team-a"}`))
	r = r.WithContext(auth.WithSession(r.Context(), f.caller))
	w := httptest.NewRecorder()
	w.Header().Set(apperr.RequestIDHeader, "0123456789abcdef")
	f.handler.ServeHTTP(w, r)
	mustStatus(t, w, http.StatusCreated)

	events, _ := auditPage(t, f, "/api/tenants/team-a/audit")
	if len(events) != 1 || events[0]["request_id"] != "0123456789abcdef" {
		t.Errorf("events = %v", events)
	}
}
