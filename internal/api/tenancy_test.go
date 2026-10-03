package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/auth"
)

// createTenant makes a team owned by the current caller.
func createTenant(t *testing.T, f *fixture, name string) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/tenants", `{"name":"`+name+`"}`,
		"Content-Type", "application/json")
	mustStatus(t, w, http.StatusCreated)
}

// createNamespaceIn makes a namespace owned by a team.
func createNamespaceIn(t *testing.T, f *fixture, namespace, tenant string) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/namespaces",
		`{"name":"`+namespace+`","tenant":"`+tenant+`"}`,
		"Content-Type", "application/json")
	mustStatus(t, w, http.StatusCreated)
}

// invite has the current caller invite email to tenant with role.
func invite(t *testing.T, f *fixture, tenant, email, role string) {
	t.Helper()
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/"+tenant+"/invitations",
		`{"email":"`+email+`","role":"`+role+`"}`, "Content-Type", "application/json"),
		http.StatusCreated)
}

// join makes email a member of tenant with role the only way there is: the
// current caller, an owner, invites the address, and its holder accepts. The
// caller is the same afterwards.
func join(t *testing.T, f *fixture, tenant, email, role string) {
	t.Helper()
	owner := f.caller
	invite(t, f, tenant, email, role)
	f.signIn(email)
	mustStatus(t, f.do(t, http.MethodPost, "/api/invitations/"+tenant+"/accept", ""),
		http.StatusNoContent)
	f.caller = owner
}

// memberPath is the member endpoint for whoever in tenant has email, as the
// current caller sees the roster.
func memberPath(t *testing.T, f *fixture, tenant, email string) string {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/tenants/"+tenant+"/members", "")
	mustStatus(t, w, http.StatusOK)
	for _, m := range decodeArray(t, w) {
		if m["email"] == email {
			return fmt.Sprintf("/api/tenants/%s/members/%v", tenant, m["id"])
		}
	}
	t.Fatalf("%s is not a member of %s", email, tenant)
	return ""
}

func TestTenantEndpointsRequireSignIn(t *testing.T) {
	f := newFixture(t)

	// No caller at all: the untenanted admin plane has nobody for a team to
	// belong to.
	for _, target := range []string{"/api/tenants", "/api/invitations"} {
		w := f.do(t, http.MethodGet, target, "")
		mustStatus(t, w, http.StatusForbidden)
		if code, _ := errorBody(t, w); code != "AccessDenied" {
			t.Errorf("%s code = %q", target, code)
		}
	}
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants", `{"name":"team-a"}`), http.StatusForbidden)
}

// Teams belong to the account, so a provider that verifies no address is no bar
// to having one. The address only matters for accepting invitations.
func TestUnverifiedCallerCanRunTheirOwnTeam(t *testing.T) {
	f := newFixture(t)
	f.signInUnverified("dev@example.com")

	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "photos", "team-a")
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/photos/objects/k", "abc"), http.StatusOK)

	w := f.do(t, http.MethodGet, "/api/tenants/team-a/members", "")
	mustStatus(t, w, http.StatusOK)
	members := decodeArray(t, w)
	// An unverified address is not displayed as theirs.
	if len(members) != 1 || members[0]["email"] != "" || members[0]["role"] != "owner" {
		t.Errorf("members = %#v, want one owner with no address", members)
	}
}

func TestCreateAndListTenants(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")

	createTenant(t, f, "team-a")

	w := f.do(t, http.MethodGet, "/api/tenants", "")
	mustStatus(t, w, http.StatusOK)
	list := decodeArray(t, w)
	if len(list) != 1 {
		t.Fatalf("tenants = %#v", list)
	}
	// The PWA's Tenant type: name, role, created_at.
	if list[0]["name"] != "team-a" || list[0]["role"] != "owner" {
		t.Errorf("tenant = %#v", list[0])
	}
	if _, ok := list[0]["created_at"]; !ok {
		t.Errorf("missing created_at: %#v", list[0])
	}

	// Duplicate and invalid names.
	w = f.do(t, http.MethodPost, "/api/tenants", `{"name":"team-a"}`)
	mustStatus(t, w, http.StatusConflict)
	if code, _ := errorBody(t, w); code != "TenantAlreadyExists" {
		t.Errorf("code = %q", code)
	}
	w = f.do(t, http.MethodPost, "/api/tenants", `{"name":"Bad_Name"}`)
	mustStatus(t, w, http.StatusBadRequest)
	if code, _ := errorBody(t, w); code != "InvalidTenantName" {
		t.Errorf("code = %q", code)
	}

	// Another user sees none of it.
	f.signIn("stranger@example.com")
	w = f.do(t, http.MethodGet, "/api/tenants", "")
	mustStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("a stranger's tenant list = %q, want []", got)
	}
}

func TestInvitationFlow(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "photos", "team-a")

	// The address is normalised on the way in, or the invitation would never
	// match the lowercased address a login presents.
	invite(t, f, "team-a", " Dev@Example.COM", "member")

	w := f.do(t, http.MethodGet, "/api/tenants/team-a/invitations", "")
	mustStatus(t, w, http.StatusOK)
	sent := decodeArray(t, w)
	if len(sent) != 1 || sent[0]["email"] != "dev@example.com" || sent[0]["role"] != "member" ||
		sent[0]["invited_by"] != "boss@example.com" || sent[0]["tenant"] != "team-a" {
		t.Fatalf("team's invitations = %#v", sent)
	}
	for _, field := range []string{"created_at", "expires_at"} {
		if sent[0][field] == nil {
			t.Errorf("invitation is missing %s: %#v", field, sent[0])
		}
	}
	// Pending is not membership.
	if w := f.do(t, http.MethodGet, "/api/tenants/team-a/members", ""); len(decodeArray(t, w)) != 1 {
		t.Errorf("roster = %s, want only the owner before acceptance", w.Body.String())
	}

	// The invitee sees it, and nothing of the team until they accept.
	f.signIn("dev@example.com")
	w = f.do(t, http.MethodGet, "/api/invitations", "")
	mustStatus(t, w, http.StatusOK)
	mine := decodeArray(t, w)
	if len(mine) != 1 || mine[0]["tenant"] != "team-a" || mine[0]["invited_by"] != "boss@example.com" {
		t.Fatalf("invitee's invitations = %#v", mine)
	}
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/tenants", "").Body.String()); got != "[]" {
		t.Errorf("tenants before accepting = %s, want []", got)
	}
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/photos/objects", ""), http.StatusNotFound)

	mustStatus(t, f.do(t, http.MethodPost, "/api/invitations/team-a/accept", ""), http.StatusNoContent)

	w = f.do(t, http.MethodGet, "/api/tenants", "")
	list := decodeArray(t, w)
	if len(list) != 1 || list[0]["name"] != "team-a" || list[0]["role"] != "member" {
		t.Errorf("tenants after accepting = %#v", list)
	}
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/photos/objects", ""), http.StatusOK)
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/invitations", "").Body.String()); got != "[]" {
		t.Errorf("invitations after accepting = %s, want []", got)
	}

	// The roster, in the PWA's Member shape.
	w = f.do(t, http.MethodGet, "/api/tenants/team-a/members", "")
	members := decodeArray(t, w)
	if len(members) != 2 {
		t.Fatalf("members = %#v", members)
	}
	for _, m := range members {
		for _, field := range []string{"id", "email", "name", "role", "created_at", "you"} {
			if _, ok := m[field]; !ok {
				t.Errorf("missing field %q: %#v", field, m)
			}
		}
		// The caller's own row, and only it, is marked.
		if you := m["email"] == "dev@example.com"; m["you"] != you {
			t.Errorf("you = %v for %v", m["you"], m["email"])
		}
	}

	// An invitation is used once.
	w = f.do(t, http.MethodPost, "/api/invitations/team-a/accept", "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchInvitation" {
		t.Errorf("second accept code = %q, want NoSuchInvitation", code)
	}
}

// Only the verified holder of the invited address can answer an invitation.
func TestInvitationNeedsItsVerifiedAddress(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	invite(t, f, "team-a", "dev@example.com", "owner")

	// The same address, unverified: nothing listed, and no answering.
	f.signInUnverified("dev@example.com")
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/invitations", "").Body.String()); got != "[]" {
		t.Errorf("unverified caller's invitations = %s, want []", got)
	}
	for _, verb := range []string{"accept", "decline"} {
		w := f.do(t, http.MethodPost, "/api/invitations/team-a/"+verb, "")
		mustStatus(t, w, http.StatusForbidden)
		if _, message := errorBody(t, w); !strings.Contains(message, "verified email") {
			t.Errorf("%s message = %q", verb, message)
		}
	}

	// Someone else entirely finds nothing to accept, the same answer as for a
	// team that does not exist.
	f.signIn("stranger@example.com")
	for _, tenant := range []string{"team-a", "never-existed"} {
		w := f.do(t, http.MethodPost, "/api/invitations/"+tenant+"/accept", "")
		mustStatus(t, w, http.StatusNotFound)
		if code, _ := errorBody(t, w); code != "NoSuchInvitation" {
			t.Errorf("%s code = %q, want NoSuchInvitation", tenant, code)
		}
	}

	// The invitation survives all of that.
	f.signIn("boss@example.com")
	if w := f.do(t, http.MethodGet, "/api/tenants/team-a/invitations", ""); len(decodeArray(t, w)) != 1 {
		t.Errorf("invitations = %s, want it still pending", w.Body.String())
	}
}

// Membership belongs to the account that accepted. Another account, at another
// provider, that presents the same verified address inherits none of it.
func TestMembershipDoesNotFollowTheEmail(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "photos", "team-a")

	f.caller = &auth.Session{
		Issuer: "https://open-signup.test", Subject: "anyone", Provider: "other",
		Email: "boss@example.com", EmailVerified: true,
	}
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/tenants", "").Body.String()); got != "[]" {
		t.Errorf("tenants = %s, want []", got)
	}
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/members", ""), http.StatusNotFound)
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/photos/objects", ""), http.StatusNotFound)
}

func TestDeclineAndRevokeInvitations(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	invite(t, f, "team-a", "dev@example.com", "member")
	invite(t, f, "team-a", "ops@example.com", "member")

	f.signIn("dev@example.com")
	mustStatus(t, f.do(t, http.MethodPost, "/api/invitations/team-a/decline", ""), http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodPost, "/api/invitations/team-a/accept", ""), http.StatusNotFound)

	f.signIn("boss@example.com")
	// Revoking is idempotent, and normalises the address like inviting does.
	for range 2 {
		mustStatus(t, f.do(t, http.MethodDelete, "/api/tenants/team-a/invitations/OPS@example.com", ""),
			http.StatusNoContent)
	}
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/tenants/team-a/invitations", "").Body.String()); got != "[]" {
		t.Errorf("invitations = %s, want none left", got)
	}

	f.signIn("ops@example.com")
	mustStatus(t, f.do(t, http.MethodPost, "/api/invitations/team-a/accept", ""), http.StatusNotFound)
}

func TestInvitationValidation(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")

	for _, body := range []string{
		`{"email":"","role":"member"}`,
		`{"email":"not-an-email","role":"member"}`,
		`{"email":"x@y.com","role":"admin"}`,
		`not json`,
	} {
		w := f.do(t, http.MethodPost, "/api/tenants/team-a/invitations", body)
		mustStatus(t, w, http.StatusBadRequest)
	}

	// An omitted role defaults to member.
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/invitations",
		`{"email":"third@example.com"}`), http.StatusCreated)
	w := f.do(t, http.MethodGet, "/api/tenants/team-a/invitations", "")
	if list := decodeArray(t, w); len(list) != 1 || list[0]["role"] != "member" {
		t.Errorf("invitations = %#v, want one member invitation", list)
	}

	// Members are no longer added directly.
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/members",
		`{"email":"x@y.com"}`), http.StatusMethodNotAllowed)
}

func TestMemberRoleChanges(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	join(t, f, "team-a", "dev@example.com", "member")
	dev := memberPath(t, f, "team-a", "dev@example.com")
	boss := memberPath(t, f, "team-a", "boss@example.com")

	mustStatus(t, f.do(t, http.MethodPatch, dev, `{"role":"owner"}`), http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodPatch, boss, `{"role":"member"}`), http.StatusNoContent)

	// boss is a member now, so dev, the last owner, does the rest.
	f.signIn("dev@example.com")
	w := f.do(t, http.MethodPatch, dev, `{"role":"member"}`)
	mustStatus(t, w, http.StatusBadRequest)
	if _, message := errorBody(t, w); !strings.Contains(message, "last owner") {
		t.Errorf("message = %q, want the last-owner refusal", message)
	}

	for _, body := range []string{`{"role":"admin"}`, `{}`, `nope`} {
		mustStatus(t, f.do(t, http.MethodPatch, boss, body), http.StatusBadRequest)
	}
	mustStatus(t, f.do(t, http.MethodPatch, "/api/tenants/team-a/members/abc", `{"role":"owner"}`),
		http.StatusBadRequest)
	w = f.do(t, http.MethodPatch, "/api/tenants/team-a/members/999999", `{"role":"owner"}`)
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchMember" {
		t.Errorf("code = %q, want NoSuchMember", code)
	}
}

func TestMemberRemoval(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	join(t, f, "team-a", "dev@example.com", "member")
	join(t, f, "team-a", "ops@example.com", "member")
	dev := memberPath(t, f, "team-a", "dev@example.com")
	ops := memberPath(t, f, "team-a", "ops@example.com")
	boss := memberPath(t, f, "team-a", "boss@example.com")

	// An owner removes anyone; removal is idempotent.
	for range 2 {
		mustStatus(t, f.do(t, http.MethodDelete, ops, ""), http.StatusNoContent)
	}

	// The last owner cannot be removed, or the team becomes unmanageable.
	mustStatus(t, f.do(t, http.MethodDelete, boss, ""), http.StatusBadRequest)

	// A member may leave, but not remove anyone else.
	f.signIn("dev@example.com")
	mustStatus(t, f.do(t, http.MethodDelete, boss, ""), http.StatusForbidden)
	mustStatus(t, f.do(t, http.MethodDelete, dev, ""), http.StatusNoContent)
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/tenants", "").Body.String()); got != "[]" {
		t.Errorf("tenants after leaving = %s, want []", got)
	}
}

// Membership grants read access; only owners may change the team.
func TestOwnerOnlyOperations(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	join(t, f, "team-a", "dev@example.com", "member")
	boss := memberPath(t, f, "team-a", "boss@example.com")

	f.signIn("dev@example.com")

	// A member may read the roster.
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/members", ""), http.StatusOK)

	// But not change it, see who is invited, or delete the team.
	ownerOnly := []struct{ method, target, body string }{
		{http.MethodPost, "/api/tenants/team-a/invitations", `{"email":"x@y.com"}`},
		{http.MethodGet, "/api/tenants/team-a/invitations", ""},
		{http.MethodDelete, "/api/tenants/team-a/invitations/x@y.com", ""},
		{http.MethodPatch, boss, `{"role":"member"}`},
		{http.MethodDelete, boss, ""},
		{http.MethodDelete, "/api/tenants/team-a", ""},
	}
	for _, tc := range ownerOnly {
		w := f.do(t, tc.method, tc.target, tc.body)
		mustStatus(t, w, http.StatusForbidden)
		if _, message := errorBody(t, w); !strings.Contains(message, "owner") {
			t.Errorf("%s %s message = %q, want it to mention the owner role", tc.method, tc.target, message)
		}
	}
}

// A non-member must not be able to tell whether a team exists.
func TestNonMemberCannotSeeATenantExists(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	boss := memberPath(t, f, "team-a", "boss@example.com")

	f.signIn("stranger@example.com")
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/api/tenants/team-a/members"},
		{http.MethodPatch, boss},
		{http.MethodDelete, boss},
		{http.MethodGet, "/api/tenants/team-a/invitations"},
		{http.MethodPost, "/api/tenants/team-a/invitations"},
		{http.MethodDelete, "/api/tenants/team-a/invitations/x@y.com"},
		{http.MethodDelete, "/api/tenants/team-a"},
	} {
		w := f.do(t, tc.method, tc.target, `{"email":"x@y.com","role":"owner"}`)
		mustStatus(t, w, http.StatusNotFound)
		if code, _ := errorBody(t, w); code != "NoSuchTenant" {
			t.Errorf("%s %s code = %q, want NoSuchTenant", tc.method, tc.target, code)
		}
	}

	// And a team that genuinely does not exist looks identical.
	w := f.do(t, http.MethodGet, "/api/tenants/never-existed/members", "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchTenant" {
		t.Errorf("code = %q", code)
	}
}

func TestDeleteTenantRequiresItToBeEmpty(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "photos", "team-a")

	w := f.do(t, http.MethodDelete, "/api/tenants/team-a", "")
	mustStatus(t, w, http.StatusConflict)
	if code, _ := errorBody(t, w); code != "TenantNotEmpty" {
		t.Errorf("code = %q", code)
	}

	mustStatus(t, f.do(t, http.MethodDelete, "/api/namespaces/photos", ""), http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodDelete, "/api/tenants/team-a", ""), http.StatusNoContent)
}

// A signed-in caller must name the owning team, so no namespace is created
// without an owner on the tenanted plane.
func TestCreateNamespaceRequiresATenantWhenSignedIn(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")

	w := f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos"}`)
	mustStatus(t, w, http.StatusBadRequest)
	if _, message := errorBody(t, w); !strings.Contains(message, "tenant") {
		t.Errorf("message = %q, want it to mention the missing tenant", message)
	}

	// And it must be a team they belong to.
	f.signIn("stranger@example.com")
	createTenant(t, f, "team-b")
	w = f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos","tenant":"team-a"}`)
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchTenant" {
		t.Errorf("code = %q", code)
	}
}

// Namespace names are global, so a clash is a 409 whoever holds the name. It is
// reported as the caller's own only for a namespace they can reach; another
// team's and an unowned one get the same BucketAlreadyExists.
func TestCreateNamespaceClash(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"unowned"}`),
		http.StatusCreated)

	f.signIn("bob@example.com")
	createTenant(t, f, "team-b")
	createNamespaceIn(t, f, "bob-ns", "team-b")

	f.signIn("alice@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "alice-ns", "team-a")

	create := func(name string) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPost, "/api/namespaces",
			`{"name":"`+name+`","tenant":"team-a"}`, "Content-Type", "application/json")
	}

	w := create("alice-ns")
	mustStatus(t, w, http.StatusConflict)
	if code, _ := errorBody(t, w); code != "BucketAlreadyOwnedByYou" {
		t.Errorf("own clash code = %q", code)
	}

	other := create("bob-ns")
	mustStatus(t, other, http.StatusConflict)
	if code, _ := errorBody(t, other); code != "BucketAlreadyExists" {
		t.Errorf("another team's clash code = %q", code)
	}
	unowned := create("unowned")
	mustStatus(t, unowned, http.StatusConflict)
	if other.Body.String() != unowned.Body.String() {
		t.Errorf("clash bodies differ:\nanother team's: %s\nunowned:        %s",
			other.Body.String(), unowned.Body.String())
	}

	// Once Alice is in team-b too, bob-ns is within her reach and so hers,
	// though she asked to create it in team-a.
	f.signIn("bob@example.com")
	join(t, f, "team-b", "alice@example.com", "member")
	f.signIn("alice@example.com")
	w = create("bob-ns")
	mustStatus(t, w, http.StatusConflict)
	if code, _ := errorBody(t, w); code != "BucketAlreadyOwnedByYou" {
		t.Errorf("clash in a second team code = %q", code)
	}

	// Reserved names are refused before any of that.
	w = create("healthz")
	mustStatus(t, w, http.StatusBadRequest)
	if code, _ := errorBody(t, w); code != "InvalidBucketName" {
		t.Errorf("reserved name code = %q", code)
	}
}

// The central isolation guarantee: one team's data is invisible and untouchable
// to another, and indistinguishable from data that does not exist.
func TestCrossTenantIsolation(t *testing.T) {
	f := newFixture(t)

	f.signIn("alice@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "alice-ns", "team-a")
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/alice-ns/objects/secret.txt", "abc"),
		http.StatusOK)

	f.signIn("bob@example.com")
	createTenant(t, f, "team-b")
	createNamespaceIn(t, f, "bob-ns", "team-b")

	// Bob's listing shows only his own.
	w := f.do(t, http.MethodGet, "/api/namespaces", "")
	mustStatus(t, w, http.StatusOK)
	list := decodeArray(t, w)
	if len(list) != 1 || list[0]["name"] != "bob-ns" {
		t.Fatalf("bob's namespaces = %#v, want only bob-ns", list)
	}

	// Every route into Alice's namespace is a 404 for Bob.
	attempts := []struct{ method, target, body string }{
		{http.MethodGet, "/api/namespaces/alice-ns/objects", ""},
		{http.MethodGet, "/api/namespaces/alice-ns/objects/secret.txt", ""},
		{http.MethodPut, "/api/namespaces/alice-ns/objects/intruder.txt", "x"},
		{http.MethodDelete, "/api/namespaces/alice-ns/objects/secret.txt", ""},
		{http.MethodDelete, "/api/namespaces/alice-ns", ""},
		{http.MethodPost, "/api/namespaces/alice-ns/objects/x?uploads", ""},
	}
	for _, tc := range attempts {
		w := f.do(t, tc.method, tc.target, tc.body)
		mustStatus(t, w, http.StatusNotFound)
		if code, _ := errorBody(t, w); code != "NoSuchBucket" {
			t.Errorf("%s %s code = %q, want NoSuchBucket", tc.method, tc.target, code)
		}
	}

	// Alice's own access is unaffected.
	f.signIn("alice@example.com")
	w = f.do(t, http.MethodGet, "/api/namespaces/alice-ns/objects/secret.txt", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("body = %q", w.Body.String())
	}
	// And no intruder object was created.
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/alice-ns/objects/intruder.txt", ""),
		http.StatusNotFound)
}

// Namespaces created through the S3 admin plane have no owning tenant and must
// be invisible to signed-in callers.
func TestUnownedNamespacesAreHiddenFromTenantCallers(t *testing.T) {
	f := newFixture(t)

	// With no caller, this is the untenanted admin plane.
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"unowned"}`),
		http.StatusCreated)
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/unowned/objects/k", "abc"),
		http.StatusOK)

	f.signIn("dev@example.com")
	createTenant(t, f, "team-a")

	w := f.do(t, http.MethodGet, "/api/namespaces", "")
	mustStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("signed-in listing = %q, want [] — unowned namespaces are hidden", got)
	}
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/unowned/objects", ""),
		http.StatusNotFound)
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/unowned/objects/k", ""),
		http.StatusNotFound)
}

// ?tenant scopes the listing to one team, and requires membership in it.
func TestNamespaceListingScopedToOneTenant(t *testing.T) {
	f := newFixture(t)
	f.signIn("dev@example.com")
	createTenant(t, f, "team-a")
	createTenant(t, f, "team-b")
	createNamespaceIn(t, f, "ns-a", "team-a")
	createNamespaceIn(t, f, "ns-b", "team-b")

	// Both teams by default.
	w := f.do(t, http.MethodGet, "/api/namespaces", "")
	if len(decodeArray(t, w)) != 2 {
		t.Errorf("unscoped listing = %s, want both", w.Body.String())
	}

	// One team when asked.
	w = f.do(t, http.MethodGet, "/api/namespaces?tenant=team-a", "")
	mustStatus(t, w, http.StatusOK)
	list := decodeArray(t, w)
	if len(list) != 1 || list[0]["name"] != "ns-a" {
		t.Errorf("scoped listing = %#v", list)
	}

	// A team the caller does not belong to does not exist as far as they know.
	f.signIn("stranger@example.com")
	w = f.do(t, http.MethodGet, "/api/namespaces?tenant=team-a", "")
	mustStatus(t, w, http.StatusNotFound)
}

// Stats are scoped to the caller's teams.
func TestStatsScopedToCallersTenants(t *testing.T) {
	f := newFixture(t)

	f.signIn("alice@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "alice-ns", "team-a")
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/alice-ns/objects/k", "abc"), http.StatusOK)

	// Bob has a team but nothing in it.
	f.signIn("bob@example.com")
	createTenant(t, f, "team-b")
	w := f.do(t, http.MethodGet, "/api/stats", "")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)
	if body["object_count"] != float64(0) || body["logical_bytes"] != float64(0) {
		t.Errorf("bob's stats = %#v, want zeroes", body)
	}
	if body["namespace_count"] != float64(0) {
		t.Errorf("namespace_count = %v, want 0", body["namespace_count"])
	}

	// Alice sees her own.
	f.signIn("alice@example.com")
	w = f.do(t, http.MethodGet, "/api/stats", "")
	body = decodeObject(t, w)
	if body["object_count"] != float64(1) || body["logical_bytes"] != float64(3) {
		t.Errorf("alice's stats = %#v", body)
	}

	// A caller with no team at all sees nothing.
	f.signIn("nobody@example.com")
	w = f.do(t, http.MethodGet, "/api/stats", "")
	body = decodeObject(t, w)
	if body["namespace_count"] != float64(0) || body["object_count"] != float64(0) {
		t.Errorf("a teamless caller's stats = %#v, want zeroes", body)
	}
}

// The dedup link endpoint must not become a cross-tenant existence oracle: a
// caller may only link content their own team already holds.
func TestLinkIsTenantScoped(t *testing.T) {
	f := newFixture(t)

	f.signIn("alice@example.com")
	createTenant(t, f, "team-a")
	createNamespaceIn(t, f, "alice-ns", "team-a")
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/alice-ns/objects/secret.txt", "abc"),
		http.StatusOK)

	f.signIn("bob@example.com")
	createTenant(t, f, "team-b")
	createNamespaceIn(t, f, "bob-ns", "team-b")

	// Bob knows the hash but not the content. The link must be declined with
	// exactly the answer a hash nobody stores gets, or the difference would
	// tell Bob that some other team holds this content.
	w := f.do(t, http.MethodPut, "/api/namespaces/bob-ns/objects/guess.txt?link="+abcHash, "")
	mustStatus(t, w, http.StatusNotFound)
	const unstored = "0000000000000000000000000000000000000000000000000000000000000000"
	miss := f.do(t, http.MethodPut, "/api/namespaces/bob-ns/objects/guess.txt?link="+unstored, "")
	mustStatus(t, miss, http.StatusNotFound)
	if w.Body.String() != miss.Body.String() {
		t.Errorf("another team's hash answers %q but an unstored hash answers %q; they must be identical",
			w.Body.String(), miss.Body.String())
	}
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/bob-ns/objects/guess.txt", ""),
		http.StatusNotFound)

	// Once Bob uploads the same bytes himself, linking within his team works —
	// and physical dedup still stored them only once.
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/bob-ns/objects/own.txt", "abc"),
		http.StatusOK)
	w = f.do(t, http.MethodPut, "/api/namespaces/bob-ns/objects/guess.txt?link="+abcHash, "")
	mustStatus(t, w, http.StatusOK)
	if decodeObject(t, w)["linked"] != true {
		t.Errorf("link within the team = %s, want linked:true", w.Body.String())
	}

	var blobs int
	if err := f.pool.QueryRow(t.Context(), "SELECT COUNT(*) FROM blobs").Scan(&blobs); err != nil {
		t.Fatal(err)
	}
	if blobs != 1 {
		t.Errorf("stored %d blob rows, want 1 — dedup is global even though linking is scoped", blobs)
	}
}

// Alice's namespace is owned; the S3 gateway's unowned namespaces link freely.
func TestLinkUnscopedOnTheUntenantedPlane(t *testing.T) {
	f := newFixture(t)

	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"one"}`), http.StatusCreated)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"two"}`), http.StatusCreated)
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/one/objects/k", "abc"), http.StatusOK)

	// No tenant owns either namespace, so the link is unrestricted.
	w := f.do(t, http.MethodPut, "/api/namespaces/two/objects/k?link="+abcHash, "")
	mustStatus(t, w, http.StatusOK)
	if decodeObject(t, w)["linked"] != true {
		t.Errorf("link = %s, want linked:true on the untenanted plane", w.Body.String())
	}
}
