package api

import (
	"net/http"
	"strings"
	"testing"
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

func TestTenantEndpointsRequireAVerifiedEmail(t *testing.T) {
	f := newFixture(t)

	// No caller at all: the untenanted admin plane has no tenant identity.
	w := f.do(t, http.MethodGet, "/api/tenants", "")
	mustStatus(t, w, http.StatusForbidden)
	if code, _ := errorBody(t, w); code != "AccessDenied" {
		t.Errorf("code = %q", code)
	}

	// Signed in, but the provider did not verify the address. Membership is
	// granted by email, so an unverified one must grant nothing.
	f.signInUnverified("dev@example.com")
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants", ""), http.StatusForbidden)
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants", `{"name":"team-a"}`), http.StatusForbidden)
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

func TestMemberManagement(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")

	// Invite, with the PWA's Member field names in the response.
	w := f.do(t, http.MethodPost, "/api/tenants/team-a/members",
		`{"email":"Dev@Example.COM","role":"member"}`, "Content-Type", "application/json")
	mustStatus(t, w, http.StatusCreated)

	w = f.do(t, http.MethodGet, "/api/tenants/team-a/members", "")
	mustStatus(t, w, http.StatusOK)
	members := decodeArray(t, w)
	if len(members) != 2 {
		t.Fatalf("members = %#v", members)
	}
	for _, m := range members {
		for _, field := range []string{"email", "role", "created_at"} {
			if _, ok := m[field]; !ok {
				t.Errorf("missing field %q: %#v", field, m)
			}
		}
	}
	// The address is normalised on the way in, or an invitation would never
	// match the lowercased address a login presents.
	var found bool
	for _, m := range members {
		if m["email"] == "dev@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("invited address was not normalised: %#v", members)
	}

	// Bad input.
	for _, body := range []string{
		`{"email":"","role":"member"}`,
		`{"email":"not-an-email","role":"member"}`,
		`{"email":"x@y.com","role":"admin"}`,
	} {
		w := f.do(t, http.MethodPost, "/api/tenants/team-a/members", body)
		mustStatus(t, w, http.StatusBadRequest)
	}

	// An omitted role defaults to member.
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/members",
		`{"email":"third@example.com"}`), http.StatusCreated)

	// Removal.
	mustStatus(t, f.do(t, http.MethodDelete, "/api/tenants/team-a/members/dev@example.com", ""),
		http.StatusNoContent)
	// Idempotent.
	mustStatus(t, f.do(t, http.MethodDelete, "/api/tenants/team-a/members/dev@example.com", ""),
		http.StatusNoContent)

	// The last owner cannot be removed, or the team becomes unmanageable.
	w = f.do(t, http.MethodDelete, "/api/tenants/team-a/members/boss@example.com", "")
	mustStatus(t, w, http.StatusBadRequest)
}

// Membership grants read access; only owners may change the team.
func TestOwnerOnlyOperations(t *testing.T) {
	f := newFixture(t)
	f.signIn("boss@example.com")
	createTenant(t, f, "team-a")
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/members",
		`{"email":"dev@example.com","role":"member"}`), http.StatusCreated)

	f.signIn("dev@example.com")

	// A member may read the roster.
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/members", ""), http.StatusOK)

	// But not change it, or delete the team.
	ownerOnly := []struct{ method, target, body string }{
		{http.MethodPost, "/api/tenants/team-a/members", `{"email":"x@y.com"}`},
		{http.MethodDelete, "/api/tenants/team-a/members/boss@example.com", ""},
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

	f.signIn("stranger@example.com")
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/api/tenants/team-a/members"},
		{http.MethodPost, "/api/tenants/team-a/members"},
		{http.MethodDelete, "/api/tenants/team-a"},
	} {
		w := f.do(t, tc.method, tc.target, `{"email":"x@y.com"}`)
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

	// Bob knows the hash but not the content. The link must be declined.
	w := f.do(t, http.MethodPut, "/api/namespaces/bob-ns/objects/guess.txt?link="+abcHash, "")
	mustStatus(t, w, http.StatusOK)
	if decodeObject(t, w)["linked"] != false {
		t.Fatalf("link across tenants = %s, want linked:false", w.Body.String())
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
