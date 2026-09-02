package api

import (
	"net/http"
	"strings"
	"testing"
)

// mintCredential creates an S3 key for a tenant and returns the create
// response, which is the only place the secret ever appears.
func mintCredential(t *testing.T, f *fixture, tenant, description string) map[string]any {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/tenants/"+tenant+"/credentials",
		`{"description":"`+description+`"}`, "Content-Type", "application/json")
	mustStatus(t, w, http.StatusCreated)
	return decodeObject(t, w)
}

func TestMintAndListCredentials(t *testing.T) {
	f := newFixture(t)
	f.signIn("owner@example.com")
	createTenant(t, f, "team-a")

	created := mintCredential(t, f, "team-a", "ci pipeline")

	accessKeyID, _ := created["access_key_id"].(string)
	secret, _ := created["secret_access_key"].(string)
	if !strings.HasPrefix(accessKeyID, accessKeyPrefix) {
		t.Errorf("access_key_id = %q, want the %s prefix", accessKeyID, accessKeyPrefix)
	}
	if len(secret) < 32 {
		t.Errorf("secret_access_key = %q, want at least 32 characters", secret)
	}

	// The listing shows the key but never the secret again.
	list := decodeArray(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""))
	if len(list) != 1 {
		t.Fatalf("listed %d credentials, want 1", len(list))
	}
	if list[0]["access_key_id"] != accessKeyID {
		t.Errorf("listed key = %v, want %q", list[0]["access_key_id"], accessKeyID)
	}
	if list[0]["description"] != "ci pipeline" {
		t.Errorf("description = %v", list[0]["description"])
	}
	if _, leaked := list[0]["secret_access_key"]; leaked {
		t.Error("the listing returned the secret")
	}
}

func TestCredentialsAreUnique(t *testing.T) {
	f := newFixture(t)
	f.signIn("owner@example.com")
	createTenant(t, f, "team-a")

	seen := map[string]bool{}
	for range 8 {
		created := mintCredential(t, f, "team-a", "")
		id, _ := created["access_key_id"].(string)
		secret, _ := created["secret_access_key"].(string)
		if seen[id] || seen[secret] {
			t.Fatalf("generator repeated a value: %q", id)
		}
		seen[id], seen[secret] = true, true
	}
}

// A credential is unrestricted access to everything the tenant owns, so minting
// one is an owner's call rather than any member's.
func TestCredentialManagementIsOwnerOnly(t *testing.T) {
	f := newFixture(t)
	f.signIn("owner@example.com")
	createTenant(t, f, "team-a")
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/members",
		`{"email":"member@example.com","role":"member"}`,
		"Content-Type", "application/json"), http.StatusCreated)
	created := mintCredential(t, f, "team-a", "owned")
	accessKeyID, _ := created["access_key_id"].(string)

	f.signIn("member@example.com")
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""), http.StatusForbidden)
	mustStatus(t, f.do(t, http.MethodPost, "/api/tenants/team-a/credentials", ""), http.StatusForbidden)
	mustStatus(t, f.do(t, http.MethodDelete,
		"/api/tenants/team-a/credentials/"+accessKeyID, ""), http.StatusForbidden)
}

func TestNonMemberCannotSeeOrMintCredentials(t *testing.T) {
	f := newFixture(t)
	f.signIn("owner@example.com")
	createTenant(t, f, "team-a")

	// A stranger gets NoSuchTenant, so the endpoint does not confirm the team
	// exists — the same treatment every other tenant-scoped route gives.
	f.signIn("stranger@example.com")
	w := f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchTenant" {
		t.Errorf("code = %q, want NoSuchTenant", code)
	}
}

func TestRevokeCredential(t *testing.T) {
	f := newFixture(t)
	f.signIn("owner@example.com")
	createTenant(t, f, "team-a")
	created := mintCredential(t, f, "team-a", "temporary")
	accessKeyID, _ := created["access_key_id"].(string)

	mustStatus(t, f.do(t, http.MethodDelete,
		"/api/tenants/team-a/credentials/"+accessKeyID, ""), http.StatusNoContent)

	list := decodeArray(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""))
	if len(list) != 0 {
		t.Fatalf("listed %d credentials after revoking, want 0", len(list))
	}

	// Revoking it again reports NotFound rather than succeeding silently.
	mustStatus(t, f.do(t, http.MethodDelete,
		"/api/tenants/team-a/credentials/"+accessKeyID, ""), http.StatusNotFound)
}

// The revoke path takes an id from the URL, so it has to be scoped by tenant
// rather than trusting that an owner only names their own keys.
func TestOwnerCannotRevokeAnotherTenantsCredential(t *testing.T) {
	f := newFixture(t)

	f.signIn("a@example.com")
	createTenant(t, f, "team-a")
	victim := mintCredential(t, f, "team-a", "team a key")
	victimKey, _ := victim["access_key_id"].(string)

	// An owner of their own team aims the revoke at team A's key id.
	f.signIn("b@example.com")
	createTenant(t, f, "team-b")
	mustStatus(t, f.do(t, http.MethodDelete,
		"/api/tenants/team-b/credentials/"+victimKey, ""), http.StatusNotFound)

	// Naming team A directly is refused earlier, at the membership check.
	mustStatus(t, f.do(t, http.MethodDelete,
		"/api/tenants/team-a/credentials/"+victimKey, ""), http.StatusNotFound)

	// The key survived both attempts.
	f.signIn("a@example.com")
	list := decodeArray(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""))
	if len(list) != 1 {
		t.Fatalf("team A has %d credentials, want its key intact", len(list))
	}
}

func TestCredentialEndpointsRequireAVerifiedEmail(t *testing.T) {
	f := newFixture(t)

	// No caller at all.
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""), http.StatusForbidden)

	// Signed in but unverified: membership is keyed on the address, so an
	// unverified one must not reach a tenant's keys.
	f.signInUnverified("dev@example.com")
	mustStatus(t, f.do(t, http.MethodGet, "/api/tenants/team-a/credentials", ""), http.StatusForbidden)
}
