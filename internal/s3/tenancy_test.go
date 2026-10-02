package s3

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// The admin credential every tenanted fixture is configured with. A tenant key
// must never be mistaken for it, and it must keep seeing everything.
const (
	adminKeyID  = "SCASADMINKEYID"
	adminSecret = "admin-secret-key"
)

// tenantFixture is a gateway with auth on, two tenants, a namespace each, and
// a per-tenant S3 credential for both — the arrangement every isolation
// question below is asked against.
type tenantFixture struct {
	g *Gateway
	// pool is a raw handle for the assertions that inspect blob refcounts
	// directly, which no exported query surfaces.
	pool *pgxpool.Pool

	tenantA, tenantB     int64
	keyA, secretA        string
	keyB, secretB        string
	namespaceA, namespcB string
}

// newTenantFixture builds the gateway with signature checking enabled, which is
// what makes per-tenant credentials meaningful: with auth off every caller is
// the admin.
func newTenantFixture(t *testing.T) *tenantFixture {
	t.Helper()
	ctx := t.Context()
	dsn := testdb.URL(t)

	database, err := db.Connect(ctx, dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)

	bucket, err := storage.Open(ctx, config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("open bucket: %v", err)
	}
	t.Cleanup(func() { _ = bucket.Close() })

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	t.Cleanup(pool.Close)

	cfg := config.Default()
	cfg.Database.URL = dsn
	cfg.Auth = config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     adminKeyID,
		SecretAccessKey: adminSecret,
	}
	gc := config.GcConfig{IntervalSecs: 60, GraceSecs: 300, MultipartExpirySecs: 86400}
	log := slog.New(slog.DiscardHandler)

	f := &tenantFixture{
		g:          New(database, bucket, cas.New(database, bucket, gc, cfg.Limits, log), &cfg, log),
		pool:       pool,
		namespaceA: "ns-a",
		namespcB:   "ns-b",
	}

	f.tenantA = mustCreateTenant(t, database, "team-a", "a@example.com")
	f.tenantB = mustCreateTenant(t, database, "team-b", "b@example.com")
	mustCreateNamespace(t, database, f.namespaceA, &f.tenantA)
	mustCreateNamespace(t, database, f.namespcB, &f.tenantB)

	f.keyA, f.secretA = mustCreateCredential(t, database, f.tenantA, "key-a")
	f.keyB, f.secretB = mustCreateCredential(t, database, f.tenantB, "key-b")
	return f
}

func mustCreateTenant(t *testing.T, d *db.DB, name, owner string) int64 {
	t.Helper()
	id, err := d.CreateTenant(context.Background(), name, owner)
	if err != nil {
		t.Fatalf("create tenant %s: %v", name, err)
	}
	return id
}

func mustCreateNamespace(t *testing.T, d *db.DB, name string, tenantID *int64) {
	t.Helper()
	if err := d.CreateNamespace(context.Background(), name, tenantID); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
}

func mustCreateCredential(t *testing.T, d *db.DB, tenantID int64, label string) (id, secret string) {
	t.Helper()
	// The ids only have to be distinct and non-colliding with the admin key;
	// the API's generator is exercised in the api package.
	id = "SCASTESTKEY" + strings.ToUpper(strings.ReplaceAll(label, "-", ""))
	secret = "secret-for-" + label
	if err := d.CreateS3Credential(context.Background(), tenantID, id, secret, label); err != nil {
		t.Fatalf("create credential %s: %v", label, err)
	}
	return id, secret
}

// signed issues a correctly SigV4-signed request against the gateway as the
// given credential. The payload is sent unsigned, which is what streaming S3
// clients do and what lets this helper sign without buffering.
func (f *tenantFixture) signed(t *testing.T, keyID, secret, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.Host = "cas.example.com"
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	signAt(r, keyID, secret, now(), "s3")

	w := httptest.NewRecorder()
	f.g.ServeHTTP(w, r)
	return w
}

// asA, asB and asAdmin are the three callers every test speaks as.
func (f *tenantFixture) asA(t *testing.T, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	return f.signed(t, f.keyA, f.secretA, method, target, body, headers...)
}

func (f *tenantFixture) asB(t *testing.T, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	return f.signed(t, f.keyB, f.secretB, method, target, body, headers...)
}

func (f *tenantFixture) asAdmin(t *testing.T, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	return f.signed(t, adminKeyID, adminSecret, method, target, body, headers...)
}

func mustCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, status, w.Body.String())
	}
	if code == "" {
		return
	}
	if got := errorCode(t, w); got != code {
		t.Fatalf("error code = %q, want %q", got, code)
	}
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

func TestTenantCredentialAuthenticates(t *testing.T) {
	f := newTenantFixture(t)

	if w := f.asA(t, http.MethodPut, "/ns-a/hello.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("tenant A could not write to its own namespace: %d %s", w.Code, w.Body.String())
	}
}

func TestUnknownAccessKeyIsDenied(t *testing.T) {
	f := newTenantFixture(t)

	// An access key id that was never minted.
	unknown := f.signed(t, "SCASNEVERMINTEDKEY", "whatever", http.MethodGet, "/ns-a/hello.txt", "")
	// A real key with the wrong secret.
	badSig := f.signed(t, f.keyA, "wrong-secret", http.MethodGet, "/ns-a/hello.txt", "")

	if unknown.Code != http.StatusForbidden || badSig.Code != http.StatusForbidden {
		t.Fatalf("unknown key = %d, bad signature = %d; want both 403", unknown.Code, badSig.Code)
	}
	// Both are 403s. The codes differ (AccessDenied vs SignatureDoesNotMatch) —
	// the same distinction AWS makes — so this is not a claim that the two are
	// indistinguishable. What matters is that neither reveals anything about
	// the namespace being addressed, and that an unknown id never resolves to
	// a tenant scope.
	if got := errorCode(t, unknown); got != "AccessDenied" {
		t.Errorf("unknown key code = %q, want AccessDenied", got)
	}
}

func TestRevokedCredentialStopsWorking(t *testing.T) {
	f := newTenantFixture(t)

	if w := f.asA(t, http.MethodPut, "/ns-a/hello.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d", w.Code)
	}
	if err := f.g.db.DeleteS3Credential(t.Context(), f.tenantA, f.keyA); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	mustCode(t, f.asA(t, http.MethodGet, "/ns-a/hello.txt", ""), http.StatusForbidden, "AccessDenied")
}

// A tenant_credentials row carrying the admin key id must not be able to
// impersonate the admin credential — nor demote it to a tenant scope.
func TestAdminKeyCannotBeShadowedByATenantRow(t *testing.T) {
	f := newTenantFixture(t)

	err := f.g.db.CreateS3Credential(t.Context(), f.tenantB, adminKeyID, "attacker-chosen-secret", "shadow")
	if err != nil {
		t.Fatalf("plant shadow row: %v", err)
	}

	// Signing with the attacker's secret must fail: the admin branch is
	// matched on the id first and verifies against the configured secret.
	shadowed := f.signed(t, adminKeyID, "attacker-chosen-secret", http.MethodGet, "/ns-a/", "")
	if shadowed.Code == http.StatusOK {
		t.Fatal("a planted tenant_credentials row impersonated the admin credential")
	}

	// And the real admin credential still works, at admin scope.
	if w := f.asAdmin(t, http.MethodHead, "/ns-a/", ""); w.Code != http.StatusOK {
		t.Fatalf("admin credential broke: %d %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Namespace visibility
// ---------------------------------------------------------------------------

func TestListBucketsIsScopedToTheCredentialsTenant(t *testing.T) {
	f := newTenantFixture(t)
	mustCreateNamespace(t, f.g.db, "ns-unowned", nil)

	var listing listAllMyBucketsResult
	decode(t, f.asA(t, http.MethodGet, "/", ""), &listing)

	var names []string
	for _, b := range listing.Buckets.Bucket {
		names = append(names, b.Name)
	}
	if len(names) != 1 || names[0] != "ns-a" {
		t.Fatalf("tenant A sees buckets %v, want only [ns-a]", names)
	}

	// The admin credential still sees every namespace, owned or not.
	var adminListing listAllMyBucketsResult
	decode(t, f.asAdmin(t, http.MethodGet, "/", ""), &adminListing)
	if len(adminListing.Buckets.Bucket) != 3 {
		t.Fatalf("admin sees %d buckets, want 3", len(adminListing.Buckets.Bucket))
	}
}

func TestAnotherTenantsNamespaceLooksMissing(t *testing.T) {
	f := newTenantFixture(t)
	if w := f.asB(t, http.MethodPut, "/ns-b/secret.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d", w.Code)
	}

	// Every level of addressing must agree that ns-b does not exist for A.
	// NoSuchBucket, never AccessDenied: a 403 would confirm it is there.
	for _, tc := range []struct {
		name   string
		method string
		target string
		body   string
	}{
		{"HeadBucket", http.MethodHead, "/ns-b/", ""},
		{"ListObjects", http.MethodGet, "/ns-b/?list-type=2", ""},
		{"GetObject", http.MethodGet, "/ns-b/secret.txt", ""},
		{"HeadObject", http.MethodHead, "/ns-b/secret.txt", ""},
		{"PutObject", http.MethodPut, "/ns-b/planted.txt", "xyz"},
		{"DeleteObject", http.MethodDelete, "/ns-b/secret.txt", ""},
		{"DeleteBucket", http.MethodDelete, "/ns-b/", ""},
		{"InitiateMultipart", http.MethodPost, "/ns-b/big.bin?uploads", ""},
		{"ListMultipartUploads", http.MethodGet, "/ns-b/?uploads", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.asA(t, tc.method, tc.target, tc.body)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
			}
		})
	}

	// The object is untouched: nothing above was allowed to delete it.
	if w := f.asB(t, http.MethodGet, "/ns-b/secret.txt", ""); w.Body.String() != "abc" {
		t.Fatalf("tenant B's object was disturbed: %q", w.Body.String())
	}
}

func TestUnownedNamespacesAreInvisibleToTenantCredentials(t *testing.T) {
	f := newTenantFixture(t)
	mustCreateNamespace(t, f.g.db, "ns-unowned", nil)
	if w := f.asAdmin(t, http.MethodPut, "/ns-unowned/admin.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("admin setup write failed: %d %s", w.Code, w.Body.String())
	}

	mustCode(t, f.asA(t, http.MethodGet, "/ns-unowned/admin.txt", ""), http.StatusNotFound, "NoSuchBucket")
	mustCode(t, f.asA(t, http.MethodHead, "/ns-unowned/", ""), http.StatusNotFound, "")
}

// ---------------------------------------------------------------------------
// The blob-referencing paths
// ---------------------------------------------------------------------------

// Copy is the sharpest edge: it names a source bucket in a header, so before
// scoping it was a way to pull any tenant's object into your own namespace
// knowing only its bucket and key.
func TestCrossTenantCopyIsRefused(t *testing.T) {
	f := newTenantFixture(t)
	if w := f.asB(t, http.MethodPut, "/ns-b/secret.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d", w.Code)
	}

	// A names B's bucket as the copy source.
	stolen := f.asA(t, http.MethodPut, "/ns-a/stolen.txt", "",
		"x-amz-copy-source", "/ns-b/secret.txt")
	mustCode(t, stolen, http.StatusNotFound, "NoSuchBucket")

	// And nothing landed in A.
	mustCode(t, f.asA(t, http.MethodGet, "/ns-a/stolen.txt", ""), http.StatusNotFound, "NoSuchKey")

	// The reverse direction — pushing into another tenant's namespace — is
	// refused on the destination for the same reason.
	pushed := f.asA(t, http.MethodPut, "/ns-b/planted.txt", "",
		"x-amz-copy-source", "/ns-a/whatever.txt")
	if pushed.Code != http.StatusNotFound {
		t.Fatalf("push into another tenant = %d, want 404", pushed.Code)
	}
}

func TestSameTenantCopyStillWorks(t *testing.T) {
	f := newTenantFixture(t)
	mustCreateNamespace(t, f.g.db, "ns-a2", &f.tenantA)

	if w := f.asA(t, http.MethodPut, "/ns-a/source.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d", w.Code)
	}
	copied := f.asA(t, http.MethodPut, "/ns-a2/dest.txt", "",
		"x-amz-copy-source", "/ns-a/source.txt")
	if copied.Code != http.StatusOK {
		t.Fatalf("copy within one tenant = %d, want 200 (body: %s)", copied.Code, copied.Body.String())
	}
	if got := f.asA(t, http.MethodGet, "/ns-a2/dest.txt", "").Body.String(); got != "abc" {
		t.Fatalf("copied body = %q, want abc", got)
	}
}

// Batch delete resolves the bucket once and then loops over keys, so it needs
// its own check that the resolution is scoped.
func TestCrossTenantBatchDeleteIsRefused(t *testing.T) {
	f := newTenantFixture(t)
	if w := f.asB(t, http.MethodPut, "/ns-b/secret.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d", w.Code)
	}

	body := `<Delete><Object><Key>secret.txt</Key></Object></Delete>`
	mustCode(t, f.asA(t, http.MethodPost, "/ns-b/?delete", body), http.StatusNotFound, "NoSuchBucket")

	if got := f.asB(t, http.MethodGet, "/ns-b/secret.txt", "").Body.String(); got != "abc" {
		t.Fatalf("tenant B's object was deleted across the boundary: %q", got)
	}
}

// Physical dedup is global and must stay that way: isolation is about what a
// tenant can *refer to*, not about storing the same bytes twice.
func TestDedupStillSharesBytesAcrossTenants(t *testing.T) {
	f := newTenantFixture(t)

	if w := f.asA(t, http.MethodPut, "/ns-a/same.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("A write failed: %d", w.Code)
	}
	if w := f.asB(t, http.MethodPut, "/ns-b/same.txt", "abc"); w.Code != http.StatusOK {
		t.Fatalf("B write failed: %d", w.Code)
	}

	// One blob row, two references: both tenants uploaded the bytes they
	// already had, so sharing them physically leaks nothing.
	var count, refcount int64
	err := f.pool.QueryRow(t.Context(),
		"SELECT COUNT(*), COALESCE(SUM(refcount), 0) FROM blobs WHERE hash = $1", abcHash).
		Scan(&count, &refcount)
	if err != nil {
		t.Fatalf("query blobs: %v", err)
	}
	if count != 1 || refcount != 2 {
		t.Fatalf("blob rows = %d, refcount = %d; want 1 row at refcount 2", count, refcount)
	}
}

// ---------------------------------------------------------------------------
// Creation attribution
// ---------------------------------------------------------------------------

func TestBucketCreatedByATenantCredentialIsOwnedByThatTenant(t *testing.T) {
	f := newTenantFixture(t)

	if w := f.asA(t, http.MethodPut, "/ns-a-new/", ""); w.Code != http.StatusOK {
		t.Fatalf("create = %d (body: %s)", w.Code, w.Body.String())
	}

	ns, err := f.g.db.GetNamespace(t.Context(), "ns-a-new")
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	if ns.TenantID == nil || *ns.TenantID != f.tenantA {
		t.Fatalf("tenant_id = %v, want %d", ns.TenantID, f.tenantA)
	}

	// Which means the other tenant cannot reach it, and A can.
	mustCode(t, f.asB(t, http.MethodHead, "/ns-a-new/", ""), http.StatusNotFound, "")
	if w := f.asA(t, http.MethodHead, "/ns-a-new/", ""); w.Code != http.StatusOK {
		t.Fatalf("creator cannot reach its own bucket: %d", w.Code)
	}
}

func TestBucketCreatedByTheAdminCredentialStaysUnowned(t *testing.T) {
	f := newTenantFixture(t)

	if w := f.asAdmin(t, http.MethodPut, "/ns-admin-new/", ""); w.Code != http.StatusOK {
		t.Fatalf("create = %d (body: %s)", w.Code, w.Body.String())
	}
	ns, err := f.g.db.GetNamespace(t.Context(), "ns-admin-new")
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	if ns.TenantID != nil {
		t.Fatalf("tenant_id = %v, want nil", *ns.TenantID)
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

// Multipart spans several requests, and the upload id is the only thing tying
// them together — so each step has to re-resolve the namespace in scope rather
// than trust the id.
func TestMultipartIsScopedAtEveryStep(t *testing.T) {
	f := newTenantFixture(t)

	var initiated initiateMultipartUploadResult
	decode(t, f.asB(t, http.MethodPost, "/ns-b/big.bin?uploads", ""), &initiated)
	if initiated.UploadID == "" {
		t.Fatal("no upload id")
	}
	upload := initiated.UploadID

	// Tenant A, holding B's upload id, cannot advance it at any step.
	mustCode(t, f.asA(t, http.MethodPut, "/ns-b/big.bin?partNumber=1&uploadId="+upload, "abc"),
		http.StatusNotFound, "NoSuchBucket")
	mustCode(t, f.asA(t, http.MethodGet, "/ns-b/big.bin?uploadId="+upload, ""),
		http.StatusNotFound, "NoSuchBucket")
	mustCode(t, f.asA(t, http.MethodDelete, "/ns-b/big.bin?uploadId="+upload, ""),
		http.StatusNotFound, "NoSuchBucket")

	manifest := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`
	mustCode(t, f.asA(t, http.MethodPost, "/ns-b/big.bin?uploadId="+upload, manifest),
		http.StatusNotFound, "NoSuchBucket")

	// B can still finish its own upload.
	if w := f.asB(t, http.MethodPut, "/ns-b/big.bin?partNumber=1&uploadId="+upload, "abc"); w.Code != http.StatusOK {
		t.Fatalf("owner could not upload a part: %d %s", w.Code, w.Body.String())
	}
	if w := f.asB(t, http.MethodPost, "/ns-b/big.bin?uploadId="+upload, manifest); w.Code != http.StatusOK {
		t.Fatalf("owner could not complete: %d %s", w.Code, w.Body.String())
	}
	if got := f.asB(t, http.MethodGet, "/ns-b/big.bin", "").Body.String(); got != "abc" {
		t.Fatalf("completed body = %q, want abc", got)
	}
}
