package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// testDB hands back a DB over a schema created for this test alone, so tests
// in different packages cannot interfere. Without SIMPLECAS_TEST_DATABASE_URL
// the database-backed tests skip, so `go test ./...` stays runnable with no
// services; `mise run test:integration` starts the dev Postgres and sets it.
func testDB(t *testing.T) *DB {
	t.Helper()
	d, err := Connect(t.Context(), testdb.URL(t), 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// mustNamespace creates a namespace and returns its id.
func mustNamespace(t *testing.T, d *DB, name string, tenantID *int64) int64 {
	t.Helper()
	if err := d.CreateNamespace(t.Context(), name, tenantID); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	ns, err := d.GetNamespace(t.Context(), name)
	if err != nil {
		t.Fatalf("get namespace %s: %v", name, err)
	}
	return ns.ID
}

// putObject stages a blob reference and points a key at it, the way the CAS
// write path does.
func putObject(t *testing.T, d *DB, nsID int64, key, hash string, size int64) {
	t.Helper()
	err := d.InTx(t.Context(), func(tx pgx.Tx) error {
		if _, err := ClaimBlob(t.Context(), tx, hash, size); err != nil {
			return err
		}
		return UpsertObject(t.Context(), tx, nsID, key, hash, size, "application/octet-stream")
	})
	if err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// refcount reads a blob's current reference count, or ok=false if the row is gone.
func refcount(t *testing.T, d *DB, hash string) (int64, bool) {
	t.Helper()
	var n int64
	err := d.pool.QueryRow(t.Context(), "SELECT refcount FROM blobs WHERE hash = $1", hash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("read refcount: %v", err)
	}
	return n, true
}

// hashOf builds a distinct 64-hex-character digest per test fixture.
func hashOf(seed string) string {
	h := fmt.Sprintf("%x", seed)
	for len(h) < 64 {
		h += "0"
	}
	return h[:64]
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

// The embedded files have to parse and be uniquely versioned even without a
// database, so this one always runs.
func TestLoadMigrations(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(ms) < 2 {
		t.Fatalf("expected the init and tenancy migrations, got %d", len(ms))
	}
	if ms[0].version != 1 || ms[0].name != "init" {
		t.Errorf("first migration = %d_%s", ms[0].version, ms[0].name)
	}
	for i, m := range ms {
		if m.sql == "" {
			t.Errorf("migration %d has empty SQL", m.version)
		}
		if i > 0 && m.version <= ms[i-1].version {
			t.Errorf("migrations are not strictly ordered at index %d", i)
		}
	}
}

// Connect runs migrations, so connecting twice must be a no-op the second time.
func TestMigrateIsIdempotent(t *testing.T) {
	dsn := testdb.URL(t)
	d, err := Connect(t.Context(), dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer d.Close()

	second, err := Connect(t.Context(), dsn, 4)
	if err != nil {
		t.Fatalf("second connect should be a no-op: %v", err)
	}
	defer second.Close()

	var applied int
	if err := d.pool.QueryRow(t.Context(), "SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	ms, _ := loadMigrations()
	if applied != len(ms) {
		t.Errorf("schema_migrations has %d rows, want %d", applied, len(ms))
	}
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

func TestNamespaceLifecycle(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	if err := d.CreateNamespace(ctx, "alpha", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.CreateNamespace(ctx, "alpha", nil); !errors.Is(err, apperr.ErrNamespaceAlreadyExists) {
		t.Errorf("duplicate create = %v, want ErrNamespaceAlreadyExists", err)
	}

	ns, err := d.GetNamespace(ctx, "alpha")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ns.Name != "alpha" || ns.TenantID != nil {
		t.Errorf("namespace = %+v, want an unowned namespace named alpha", ns)
	}
	if ns.CreatedAt.IsZero() {
		t.Error("created_at was not populated")
	}

	if _, err := d.GetNamespace(ctx, "missing"); !errors.Is(err, apperr.ErrNoSuchNamespace) {
		t.Errorf("get missing = %v, want ErrNoSuchNamespace", err)
	}

	if err := d.DeleteNamespace(ctx, "alpha"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := d.DeleteNamespace(ctx, "alpha"); !errors.Is(err, apperr.ErrNoSuchNamespace) {
		t.Errorf("delete missing = %v, want ErrNoSuchNamespace", err)
	}
}

// S3 semantics: a namespace holding objects is a conflict, never a cascade.
func TestDeleteNamespaceRefusesWhenOccupied(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	id := mustNamespace(t, d, "occupied", nil)
	putObject(t, d, id, "a.txt", hashOf("a"), 3)

	if err := d.DeleteNamespace(ctx, "occupied"); !errors.Is(err, apperr.ErrNamespaceNotEmpty) {
		t.Fatalf("delete occupied = %v, want ErrNamespaceNotEmpty", err)
	}
	// Still there, and the object with it.
	if _, err := d.GetNamespace(ctx, "occupied"); err != nil {
		t.Errorf("namespace should have survived: %v", err)
	}

	if _, err := d.DeleteObject(ctx, id, "a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteNamespace(ctx, "occupied"); err != nil {
		t.Errorf("delete after emptying: %v", err)
	}
}

func TestListNamespaces(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	tenantA, err := d.CreateTenant(ctx, "team-a", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := d.CreateTenant(ctx, "team-b", "b@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mustNamespace(t, d, "zeta", &tenantA)
	mustNamespace(t, d, "alpha", &tenantB)
	mustNamespace(t, d, "unowned", nil)

	all, err := d.ListNamespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("global listing returned %d namespaces, want 3", len(all))
	}
	if all[0].Name != "alpha" || all[2].Name != "zeta" {
		t.Errorf("global listing is not name-ordered: %v", names(all))
	}

	// The tenant plane sees only its own, and never the unowned namespace.
	scoped, err := d.ListNamespacesForTenants(ctx, []int64{tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].Name != "zeta" {
		t.Errorf("tenant-scoped listing = %v, want [zeta]", names(scoped))
	}

	// No memberships at all must not leak the unowned namespace either.
	none, err := d.ListNamespacesForTenants(ctx, []int64{})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("empty tenant set returned %v, want nothing", names(none))
	}
}

func names(ns []Namespace) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.Name
	}
	return out
}

// A namespace the caller cannot reach must be indistinguishable from one that
// does not exist, so the tenant plane never leaks its existence.
func TestGetNamespaceForMemberHidesEverythingElse(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	mine, err := d.CreateTenant(ctx, "mine", "me@example.com")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := d.CreateTenant(ctx, "theirs", "them@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mustNamespace(t, d, "ours", &mine)
	mustNamespace(t, d, "hidden", &theirs)
	mustNamespace(t, d, "unowned", nil)

	if _, err := d.GetNamespaceForMember(ctx, "ours", "me@example.com"); err != nil {
		t.Errorf("a member should resolve their own namespace: %v", err)
	}

	for _, name := range []string{"hidden", "unowned", "does-not-exist"} {
		if _, err := d.GetNamespaceForMember(ctx, name, "me@example.com"); !errors.Is(err, apperr.ErrNoSuchNamespace) {
			t.Errorf("%s resolved to %v, want ErrNoSuchNamespace", name, err)
		}
	}
}
