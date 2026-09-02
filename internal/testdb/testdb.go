// Package testdb provisions an isolated Postgres schema per test.
//
// Tests across several packages share one database, and `go test ./...` runs
// packages concurrently, so a fixture that truncated shared tables would have
// them stomping on each other. Instead each test gets its own schema, created
// on entry and dropped on exit: no truncation, no cross-test interference, and
// tests within a package are free to run in parallel too.
//
// It imports testing because it is only ever used from tests; nothing in the
// server binary references it.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// EnvVar names the database the tests run against. When it is unset the
// database-backed tests skip, so `go test ./...` works with no services.
const EnvVar = "SIMPLECAS_TEST_DATABASE_URL"

// URL returns a connection string scoped to a freshly created, empty schema.
// The schema is dropped when the test finishes.
//
// Migrations therefore run per test, against an empty schema, which also means
// every test exercises the migration path rather than trusting a shared one.
func URL(t *testing.T) string {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		t.Skipf("set %s to run the database tests", EnvVar)
	}

	schema := "test_" + randomSuffix(t)
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to %s: %v", EnvVar, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	// The name is generated from crypto/rand hex, so it needs no quoting
	// beyond the identifier quotes.
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		conn, err := pgx.Connect(cleanupCtx, base)
		if err != nil {
			t.Logf("could not connect to drop schema %s: %v", schema, err)
			return
		}
		defer func() { _ = conn.Close(cleanupCtx) }()
		if _, err := conn.Exec(cleanupCtx, `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Logf("could not drop schema %s: %v", schema, err)
		}
	})

	scoped, err := withSearchPath(base, schema)
	if err != nil {
		t.Fatalf("build scoped DSN: %v", err)
	}
	return scoped
}

// withSearchPath adds search_path to the DSN's parameters. pgx forwards
// unrecognised query parameters as startup runtime settings, so every
// connection the pool opens lands in the right schema.
func withSearchPath(base, schema string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", EnvVar, err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return hex.EncodeToString(buf[:])
}
