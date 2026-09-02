package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockKey is an arbitrary but fixed advisory-lock key. Instances are
// stateless and start in parallel, so without this two of them could try to
// create the same table at the same time.
const migrationLockKey int64 = 0x5121_ca5_0001

// migration is one embedded SQL file.
type migration struct {
	version int64
	name    string
	sql     string
}

// migrate brings the schema up to date, applying each pending migration in its
// own transaction so a failure leaves the recorded history consistent with what
// actually ran.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	// Hold the lock on one dedicated connection for the whole run; a pooled
	// query could otherwise unlock on a different session than it locked.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	_, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		    version    BIGINT PRIMARY KEY,
		    name       TEXT NOT NULL,
		    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	if err := adoptSqlxHistory(ctx, conn); err != nil {
		return err
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
				m.version, m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

// adoptSqlxHistory carries over the migration history written by the previous
// (sqlx-based) implementation, so an existing deployment does not try to re-run
// migrations it has already applied. Safe to keep indefinitely; it is a no-op
// once the legacy table is gone.
func adoptSqlxHistory(ctx context.Context, conn *pgxpool.Conn) error {
	_, err := conn.Exec(ctx, `
		INSERT INTO schema_migrations (version, name)
		SELECT version, COALESCE(description, 'adopted')
		FROM _sqlx_migrations
		WHERE success
		ON CONFLICT (version) DO NOTHING`)
	if err != nil {
		// The legacy table simply does not exist on a fresh database. Any
		// other failure is worth surfacing.
		if isUndefinedTable(err) {
			return nil
		}
		return fmt.Errorf("adopt sqlx migration history: %w", err)
	}
	return nil
}

func appliedVersions(ctx context.Context, conn *pgxpool.Conn) (map[int64]bool, error) {
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// loadMigrations reads the embedded SQL files, ordered by version. Names follow
// <version>_<name>.sql, e.g. 0001_init.sql.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}

	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		versionStr, name, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q is not named <version>_<name>.sql", e.Name())
		}
		version, err := strconv.ParseInt(versionStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migration %q has a non-numeric version: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile(path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

// isUndefinedTable reports whether err is Postgres's "relation does not exist".
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
