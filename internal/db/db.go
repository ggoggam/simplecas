// Package db is the Postgres metadata store: namespaces, tenants, the global
// blob table with its refcounts, objects, multipart uploads, and the queries
// the garbage collector runs.
//
// Every server instance is stateless and shares this database, so the
// concurrency-sensitive operations (claiming and releasing blob references,
// sweeping unreferenced blobs) are written to be safe with N servers and a
// concurrent GC. The row locks are load-bearing — see ClaimBlob and GCSweep.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is a handle on the metadata store.
type DB struct {
	pool *pgxpool.Pool
}

// Connect opens the pool and brings the schema up to date. It fails fast on an
// unreachable database so a misconfigured instance never starts serving.
func Connect(ctx context.Context, url string, maxConns int32) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = maxConns

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases every pooled connection.
func (d *DB) Close() {
	d.pool.Close()
}

// InTx runs fn inside a transaction, committing on success and rolling back on
// any error or panic. Exported because the content-addressed write path has to
// interleave storage writes with the transaction that claims the blob — see
// cas.Store.Commit.
func (d *DB) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	// A Rollback after a successful Commit is a no-op, so this covers both the
	// error paths and an early return that forgot to unwind.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// Row types
//
// The list queries below are collected with pgx.RowToStructByPos, so each
// struct's field order must match its SELECT list column for column. Reordering
// fields without reordering the query is a silent mismatch.
// ---------------------------------------------------------------------------

// Namespace is an S3 bucket in gateway terms.
type Namespace struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	// TenantID is the owning tenant, or nil for an unowned namespace — one
	// created with the S3 superuser credential, or predating tenancy. Unowned
	// namespaces are invisible to tenant-scoped callers, whether they are
	// scoped by a signed-in user's membership or by an S3 key's tenant.
	TenantID *int64
}

// ObjectMeta is one stored object's metadata. BlobHash doubles as the ETag.
type ObjectMeta struct {
	Key         string
	BlobHash    string
	Size        int64
	ContentType string
	UpdatedAt   time.Time
}

// PartMeta is one staged multipart part.
type PartMeta struct {
	PartNumber int32
	StagingKey string
	Size       int64
	ETag       string
}

// MultipartUpload is an in-flight multipart upload.
type MultipartUpload struct {
	ID          uuid.UUID
	NamespaceID int64
	Key         string
	ContentType string
}

// MultipartUploadEntry is the listing projection of an in-flight upload.
type MultipartUploadEntry struct {
	ID        uuid.UUID
	Key       string
	CreatedAt time.Time
}

// TenantMembership is a tenant the caller belongs to, with their role in it.
type TenantMembership struct {
	Name      string
	Role      string
	CreatedAt time.Time
}

// Member is one row of a tenant's membership list.
type Member struct {
	Email     string
	Role      string
	CreatedAt time.Time
}

// Stats is the dedup accounting the admin API reports. The JSON names are part
// of the API contract the bundled PWA reads.
type Stats struct {
	NamespaceCount int64 `json:"namespace_count"`
	ObjectCount    int64 `json:"object_count"`
	BlobCount      int64 `json:"blob_count"`
	LogicalBytes   int64 `json:"logical_bytes"`
	PhysicalBytes  int64 `json:"physical_bytes"`
}

// notFound reports whether err is pgx's no-rows sentinel, which several
// lookups translate into a domain-level "does not exist" error.
func notFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
