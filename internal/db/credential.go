package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// S3Credential is a per-tenant S3 access key, including its secret. It is
// returned only by LookupS3Credential, which the SigV4 check calls to
// re-derive a signing key; nothing user-facing hands the secret back out after
// the one response that creates it.
type S3Credential struct {
	AccessKeyID     string
	SecretAccessKey string
	TenantID        int64
}

// S3CredentialInfo is the listing projection: everything except the secret.
type S3CredentialInfo struct {
	AccessKeyID string
	Description string
	CreatedAt   time.Time
}

// LookupS3Credential resolves an access key id to its secret and owning tenant.
// ok is false for an unknown key, which the gateway reports as access denied
// without distinguishing it from a bad signature.
func (d *DB) LookupS3Credential(ctx context.Context, accessKeyID string) (S3Credential, bool, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT access_key_id, secret_access_key, tenant_id
		FROM tenant_credentials WHERE access_key_id = $1`, accessKeyID)
	if err != nil {
		return S3Credential{}, false, apperr.Internal(err)
	}
	cred, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[S3Credential])
	if notFound(err) {
		return S3Credential{}, false, nil
	}
	if err != nil {
		return S3Credential{}, false, apperr.Internal(err)
	}
	return cred, true, nil
}

// CreateS3Credential stores a freshly minted key for tenantID.
func (d *DB) CreateS3Credential(ctx context.Context, tenantID int64, accessKeyID, secret, description string) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO tenant_credentials
		    (access_key_id, secret_access_key, tenant_id, description)
		VALUES ($1, $2, $3, $4)`,
		accessKeyID, secret, tenantID, description)
	return apperr.Internal(err)
}

// ListS3Credentials returns tenantID's keys, newest first, without secrets.
func (d *DB) ListS3Credentials(ctx context.Context, tenantID int64) ([]S3CredentialInfo, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT access_key_id, description, created_at
		FROM tenant_credentials WHERE tenant_id = $1
		ORDER BY created_at DESC, access_key_id`, tenantID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[S3CredentialInfo])
	return out, apperr.Internal(err)
}

// DeleteS3Credential revokes a key. The tenant is part of the predicate, so an
// owner of one tenant cannot revoke another tenant's key by guessing its id.
// Revoking a key that is not theirs (or not there) reports NotFound rather than
// succeeding silently, so the UI can tell a real revocation from a no-op.
func (d *DB) DeleteS3Credential(ctx context.Context, tenantID int64, accessKeyID string) error {
	tag, err := d.pool.Exec(ctx,
		"DELETE FROM tenant_credentials WHERE tenant_id = $1 AND access_key_id = $2",
		tenantID, accessKeyID)
	if err != nil {
		return apperr.Internal(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNoSuchCredential
	}
	return nil
}
