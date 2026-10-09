package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// StoredSecret is a per-tenant S3 secret as the row holds it: sealed under a
// named server key, or — for a key minted before sealing, on a server that has
// not yet started with keys configured — still in plaintext. Exactly one form
// is set; the table's CHECK constraint guarantees it. This package never seals
// or opens anything: the keys live in the gateway's configuration.
type StoredSecret struct {
	Plaintext *string
	KeyID     *string
	Sealed    []byte
}

// S3Credential is a per-tenant S3 access key with its stored secret. It is
// returned only to the gateway, which needs the secret to re-derive a SigV4
// signing key; nothing user-facing hands the secret back out after the one
// response that creates it.
type S3Credential struct {
	AccessKeyID string
	TenantID    int64
	Secret      StoredSecret
	// LastUsedAt is nil for a key that has never verified a request.
	LastUsedAt *time.Time
}

// NewS3Credential is a key to store. The secret arrives already sealed.
type NewS3Credential struct {
	AccessKeyID string
	TenantID    int64
	KeyID       string
	Sealed      []byte
	Description string
	// CreatedBy is the minting user, or nil when nobody signed in did.
	CreatedBy *int64
	// ExpiresAt is nil for a key that never expires.
	ExpiresAt *time.Time
}

// S3CredentialInfo is the listing projection: everything except the secret.
type S3CredentialInfo struct {
	AccessKeyID string
	Description string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	// CreatedBy is the minting user's address, or "" when it is not known.
	CreatedBy string
}

// LookupS3Credential resolves an access key id to its secret and owning tenant.
// ok is false for an unknown or expired key, which the gateway reports as
// access denied without distinguishing it from a bad signature.
func (d *DB) LookupS3Credential(ctx context.Context, accessKeyID string) (S3Credential, bool, error) {
	var c S3Credential
	err := d.pool.QueryRow(ctx, `
		SELECT access_key_id, tenant_id, secret_access_key, secret_key_id, secret_sealed, last_used_at
		FROM tenant_credentials
		WHERE access_key_id = $1 AND (expires_at IS NULL OR expires_at > now())`,
		accessKeyID).Scan(&c.AccessKeyID, &c.TenantID,
		&c.Secret.Plaintext, &c.Secret.KeyID, &c.Secret.Sealed, &c.LastUsedAt)
	switch {
	case err == nil:
		return c, true, nil
	case notFound(err):
		return S3Credential{}, false, nil
	default:
		return S3Credential{}, false, apperr.Internal(err)
	}
}

// CreateS3Credential stores a freshly minted key.
func (d *DB) CreateS3Credential(ctx context.Context, c NewS3Credential) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO tenant_credentials
		    (access_key_id, tenant_id, secret_key_id, secret_sealed, description, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.AccessKeyID, c.TenantID, c.KeyID, c.Sealed, c.Description, c.CreatedBy, c.ExpiresAt)
	return apperr.Internal(err)
}

// ListS3Credentials returns tenantID's keys, newest first, without secrets.
// Expired keys are listed too, so an owner can see why one stopped working.
func (d *DB) ListS3Credentials(ctx context.Context, tenantID int64) ([]S3CredentialInfo, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT c.access_key_id, c.description, c.created_at, c.expires_at, c.last_used_at,
		       COALESCE(u.email, '')
		FROM tenant_credentials c
		LEFT JOIN users u ON u.id = c.created_by
		WHERE c.tenant_id = $1
		ORDER BY c.created_at DESC, c.access_key_id`, tenantID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[S3CredentialInfo])
	return out, apperr.Internal(err)
}

// TouchS3Credential records that a key just verified a request. The update
// re-checks the stored time, so concurrent requests that all saw a stale value
// write it once between them; callers skip the call entirely while the value
// they looked up is fresh.
func (d *DB) TouchS3Credential(ctx context.Context, accessKeyID string, touchAfter time.Duration) error {
	_, err := d.pool.Exec(ctx, `
		UPDATE tenant_credentials SET last_used_at = now()
		WHERE access_key_id = $1
		  AND (last_used_at IS NULL OR last_used_at < now() - make_interval(secs => $2))`,
		accessKeyID, touchAfter.Seconds())
	return apperr.Internal(err)
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

// S3CredentialsToSeal returns every key whose secret is not sealed under
// currentKeyID: plaintext ones, and ones sealed under an older key. Expired
// keys are included, since they are still secret material at rest.
func (d *DB) S3CredentialsToSeal(ctx context.Context, currentKeyID string) ([]S3Credential, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT access_key_id, tenant_id, secret_access_key, secret_key_id, secret_sealed, last_used_at
		FROM tenant_credentials
		WHERE secret_key_id IS DISTINCT FROM $1
		ORDER BY access_key_id`, currentKeyID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (S3Credential, error) {
		var c S3Credential
		err := row.Scan(&c.AccessKeyID, &c.TenantID,
			&c.Secret.Plaintext, &c.Secret.KeyID, &c.Secret.Sealed, &c.LastUsedAt)
		return c, err
	})
	return out, apperr.Internal(err)
}

// ResealS3Credential replaces a key's stored secret with one sealed under
// keyID, provided the row still holds from. ok is false when it does not —
// another instance resealed it first, or the key was revoked — which is not
// an error: either way there is nothing left to do for this row.
func (d *DB) ResealS3Credential(ctx context.Context, accessKeyID string, from StoredSecret, keyID string, sealed []byte) (ok bool, err error) {
	tag, err := d.pool.Exec(ctx, `
		UPDATE tenant_credentials
		SET secret_access_key = NULL, secret_key_id = $2, secret_sealed = $3
		WHERE access_key_id = $1
		  AND secret_access_key IS NOT DISTINCT FROM $4
		  AND secret_key_id IS NOT DISTINCT FROM $5
		  AND secret_sealed IS NOT DISTINCT FROM $6`,
		accessKeyID, keyID, sealed, from.Plaintext, from.KeyID, from.Sealed)
	if err != nil {
		return false, apperr.Internal(err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountS3CredentialSecrets reports how many keys hold a plaintext secret and
// how many a sealed one, which is what a server started without
// auth.credential_keys checks before serving.
func (d *DB) CountS3CredentialSecrets(ctx context.Context) (plaintext, sealed int64, err error) {
	err = d.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE secret_access_key IS NOT NULL),
		       count(*) FILTER (WHERE secret_sealed IS NOT NULL)
		FROM tenant_credentials`).Scan(&plaintext, &sealed)
	if err != nil {
		return 0, 0, apperr.Internal(err)
	}
	return plaintext, sealed, nil
}
