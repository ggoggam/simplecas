package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
)

// Per-team secrets are sealed under the server's auth.credential_keys before
// they reach the database, and opened again only here, to verify a signature.
// Each secret is sealed with its access key id as authenticated context, so a
// sealed secret copied onto another row does not open there.

// credentialTouchInterval is how stale a key's last_used_at may get before a
// verified request refreshes it. It bounds the writes a busy key causes to one
// per interval, at the cost of the listing being that much behind.
const credentialTouchInterval = 5 * time.Minute

// Credential is a per-team S3 key to store.
type Credential struct {
	AccessKeyID string
	Secret      string
	TenantID    int64
	Description string
	// CreatedBy is the minting user, or nil when nobody signed in did.
	CreatedBy *int64
	// ExpiresAt is nil for a key that never expires.
	ExpiresAt *time.Time
	// Permissions is nil for a key that holds every permission.
	Permissions []Permission
	// Namespaces is nil for a key that reaches every namespace the team
	// owns, now and later. Otherwise each must be the team's when minted.
	Namespaces []string
}

// StoreCredential checks c's scope against the team, seals its secret under
// the current credential key, and stores it. It returns the scope as stored. It
// fails without auth.credential_keys, which configuration validation requires
// wherever someone can sign in to mint a key.
func (g *Gateway) StoreCredential(ctx context.Context, c Credential) (db.S3Scope, error) {
	if g.keys == nil {
		return db.S3Scope{}, apperr.Internalf("s3: cannot store a team key: auth.credential_keys is not set")
	}
	scope, err := g.normalizeScope(ctx, c.TenantID, c.Permissions, c.Namespaces)
	if err != nil {
		return db.S3Scope{}, err
	}
	keyID, sealed, err := g.keys.Seal([]byte(c.Secret), []byte(c.AccessKeyID))
	if err != nil {
		return db.S3Scope{}, apperr.Internal(err)
	}
	err = g.db.CreateS3Credential(ctx, db.NewS3Credential{
		AccessKeyID: c.AccessKeyID,
		TenantID:    c.TenantID,
		KeyID:       keyID,
		Sealed:      sealed,
		Description: c.Description,
		CreatedBy:   c.CreatedBy,
		ExpiresAt:   c.ExpiresAt,
		Scope:       scope,
	})
	if err != nil {
		return db.S3Scope{}, err
	}
	return scope, nil
}

// openSecret recovers a stored secret for signature checking.
func (g *Gateway) openSecret(c db.S3Credential) (string, error) {
	if c.Secret.Plaintext != nil {
		// Only a server with no credential keys leaves these in place;
		// SealStoredCredentials seals every one on a start with keys.
		return *c.Secret.Plaintext, nil
	}
	if g.keys == nil || c.Secret.KeyID == nil {
		return "", apperr.Internalf("s3: key %s is sealed but auth.credential_keys is not set", c.AccessKeyID)
	}
	secret, err := g.keys.Open(*c.Secret.KeyID, c.Secret.Sealed, []byte(c.AccessKeyID))
	if err != nil {
		return "", apperr.Internalf("s3: open the secret of key %s: %w", c.AccessKeyID, err)
	}
	return string(secret), nil
}

// touchCredential records a verified use of c, at most once per
// credentialTouchInterval. A failure is logged, not returned: the request was
// verified, and a missed refresh only leaves the listing a little stale.
func (g *Gateway) touchCredential(ctx context.Context, c db.S3Credential) {
	if c.LastUsedAt != nil && time.Since(*c.LastUsedAt) < credentialTouchInterval {
		return
	}
	if err := g.db.TouchS3Credential(ctx, c.AccessKeyID, credentialTouchInterval); err != nil {
		g.log.Warn("could not record an S3 key's use", "accessKeyId", c.AccessKeyID, "err", err)
	}
}

// SealStoredCredentials brings every stored team secret under the current
// credential key: plaintext ones written before sealing existed, and ones
// sealed under a key that has since been rotated out of first place. It runs
// at startup, before the gateway serves, and is safe to run on several
// instances at once.
//
// With no credential keys configured, it seals nothing, and refuses to start
// if any secret is already sealed, since those keys could no longer sign in.
// It also refuses when a secret is sealed under a key the list no longer
// holds: dropping a key before the rows sealed under it were resealed would
// otherwise lock those keys out one request at a time.
func (g *Gateway) SealStoredCredentials(ctx context.Context) error {
	if g.keys == nil {
		plaintext, sealed, err := g.db.CountS3CredentialSecrets(ctx)
		if err != nil {
			return err
		}
		if sealed > 0 {
			return fmt.Errorf("%d team S3 keys are sealed, but auth.credential_keys is not set: "+
				"restore the keys they were sealed under", sealed)
		}
		if plaintext > 0 {
			g.log.Warn("team S3 secrets are stored in plaintext; set auth.credential_keys to seal them",
				"keys", plaintext)
		}
		return nil
	}

	todo, err := g.db.S3CredentialsToSeal(ctx, g.keys.Current())
	if err != nil {
		return err
	}
	resealed := 0
	for _, c := range todo {
		if c.Secret.KeyID != nil && !g.keys.Has(*c.Secret.KeyID) {
			return fmt.Errorf("team S3 key %s is sealed under %q, which auth.credential_keys no longer lists: "+
				"add that key back after the current one until every instance has started once",
				c.AccessKeyID, *c.Secret.KeyID)
		}
		secret, err := g.openSecret(c)
		if err != nil {
			return err
		}
		keyID, sealed, err := g.keys.Seal([]byte(secret), []byte(c.AccessKeyID))
		if err != nil {
			return err
		}
		ok, err := g.db.ResealS3Credential(ctx, c.AccessKeyID, c.Secret, keyID, sealed)
		if err != nil {
			return err
		}
		if ok {
			resealed++
		}
	}
	if resealed > 0 {
		g.log.Info("sealed team S3 secrets under the current credential key",
			"keys", resealed, "keyId", g.keys.Current())
	}
	return nil
}
