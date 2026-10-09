package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/s3"
)

// S3 credentials are minted here so a team can point ordinary S3 tooling at
// the gateway and reach only its own namespaces. See internal/s3/principal.go
// for how a key resolves to a tenant scope on the way in.
//
// Minting and revoking are owner-only. A key minted without a scope is full
// read/write access to every namespace the tenant owns, now and later, so
// handing one out is closer to adding an owner than to adding a member. A scope
// narrows it: to some of read, list, write and delete, and to named namespaces
// (see s3.Permission for what each permission covers). A key can also be given
// an expiry when it is minted, after which it verifies nothing; it stays listed
// until an owner revokes it. A scope cannot be changed after minting: mint a
// new key and revoke the old one.

// maxCredentialDays caps a key's lifetime when one is asked for. A key that
// should outlive this is a key minted without an expiry.
const maxCredentialDays = 3650

// accessKeyIDBytes and secretBytes size the generated credential. The shapes
// mirror AWS's (a short opaque id, a long high-entropy secret) because clients
// and their config files are written expecting roughly these lengths.
const (
	accessKeyIDBytes = 12
	secretBytes      = 30
)

// accessKeyPrefix marks a key as this server's, so one found in a config file
// is identifiable at a glance.
const accessKeyPrefix = "SCAS"

// generateCredential mints an access key id and its secret.
//
// The id is base32 so it survives being pasted into places that mangle case,
// which is what AWS-style tooling expects of an access key id. The secret is
// base64 and is shown exactly once, in the response that creates it: the
// server needs it verbatim to verify SigV4 signatures, so it is stored sealed
// rather than hashed (see s3.StoreCredential) and never re-displayed.
func generateCredential() (accessKeyID, secret string, err error) {
	idRaw := make([]byte, accessKeyIDBytes)
	if _, err := rand.Read(idRaw); err != nil {
		return "", "", apperr.Internalf("generate access key id: %w", err)
	}
	secretRaw := make([]byte, secretBytes)
	if _, err := rand.Read(secretRaw); err != nil {
		return "", "", apperr.Internalf("generate secret key: %w", err)
	}

	id := accessKeyPrefix + base32Upper(idRaw)
	return id, base64.RawURLEncoding.EncodeToString(secretRaw), nil
}

// base32Upper renders bytes as unpadded uppercase base32 (RFC 4648 alphabet).
func base32Upper(raw []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b strings.Builder
	// Five bytes of input produce eight characters of output; the input length
	// is a multiple of four here, so a partial final group is handled by
	// flushing whatever bits remain.
	var acc uint32
	var bits int
	for _, c := range raw {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			b.WriteByte(alphabet[(acc>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		b.WriteByte(alphabet[(acc<<uint(5-bits))&0x1f])
	}
	return b.String()
}

type credentialJSON struct {
	AccessKeyID string     `json:"access_key_id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	// CreatedBy is the minting owner's address, or "" when it is not known.
	CreatedBy   string   `json:"created_by"`
	Permissions []string `json:"permissions"`
	// Namespaces is null for a key that reaches every namespace.
	Namespaces []string `json:"namespaces"`
}

// createdCredentialJSON is the create response, and the only time the secret
// is ever sent.
type createdCredentialJSON struct {
	AccessKeyID     string     `json:"access_key_id"`
	SecretAccessKey string     `json:"secret_access_key"`
	Description     string     `json:"description"`
	ExpiresAt       *time.Time `json:"expires_at"`
	Permissions     []string   `json:"permissions"`
	Namespaces      []string   `json:"namespaces"`
}

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	creds, err := h.db.ListS3Credentials(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	out := make([]credentialJSON, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialJSON{
			AccessKeyID: c.AccessKeyID,
			Description: c.Description,
			CreatedAt:   c.CreatedAt,
			ExpiresAt:   c.ExpiresAt,
			LastUsedAt:  c.LastUsedAt,
			CreatedBy:   c.CreatedBy,
			Permissions: c.Permissions,
			Namespaces:  c.Namespaces,
		})
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createCredential(w http.ResponseWriter, r *http.Request) {
	access, err := h.authorizeTenantAccess(r, r.PathValue("tenant"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if access.role != "owner" {
		h.writeError(w, r, apperr.Forbidden("owner role required"))
		return
	}

	// The body is optional: a label, an expiry and a scope are conveniences,
	// not requirements. A missing expiry is a key that never expires, missing
	// permissions are all of them, and missing namespaces are every one the
	// team owns. An empty list of either is refused rather than read as
	// "all", so a client that meant to grant nothing never grants everything.
	var req struct {
		Description   string          `json:"description"`
		ExpiresInDays *int            `json:"expires_in_days"`
		Permissions   []s3.Permission `json:"permissions"`
		Namespaces    []string        `json:"namespaces"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > 200 {
		h.writeError(w, r, apperr.InvalidArgument("description must be 200 characters or fewer"))
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInDays != nil {
		days := *req.ExpiresInDays
		if days < 1 || days > maxCredentialDays {
			h.writeError(w, r, apperr.InvalidArgument(
				"expires_in_days must be between 1 and %d; omit it for a key that does not expire", maxCredentialDays))
			return
		}
		// Truncated so the stored and returned times agree to the
		// microsecond Postgres keeps.
		at := time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC().Truncate(time.Microsecond)
		expiresAt = &at
	}

	accessKeyID, secret, err := generateCredential()
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	scope, err := h.gateway.StoreCredential(r.Context(), s3.Credential{
		AccessKeyID: accessKeyID,
		Secret:      secret,
		TenantID:    access.id,
		Description: description,
		CreatedBy:   &access.user.ID,
		ExpiresAt:   expiresAt,
		Permissions: req.Permissions,
		Namespaces:  req.Namespaces,
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, createdCredentialJSON{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secret,
		Description:     description,
		ExpiresAt:       expiresAt,
		Permissions:     scope.Permissions,
		Namespaces:      scope.Namespaces,
	})
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	// DeleteS3Credential has the tenant in its predicate, so a key belonging to
	// another tenant reports NotFound rather than being revoked.
	if err := h.db.DeleteS3Credential(r.Context(), tenantID, r.PathValue("accessKeyId")); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
