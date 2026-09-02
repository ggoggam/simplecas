package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// S3 credentials are minted here so a team can point ordinary S3 tooling at
// the gateway and reach only its own namespaces. See internal/s3/principal.go
// for how a key resolves to a tenant scope on the way in.
//
// Minting and revoking are owner-only. A credential is full read/write access
// to every namespace the tenant owns, so handing one out is closer to adding an
// owner than to adding a member — there are no per-namespace or read-only keys.

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
// server needs it verbatim to verify SigV4 signatures, so it is stored
// recoverably and never re-displayed.
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
	AccessKeyID string    `json:"access_key_id"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// createdCredentialJSON is the create response, and the only time the secret
// is ever sent.
type createdCredentialJSON struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Description     string `json:"description"`
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
		})
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	// The body is optional: a label is a convenience, not a requirement.
	var req struct {
		Description string `json:"description"`
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

	accessKeyID, secret, err := generateCredential()
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.CreateS3Credential(r.Context(), tenantID, accessKeyID, secret, description); err != nil {
		h.writeError(w, r, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, createdCredentialJSON{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secret,
		Description:     description,
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
