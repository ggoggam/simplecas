// Package api is the JSON admin API the bundled PWA consumes. It covers the
// same ground as the S3 gateway with a friendlier wire format.
//
// Authorization: when OIDC is enabled the guard middleware attaches the
// caller's session to each request, and every namespace is scoped to the tenant
// that owns it — a caller sees and touches only namespaces belonging to a team
// they are a member of. Namespaces with no tenant (those created with the S3
// superuser credential) are invisible here.
//
// This plane also mints the per-team S3 credentials the gateway authenticates;
// see credential.go.
//
// When OIDC is disabled there is no caller and this is the unauthenticated
// full-access plane it has always been: put it behind ingress auth or bind it
// privately. config.Validate refuses a non-loopback bind in that mode unless
// server.insecure_open_api says something in front has been arranged.
//
// The JSON field names below are the contract with the PWA (see
// web/src/lib/api.ts). Renaming one breaks the UI silently, and list responses
// must serialise as [] rather than null for the same reason.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/s3"
)

// maxJSONBody caps the request bodies parsed as JSON (the multipart completion
// manifest is the largest of them).
const maxJSONBody = 8 << 20

// listing defaults and caps for the object listing endpoint.
const (
	defaultListMax = 500
	maxListMax     = 1000
	maxPartNumber  = 10000
)

// Handler serves the admin API.
type Handler struct {
	db  *db.DB
	cas *cas.Store
	// gateway serves object downloads, so /api and the S3 gateway share one
	// read path rather than two that can drift.
	gateway *s3.Gateway
	log     *slog.Logger
}

// New returns a Handler over the given store.
func New(database *db.DB, store *cas.Store, gateway *s3.Gateway, log *slog.Logger) *Handler {
	return &Handler{db: database, cas: store, gateway: gateway, log: log}
}

// Routes returns the API's routes. The object endpoints use a trailing wildcard
// because keys are hierarchical.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", h.stats)

	mux.HandleFunc("GET /api/tenants", h.listTenants)
	mux.HandleFunc("POST /api/tenants", h.createTenant)
	mux.HandleFunc("DELETE /api/tenants/{tenant}", h.deleteTenant)
	mux.HandleFunc("GET /api/tenants/{tenant}/members", h.listMembers)
	mux.HandleFunc("PATCH /api/tenants/{tenant}/members/{user}", h.setMemberRole)
	mux.HandleFunc("DELETE /api/tenants/{tenant}/members/{user}", h.removeMember)

	mux.HandleFunc("GET /api/tenants/{tenant}/invitations", h.listInvitations)
	mux.HandleFunc("POST /api/tenants/{tenant}/invitations", h.createInvitation)
	mux.HandleFunc("DELETE /api/tenants/{tenant}/invitations/{email}", h.revokeInvitation)

	mux.HandleFunc("GET /api/invitations", h.myInvitations)
	mux.HandleFunc("POST /api/invitations/{tenant}/accept", h.acceptInvitation)
	mux.HandleFunc("POST /api/invitations/{tenant}/decline", h.declineInvitation)

	mux.HandleFunc("GET /api/tenants/{tenant}/credentials", h.listCredentials)
	mux.HandleFunc("POST /api/tenants/{tenant}/credentials", h.createCredential)
	mux.HandleFunc("DELETE /api/tenants/{tenant}/credentials/{accessKeyId}", h.deleteCredential)

	mux.HandleFunc("GET /api/namespaces", h.listNamespaces)
	mux.HandleFunc("POST /api/namespaces", h.createNamespace)
	mux.HandleFunc("DELETE /api/namespaces/{namespace}", h.deleteNamespace)
	mux.HandleFunc("GET /api/namespaces/{namespace}/objects", h.listObjects)

	mux.HandleFunc("GET /api/namespaces/{namespace}/objects/{key...}", h.getObject)
	mux.HandleFunc("PUT /api/namespaces/{namespace}/objects/{key...}", h.putObject)
	mux.HandleFunc("POST /api/namespaces/{namespace}/objects/{key...}", h.postObject)
	mux.HandleFunc("DELETE /api/namespaces/{namespace}/objects/{key...}", h.deleteObject)

	return h.identify(mux)
}

// ---------------------------------------------------------------------------
// Response plumbing
// ---------------------------------------------------------------------------

// writeJSON sends v as the response body.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.log.Warn("could not write JSON response", "err", err)
	}
}

// writeError renders err as the API's {code, message} body, logging the
// internal ones.
func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if e := apperr.From(err); e.IsInternal() {
		h.log.Error("admin api error", "method", r.Method, "path", r.URL.Path,
			"requestId", w.Header().Get(apperr.RequestIDHeader), "err", err)
	}
	apperr.WriteJSON(w, err)
}

// decodeJSON parses a bounded request body.
func decodeJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody))
	if err != nil {
		return apperr.InvalidArgument("%v", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apperr.InvalidArgument("%v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// userContextKey carries the caller's users row down to the handlers.
type userContextKey struct{}

// identify maps the signed-in identity the guard attached to its users row,
// creating the row on first sight, so every handler authorizes on a user id.
// With no session (OIDC off) the request passes through untouched and is
// served by the untenanted plane.
func (h *Handler) identify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := auth.FromContext(r.Context())
		if session == nil {
			next.ServeHTTP(w, r)
			return
		}
		if session.Issuer == "" || session.Subject == "" {
			h.writeError(w, r, apperr.Forbidden("the session carries no identity"))
			return
		}
		user, err := h.db.ResolveUser(r.Context(),
			session.Issuer, session.Subject, session.VerifiedEmail(), session.Name)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	})
}

// requireUser returns the signed-in caller, or a 403 on the untenanted plane,
// where there is nobody for a team to belong to.
func requireUser(r *http.Request) (db.User, error) {
	user, ok := r.Context().Value(userContextKey{}).(db.User)
	if !ok {
		return db.User{}, apperr.Forbidden("sign-in is required")
	}
	return user, nil
}

// authorizeNamespace resolves a namespace, enforcing tenant membership when
// there is a caller.
//
// With no caller (OIDC disabled) any namespace resolves. With a caller, only
// namespaces owned by a tenant they belong to resolve; everything else —
// missing, unowned, or another tenant's — is NoSuchNamespace, so existence
// never leaks across tenants.
func (h *Handler) authorizeNamespace(r *http.Request, name string) (db.Namespace, error) {
	if auth.FromContext(r.Context()) == nil {
		return h.db.GetNamespace(r.Context(), name)
	}
	user, err := requireUser(r)
	if err != nil {
		return db.Namespace{}, err
	}
	return h.db.GetNamespaceForMember(r.Context(), name, user.ID)
}

// tenantAccess is what authorizeTenantAccess establishes: which tenant, who is
// asking, and the role they hold in it.
type tenantAccess struct {
	id   int64
	user db.User
	role string
}

// authorizeTenantAccess resolves a tenant by name and the caller's role in it.
// A non-member gets NoSuchTenant, hiding its existence.
func (h *Handler) authorizeTenantAccess(r *http.Request, name string) (tenantAccess, error) {
	user, err := requireUser(r)
	if err != nil {
		return tenantAccess{}, err
	}
	tenantID, err := h.db.TenantIDByName(r.Context(), name)
	if err != nil {
		return tenantAccess{}, err
	}
	role, ok, err := h.db.TenantRole(r.Context(), tenantID, user.ID)
	if err != nil {
		return tenantAccess{}, err
	}
	if !ok {
		return tenantAccess{}, apperr.ErrNoSuchTenant
	}
	return tenantAccess{id: tenantID, user: user, role: role}, nil
}

// authorizeTenant is authorizeTenantAccess for the common case: when needOwner
// is set, a member who is not an owner gets a 403.
func (h *Handler) authorizeTenant(r *http.Request, name string, needOwner bool) (int64, error) {
	access, err := h.authorizeTenantAccess(r, name)
	if err != nil {
		return 0, err
	}
	if needOwner && access.role != "owner" {
		return 0, apperr.Forbidden("owner role required")
	}
	return access.id, nil
}

// validName is the shared naming rule for tenants and namespaces (the S3
// bucket-name shape).
func validName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		lower := c >= 'a' && c <= 'z'
		digit := c >= '0' && c <= '9'
		if !lower && !digit && c != '-' && c != '.' {
			return false
		}
	}
	return isAlphanumeric(name[0]) && isAlphanumeric(name[len(name)-1])
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// statsResponse embeds db.Stats so its fields inline into this object, matching
// the PWA's flat Stats type.
type statsResponse struct {
	db.Stats
	DedupRatio float64 `json:"dedup_ratio"`
	SavedBytes int64   `json:"saved_bytes"`
}

func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	var (
		stats db.Stats
		err   error
	)
	if auth.FromContext(r.Context()) != nil {
		// A signed-in caller sees only their own teams' footprint.
		var ids []int64
		ids, err = h.callerTenantIDs(r)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		stats, err = h.db.StatsForTenants(r.Context(), ids)
	} else {
		stats, err = h.db.Stats(r.Context())
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	// With nothing stored the ratio is 1.0, not a division by zero.
	ratio := 1.0
	if stats.PhysicalBytes > 0 {
		ratio = float64(stats.LogicalBytes) / float64(stats.PhysicalBytes)
	}
	h.writeJSON(w, http.StatusOK, statsResponse{
		Stats:      stats,
		DedupRatio: ratio,
		SavedBytes: stats.LogicalBytes - stats.PhysicalBytes,
	})
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

type tenantJSON struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// callerTenantIDs returns the ids of the teams the signed-in caller belongs to.
func (h *Handler) callerTenantIDs(r *http.Request) ([]int64, error) {
	user, err := requireUser(r)
	if err != nil {
		return nil, err
	}
	return h.db.TenantIDsForUser(r.Context(), user.ID)
}

func (h *Handler) listTenants(w http.ResponseWriter, r *http.Request) {
	user, err := requireUser(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	tenants, err := h.db.ListTenantsForUser(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	out := make([]tenantJSON, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, tenantJSON{Name: t.Name, Role: t.Role, CreatedAt: t.CreatedAt})
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createTenant(w http.ResponseWriter, r *http.Request) {
	user, err := requireUser(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, err)
		return
	}
	if !validName(req.Name) {
		h.writeError(w, r, apperr.ErrInvalidTenantName)
		return
	}
	if _, err := h.db.CreateTenant(r.Context(), req.Name, user.ID); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) deleteTenant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.DeleteTenant(r.Context(), tenantID); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

type namespaceJSON struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *Handler) listNamespaces(w http.ResponseWriter, r *http.Request) {
	var (
		namespaces []db.Namespace
		err        error
	)
	session := auth.FromContext(r.Context())
	switch {
	case session == nil:
		namespaces, err = h.db.ListNamespaces(r.Context())

	case r.URL.Query().Get("tenant") != "":
		// Scoped to one team, which requires membership in it.
		var tenantID int64
		tenantID, err = h.authorizeTenant(r, r.URL.Query().Get("tenant"), false)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		namespaces, err = h.db.ListNamespacesForTenants(r.Context(), []int64{tenantID})

	default:
		// Every team the caller belongs to.
		var ids []int64
		ids, err = h.callerTenantIDs(r)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		namespaces, err = h.db.ListNamespacesForTenants(r.Context(), ids)
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	out := make([]namespaceJSON, 0, len(namespaces))
	for _, ns := range namespaces {
		out = append(out, namespaceJSON{Name: ns.Name, CreatedAt: ns.CreatedAt})
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createNamespace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		// Tenant names the owning team. Required when signed in; ignored on
		// the unauthenticated plane, where namespaces are unowned.
		Tenant string `json:"tenant"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, err)
		return
	}
	if !validName(req.Name) {
		h.writeError(w, r, apperr.ErrInvalidNamespaceName)
		return
	}

	var tenantID *int64
	if auth.FromContext(r.Context()) != nil {
		if req.Tenant == "" {
			h.writeError(w, r, apperr.InvalidArgument("tenant is required"))
			return
		}
		id, err := h.authorizeTenant(r, req.Tenant, false)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		tenantID = &id
	}

	if err := h.db.CreateNamespace(r.Context(), req.Name, tenantID); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) deleteNamespace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("namespace")
	if _, err := h.authorizeNamespace(r, name); err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.DeleteNamespace(r.Context(), name); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

type objectJSON struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	ContentType  string    `json:"content_type"`
	LastModified time.Time `json:"last_modified"`
}

type listResponse struct {
	Objects        []objectJSON `json:"objects"`
	CommonPrefixes []string     `json:"common_prefixes"`
	// NextToken is null on the last page.
	NextToken *string `json:"next_token"`
}

func (h *Handler) listObjects(w http.ResponseWriter, r *http.Request) {
	ns, err := h.authorizeNamespace(r, r.PathValue("namespace"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	query := r.URL.Query()

	delimiter, err := parseDelimiter(query.Get("delimiter"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	marker := ""
	if token := query.Get("token"); token != "" {
		marker, err = db.DecodeMarker(token)
		if err != nil {
			h.writeError(w, r, apperr.InvalidArgument("bad token"))
			return
		}
	}

	limit := defaultListMax
	if raw := query.Get("max"); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			limit = min(maxListMax, max(1, n))
		}
	}

	listing, err := h.db.ListObjects(r.Context(), ns.ID, query.Get("prefix"), delimiter, marker, limit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	// Empty slices, never nil: the PWA types these as arrays.
	out := listResponse{
		Objects:        make([]objectJSON, 0, len(listing.Objects)),
		CommonPrefixes: listing.CommonPrefixes,
	}
	for _, o := range listing.Objects {
		out.Objects = append(out.Objects, objectJSON{
			Key:          o.Key,
			Size:         o.Size,
			ETag:         o.BlobHash,
			ContentType:  o.ContentType,
			LastModified: o.UpdatedAt,
		})
	}
	if listing.IsTruncated {
		token := db.EncodeMarker(listing.NextMarker)
		out.NextToken = &token
	}
	h.writeJSON(w, http.StatusOK, out)
}

// parseDelimiter accepts a single printable-ASCII delimiter, matching the
// gateway's rule (see db.ListObjects for why the range is bounded).
func parseDelimiter(raw string) (byte, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) != 1 || raw[0] < 0x20 || raw[0] > 0x7e {
		return 0, apperr.InvalidArgument("delimiter must be one printable ASCII character")
	}
	return raw[0], nil
}

// resolveContentType prefers the client's declared type, falling back to a
// guess from the key's extension so a browser download renders sensibly.
func resolveContentType(r *http.Request, key string) string {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		return ct
	}
	if guessed := mime.TypeByExtension(filepath.Ext(key)); guessed != "" {
		// Drop any charset parameter: only the essence type is stored.
		if essence, _, err := mime.ParseMediaType(guessed); err == nil {
			return essence
		}
		return guessed
	}
	return "application/octet-stream"
}

// getObject serves a download, or lists an in-progress upload's parts when
// ?uploadId is given (which is how the PWA resumes one).
func (h *Handler) getObject(w http.ResponseWriter, r *http.Request) {
	namespace, key := r.PathValue("namespace"), r.PathValue("key")
	ns, err := h.authorizeNamespace(r, namespace)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	if rawUploadID := r.URL.Query().Get("uploadId"); rawUploadID != "" {
		uploadID, err := parseUploadID(rawUploadID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		upload, err := h.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		parts, err := h.db.ListParts(r.Context(), upload.ID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		out := make([]map[string]any, 0, len(parts))
		for _, p := range parts {
			out = append(out, map[string]any{
				"part_number": p.PartNumber,
				"etag":        p.ETag,
				"size":        p.Size,
			})
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"parts": out})
		return
	}

	// The gateway supplies the read path for both planes; it takes the row
	// this handler already authorized rather than resolving the name again,
	// so /api's membership check is the only authorization that applies.
	//
	// The bytes are user content, so they carry the gateway's content-safety
	// headers rather than the API's (see internal/server/headers.go). The
	// API's policy would also refuse the frame the PWA previews a PDF in.
	w.Header().Del("Content-Security-Policy")
	w.Header().Del("X-Frame-Options")
	h.gateway.ServeObject(w, r, ns, key)
}

// putObject dispatches a PUT: upload a part (?uploadId&partNumber), link an
// already-stored blob by hash (?link=<hash>, empty body — the dedup fast path),
// or a plain whole-object upload.
func (h *Handler) putObject(w http.ResponseWriter, r *http.Request) {
	namespace, key := r.PathValue("namespace"), r.PathValue("key")
	ns, err := h.authorizeNamespace(r, namespace)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	query := r.URL.Query()

	if uploadID, partNumber := query.Get("uploadId"), query.Get("partNumber"); uploadID != "" && partNumber != "" {
		h.uploadPart(w, r, ns, key, uploadID, partNumber)
		return
	}
	if hash := query.Get("link"); hash != "" {
		h.linkObject(w, r, ns, key, hash)
		return
	}

	contentType := resolveContentType(r, key)
	etag, size, err := h.cas.Put(r.Context(), ns.ID, key, contentType, r.Body, r.ContentLength)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"key": key, "etag": etag, "size": size,
	})
}

// linkObject points key at content that is already stored, transferring no
// bytes. It answers {linked: true, …} on a dedup hit, and 404 NoSuchKey
// otherwise, so the client uploads the bytes for real.
//
// Dedup is global, but a link only succeeds for content the caller's own team
// already holds. Every miss — a hash nobody stores, or one only another team
// stores — gets the same 404 with the same body: if those two answers differed
// in any way, this endpoint would tell a caller what other teams have stored.
func (h *Handler) linkObject(w http.ResponseWriter, r *http.Request, ns db.Namespace, key, hash string) {
	contentType := resolveContentType(r, key)
	size, linked, err := h.cas.LinkBlob(r.Context(), ns.ID, key, hash, contentType, ns.TenantID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if !linked {
		h.writeError(w, r, apperr.ErrNoSuchKey)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"linked": true, "key": key, "etag": hash, "size": size,
	})
}

func (h *Handler) uploadPart(w http.ResponseWriter, r *http.Request, ns db.Namespace, key, rawUploadID, rawPartNumber string) {
	partNumber, err := strconv.Atoi(rawPartNumber)
	if err != nil || partNumber < 1 || partNumber > maxPartNumber {
		h.writeError(w, r, apperr.InvalidArgument("partNumber must be 1-%d", maxPartNumber))
		return
	}
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	upload, err := h.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	staged, err := h.cas.PutPart(r.Context(), upload, int32(partNumber), r.Body, r.ContentLength)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"part_number": partNumber, "etag": staged.Hash,
	})
}

// postObject dispatches a POST: initiate a multipart upload (?uploads) or
// complete one (?uploadId, with a JSON manifest body).
func (h *Handler) postObject(w http.ResponseWriter, r *http.Request) {
	namespace, key := r.PathValue("namespace"), r.PathValue("key")
	ns, err := h.authorizeNamespace(r, namespace)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	query := r.URL.Query()

	if query.Has("uploads") {
		id, err := h.db.CreateMultipart(r.Context(), ns.ID, key, resolveContentType(r, key))
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"upload_id": id.String()})
		return
	}
	if rawUploadID := query.Get("uploadId"); rawUploadID != "" {
		h.completeMultipart(w, r, ns, key, rawUploadID)
		return
	}
	h.writeError(w, r, apperr.InvalidArgument("missing ?uploads or ?uploadId"))
}

func (h *Handler) completeMultipart(w http.ResponseWriter, r *http.Request, ns db.Namespace, key, rawUploadID string) {
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	upload, err := h.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	var req struct {
		Parts []struct {
			PartNumber int32   `json:"part_number"`
			ETag       *string `json:"etag"`
		} `json:"parts"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, err)
		return
	}

	manifest := make([]cas.ManifestPart, 0, len(req.Parts))
	for _, p := range req.Parts {
		manifest = append(manifest, cas.ManifestPart{PartNumber: p.PartNumber, ETag: p.ETag})
	}

	stored, err := h.db.ListParts(r.Context(), upload.ID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	ordered, err := cas.ResolveManifest(manifest, stored)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	var size int64
	for _, p := range ordered {
		size += p.Size
	}
	etag, err := h.cas.CompleteMultipart(r.Context(), upload, ordered)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"key": key, "etag": etag, "size": size,
	})
}

// deleteObject dispatches a DELETE: abort an in-progress upload (?uploadId) or
// delete the object.
func (h *Handler) deleteObject(w http.ResponseWriter, r *http.Request) {
	namespace, key := r.PathValue("namespace"), r.PathValue("key")
	ns, err := h.authorizeNamespace(r, namespace)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	if rawUploadID := r.URL.Query().Get("uploadId"); rawUploadID != "" {
		uploadID, err := parseUploadID(rawUploadID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		upload, err := h.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		keys, err := h.db.RemoveMultipart(r.Context(), upload.ID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		for _, stagingKey := range keys {
			h.cas.DiscardStaging(r.Context(), stagingKey)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if _, err := h.db.DeleteObject(r.Context(), ns.ID, key); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseUploadID rejects a malformed upload id as an unknown upload.
func parseUploadID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, apperr.ErrNoSuchUpload
	}
	return id, nil
}
