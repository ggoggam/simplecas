// Package s3 is the S3-compatible gateway, using path-style addressing.
//
// Supported: ListBuckets, Create/Delete/HeadBucket, GetBucketLocation,
// ListObjects V1 and V2 (prefix, delimiter, pagination), Put/Get/Head/Delete
// Object, CopyObject, DeleteObjects (batch), range GETs, multipart uploads
// (initiate, upload part, upload part copy, list parts, list uploads,
// complete, abort), and GetObjectTagging, which always answers an empty tag set.
//
// ETags are MD5s as S3 computes them: the content's MD5, or for a multipart
// upload the MD5 of its parts' MD5s and "-N". The BLAKE3 digest content is
// stored under is never sent; with global dedup it would identify every
// tenant's copy of the same bytes (see package cas).
// Deliberately unsupported: versioning, ACLs and policies, POST-policy
// uploads, virtual-host addressing, and storing tags.
//
// Authorization: every request is SigV4-verified, signed in its Authorization
// header or as a presigned URL (see sigv4.go), and the credential decides
// what it can address. The key in simplecas.toml is a superuser that reaches
// every namespace; a key from tenant_credentials reaches only its own tenant's
// namespaces, with everything else reported as NoSuchBucket, and its scope may
// narrow that to some of them and to some of read, list, write and delete. See
// principal.go and scope.go — g.authorize is the single chokepoint that turns
// a name from a request into a row, and it takes the action the row is for, so
// no handler here can resolve a namespace outside the caller's scope or act on
// it beyond its permissions. CreateBucket is the one place a name outside the
// scope shows: names are global, so a taken one answers BucketAlreadyExists
// (see nameTaken).
//
// The gateway parses the request path itself rather than going through
// http.ServeMux. ServeMux cleans paths — collapsing "//" and resolving "."
// and ".." segments, with a redirect — and S3 keys may legitimately contain
// those sequences. Routing here therefore works on the escaped path and
// unescapes the namespace and key separately.
package s3

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/reserved"
	"github.com/ggoggam/simplecas/internal/seal"
	"github.com/ggoggam/simplecas/internal/storage"
)

// maxXMLBody caps the request bodies the gateway parses as XML (the batch
// delete and multipart completion manifests).
const maxXMLBody = 8 << 20

// maxKeysLimit and related caps mirror S3's documented maxima.
const (
	maxKeysLimit    = 1000
	maxPartsLimit   = 1000
	maxUploadsLimit = 1000
	maxPartNumber   = 10000
)

// Gateway serves the S3 API over the content-addressed store.
type Gateway struct {
	db   *db.DB
	blob *storage.Bucket
	cas  *cas.Store
	cfg  *config.Config
	log  *slog.Logger
	// keys seals and opens the per-team secrets; nil when
	// auth.credential_keys is unset. See credential.go.
	keys *seal.Keyring
}

// New returns a Gateway over the given store. It panics on malformed
// auth.credential_keys, which config.Validate rejects before this runs.
func New(database *db.DB, bucket *storage.Bucket, store *cas.Store, cfg *config.Config, log *slog.Logger) *Gateway {
	keys, err := cfg.Auth.Keyring()
	if err != nil {
		panic(err)
	}
	return &Gateway{db: database, blob: bucket, cas: store, cfg: cfg, log: log, keys: keys}
}

// ServeHTTP verifies the request signature and resolves the tenant scope its
// credential grants, holds the body to the digests its headers claim (see
// payload.go), then dispatches on the addressed level: service, namespace, or
// object.
//
// The resolved principal rides on the request context from here on, and
// g.authorize is the only way a handler turns a namespace name into a row — so
// every level below this point is scoped by construction.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, signer, err := g.authenticate(r)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	body, err := newPayload(r, signer)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ctx := db.WithActor(withPrincipal(r.Context(), p), db.Actor{
		AccessKeyID: p.accessKeyID,
		RequestID:   w.Header().Get(apperr.RequestIDHeader),
	})
	r = r.WithContext(ctx)
	r.Body = body

	namespace, key, err := splitPath(r.URL.EscapedPath())
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	lvl := levelObject
	switch {
	case namespace == "":
		lvl = levelService
	case key == "":
		lvl = levelNamespace
	}
	// Before dispatch: the dispatchers fall through to the plain operation on
	// a query they don't recognise, so an unimplemented subresource would act
	// on the object or bucket itself. See subresource.go.
	if name := unsupportedSubresource(r.Method, lvl, r.URL.Query()); name != "" {
		g.writeError(w, r, apperr.NotImplemented("the ?%s subresource is not supported for %s", name, r.Method))
		return
	}

	switch lvl {
	case levelService:
		g.serviceDispatch(w, r)
	case levelNamespace:
		g.namespaceDispatch(w, r, namespace)
	default:
		g.objectDispatch(w, r, namespace, key)
	}
}

// splitPath separates "/namespace/key..." into its two parts, unescaping each.
// An empty namespace means the request addressed the service root.
func splitPath(escapedPath string) (namespace, key string, err error) {
	trimmed := strings.TrimPrefix(escapedPath, "/")
	rawNamespace, rawKey, _ := strings.Cut(trimmed, "/")

	namespace, unescapeErr := url.PathUnescape(rawNamespace)
	if unescapeErr != nil {
		return "", "", apperr.InvalidArgument("malformed namespace in path")
	}
	key, unescapeErr = url.PathUnescape(rawKey)
	if unescapeErr != nil {
		return "", "", apperr.InvalidArgument("malformed key in path")
	}
	return namespace, key, nil
}

// writeError renders err as an S3 XML error, logging the internal ones.
func (g *Gateway) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if e := apperr.From(err); e.IsInternal() {
		g.log.Error("s3 gateway error", "method", r.Method, "path", r.URL.Path,
			"requestId", w.Header().Get(apperr.RequestIDHeader), "err", err)
	}
	apperr.WriteXML(w, err)
}

// writeXML sends a rendered wire type. A marshalling failure is a bug in a wire
// type rather than a bad request, so it is logged and reported as a 500.
func (g *Gateway) writeXML(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := render(v)
	if err != nil {
		g.writeError(w, r, apperr.Internalf("render response: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		g.log.Warn("could not write response body", "path", r.URL.Path, "err", err)
	}
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// iso8601 is the timestamp format S3 uses in listings, to milliseconds.
func iso8601(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// httpDate is the RFC 1123 form used for Last-Modified.
func httpDate(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

// quotedETag wraps a digest in the quotes S3 clients expect.
func quotedETag(hash string) string { return `"` + hash + `"` }

// validNamespaceName applies S3's bucket-naming rules.
func validNamespaceName(name string) bool {
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

// contentTypeOf reads the request's declared media type, defaulting to opaque
// bytes.
func contentTypeOf(r *http.Request) string {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// readXMLBody reads a bounded request body for XML parsing. It reads to the
// end, so the body's digests are checked before any of it is acted on, and a
// failed check comes back as itself rather than as malformed XML.
func readXMLBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxXMLBody+1))
	if err != nil {
		if errors.As(err, new(*apperr.Error)) {
			return nil, err
		}
		return nil, apperr.MalformedXML("%v", err)
	}
	if len(body) > maxXMLBody {
		return nil, apperr.MalformedXML("body exceeds %d bytes", maxXMLBody)
	}
	return body, nil
}

// clampInt parses a query parameter into [1, max], falling back to max when it
// is absent or unparseable — which is how S3 treats a missing limit.
func clampInt(raw string, max int) int {
	if raw == "" {
		return max
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return max
	}
	if n < 1 {
		return 1
	}
	if n > max {
		return max
	}
	return n
}

// parseDelimiter validates the delimiter query parameter.
//
// Only a single printable-ASCII byte is accepted. Delimiter grouping walks the
// keyspace by incrementing the delimiter's byte to skip past a group, and
// keeping it inside printable ASCII guarantees the incremented byte is still
// valid UTF-8 — which the resume marker has to be, since it goes back into
// Postgres as text.
func parseDelimiter(raw string) (byte, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) != 1 || raw[0] < 0x20 || raw[0] > 0x7e {
		return 0, apperr.InvalidArgument("only single printable ASCII delimiters are supported")
	}
	return raw[0], nil
}

// parseRange interprets a Range header against a known object size.
//
// present is false for a header this server does not honour (a multi-range
// request, or an unrecognised unit), which RFC 7233 allows to be ignored by
// serving the whole object. A header that is recognised but unsatisfiable is an
// error.
func parseRange(header string, size int64) (start, end int64, present bool, err error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return 0, 0, false, nil
	}
	// S3 honours a single range per request.
	if strings.Contains(spec, ",") {
		return 0, 0, false, nil
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, false, nil
	}
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)

	switch {
	case first == "":
		// A suffix range: the final n bytes.
		n, convErr := strconv.ParseInt(last, 10, 64)
		if convErr != nil || n == 0 {
			return 0, 0, false, apperr.ErrInvalidRange
		}
		start, end = max(size-n, 0), size-1
	case last == "":
		// An open-ended range: from first to the end.
		start, err = parseOffset(first)
		if err != nil {
			return 0, 0, false, err
		}
		end = size - 1
	default:
		start, err = parseOffset(first)
		if err != nil {
			return 0, 0, false, err
		}
		end, err = parseOffset(last)
		if err != nil {
			return 0, 0, false, err
		}
		end = min(end, size-1)
	}

	if start < 0 || start >= size || start > end {
		return 0, 0, false, apperr.ErrInvalidRange
	}
	return start, end, true, nil
}

func parseOffset(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, apperr.ErrInvalidRange
	}
	return n, nil
}

// parseUploadID rejects a malformed upload id as an unknown upload, so a
// client cannot distinguish a typo from someone else's upload.
func parseUploadID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, apperr.ErrNoSuchUpload
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Service level
// ---------------------------------------------------------------------------

func (g *Gateway) serviceDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	g.listNamespaces(w, r)
}

func (g *Gateway) listNamespaces(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		g.writeError(w, r, apperr.Internalf("s3: ListBuckets without authentication"))
		return
	}

	var (
		namespaces []db.Namespace
		err        error
	)
	if p.tenantID != nil {
		namespaces, err = g.db.ListNamespacesForTenants(r.Context(), []int64{*p.tenantID})
	} else {
		namespaces, err = g.db.ListNamespaces(r.Context())
	}
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	entries := make([]bucketEntry, 0, len(namespaces))
	for _, ns := range namespaces {
		// A key limited to some namespaces lists only those, as every
		// other request would answer NoSuchBucket for the rest.
		if !p.reaches(ns.Name) {
			continue
		}
		entries = append(entries, bucketEntry{
			Name:         ns.Name,
			CreationDate: iso8601(ns.CreatedAt),
		})
	}
	g.writeXML(w, r, http.StatusOK, listAllMyBucketsResult{
		Xmlns:   xmlns,
		Owner:   owner{ID: "simplecas", DisplayName: "simplecas"},
		Buckets: buckets{Bucket: entries},
	})
}

// ---------------------------------------------------------------------------
// Namespace level
// ---------------------------------------------------------------------------

func (g *Gateway) namespaceDispatch(w http.ResponseWriter, r *http.Request, namespace string) {
	query := r.URL.Query()

	switch r.Method {
	case http.MethodPut:
		g.createNamespace(w, r, namespace)

	case http.MethodDelete:
		// Resolved in scope first: a tenant must not be able to delete a
		// namespace it cannot address, and an out-of-scope name has to look
		// missing rather than forbidden.
		if _, err := g.authorize(r, namespace, actionDeleteNamespace); err != nil {
			g.writeError(w, r, err)
			return
		}
		if err := g.db.DeleteNamespace(r.Context(), namespace); err != nil {
			g.writeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodHead:
		if _, err := g.authorize(r, namespace, actionLocate); err != nil {
			g.writeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		switch {
		case query.Has("location"), query.Has("versioning"):
			// These say nothing about the namespace's contents, but they
			// still answer only for one the caller reaches, as S3 does.
			if _, err := g.authorize(r, namespace, actionLocate); err != nil {
				g.writeError(w, r, err)
				return
			}
			if query.Has("location") {
				g.writeXML(w, r, http.StatusOK, locationConstraint{
					Xmlns:  xmlns,
					Region: g.cfg.Server.Region,
				})
				return
			}
			g.writeXML(w, r, http.StatusOK, versioningConfiguration{Xmlns: xmlns})
		case query.Has("uploads"):
			g.listMultipartUploads(w, r, namespace, query)
		default:
			g.listObjects(w, r, namespace, query)
		}

	case http.MethodPost:
		if query.Has("delete") {
			g.deleteObjects(w, r, namespace)
			return
		}
		w.Header().Set("Allow", "GET, PUT, HEAD, DELETE, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)

	default:
		w.Header().Set("Allow", "GET, PUT, HEAD, DELETE, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) createNamespace(w http.ResponseWriter, r *http.Request, namespace string) {
	if !validNamespaceName(namespace) {
		g.writeError(w, r, apperr.ErrInvalidNamespaceName)
		return
	}
	if reserved.Name(namespace) {
		g.writeError(w, r, apperr.ErrReservedNamespaceName)
		return
	}
	// A tenanted credential owns what it creates, so the namespace is visible
	// to that team in /ui and /api too. The admin credential has no tenant
	// identity to attribute, so its namespaces stay unowned.
	p, err := permit(r.Context(), namespace, actionCreateNamespace)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	if err := g.db.CreateNamespace(r.Context(), namespace, p.tenantID); err != nil {
		if errors.Is(err, apperr.ErrNamespaceAlreadyExists) {
			err = g.nameTaken(r, namespace)
		}
		g.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/"+namespace)
	w.WriteHeader(http.StatusOK)
}

// nameTaken answers a CreateBucket whose name already exists. As on S3, names
// are global, so the clash itself reveals that the name is in use; the answer
// says no more than that unless the namespace is the caller's.
//
// "The caller's" means the name resolves through g.authorize, the same scope
// every other request is held to: a team key owns its team's namespaces, and
// the admin credential, which addresses every namespace, owns them all.
// BucketAlreadyOwnedByYou tells a create-if-missing client it can go ahead and
// use the bucket, which is true exactly when g.authorize would serve it.
func (g *Gateway) nameTaken(r *http.Request, name string) error {
	_, err := g.authorize(r, name, actionLocate)
	switch {
	case err == nil:
		return apperr.ErrNamespaceAlreadyOwned
	case errors.Is(err, apperr.ErrNoSuchNamespace):
		// A team key clashing with another team's namespace or an unowned
		// one. Also a namespace deleted since the insert clashed, which is
		// gone either way.
		return apperr.ErrNamespaceAlreadyExists
	default:
		return err
	}
}

func (g *Gateway) listObjects(w http.ResponseWriter, r *http.Request, namespace string, query url.Values) {
	ns, err := g.authorize(r, namespace, actionList)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	v2 := query.Get("list-type") == "2"
	prefix := query.Get("prefix")
	delimiter, err := parseDelimiter(query.Get("delimiter"))
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	maxKeys := clampInt(query.Get("max-keys"), maxKeysLimit)

	marker, err := listStartMarker(query, v2)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	listing, err := g.db.ListObjects(r.Context(), ns.ID, prefix, delimiter, marker, maxKeys)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	result := listBucketResult{
		Xmlns:       xmlns,
		Name:        namespace,
		Prefix:      prefix,
		MaxKeys:     maxKeys,
		KeyCount:    len(listing.Objects) + len(listing.CommonPrefixes),
		IsTruncated: listing.IsTruncated,
	}
	if delimiter != 0 {
		d := string(delimiter)
		result.Delimiter = &d
	}

	if v2 {
		if token := query.Get("continuation-token"); token != "" {
			result.ContinuationToken = &token
		}
		if listing.IsTruncated {
			next := encodeToken(listing.NextMarker)
			result.NextContinuationToken = &next
		}
	} else {
		result.Marker = &marker
		if listing.IsTruncated {
			// V1 falls back to the last returned key when the listing has no
			// marker of its own.
			next := listing.NextMarker
			if next == "" && len(listing.Objects) > 0 {
				next = listing.Objects[len(listing.Objects)-1].Key
			}
			result.NextMarker = &next
		}
	}

	result.Contents = make([]contents, 0, len(listing.Objects))
	for _, o := range listing.Objects {
		result.Contents = append(result.Contents, contents{
			Key:          o.Key,
			LastModified: iso8601(o.UpdatedAt),
			ETag:         quotedETag(o.ETag()),
			Size:         o.Size,
			StorageClass: "STANDARD",
		})
	}
	result.CommonPrefixes = make([]commonPrefix, 0, len(listing.CommonPrefixes))
	for _, p := range listing.CommonPrefixes {
		result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix{Prefix: p})
	}

	g.writeXML(w, r, http.StatusOK, result)
}

// listStartMarker resolves where a listing resumes from. V2 uses an opaque
// base64 continuation token (or start-after on the first page); V1 uses a raw
// marker.
func listStartMarker(query url.Values, v2 bool) (string, error) {
	if !v2 {
		return query.Get("marker"), nil
	}
	if token := query.Get("continuation-token"); token != "" {
		marker, err := decodeToken(token)
		if err != nil {
			return "", apperr.InvalidArgument("bad continuation-token")
		}
		return marker, nil
	}
	return query.Get("start-after"), nil
}

func (g *Gateway) deleteObjects(w http.ResponseWriter, r *http.Request, namespace string) {
	ns, err := g.authorize(r, namespace, actionDelete)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	raw, err := readXMLBody(r)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	var req deleteRequest
	if err := unmarshalXML(raw, &req); err != nil {
		g.writeError(w, r, err)
		return
	}

	deleted := make([]deletedEntry, 0, len(req.Objects))
	var failures []deleteErrorEntry
	for _, entry := range req.Objects {
		if _, err := g.db.DeleteObject(r.Context(), ns.ID, entry.Key); err != nil {
			e := apperr.From(err)
			failures = append(failures, deleteErrorEntry{
				Key:     entry.Key,
				Code:    e.S3Code(),
				Message: e.Error(),
			})
			continue
		}
		// S3 reports an absent key as deleted too: DELETE is idempotent.
		// The request and response entries carry the same single Key field,
		// so a conversion says it without restating the field.
		deleted = append(deleted, deletedEntry(entry))
	}
	if req.Quiet {
		deleted = nil
	}

	g.writeXML(w, r, http.StatusOK, deleteResult{
		Xmlns:   xmlns,
		Deleted: deleted,
		Errors:  failures,
	})
}

// ---------------------------------------------------------------------------
// Object level
// ---------------------------------------------------------------------------

func (g *Gateway) objectDispatch(w http.ResponseWriter, r *http.Request, namespace, key string) {
	query := r.URL.Query()

	switch r.Method {
	case http.MethodPut:
		partNumber, uploadID := query.Get("partNumber"), query.Get("uploadId")
		switch {
		case partNumber != "" && uploadID != "":
			if r.Header.Get("x-amz-copy-source") != "" {
				g.uploadPartCopy(w, r, namespace, key, partNumber, uploadID)
				return
			}
			g.uploadPart(w, r, namespace, key, partNumber, uploadID)
		case r.Header.Get("x-amz-copy-source") != "":
			g.copyObject(w, r, namespace, key)
		default:
			g.putObject(w, r, namespace, key)
		}

	case http.MethodGet:
		if uploadID := query.Get("uploadId"); uploadID != "" {
			g.listParts(w, r, namespace, key, uploadID, query)
			return
		}
		if query.Has("tagging") {
			g.getObjectTagging(w, r, namespace, key)
			return
		}
		g.serveObject(w, r, namespace, key, false)

	case http.MethodHead:
		g.serveObject(w, r, namespace, key, true)

	case http.MethodDelete:
		if uploadID := query.Get("uploadId"); uploadID != "" {
			g.abortMultipart(w, r, namespace, key, uploadID)
			return
		}
		g.deleteObject(w, r, namespace, key)

	case http.MethodPost:
		switch {
		case query.Has("uploads"):
			g.initiateMultipart(w, r, namespace, key)
		case query.Get("uploadId") != "":
			g.completeMultipart(w, r, namespace, key, query.Get("uploadId"))
		default:
			w.Header().Set("Allow", "GET, PUT, HEAD, DELETE, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}

	default:
		w.Header().Set("Allow", "GET, PUT, HEAD, DELETE, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) putObject(w http.ResponseWriter, r *http.Request, namespace, key string) {
	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	etag, _, err := g.cas.Put(r.Context(), ns.ID, key, contentTypeOf(r), r.Body, declaredLength(r))
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quotedETag(etag))
	setChecksumHeaders(w, r)
	w.WriteHeader(http.StatusOK)
}

// copyObject is a pure metadata operation under content addressing: the
// destination claims another reference to the source blob, and no bytes move.
//
// Source and destination are both resolved in the caller's scope, so a tenanted
// credential can only copy within its own tenant. Naming another tenant's
// bucket as the source fails as NoSuchBucket — without this, copy would be a
// way to pull any tenant's object into your own namespace by name. The source
// needs read and the destination write, so a key cannot copy its way around
// either.
func (g *Gateway) copyObject(w http.ResponseWriter, r *http.Request, dstNamespace, dstKey string) {
	src, err := g.copySource(r)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	dstNS, err := g.authorize(r, dstNamespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	// COPY (the default) keeps the source's metadata; REPLACE takes it from
	// this request instead. Content-Type is the only metadata stored, so it
	// is all REPLACE can change. `aws s3 cp --content-type` between buckets
	// relies on this.
	switch r.Header.Get("x-amz-metadata-directive") {
	case "", "COPY":
	case "REPLACE":
		src.ContentType = contentTypeOf(r)
	default:
		g.writeError(w, r, apperr.InvalidArgument("x-amz-metadata-directive must be COPY or REPLACE"))
		return
	}

	etag, err := g.cas.CopyObject(r.Context(), src, dstNS.ID, dstKey)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	g.writeXML(w, r, http.StatusOK, copyObjectResult{
		Xmlns:        xmlns,
		LastModified: iso8601(time.Now()),
		ETag:         quotedETag(etag),
	})
}

// copySource resolves the object x-amz-copy-source names, in the caller's
// scope like any other namespace, for reading.
func (g *Gateway) copySource(r *http.Request) (db.ObjectMeta, error) {
	source, err := url.PathUnescape(r.Header.Get("x-amz-copy-source"))
	if err != nil {
		return db.ObjectMeta{}, apperr.InvalidArgument("bad x-amz-copy-source")
	}
	srcNamespace, srcKey, ok := strings.Cut(strings.TrimPrefix(source, "/"), "/")
	if !ok || srcKey == "" {
		return db.ObjectMeta{}, apperr.InvalidArgument("x-amz-copy-source must be bucket/key")
	}
	srcNS, err := g.authorize(r, srcNamespace, actionRead)
	if err != nil {
		return db.ObjectMeta{}, err
	}
	return g.db.GetObject(r.Context(), srcNS.ID, srcKey)
}

// getObjectTagging answers an empty tag set for an existing object. Tags are
// not stored, but the AWS CLI asks for them before every s3-to-s3 copy, and a
// refusal there fails the copy itself.
func (g *Gateway) getObjectTagging(w http.ResponseWriter, r *http.Request, namespace, key string) {
	ns, err := g.authorize(r, namespace, actionRead)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	if _, err := g.db.GetObject(r.Context(), ns.ID, key); err != nil {
		g.writeError(w, r, err)
		return
	}
	g.writeXML(w, r, http.StatusOK, tagging{Xmlns: xmlns})
}

func (g *Gateway) deleteObject(w http.ResponseWriter, r *http.Request, namespace, key string) {
	ns, err := g.authorize(r, namespace, actionDelete)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	if _, err := g.db.DeleteObject(r.Context(), ns.ID, key); err != nil {
		g.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ServeObject writes an object (or just its headers) to w. It is exported so
// the admin API can serve downloads through the same code path.
//
// It takes an already-resolved namespace rather than a name: /api authorizes
// through tenant membership, which is a different check from the S3 plane's
// credential scope, and re-resolving here would either redo the wrong one or
// silently depend on /api having done it. Passing the row makes the caller's
// authorization the only one that applies.
func (g *Gateway) ServeObject(w http.ResponseWriter, r *http.Request, ns db.Namespace, key string) {
	g.serveResolvedObject(w, r, ns, key, false)
}

// serveObject resolves the namespace in the caller's S3 scope, then serves it.
func (g *Gateway) serveObject(w http.ResponseWriter, r *http.Request, namespace, key string, headOnly bool) {
	ns, err := g.authorize(r, namespace, actionRead)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	g.serveResolvedObject(w, r, ns, key, headOnly)
}

func (g *Gateway) serveResolvedObject(w http.ResponseWriter, r *http.Request, ns db.Namespace, key string, headOnly bool) {
	meta, err := g.db.GetObject(r.Context(), ns.ID, key)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	start, end := int64(0), meta.Size-1
	status := http.StatusOK
	// A zero-byte object has no satisfiable range, so the whole (empty) body
	// is served instead of rejecting the request.
	if header := r.Header.Get("Range"); header != "" && meta.Size > 0 {
		rangeStart, rangeEnd, present, err := parseRange(header, meta.Size)
		if err != nil {
			g.writeError(w, r, err)
			return
		}
		if present {
			start, end = rangeStart, rangeEnd
			status = http.StatusPartialContent
			w.Header().Set("Content-Range",
				fmt.Sprintf("bytes %d-%d/%d", start, end, meta.Size))
		}
	}

	length := int64(0)
	if meta.Size > 0 {
		length = end - start + 1
	}

	w.Header().Set("Content-Type", meta.ContentType)
	setContentSafetyHeaders(w.Header(), meta.ContentType)
	w.Header().Set("ETag", quotedETag(meta.ETag()))
	w.Header().Set("Last-Modified", httpDate(meta.UpdatedAt))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))

	if headOnly || length == 0 {
		w.WriteHeader(status)
		return
	}

	reader, err := g.blob.NewRangeReader(r.Context(), storage.BlobPath(meta.BlobHash), start, length, nil)
	if err != nil {
		g.writeError(w, r, apperr.Internalf("open blob: %w", err))
		return
	}
	defer func() { _ = reader.Close() }()

	w.WriteHeader(status)
	// Past this point the status and headers are committed, so a failure can
	// only be logged — the client sees a truncated body.
	if _, err := io.Copy(w, reader); err != nil {
		g.log.Warn("object stream interrupted",
			"namespace", ns.Name, "key", key, "err", err)
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

func (g *Gateway) initiateMultipart(w http.ResponseWriter, r *http.Request, namespace, key string) {
	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	id, err := g.db.CreateMultipart(r.Context(), ns.ID, key, contentTypeOf(r))
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	g.writeXML(w, r, http.StatusOK, initiateMultipartUploadResult{
		Xmlns:    xmlns,
		Bucket:   namespace,
		Key:      key,
		UploadID: id.String(),
	})
}

func (g *Gateway) uploadPart(w http.ResponseWriter, r *http.Request, namespace, key, rawPartNumber, rawUploadID string) {
	partNumber, err := strconv.Atoi(rawPartNumber)
	if err != nil || partNumber < 1 || partNumber > maxPartNumber {
		g.writeError(w, r, apperr.InvalidArgument("partNumber must be 1-%d", maxPartNumber))
		return
	}
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	upload, err := g.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	// Parts stay in staging, answered with their own MD5; dedup happens once
	// at completion, when the hash of the whole object is known.
	staged, err := g.cas.PutPart(r.Context(), upload, int32(partNumber), r.Body, declaredLength(r))
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	w.Header().Set("ETag", quotedETag(staged.ETag))
	setChecksumHeaders(w, r)
	w.WriteHeader(http.StatusOK)
}

// uploadPartCopy stages a byte range of an existing object as a part. Unlike
// CopyObject this does move bytes: a part is staged under its own digest, and
// the whole object is hashed only at completion. The AWS CLI uses it for every
// s3-to-s3 copy above its multipart threshold (8 MiB by default).
//
// The source resolves in the caller's scope, as for CopyObject, and the part
// goes through the same size limit and quota as an uploaded one.
func (g *Gateway) uploadPartCopy(w http.ResponseWriter, r *http.Request, namespace, key, rawPartNumber, rawUploadID string) {
	partNumber, err := strconv.Atoi(rawPartNumber)
	if err != nil || partNumber < 1 || partNumber > maxPartNumber {
		g.writeError(w, r, apperr.InvalidArgument("partNumber must be 1-%d", maxPartNumber))
		return
	}
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	upload, err := g.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	src, err := g.copySource(r)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	start, length := int64(0), src.Size
	if header := r.Header.Get("x-amz-copy-source-range"); header != "" {
		first, last, err := parseCopySourceRange(header, src.Size)
		if err != nil {
			g.writeError(w, r, err)
			return
		}
		start, length = first, last-first+1
	}

	var body io.Reader = strings.NewReader("")
	if length > 0 {
		reader, err := g.blob.NewRangeReader(r.Context(), storage.BlobPath(src.BlobHash), start, length, nil)
		if err != nil {
			g.writeError(w, r, apperr.Internalf("open copy source: %w", err))
			return
		}
		defer func() { _ = reader.Close() }()
		body = sourceReader{reader}
	}

	staged, err := g.cas.PutPart(r.Context(), upload, int32(partNumber), body, length)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	g.writeXML(w, r, http.StatusOK, copyPartResult{
		Xmlns:        xmlns,
		LastModified: iso8601(time.Now()),
		ETag:         quotedETag(staged.ETag),
	})
}

// parseCopySourceRange parses x-amz-copy-source-range, which unlike Range
// must name both ends ("bytes=first-last") and lie inside the source.
func parseCopySourceRange(header string, size int64) (first, last int64, err error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return 0, 0, apperr.InvalidArgument("x-amz-copy-source-range must be bytes=first-last")
	}
	rawFirst, rawLast, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, apperr.InvalidArgument("x-amz-copy-source-range must be bytes=first-last")
	}
	first, err1 := strconv.ParseInt(strings.TrimSpace(rawFirst), 10, 64)
	last, err2 := strconv.ParseInt(strings.TrimSpace(rawLast), 10, 64)
	if err1 != nil || err2 != nil || first < 0 || last < first || last >= size {
		return 0, 0, apperr.InvalidArgument("x-amz-copy-source-range %q is not within the %d-byte source", header, size)
	}
	return first, last, nil
}

// sourceReader marks a failure reading a stored blob as the server's, so
// staging reports it as an internal error rather than a bad request body.
type sourceReader struct{ r io.Reader }

func (s sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF {
		err = apperr.Internalf("read copy source: %w", err)
	}
	return n, err
}

func (g *Gateway) listParts(w http.ResponseWriter, r *http.Request, namespace, key, rawUploadID string, query url.Values) {
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ns, err := g.authorize(r, namespace, actionList)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	upload, err := g.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	marker := 0
	if raw := query.Get("part-number-marker"); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			marker = n
		}
	}
	maxParts := clampInt(query.Get("max-parts"), maxPartsLimit)

	page, err := g.db.ListPartsPage(r.Context(), upload.ID, int32(marker), int64(maxParts))
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	result := listPartsResult{
		Xmlns:            xmlns,
		Bucket:           namespace,
		Key:              key,
		UploadID:         rawUploadID,
		PartNumberMarker: int32(marker),
		MaxParts:         int64(maxParts),
		IsTruncated:      page.IsTruncated,
		Parts:            make([]partEntry, 0, len(page.Parts)),
	}
	if page.IsTruncated && len(page.Parts) > 0 {
		next := page.Parts[len(page.Parts)-1].PartNumber
		result.NextPartNumberMarker = &next
	}
	for _, p := range page.Parts {
		result.Parts = append(result.Parts, partEntry{
			PartNumber: p.PartNumber,
			ETag:       quotedETag(p.ETag),
			Size:       p.Size,
		})
	}
	g.writeXML(w, r, http.StatusOK, result)
}

func (g *Gateway) listMultipartUploads(w http.ResponseWriter, r *http.Request, namespace string, query url.Values) {
	ns, err := g.authorize(r, namespace, actionList)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	prefix := query.Get("prefix")
	maxUploads := clampInt(query.Get("max-uploads"), maxUploadsLimit)

	uploads, err := g.db.ListMultipartUploads(r.Context(), ns.ID, prefix, int64(maxUploads))
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	entries := make([]uploadEntry, 0, len(uploads))
	for _, u := range uploads {
		entries = append(entries, uploadEntry{
			Key:       u.Key,
			UploadID:  u.ID.String(),
			Initiated: iso8601(u.CreatedAt),
		})
	}
	g.writeXML(w, r, http.StatusOK, listMultipartUploadsResult{
		Xmlns:       xmlns,
		Bucket:      namespace,
		Prefix:      prefix,
		MaxUploads:  int64(maxUploads),
		IsTruncated: false,
		Uploads:     entries,
	})
}

func (g *Gateway) completeMultipart(w http.ResponseWriter, r *http.Request, namespace, key, rawUploadID string) {
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	upload, err := g.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	raw, err := readXMLBody(r)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	var manifest completeMultipartUpload
	if err := unmarshalXML(raw, &manifest); err != nil {
		g.writeError(w, r, err)
		return
	}

	stored, err := g.db.ListParts(r.Context(), upload.ID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ordered, err := resolveManifest(manifest.Parts, stored)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	etag, err := g.cas.CompleteMultipart(r.Context(), upload, ordered)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	g.writeXML(w, r, http.StatusOK, completeMultipartUploadResult{
		Xmlns:    xmlns,
		Location: "/" + namespace + "/" + key,
		Bucket:   namespace,
		Key:      key,
		ETag:     quotedETag(etag),
	})
}

func (g *Gateway) abortMultipart(w http.ResponseWriter, r *http.Request, namespace, key, rawUploadID string) {
	uploadID, err := parseUploadID(rawUploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	ns, err := g.authorize(r, namespace, actionWrite)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	upload, err := g.db.GetMultipart(r.Context(), ns.ID, key, uploadID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}

	keys, err := g.db.RemoveMultipart(r.Context(), upload.ID)
	if err != nil {
		g.writeError(w, r, err)
		return
	}
	for _, stagingKey := range keys {
		g.cas.DiscardStaging(r.Context(), stagingKey)
	}
	w.WriteHeader(http.StatusNoContent)
}
