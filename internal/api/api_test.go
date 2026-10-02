package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/s3"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// Published BLAKE3 digest of "abc".
const abcHash = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"

type fixture struct {
	handler http.Handler
	db      *db.DB
	pool    *pgxpool.Pool
	// caller is attached to every request when non-nil, standing in for what
	// the OIDC guard would have established.
	caller *auth.Session
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	dsn := testdb.URL(t)

	database, err := db.Connect(ctx, dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)

	// A raw pool for the assertions that check physical dedup directly.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	t.Cleanup(pool.Close)

	bucket, err := storage.Open(ctx, config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("open bucket: %v", err)
	}
	t.Cleanup(func() { _ = bucket.Close() })

	cfg := config.Default()
	cfg.Database.URL = dsn
	log := slog.New(slog.DiscardHandler)
	store := cas.New(database, bucket, config.GcConfig{
		IntervalSecs: 60, GraceSecs: 300, MultipartExpirySecs: 86400,
	}, cfg.Limits, log)
	gateway := s3.New(database, bucket, store, &cfg, log)

	return &fixture{
		handler: New(database, store, gateway, log).Routes(),
		db:      database,
		pool:    pool,
	}
}

// signIn makes subsequent requests carry a verified identity, the way the OIDC
// guard would.
func (f *fixture) signIn(email string) {
	f.caller = &auth.Session{
		Issuer: testIssuer, Subject: "sub-" + email, Email: email, EmailVerified: true, Provider: "test",
	}
}

// signInUnverified establishes a caller whose address the provider did not
// verify: a distinct account that can hold its own teams, but cannot accept an
// invitation addressed to that address.
func (f *fixture) signInUnverified(email string) {
	f.caller = &auth.Session{
		Issuer: testIssuer, Subject: "unverified-" + email, Email: email, Provider: "test",
	}
}

// testIssuer is the issuer every fixture session claims.
const testIssuer = "https://idp.test"

func (f *fixture) do(t *testing.T, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	if f.caller != nil {
		r = r.WithContext(auth.WithSession(r.Context(), f.caller))
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func mustStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d\nbody: %s", w.Code, want, w.Body.String())
	}
}

// decodeObject parses a JSON object response.
func decodeObject(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, w.Body.String())
	}
	return out
}

// decodeArray parses a JSON array response.
func decodeArray(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, w.Body.String())
	}
	return out
}

// errorBody parses the API's {code, message} error shape.
func errorBody(t *testing.T, w *httptest.ResponseRecorder) (code, message string) {
	t.Helper()
	body := decodeObject(t, w)
	code, _ = body["code"].(string)
	message, _ = body["message"].(string)
	return code, message
}

// ---------------------------------------------------------------------------
// Naming and content type
// ---------------------------------------------------------------------------

func TestValidName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"typical", "team-a.01", true},
		{"minimum length", "abc", true},
		{"maximum length", strings.Repeat("a", 63), true},
		{"too short", "ab", false},
		{"too long", strings.Repeat("a", 64), false},
		{"must start alphanumeric", "-bad", false},
		{"must end alphanumeric", "bad-", false},
		{"no uppercase", "Bad", false},
		{"no underscore", "a_b", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validName(tc.input); got != tc.want {
				t.Errorf("validName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveContentType(t *testing.T) {
	tests := []struct {
		name   string
		header string
		key    string
		want   string
	}{
		{"an explicit header wins", "image/png", "photo.jpg", "image/png"},
		{"guessed from the extension", "", "notes.txt", "text/plain"},
		{"charset parameters are dropped", "", "page.html", "text/html"},
		{"unknown extension falls back to bytes", "", "archive.zzz", "application/octet-stream"},
		{"no extension falls back to bytes", "", "README", "application/octet-stream"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/api/x", nil)
			if tc.header != "" {
				r.Header.Set("Content-Type", tc.header)
			}
			if got := resolveContentType(r, tc.key); got != tc.want {
				t.Errorf("resolveContentType(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestParseDelimiter(t *testing.T) {
	if got, err := parseDelimiter(""); err != nil || got != 0 {
		t.Errorf("empty delimiter = %q, %v", got, err)
	}
	if got, err := parseDelimiter("/"); err != nil || got != '/' {
		t.Errorf("slash delimiter = %q, %v", got, err)
	}
	for _, bad := range []string{"//", "é", "\x01"} {
		if _, err := parseDelimiter(bad); err == nil {
			t.Errorf("delimiter %q should be rejected", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// The field names asserted here are the PWA's Stats interface, verbatim.
func TestStatsContract(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"ns-a"}`,
		"Content-Type", "application/json"), http.StatusCreated)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"ns-b"}`,
		"Content-Type", "application/json"), http.StatusCreated)

	// Two objects share one blob, so logical bytes exceed physical bytes.
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/ns-a/objects/one", "abc"), http.StatusOK)
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/ns-b/objects/two", "abc"), http.StatusOK)

	w := f.do(t, http.MethodGet, "/api/stats", "")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)

	for _, field := range []string{
		"namespace_count", "object_count", "blob_count",
		"logical_bytes", "physical_bytes", "dedup_ratio", "saved_bytes",
	} {
		if _, ok := body[field]; !ok {
			t.Errorf("missing field %q — the PWA reads it: %#v", field, body)
		}
	}
	if body["namespace_count"] != float64(2) || body["object_count"] != float64(2) {
		t.Errorf("counts = %#v", body)
	}
	if body["blob_count"] != float64(1) {
		t.Errorf("blob_count = %v, want 1 (deduped)", body["blob_count"])
	}
	if body["logical_bytes"] != float64(6) || body["physical_bytes"] != float64(3) {
		t.Errorf("bytes = %#v", body)
	}
	if body["dedup_ratio"] != float64(2) {
		t.Errorf("dedup_ratio = %v, want 2", body["dedup_ratio"])
	}
	if body["saved_bytes"] != float64(3) {
		t.Errorf("saved_bytes = %v, want 3", body["saved_bytes"])
	}
}

// An empty store must report a 1.0 ratio, not a division by zero.
func TestStatsOnEmptyStore(t *testing.T) {
	f := newFixture(t)

	w := f.do(t, http.MethodGet, "/api/stats", "")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)

	if body["dedup_ratio"] != float64(1) {
		t.Errorf("dedup_ratio = %v, want 1.0 on an empty store", body["dedup_ratio"])
	}
	if body["saved_bytes"] != float64(0) {
		t.Errorf("saved_bytes = %v, want 0", body["saved_bytes"])
	}
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

func TestNamespaceEndpointsUntenanted(t *testing.T) {
	f := newFixture(t)

	w := f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos"}`,
		"Content-Type", "application/json")
	mustStatus(t, w, http.StatusCreated)

	// Duplicate.
	w = f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos"}`)
	mustStatus(t, w, http.StatusConflict)
	if code, _ := errorBody(t, w); code != "BucketAlreadyOwnedByYou" {
		t.Errorf("code = %q", code)
	}

	// Invalid name.
	w = f.do(t, http.MethodPost, "/api/namespaces", `{"name":"Bad_Name"}`)
	mustStatus(t, w, http.StatusBadRequest)
	if code, _ := errorBody(t, w); code != "InvalidBucketName" {
		t.Errorf("code = %q", code)
	}

	// Malformed JSON.
	w = f.do(t, http.MethodPost, "/api/namespaces", `{not json`)
	mustStatus(t, w, http.StatusBadRequest)

	// Listing: exactly the fields the PWA's Namespace type declares.
	w = f.do(t, http.MethodGet, "/api/namespaces", "")
	mustStatus(t, w, http.StatusOK)
	list := decodeArray(t, w)
	if len(list) != 1 {
		t.Fatalf("namespaces = %#v", list)
	}
	if list[0]["name"] != "photos" {
		t.Errorf("name = %v", list[0]["name"])
	}
	if _, ok := list[0]["created_at"]; !ok {
		t.Errorf("missing created_at: %#v", list[0])
	}

	mustStatus(t, f.do(t, http.MethodDelete, "/api/namespaces/photos", ""), http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodDelete, "/api/namespaces/photos", ""), http.StatusNotFound)
}

// An empty listing must be [] so the PWA can map over it.
func TestEmptyListsSerialiseAsArrays(t *testing.T) {
	f := newFixture(t)

	w := f.do(t, http.MethodGet, "/api/namespaces", "")
	mustStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("empty namespaces = %q, want []", got)
	}

	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos"}`), http.StatusCreated)
	w = f.do(t, http.MethodGet, "/api/namespaces/photos/objects", "")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)
	if body["objects"] == nil || body["common_prefixes"] == nil {
		t.Errorf("objects/common_prefixes must be arrays, got %#v", body)
	}
	// next_token is null on the last page, and the key must be present.
	if v, ok := body["next_token"]; !ok || v != nil {
		t.Errorf("next_token = %v (present=%v), want an explicit null", v, ok)
	}
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

func TestObjectUploadDownloadDelete(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"photos"}`), http.StatusCreated)

	w := f.do(t, http.MethodPut, "/api/namespaces/photos/objects/cat.txt", "abc",
		"Content-Type", "text/plain")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)
	if body["key"] != "cat.txt" || body["etag"] != abcHash || body["size"] != float64(3) {
		t.Errorf("upload response = %#v", body)
	}

	// Download goes through the gateway's read path.
	w = f.do(t, http.MethodGet, "/api/namespaces/photos/objects/cat.txt", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("body = %q", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := w.Header().Get("ETag"); got != `"`+abcHash+`"` {
		t.Errorf("ETag = %q", got)
	}

	// Range requests work here too.
	w = f.do(t, http.MethodGet, "/api/namespaces/photos/objects/cat.txt", "", "Range", "bytes=1-2")
	mustStatus(t, w, http.StatusPartialContent)
	if w.Body.String() != "bc" {
		t.Errorf("range body = %q", w.Body.String())
	}

	mustStatus(t, f.do(t, http.MethodDelete, "/api/namespaces/photos/objects/cat.txt", ""),
		http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/photos/objects/cat.txt", ""),
		http.StatusNotFound)
}

func TestObjectContentTypeGuessedFromKey(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)

	// No Content-Type header: the extension decides.
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/files/objects/notes.txt", "abc"),
		http.StatusOK)
	w := f.do(t, http.MethodGet, "/api/namespaces/files/objects/notes.txt", "")
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
}

func TestHierarchicalKeys(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)

	const key = "a/b/c/deep.txt"
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/files/objects/"+key, "abc"), http.StatusOK)

	w := f.do(t, http.MethodGet, "/api/namespaces/files/objects/"+key, "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestListObjectsContract(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)
	for _, key := range []string{"a.txt", "photos/1.jpg", "photos/2.jpg", "z.txt"} {
		mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/files/objects/"+key, "abc"), http.StatusOK)
	}

	t.Run("object fields match the PWA's ObjectEntry", func(t *testing.T) {
		w := f.do(t, http.MethodGet, "/api/namespaces/files/objects?prefix=a.txt", "")
		mustStatus(t, w, http.StatusOK)
		body := decodeObject(t, w)
		objects, ok := body["objects"].([]any)
		if !ok || len(objects) != 1 {
			t.Fatalf("objects = %#v", body["objects"])
		}
		entry, _ := objects[0].(map[string]any)
		for _, field := range []string{"key", "size", "etag", "content_type", "last_modified"} {
			if _, ok := entry[field]; !ok {
				t.Errorf("missing field %q — the PWA reads it: %#v", field, entry)
			}
		}
		// The API reports the bare digest; only the S3 gateway quotes it.
		if entry["etag"] != abcHash {
			t.Errorf("etag = %v, want the unquoted digest", entry["etag"])
		}
	})

	t.Run("delimiter groups", func(t *testing.T) {
		w := f.do(t, http.MethodGet, "/api/namespaces/files/objects?delimiter=/", "")
		mustStatus(t, w, http.StatusOK)
		body := decodeObject(t, w)
		if got := len(body["objects"].([]any)); got != 2 {
			t.Errorf("objects = %d, want 2", got)
		}
		prefixes := body["common_prefixes"].([]any)
		if len(prefixes) != 1 || prefixes[0] != "photos/" {
			t.Errorf("common_prefixes = %#v", prefixes)
		}
	})

	t.Run("token pagination walks every key once", func(t *testing.T) {
		var seen []string
		target := "/api/namespaces/files/objects?max=2"
		for range 10 {
			w := f.do(t, http.MethodGet, target, "")
			mustStatus(t, w, http.StatusOK)
			body := decodeObject(t, w)
			for _, o := range body["objects"].([]any) {
				seen = append(seen, o.(map[string]any)["key"].(string))
			}
			token, ok := body["next_token"].(string)
			if !ok {
				break
			}
			target = "/api/namespaces/files/objects?max=2&token=" + url.QueryEscape(token)
		}
		want := "a.txt,photos/1.jpg,photos/2.jpg,z.txt"
		if strings.Join(seen, ",") != want {
			t.Errorf("paged through %v, want %s", seen, want)
		}
	})

	t.Run("bad token", func(t *testing.T) {
		w := f.do(t, http.MethodGet, "/api/namespaces/files/objects?token=!!!", "")
		mustStatus(t, w, http.StatusBadRequest)
		if code, _ := errorBody(t, w); code != "InvalidArgument" {
			t.Errorf("code = %q", code)
		}
	})

	t.Run("bad delimiter", func(t *testing.T) {
		w := f.do(t, http.MethodGet, "/api/namespaces/files/objects?delimiter=ab", "")
		mustStatus(t, w, http.StatusBadRequest)
	})
}

// ---------------------------------------------------------------------------
// The dedup link fast path
// ---------------------------------------------------------------------------

// This is the endpoint that turns a client-side hash match into a zero-byte
// upload, so both answers matter to the PWA's worker.
func TestLinkEndpoint(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)

	// Miss: nothing stored yet.
	w := f.do(t, http.MethodPut, "/api/namespaces/files/objects/copy.txt?link="+abcHash, "")
	mustStatus(t, w, http.StatusNotFound)
	body := decodeObject(t, w)
	if body["code"] != "NoSuchKey" {
		t.Fatalf("link on an empty store = %#v, want NoSuchKey", body)
	}
	// The declined link must not have created the object.
	mustStatus(t, f.do(t, http.MethodGet, "/api/namespaces/files/objects/copy.txt", ""),
		http.StatusNotFound)

	// Store the content, then link.
	mustStatus(t, f.do(t, http.MethodPut, "/api/namespaces/files/objects/orig.txt", "abc"), http.StatusOK)
	w = f.do(t, http.MethodPut, "/api/namespaces/files/objects/copy.txt?link="+abcHash, "")
	mustStatus(t, w, http.StatusOK)
	body = decodeObject(t, w)
	if body["linked"] != true {
		t.Fatalf("link = %#v, want linked:true", body)
	}
	if body["etag"] != abcHash || body["size"] != float64(3) || body["key"] != "copy.txt" {
		t.Errorf("link response = %#v", body)
	}

	// The linked object really reads back.
	w = f.do(t, http.MethodGet, "/api/namespaces/files/objects/copy.txt", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("linked content = %q", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

func TestMultipartOverAPI(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)
	base := "/api/namespaces/files/objects/big.bin"

	// Initiate.
	w := f.do(t, http.MethodPost, base+"?uploads", "", "Content-Type", "text/plain")
	mustStatus(t, w, http.StatusOK)
	uploadID, _ := decodeObject(t, w)["upload_id"].(string)
	if uploadID == "" {
		t.Fatalf("no upload_id: %s", w.Body.String())
	}

	// Two parts.
	part := func(n int, body string) string {
		t.Helper()
		w := f.do(t, http.MethodPut,
			base+"?uploadId="+uploadID+"&partNumber="+strconv.Itoa(n), body)
		mustStatus(t, w, http.StatusOK)
		got := decodeObject(t, w)
		if got["part_number"] != float64(n) {
			t.Errorf("part_number = %v, want %d", got["part_number"], n)
		}
		etag, _ := got["etag"].(string)
		if etag == "" {
			t.Fatalf("part %d returned no etag: %#v", n, got)
		}
		return etag
	}
	etag1 := part(1, "ab")
	etag2 := part(2, "c")

	// The PWA lists parts to resume an interrupted upload.
	w = f.do(t, http.MethodGet, base+"?uploadId="+uploadID, "")
	mustStatus(t, w, http.StatusOK)
	parts, ok := decodeObject(t, w)["parts"].([]any)
	if !ok || len(parts) != 2 {
		t.Fatalf("parts = %s", w.Body.String())
	}
	first, _ := parts[0].(map[string]any)
	for _, field := range []string{"part_number", "etag", "size"} {
		if _, ok := first[field]; !ok {
			t.Errorf("missing field %q: %#v", field, first)
		}
	}

	// Complete.
	manifest := `{"parts":[{"part_number":1,"etag":"` + etag1 + `"},{"part_number":2,"etag":"` + etag2 + `"}]}`
	w = f.do(t, http.MethodPost, base+"?uploadId="+uploadID, manifest,
		"Content-Type", "application/json")
	mustStatus(t, w, http.StatusOK)
	body := decodeObject(t, w)
	// The assembled object hashes as the whole content, so it dedups against a
	// single-shot upload of the same bytes.
	if body["etag"] != abcHash {
		t.Errorf("etag = %v, want %s", body["etag"], abcHash)
	}
	if body["size"] != float64(3) || body["key"] != "big.bin" {
		t.Errorf("complete response = %#v", body)
	}

	w = f.do(t, http.MethodGet, base, "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("assembled body = %q", w.Body.String())
	}
}

func TestMultipartAbortOverAPI(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)
	base := "/api/namespaces/files/objects/big.bin"

	w := f.do(t, http.MethodPost, base+"?uploads", "")
	uploadID := decodeObject(t, w)["upload_id"].(string)
	mustStatus(t, f.do(t, http.MethodPut, base+"?uploadId="+uploadID+"&partNumber=1", "abc"),
		http.StatusOK)

	mustStatus(t, f.do(t, http.MethodDelete, base+"?uploadId="+uploadID, ""), http.StatusNoContent)
	mustStatus(t, f.do(t, http.MethodGet, base+"?uploadId="+uploadID, ""), http.StatusNotFound)
	mustStatus(t, f.do(t, http.MethodGet, base, ""), http.StatusNotFound)
}

func TestMultipartValidationOverAPI(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.do(t, http.MethodPost, "/api/namespaces", `{"name":"files"}`), http.StatusCreated)
	base := "/api/namespaces/files/objects/big.bin"

	w := f.do(t, http.MethodPost, base+"?uploads", "")
	uploadID := decodeObject(t, w)["upload_id"].(string)
	mustStatus(t, f.do(t, http.MethodPut, base+"?uploadId="+uploadID+"&partNumber=1", "ab"),
		http.StatusOK)

	tests := []struct{ name, manifest string }{
		{"no parts", `{"parts":[]}`},
		{"part never uploaded", `{"parts":[{"part_number":9}]}`},
		{"descending part numbers", `{"parts":[{"part_number":2},{"part_number":1}]}`},
		{"etag mismatch", `{"parts":[{"part_number":1,"etag":"deadbeef"}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do(t, http.MethodPost, base+"?uploadId="+uploadID, tc.manifest)
			mustStatus(t, w, http.StatusBadRequest)
			if code, _ := errorBody(t, w); code != "InvalidPart" {
				t.Errorf("code = %q, want InvalidPart", code)
			}
		})
	}

	// Bad part numbers.
	for _, pn := range []string{"0", "10001", "abc"} {
		w := f.do(t, http.MethodPut, base+"?uploadId="+uploadID+"&partNumber="+pn, "x")
		mustStatus(t, w, http.StatusBadRequest)
	}

	// POST with neither ?uploads nor ?uploadId.
	w = f.do(t, http.MethodPost, base, "")
	mustStatus(t, w, http.StatusBadRequest)
}
