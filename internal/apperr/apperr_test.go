package apperr

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCodesAndStatuses(t *testing.T) {
	tests := []struct {
		name   string
		err    *Error
		code   string
		status int
	}{
		{"namespace missing maps to the S3 bucket code", ErrNoSuchNamespace, "NoSuchBucket", http.StatusNotFound},
		{"key missing", ErrNoSuchKey, "NoSuchKey", http.StatusNotFound},
		{"upload missing", ErrNoSuchUpload, "NoSuchUpload", http.StatusNotFound},
		{"namespace name taken", ErrNamespaceAlreadyExists, "BucketAlreadyExists", http.StatusConflict},
		{"namespace already yours", ErrNamespaceAlreadyOwned, "BucketAlreadyOwnedByYou", http.StatusConflict},
		{"namespace not empty", ErrNamespaceNotEmpty, "BucketNotEmpty", http.StatusConflict},
		{"bad namespace name", ErrInvalidNamespaceName, "InvalidBucketName", http.StatusBadRequest},
		{"reserved namespace name", ErrReservedNamespaceName, "InvalidBucketName", http.StatusBadRequest},
		{"tenant missing", ErrNoSuchTenant, "NoSuchTenant", http.StatusNotFound},
		{"tenant exists", ErrTenantAlreadyExists, "TenantAlreadyExists", http.StatusConflict},
		{"tenant not empty", ErrTenantNotEmpty, "TenantNotEmpty", http.StatusConflict},
		{"bad tenant name", ErrInvalidTenantName, "InvalidTenantName", http.StatusBadRequest},
		{"session missing", ErrNoSuchSession, "NoSuchSession", http.StatusNotFound},
		{"range unsatisfiable", ErrInvalidRange, "InvalidRange", http.StatusRequestedRangeNotSatisfiable},
		{"access denied", ErrAccessDenied, "AccessDenied", http.StatusForbidden},
		{"signature mismatch", ErrSignatureDoesNotMatch, "SignatureDoesNotMatch", http.StatusForbidden},
		{"forbidden reuses AccessDenied", Forbidden("nope"), "AccessDenied", http.StatusForbidden},
		{"invalid argument", InvalidArgument("bad %s", "arg"), "InvalidArgument", http.StatusBadRequest},
		{"invalid part", InvalidPart("part %d", 2), "InvalidPart", http.StatusBadRequest},
		{"malformed xml", MalformedXML("eof"), "MalformedXML", http.StatusBadRequest},
		{"not implemented", NotImplemented("?acl"), "NotImplemented", http.StatusNotImplemented},
		{"request time skewed", ErrRequestTimeTooSkewed, "RequestTimeTooSkewed", http.StatusForbidden},
		{"entity too large", EntityTooLarge("%d bytes", 9), "EntityTooLarge", http.StatusBadRequest},
		{"quota exceeded", QuotaExceeded("full"), "QuotaExceeded", http.StatusForbidden},
		{"request timeout", ErrRequestTimeout, "RequestTimeout", http.StatusBadRequest},
		{"invalid request", InvalidRequest("missing header"), "InvalidRequest", http.StatusBadRequest},
		{"bad digest", BadDigest("crc32 mismatch"), "BadDigest", http.StatusBadRequest},
		{"invalid digest", InvalidDigest("not base64"), "InvalidDigest", http.StatusBadRequest},
		{"payload hash mismatch", ErrContentSHA256Mismatch, "XAmzContentSHA256Mismatch", http.StatusBadRequest},
		{"internal", From(errors.New("boom")), "InternalError", http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.S3Code(); got != tc.code {
				t.Errorf("S3Code() = %q, want %q", got, tc.code)
			}
			if got := tc.err.Status(); got != tc.status {
				t.Errorf("Status() = %d, want %d", got, tc.status)
			}
		})
	}
}

// The zero Kind must be the internal (500) case, so a bare &Error{} can never
// be mistaken for a client error.
func TestZeroValueIsInternal(t *testing.T) {
	var e Error
	if !e.IsInternal() {
		t.Error("zero-value Error should be internal")
	}
	if e.Status() != http.StatusInternalServerError {
		t.Errorf("Status() = %d, want 500", e.Status())
	}
}

func TestFormattedMessages(t *testing.T) {
	if got := InvalidPart("etag mismatch on part %d", 3).Error(); got != "invalid part: etag mismatch on part 3" {
		t.Errorf("got %q", got)
	}
	if got := MalformedXML("unexpected EOF").Error(); got != "malformed request: unexpected EOF" {
		t.Errorf("got %q", got)
	}
}

func TestInternalUnwrapsAndClassifies(t *testing.T) {
	cause := errors.New("connection refused")
	e := Internal(cause)
	if !errors.Is(e, cause) {
		t.Error("Internal should preserve the cause for errors.Is")
	}
	if Internal(nil) != nil {
		t.Error("Internal(nil) should be nil so it composes with bare error returns")
	}
}

func TestFrom(t *testing.T) {
	if got := From(ErrNoSuchKey); got != ErrNoSuchKey {
		t.Error("From should pass an *Error through unchanged")
	}
	// A classified error wrapped in context must still be recovered.
	wrapped := Internalf("stage: %w", ErrInvalidRange)
	if got := From(wrapped); got.Kind != KindInternal {
		t.Errorf("Internalf keeps its own kind, got %v", got.Kind)
	}
	plain := From(errors.New("x"))
	if !plain.IsInternal() {
		t.Error("From should classify an unknown error as internal")
	}
	if From(nil) != nil {
		t.Error("From(nil) should be nil")
	}
}

func TestWriteXMLEscapesMessage(t *testing.T) {
	w := httptest.NewRecorder()
	WriteXML(w, InvalidArgument("bad <tag> & \"quote\""))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("content-type = %q", ct)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>") {
		t.Errorf("missing XML prolog/root: %q", body)
	}
	if !strings.Contains(body, "<Code>InvalidArgument</Code>") {
		t.Errorf("missing code: %q", body)
	}
	// The raw '<' from the message must not survive as markup.
	if strings.Contains(body, "<tag>") {
		t.Errorf("message was not escaped: %q", body)
	}
	if !strings.Contains(body, "&lt;tag&gt;") {
		t.Errorf("expected escaped message, got %q", body)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, ErrNoSuchNamespace)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if got["code"] != "NoSuchBucket" || got["message"] != "namespace not found" {
		t.Errorf("body = %#v", got)
	}
}

// WriteXML/WriteJSON accept a plain error, not just an *Error.
func TestWritersClassifyPlainErrors(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, errors.New("unexpected"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// A *Error typed nil assigned to an error return is a non-nil interface, which
// would make every success path through Internal look like a failure. Internal
// returns the error interface specifically to avoid that, so guard it.
func TestInternalNilIsATrueNilInterface(t *testing.T) {
	// Internal returns the error interface, so this is already error-typed.
	err := Internal(nil)
	if err != nil {
		t.Fatalf("Internal(nil) leaked a typed nil: %#v", err)
	}

	// The same shape the db package uses on every success path.
	pass := func() (int, error) { return 7, Internal(nil) }
	if _, err := pass(); err != nil {
		t.Fatalf("success path reported an error: %#v", err)
	}
}

// An internal error's cause (pgx text, storage paths) is for the log, never
// the client; the client gets a fixed message and the request ID to quote.
func TestWritersHideInternalCauses(t *testing.T) {
	cause := errors.New(`pq: relation "blobs" does not exist at 10.0.3.7:5432`)

	xmlW := httptest.NewRecorder()
	xmlW.Header().Set(RequestIDHeader, "ABC123")
	WriteXML(xmlW, Internalf("claim blob: %w", cause))
	body := xmlW.Body.String()
	if strings.Contains(body, "relation") || strings.Contains(body, "10.0.3.7") {
		t.Errorf("XML body leaked the cause: %q", body)
	}
	if !strings.Contains(body, "<Message>"+internalMessage+"</Message>") {
		t.Errorf("XML body lacks the generic message: %q", body)
	}
	if !strings.Contains(body, "<RequestId>ABC123</RequestId>") {
		t.Errorf("XML body lacks the request ID: %q", body)
	}

	jsonW := httptest.NewRecorder()
	jsonW.Header().Set(RequestIDHeader, "ABC123")
	WriteJSON(jsonW, cause)
	var got map[string]string
	if err := json.Unmarshal(jsonW.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["message"] != internalMessage || got["request_id"] != "ABC123" {
		t.Errorf("JSON body = %#v", got)
	}

	// Client errors keep their detail: it is the caller's own input.
	clientW := httptest.NewRecorder()
	WriteXML(clientW, InvalidArgument("bad part number"))
	if !strings.Contains(clientW.Body.String(), "bad part number") {
		t.Errorf("client error lost its message: %q", clientW.Body.String())
	}
}
