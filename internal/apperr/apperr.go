// Package apperr holds the error type shared by the S3 gateway and the admin
// API. Each error carries an S3 error code and an HTTP status, so the gateway
// can render spec-shaped XML and the admin API the same information as JSON.
package apperr

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
)

// Kind identifies what went wrong. It determines both the S3 wire code and the
// HTTP status, so adding a Kind means adding it to S3Code and Status.
type Kind uint8

const (
	// KindInternal covers database, storage and otherwise-unclassified
	// failures. It is the zero value so a bare &Error{} is never a
	// client-error by accident.
	KindInternal Kind = iota
	KindNoSuchNamespace
	KindNoSuchKey
	KindNoSuchUpload
	KindNamespaceAlreadyExists
	KindNamespaceNotEmpty
	KindInvalidNamespaceName
	KindNoSuchTenant
	KindTenantAlreadyExists
	KindTenantNotEmpty
	KindInvalidTenantName
	KindNoSuchCredential
	KindNoSuchMember
	KindNoSuchInvitation
	KindNoSuchSession
	KindForbidden
	KindInvalidArgument
	KindInvalidPart
	KindInvalidRange
	KindAccessDenied
	KindSignatureDoesNotMatch
	KindMalformedXML
	KindNotImplemented
	KindRequestTimeTooSkewed
	KindEntityTooLarge
	KindQuotaExceeded
	KindRequestTimeout
)

// Error is a classified failure. Sentinel values below cover the kinds that
// carry no detail; the constructor functions cover those that do.
type Error struct {
	Kind Kind
	msg  string
	// wrapped is the underlying cause for KindInternal, preserved for
	// errors.Is/errors.As and for logging.
	wrapped error
}

// Sentinels for the detail-free kinds. They are immutable, so sharing one
// pointer across every call site is safe.
var (
	ErrNoSuchNamespace        = &Error{Kind: KindNoSuchNamespace, msg: "namespace not found"}
	ErrNoSuchKey              = &Error{Kind: KindNoSuchKey, msg: "object not found"}
	ErrNoSuchUpload           = &Error{Kind: KindNoSuchUpload, msg: "multipart upload not found"}
	ErrNamespaceAlreadyExists = &Error{Kind: KindNamespaceAlreadyExists, msg: "namespace already exists"}
	ErrNamespaceNotEmpty      = &Error{Kind: KindNamespaceNotEmpty, msg: "namespace is not empty"}
	ErrInvalidNamespaceName   = &Error{Kind: KindInvalidNamespaceName, msg: "invalid namespace name"}
	ErrNoSuchTenant           = &Error{Kind: KindNoSuchTenant, msg: "tenant not found"}
	ErrTenantAlreadyExists    = &Error{Kind: KindTenantAlreadyExists, msg: "tenant already exists"}
	ErrTenantNotEmpty         = &Error{Kind: KindTenantNotEmpty, msg: "tenant still has namespaces"}
	ErrInvalidTenantName      = &Error{Kind: KindInvalidTenantName, msg: "invalid tenant name"}
	ErrNoSuchCredential       = &Error{Kind: KindNoSuchCredential, msg: "credential not found"}
	ErrNoSuchMember           = &Error{Kind: KindNoSuchMember, msg: "member not found"}
	ErrNoSuchInvitation       = &Error{Kind: KindNoSuchInvitation, msg: "invitation not found or expired"}
	ErrNoSuchSession          = &Error{Kind: KindNoSuchSession, msg: "session not found"}
	ErrInvalidRange           = &Error{Kind: KindInvalidRange, msg: "requested range not satisfiable"}
	ErrAccessDenied           = &Error{Kind: KindAccessDenied, msg: "access denied"}
	ErrSignatureDoesNotMatch  = &Error{Kind: KindSignatureDoesNotMatch, msg: "signature mismatch"}
	ErrRequestTimeTooSkewed   = &Error{Kind: KindRequestTimeTooSkewed, msg: "the difference between the request time and the server's time is too large"}
	ErrRequestTimeout         = &Error{Kind: KindRequestTimeout, msg: "the request body stopped arriving and the connection timed out"}
)

// RequestIDHeader carries the per-request ID the router assigns. The error
// writers read it back off the response so a client-visible error can be
// matched to the server log line that holds its cause.
const RequestIDHeader = "X-Amz-Request-Id"

// internalMessage is all a client learns about a 500. The cause (pgx and
// storage error text, paths, hostnames) is logged under the request ID instead.
const internalMessage = "We encountered an internal error. Please try again."

// Forbidden denies an authorized-but-not-permitted request.
func Forbidden(format string, a ...any) *Error {
	return &Error{Kind: KindForbidden, msg: fmt.Sprintf(format, a...)}
}

// InvalidArgument rejects a malformed or unsupported parameter.
func InvalidArgument(format string, a ...any) *Error {
	return &Error{Kind: KindInvalidArgument, msg: fmt.Sprintf(format, a...)}
}

// InvalidPart rejects a multipart manifest that doesn't match what was staged.
func InvalidPart(format string, a ...any) *Error {
	return &Error{Kind: KindInvalidPart, msg: "invalid part: " + fmt.Sprintf(format, a...)}
}

// NotImplemented rejects a recognised S3 operation the gateway does not
// support, so it is never mistaken for a plainer request on the same path.
func NotImplemented(format string, a ...any) *Error {
	return &Error{Kind: KindNotImplemented, msg: fmt.Sprintf(format, a...)}
}

// MalformedXML rejects an unparseable request body.
func MalformedXML(format string, a ...any) *Error {
	return &Error{Kind: KindMalformedXML, msg: "malformed request: " + fmt.Sprintf(format, a...)}
}

// EntityTooLarge rejects an upload, part, or assembled object over the
// configured size limit.
func EntityTooLarge(format string, a ...any) *Error {
	return &Error{Kind: KindEntityTooLarge, msg: fmt.Sprintf(format, a...)}
}

// QuotaExceeded rejects a write that would take a team past its storage quota.
func QuotaExceeded(format string, a ...any) *Error {
	return &Error{Kind: KindQuotaExceeded, msg: fmt.Sprintf(format, a...)}
}

// newInternal builds an internal error from a non-nil cause.
func newInternal(err error) *Error {
	return &Error{Kind: KindInternal, msg: err.Error(), wrapped: err}
}

// Internal wraps an unclassified failure (database, storage, anything else) as
// a 500, and returns nil for a nil cause so it composes with bare error
// returns: `return out, apperr.Internal(err)`.
//
// The return type is the error interface, not *Error, deliberately. A *Error
// typed nil assigned to an error return is a NON-nil interface value, so every
// success path through a wrapper like this would look like a failure.
func Internal(err error) error {
	if err == nil {
		return nil
	}
	return newInternal(err)
}

// Internalf wraps a cause with added context, in the style of fmt.Errorf.
func Internalf(format string, a ...any) error {
	return newInternal(fmt.Errorf(format, a...))
}

// From classifies an arbitrary error: an *Error passes through unchanged,
// anything else becomes an internal error.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newInternal(err)
}

func (e *Error) Error() string { return e.msg }

// Unwrap exposes the cause of an internal error to errors.Is/errors.As.
func (e *Error) Unwrap() error { return e.wrapped }

// S3Code is the error code sent on the wire. The gateway exposes namespaces as
// S3 buckets, so these stay the S3-spec bucket codes.
func (e *Error) S3Code() string {
	switch e.Kind {
	case KindNoSuchNamespace:
		return "NoSuchBucket"
	case KindNoSuchKey:
		return "NoSuchKey"
	case KindNoSuchUpload:
		return "NoSuchUpload"
	case KindNamespaceAlreadyExists:
		return "BucketAlreadyOwnedByYou"
	case KindNamespaceNotEmpty:
		return "BucketNotEmpty"
	case KindInvalidNamespaceName:
		return "InvalidBucketName"
	case KindNoSuchTenant:
		return "NoSuchTenant"
	case KindTenantAlreadyExists:
		return "TenantAlreadyExists"
	case KindTenantNotEmpty:
		return "TenantNotEmpty"
	case KindInvalidTenantName:
		return "InvalidTenantName"
	case KindNoSuchCredential:
		return "NoSuchCredential"
	case KindNoSuchMember:
		return "NoSuchMember"
	case KindNoSuchInvitation:
		return "NoSuchInvitation"
	case KindNoSuchSession:
		return "NoSuchSession"
	case KindForbidden, KindAccessDenied:
		return "AccessDenied"
	case KindInvalidArgument:
		return "InvalidArgument"
	case KindInvalidPart:
		return "InvalidPart"
	case KindInvalidRange:
		return "InvalidRange"
	case KindSignatureDoesNotMatch:
		return "SignatureDoesNotMatch"
	case KindMalformedXML:
		return "MalformedXML"
	case KindNotImplemented:
		return "NotImplemented"
	case KindRequestTimeTooSkewed:
		return "RequestTimeTooSkewed"
	case KindEntityTooLarge:
		return "EntityTooLarge"
	case KindQuotaExceeded:
		return "QuotaExceeded"
	case KindRequestTimeout:
		return "RequestTimeout"
	default:
		return "InternalError"
	}
}

// Status is the HTTP status this error renders as.
func (e *Error) Status() int {
	switch e.Kind {
	case KindNoSuchNamespace, KindNoSuchKey, KindNoSuchUpload, KindNoSuchTenant,
		KindNoSuchCredential, KindNoSuchMember, KindNoSuchInvitation, KindNoSuchSession:
		return http.StatusNotFound
	case KindNamespaceAlreadyExists, KindNamespaceNotEmpty,
		KindTenantAlreadyExists, KindTenantNotEmpty:
		return http.StatusConflict
	case KindInvalidNamespaceName, KindInvalidTenantName,
		KindInvalidArgument, KindInvalidPart, KindMalformedXML,
		KindEntityTooLarge, KindRequestTimeout:
		return http.StatusBadRequest
	case KindInvalidRange:
		return http.StatusRequestedRangeNotSatisfiable
	case KindAccessDenied, KindSignatureDoesNotMatch, KindForbidden,
		KindRequestTimeTooSkewed, KindQuotaExceeded:
		return http.StatusForbidden
	case KindNotImplemented:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

// IsInternal reports whether this error should be logged server-side rather
// than treated as ordinary client input.
func (e *Error) IsInternal() bool { return e.Kind == KindInternal }

// clientMessage is the message sent on the wire: the detail for client errors,
// and a fixed string for internal ones.
func (e *Error) clientMessage() string {
	if e.IsInternal() {
		return internalMessage
	}
	return e.msg
}

// WriteXML renders err as an S3-style XML error body. Used by the gateway.
func WriteXML(w http.ResponseWriter, err error) {
	e := From(err)
	var msg bytes.Buffer
	// Errors here are impossible for a bytes.Buffer sink.
	_ = xml.EscapeText(&msg, []byte(e.clientMessage()))
	var requestID bytes.Buffer
	if id := w.Header().Get(RequestIDHeader); id != "" {
		requestID.WriteString("<RequestId>")
		_ = xml.EscapeText(&requestID, []byte(id))
		requestID.WriteString("</RequestId>")
	}
	body := fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>%s</Code><Message>%s</Message>%s</Error>",
		e.S3Code(), msg.String(), requestID.String(),
	)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(e.Status())
	_, _ = w.Write([]byte(body))
}

// WriteJSON renders err as the admin API's `{code, message}` body.
func WriteJSON(w http.ResponseWriter, err error) {
	e := From(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status())
	body := map[string]string{
		"code":    e.S3Code(),
		"message": e.clientMessage(),
	}
	if id := w.Header().Get(RequestIDHeader); id != "" {
		body["request_id"] = id
	}
	_ = json.NewEncoder(w).Encode(body)
}
