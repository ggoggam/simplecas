// AWS Signature Version 4 verification.
//
// Header-signed requests only (`Authorization: AWS4-HMAC-SHA256 …`).
// Presigned-URL query auth and POST-policy uploads are rejected outright
// rather than half-supported. The payload hash is taken from
// x-amz-content-sha256 exactly as sent (streaming uploads send
// UNSIGNED-PAYLOAD), so nothing has to buffer a request body.
//
// When auth.enabled is false the check is skipped entirely, which is what lets
// `aws s3 --no-sign-request` and the bundled PWA work against a dev instance.

package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
)

const sigV4Algorithm = "AWS4-HMAC-SHA256"

// authHeader is the parsed Authorization header of a signed request.
type authHeader struct {
	accessKeyID   string
	dateStamp     string
	region        string
	service       string
	signedHeaders string
	signature     string
}

// parseAuthHeader pulls apart an AWS4-HMAC-SHA256 Authorization header.
// The credential is AKID/date/region/service/aws4_request.
func parseAuthHeader(value string) (authHeader, bool) {
	rest, ok := strings.CutPrefix(value, sigV4Algorithm)
	if !ok {
		return authHeader{}, false
	}

	var credential, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimSpace(rest), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return authHeader{}, false
		}
		switch k {
		case "Credential":
			credential = v
		case "SignedHeaders":
			signedHeaders = v
		case "Signature":
			signature = v
		}
	}
	if credential == "" || signedHeaders == "" || signature == "" {
		return authHeader{}, false
	}

	scope := strings.SplitN(credential, "/", 5)
	if len(scope) != 5 || scope[4] != "aws4_request" {
		return authHeader{}, false
	}
	return authHeader{
		accessKeyID:   scope[0],
		dateStamp:     scope[1],
		region:        scope[2],
		service:       scope[3],
		signedHeaders: signedHeaders,
		signature:     signature,
	}, true
}

// uriEncode applies RFC 3986 encoding per AWS's canonical rules: unreserved
// characters pass through, everything else is percent-encoded in uppercase.
// A slash is preserved in path context and encoded in query context.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalQueryString re-encodes and sorts the query the way SigV4 requires.
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// An unparseable query cannot match any signature; returning it
		// verbatim simply guarantees the comparison fails.
		return rawQuery
	}

	pairs := make([]string, 0, len(values))
	for key, vs := range values {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(key, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaderValue collapses internal whitespace runs to single spaces.
func canonicalHeaderValue(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signingKey derives the request-scoped signing key from the secret.
func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// signatureInput is everything the signature is computed over.
type signatureInput struct {
	secret           string
	method           string
	canonicalURI     string
	canonicalQuery   string
	signedHeaders    string
	canonicalHeaders string
	hashedPayload    string
	amzDate          string
	dateStamp        string
	region           string
	service          string
}

// computeSignature builds the canonical request and string-to-sign, then signs
// it, exactly as documented in AWS's SigV4 specification.
func computeSignature(in signatureInput) string {
	canonicalRequest := strings.Join([]string{
		in.method,
		in.canonicalURI,
		in.canonicalQuery,
		in.canonicalHeaders,
		in.signedHeaders,
		in.hashedPayload,
	}, "\n")

	scope := strings.Join([]string{in.dateStamp, in.region, in.service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		in.amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	key := signingKey(in.secret, in.dateStamp, in.region, in.service)
	return hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
}

// buildCanonicalHeaders renders the signed headers in the order the client
// declared them. A declared header that is absent from the request makes the
// signature unverifiable, so this reports failure rather than skipping it.
func buildCanonicalHeaders(r *http.Request, signedHeaders string) (string, bool) {
	var b strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value, ok := signedHeaderValue(r, name)
		if !ok {
			return "", false
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(canonicalHeaderValue(value))
		b.WriteByte('\n')
	}
	return b.String(), true
}

// signedHeaderValue reads one signed header. Host is special: net/http moves it
// out of Header and onto Request.Host, but clients sign it as a header.
func signedHeaderValue(r *http.Request, name string) (string, bool) {
	if strings.EqualFold(name, "host") {
		if r.Host == "" {
			return "", false
		}
		return r.Host, true
	}
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	// A repeated header is signed as its comma-joined values.
	return strings.Join(values, ","), true
}

// verify checks the request signature against the configured credential.
// It is called at the top of every S3 handler.
//
// The credential scope's region and service are taken from the request rather
// than pinned to the server's configured region: the signature is computed over
// whatever scope the client declared, so a mismatched scope simply fails to
// verify. This matches how the gateway behaved before.
func verify(r *http.Request, auth config.AuthConfig) error {
	if !auth.Enabled {
		return nil
	}

	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, sigV4Algorithm) {
		return apperr.ErrAccessDenied
	}
	parsed, ok := parseAuthHeader(value)
	if !ok {
		return apperr.ErrAccessDenied
	}
	if !hmac.Equal([]byte(parsed.accessKeyID), []byte(auth.AccessKeyID)) {
		return apperr.ErrAccessDenied
	}

	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return apperr.ErrAccessDenied
	}
	hashedPayload := r.Header.Get("x-amz-content-sha256")
	if hashedPayload == "" {
		hashedPayload = "UNSIGNED-PAYLOAD"
	}

	canonicalHeaders, ok := buildCanonicalHeaders(r, parsed.signedHeaders)
	if !ok {
		return apperr.ErrSignatureDoesNotMatch
	}

	expected := computeSignature(signatureInput{
		secret:           auth.SecretAccessKey,
		method:           r.Method,
		canonicalURI:     r.URL.EscapedPath(),
		canonicalQuery:   canonicalQueryString(r.URL.RawQuery),
		signedHeaders:    parsed.signedHeaders,
		canonicalHeaders: canonicalHeaders,
		hashedPayload:    hashedPayload,
		amzDate:          amzDate,
		dateStamp:        parsed.dateStamp,
		region:           parsed.region,
		service:          parsed.service,
	})

	if !hmac.Equal([]byte(expected), []byte(parsed.signature)) {
		return apperr.ErrSignatureDoesNotMatch
	}
	return nil
}
