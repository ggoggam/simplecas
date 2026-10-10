// AWS Signature Version 4 verification.
//
// A request is signed in one of two places: the Authorization header
// (`AWS4-HMAC-SHA256 …`), or the query string of a presigned URL
// (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
// `X-Amz-SignedHeaders`, `X-Amz-Signature`). Both are checked by the same code
// against the same credential, so a presigned URL is exactly as capable as the
// key that signed it, and stops working when that key expires or is deleted.
// POST-policy uploads are not supported.
//
// A header signature covers x-amz-content-sha256 as sent, which is only a
// claim about the body: the body itself is checked against it while it streams
// into staging (see payload.go), so nothing has to buffer a request body and a
// body swapped under valid headers is refused. A presigned URL is signed before
// its body exists, so it covers UNSIGNED-PAYLOAD, as on S3.
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
)

const sigV4Algorithm = "AWS4-HMAC-SHA256"

// amzDateFormat is the ISO 8601 basic form x-amz-date carries.
const amzDateFormat = "20060102T150405Z"

// maxClockSkew is how far x-amz-date may sit from the server's clock, as on
// AWS. Without a bound, a captured signed request verifies forever.
const maxClockSkew = 15 * time.Minute

// maxPresignExpiry is the longest X-Amz-Expires a presigned URL may carry: a
// week, as on S3.
const maxPresignExpiry = 7 * 24 * time.Hour

// now is the clock the skew check reads; tests replace it.
var now = time.Now

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

	parsed, ok := parseCredential(credential)
	if !ok {
		return authHeader{}, false
	}
	parsed.signedHeaders = signedHeaders
	parsed.signature = signature
	return parsed, true
}

// parseCredential splits a credential, AKID/date/region/service/aws4_request,
// into the fields of an authHeader it fills.
func parseCredential(credential string) (authHeader, bool) {
	scope := strings.SplitN(credential, "/", 5)
	if len(scope) != 5 || scope[4] != "aws4_request" {
		return authHeader{}, false
	}
	return authHeader{
		accessKeyID: scope[0],
		dateStamp:   scope[1],
		region:      scope[2],
		service:     scope[3],
	}, true
}

// signedRequest is what a request's signature declares about itself, read
// from its Authorization header or, for a presigned URL, from its query.
type signedRequest struct {
	authHeader
	amzDate       string
	hashedPayload string
	// presigned is set when the signature came in the query. expires is
	// then how long after amzDate it verifies; a header-signed request is
	// held to maxClockSkew instead.
	presigned bool
	expires   time.Duration
	// query is the parsed query a presigned signature covers, less
	// X-Amz-Signature itself; nil for a header-signed request.
	query url.Values
}

// The query parameters that carry a presigned URL's signature.
const (
	amzAlgorithm     = "X-Amz-Algorithm"
	amzCredential    = "X-Amz-Credential"
	amzDate          = "X-Amz-Date"
	amzExpires       = "X-Amz-Expires"
	amzSignedHeaders = "X-Amz-SignedHeaders"
	amzSignature     = "X-Amz-Signature"
	amzSecurityToken = "X-Amz-Security-Token"
)

// parseSignedRequest reads a request's signature from wherever it was sent.
// Signing a request both ways is refused, as on S3, rather than picking one.
func parseSignedRequest(r *http.Request) (signedRequest, error) {
	header := r.Header.Get("Authorization")
	query := r.URL.Query()
	if !query.Has(amzAlgorithm) && !query.Has(amzCredential) && !query.Has(amzSignature) {
		parsed, ok := parseAuthHeader(header)
		if !ok {
			return signedRequest{}, apperr.ErrAccessDenied
		}
		return signedRequest{
			authHeader:    parsed,
			amzDate:       r.Header.Get("x-amz-date"),
			hashedPayload: r.Header.Get("x-amz-content-sha256"),
		}, nil
	}
	if header != "" {
		return signedRequest{}, apperr.InvalidArgument("only one auth mechanism allowed: " +
			"send either the Authorization header or the X-Amz-Signature query parameter")
	}
	return parsePresignedQuery(r.URL.RawQuery)
}

// parsePresignedQuery reads the signature of a presigned URL. Each of its
// parameters must appear exactly once: url.Values would otherwise let a second
// copy ride along in the canonical query while the first is the one checked.
func parsePresignedQuery(rawQuery string) (signedRequest, error) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return signedRequest{}, apperr.AuthorizationQueryParametersError("the query string is malformed")
	}
	params := make(map[string]string, 6)
	for _, name := range []string{amzAlgorithm, amzCredential, amzDate, amzExpires, amzSignedHeaders, amzSignature} {
		values := query[name]
		if len(values) != 1 || values[0] == "" {
			return signedRequest{}, apperr.AuthorizationQueryParametersError(
				"query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, " +
					"X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters, once each")
		}
		params[name] = values[0]
	}
	if params[amzAlgorithm] != sigV4Algorithm {
		return signedRequest{}, apperr.AuthorizationQueryParametersError("X-Amz-Algorithm only supports %q", sigV4Algorithm)
	}
	parsed, ok := parseCredential(params[amzCredential])
	if !ok {
		return signedRequest{}, apperr.AuthorizationQueryParametersError("X-Amz-Credential is malformed")
	}
	seconds, err := strconv.Atoi(params[amzExpires])
	if err != nil || seconds < 1 {
		return signedRequest{}, apperr.AuthorizationQueryParametersError("X-Amz-Expires must be a positive number of seconds")
	}
	// Compared in seconds, before the conversion a huge value would overflow.
	if maxSeconds := int(maxPresignExpiry / time.Second); seconds > maxSeconds {
		return signedRequest{}, apperr.AuthorizationQueryParametersError(
			"X-Amz-Expires must be less than a week (in seconds) that is %d", maxSeconds)
	}
	// A session token would come from STS, which this server does not run:
	// no token here was ever issued, so none can be honoured.
	if query.Has(amzSecurityToken) {
		return signedRequest{}, apperr.ErrAccessDenied
	}
	// Host must be signed, or the URL would verify against any server that
	// holds the same key.
	if !slices.Contains(strings.Split(params[amzSignedHeaders], ";"), "host") {
		return signedRequest{}, apperr.AuthorizationQueryParametersError("X-Amz-SignedHeaders must include host")
	}

	parsed.signedHeaders = params[amzSignedHeaders]
	parsed.signature = params[amzSignature]
	query.Del(amzSignature)
	return signedRequest{
		authHeader:    parsed,
		amzDate:       params[amzDate],
		hashedPayload: unsignedPayload,
		presigned:     true,
		expires:       time.Duration(seconds) * time.Second,
		query:         query,
	}, nil
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
	return canonicalQuery(values)
}

// canonicalQuery is canonicalQueryString over an already parsed query.
func canonicalQuery(values url.Values) string {
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

// chunkSigner holds what the signatures of a STREAMING-AWS4-HMAC-SHA256 body
// chain from. Each chunk is signed over its own hash and the signature before
// it, starting from the request's own (the seed), so a chunk cannot be altered,
// dropped, reordered or appended without breaking every signature after it.
type chunkSigner struct {
	key     []byte
	amzDate string
	scope   string
	prev    string
}

// emptySHA256 is the hash of no bytes, which stands in for the (absent)
// headers of each chunk in its string-to-sign.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// chunkSignature is the signature the next chunk must carry, given the SHA-256
// of its data.
func (s *chunkSigner) chunkSignature(dataHash []byte) string {
	return s.sign(strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD", s.amzDate, s.scope, s.prev,
		emptySHA256, hex.EncodeToString(dataHash),
	}, "\n"))
}

// trailerSignature is the signature the trailing headers must carry, given the
// SHA-256 of their canonical form. It chains from the final chunk's.
func (s *chunkSigner) trailerSignature(trailerHash []byte) string {
	return s.sign(strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER", s.amzDate, s.scope, s.prev,
		hex.EncodeToString(trailerHash),
	}, "\n"))
}

func (s *chunkSigner) sign(stringToSign string) string {
	return hex.EncodeToString(hmacSHA256(s.key, []byte(stringToSign)))
}

// accept compares a received signature with the expected one and, on a match,
// makes it the link the next signature chains from.
func (s *chunkSigner) accept(expected, got string) bool {
	if !hmac.Equal([]byte(expected), []byte(got)) {
		return false
	}
	s.prev = expected
	return true
}

// verify checks the request signature against the configured credential.
// It returns the signing context a streaming-signed body's chunks are then
// checked against (nil when auth is disabled, as there is no secret to check
// them with). See verifySigned for what is checked.
func verify(r *http.Request, auth config.AuthConfig) (*chunkSigner, error) {
	if !auth.Enabled {
		return nil, nil
	}
	req, err := parseSignedRequest(r)
	if err != nil {
		return nil, err
	}
	return verifySigned(r, req, auth.AccessKeyID, auth.SecretAccessKey)
}

// verifySigned checks req, parsed from r, against one credential.
//
// x-amz-content-sha256 is required on a header-signed request, as on S3: it is
// the payload hash the signature covers, and without it there is nothing to
// hold the body to.
// The request must be fresh: x-amz-date within maxClockSkew of the server's
// clock (for a presigned URL, no further ahead than that and no older than its
// X-Amz-Expires), and the credential scope's date equal to it, so a captured
// request stops verifying after the window and cannot be re-scoped to another
// day. The scope's service must be s3. Its region is taken from the request
// rather than pinned to the server's configured region: the signature covers
// whatever region the client declared, a mismatch does nothing for replay, and
// pinning it would reject clients signing for their own default region.
//
// A presigned request returns no signing context: its signature was made
// before any body existed, so there is no chunk chain to seed, and a body
// framed as signed chunks is refused rather than decoded unchecked.
func verifySigned(r *http.Request, req signedRequest, accessKeyID, secret string) (*chunkSigner, error) {
	if !hmac.Equal([]byte(req.accessKeyID), []byte(accessKeyID)) {
		return nil, apperr.ErrAccessDenied
	}
	if err := checkFreshness(req); err != nil {
		return nil, err
	}
	if req.hashedPayload == "" {
		return nil, apperr.InvalidRequest("missing required header for this request: x-amz-content-sha256")
	}
	if req.presigned {
		switch r.Header.Get("x-amz-content-sha256") {
		case streamingSigned, streamingSignedTrailer:
			return nil, apperr.InvalidRequest("a presigned request cannot carry a body signed in chunks")
		}
	}

	canonicalHeaders, ok := buildCanonicalHeaders(r, req.signedHeaders)
	if !ok {
		return nil, apperr.ErrSignatureDoesNotMatch
	}
	query := canonicalQueryString(r.URL.RawQuery)
	if req.presigned {
		query = canonicalQuery(req.query)
	}

	expected := computeSignature(signatureInput{
		secret:           secret,
		method:           r.Method,
		canonicalURI:     r.URL.EscapedPath(),
		canonicalQuery:   query,
		signedHeaders:    req.signedHeaders,
		canonicalHeaders: canonicalHeaders,
		hashedPayload:    req.hashedPayload,
		amzDate:          req.amzDate,
		dateStamp:        req.dateStamp,
		region:           req.region,
		service:          req.service,
	})

	if !hmac.Equal([]byte(expected), []byte(req.signature)) {
		return nil, apperr.ErrSignatureDoesNotMatch
	}
	if req.presigned {
		return nil, nil
	}
	return &chunkSigner{
		key:     signingKey(secret, req.dateStamp, req.region, req.service),
		amzDate: req.amzDate,
		scope:   strings.Join([]string{req.dateStamp, req.region, req.service, "aws4_request"}, "/"),
		prev:    expected,
	}, nil
}

// checkFreshness validates the signing time against the clock and the
// credential scope. See verifySigned.
func checkFreshness(req signedRequest) error {
	signedAt, err := time.Parse(amzDateFormat, req.amzDate)
	if err != nil {
		return apperr.ErrAccessDenied
	}
	if req.dateStamp != signedAt.Format("20060102") || req.service != "s3" {
		return apperr.ErrAccessDenied
	}
	skew := now().Sub(signedAt)
	if req.presigned {
		// S3 answers both as AccessDenied, with these messages.
		if skew < -maxClockSkew {
			return apperr.Forbidden("request is not valid yet")
		}
		if skew > req.expires {
			return apperr.Forbidden("request has expired")
		}
		return nil
	}
	if skew > maxClockSkew || skew < -maxClockSkew {
		return apperr.ErrRequestTimeTooSkewed
	}
	return nil
}
