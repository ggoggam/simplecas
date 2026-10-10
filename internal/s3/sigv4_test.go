package s3

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
)

// AWS's published "GET Object" SigV4 example, from "Authenticating Requests:
// Using the Authorization Header" in the S3 developer guide. If this drifts,
// the gateway has stopped speaking SigV4.
func TestAWSPublishedGetObjectVector(t *testing.T) {
	const (
		secret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		want      = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	)
	canonicalHeaders := "host:examplebucket.s3.amazonaws.com\n" +
		"range:bytes=0-9\n" +
		"x-amz-content-sha256:" + emptyHash + "\n" +
		"x-amz-date:20130524T000000Z\n"

	got := computeSignature(signatureInput{
		secret:           secret,
		method:           "GET",
		canonicalURI:     "/test.txt",
		canonicalQuery:   "",
		signedHeaders:    "host;range;x-amz-content-sha256;x-amz-date",
		canonicalHeaders: canonicalHeaders,
		hashedPayload:    emptyHash,
		amzDate:          "20130524T000000Z",
		dateStamp:        "20130524",
		region:           "us-east-1",
		service:          "s3",
	})
	if got != want {
		t.Errorf("signature = %s, want %s", got, want)
	}
}

func TestCanonicalQueryString(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"empty", "", ""},
		{"sorted and slash-encoded", "prefix=foo/bar&list-type=2", "list-type=2&prefix=foo%2Fbar"},
		{"valueless keys keep the equals", "uploads", "uploads="},
		{"tilde is unreserved", "k=a~b", "k=a~b"},
		{"space becomes %20, not +", "k=a b", "k=a%20b"},
		{"already sorted stays", "a=1&b=2", "a=1&b=2"},
		{"reverse order is sorted", "b=2&a=1", "a=1&b=2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalQueryString(tc.raw); got != tc.want {
				t.Errorf("canonicalQueryString(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestURIEncode(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		encodeSlash bool
		want        string
	}{
		{"unreserved passes through", "abcXYZ019-_.~", false, "abcXYZ019-_.~"},
		{"slash kept in path context", "a/b", false, "a/b"},
		{"slash encoded in query context", "a/b", true, "a%2Fb"},
		{"space", "a b", false, "a%20b"},
		{"uppercase hex", "\n", false, "%0A"},
		{"utf-8 is encoded per byte", "é", false, "%C3%A9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := uriEncode(tc.in, tc.encodeSlash); got != tc.want {
				t.Errorf("uriEncode(%q, %v) = %q, want %q", tc.in, tc.encodeSlash, got, tc.want)
			}
		})
	}
}

func TestCanonicalHeaderValue(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"trims", "  value  ", "value"},
		{"collapses runs", "a    b", "a b"},
		{"collapses tabs and newlines", "a\t\nb", "a b"},
		{"leaves single spaces", "a b c", "a b c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalHeaderValue(tc.in); got != tc.want {
				t.Errorf("canonicalHeaderValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAuthHeader(t *testing.T) {
	valid := "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=abc123"

	got, ok := parseAuthHeader(valid)
	if !ok {
		t.Fatal("valid header failed to parse")
	}
	if got.accessKeyID != "AKID" || got.dateStamp != "20130524" ||
		got.region != "us-east-1" || got.service != "s3" {
		t.Errorf("credential scope = %+v", got)
	}
	if got.signedHeaders != "host;x-amz-date" || got.signature != "abc123" {
		t.Errorf("signed headers / signature = %+v", got)
	}

	bad := []struct{ name, header string }{
		{"wrong algorithm", "AWS2-HMAC Credential=a/b/c/d/aws4_request, SignedHeaders=host, Signature=x"},
		{"missing signature", "AWS4-HMAC-SHA256 Credential=a/b/c/d/aws4_request, SignedHeaders=host"},
		{"missing signed headers", "AWS4-HMAC-SHA256 Credential=a/b/c/d/aws4_request, Signature=x"},
		{"short credential scope", "AWS4-HMAC-SHA256 Credential=a/b/c, SignedHeaders=host, Signature=x"},
		{"scope not terminated by aws4_request", "AWS4-HMAC-SHA256 Credential=a/b/c/d/nope, SignedHeaders=host, Signature=x"},
		{"garbage", "AWS4-HMAC-SHA256 nonsense"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseAuthHeader(tc.header); ok {
				t.Errorf("%q should not parse", tc.header)
			}
		})
	}
}

// Auth disabled is the documented dev/PWA mode: no signature is required at all.
func TestVerifySkippedWhenAuthDisabled(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ns/key", nil)
	if _, err := verify(r, config.AuthConfig{Enabled: false}); err != nil {
		t.Errorf("verify with auth disabled = %v, want nil", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	auth := config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     "AKID",
		SecretAccessKey: "secret",
	}
	// Current, so these cases reach the check they name rather than failing
	// the freshness check first.
	amzDate := now().UTC().Format(amzDateFormat)
	dateStamp := amzDate[:8]

	tests := []struct {
		name    string
		prepare func(*http.Request)
		want    error
	}{
		{
			name:    "no Authorization header",
			prepare: func(*http.Request) {},
			want:    apperr.ErrAccessDenied,
		},
		{
			name: "unknown access key",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
					"Credential=OTHER/"+dateStamp+"/us-east-1/s3/aws4_request, "+
					"SignedHeaders=host, Signature=abc")
				r.Header.Set("x-amz-date", amzDate)
			},
			want: apperr.ErrAccessDenied,
		},
		{
			name: "missing x-amz-date",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
					"Credential=AKID/"+dateStamp+"/us-east-1/s3/aws4_request, "+
					"SignedHeaders=host, Signature=abc")
			},
			want: apperr.ErrAccessDenied,
		},
		{
			name: "a signed header the request does not carry",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
					"Credential=AKID/"+dateStamp+"/us-east-1/s3/aws4_request, "+
					"SignedHeaders=host;x-amz-absent, Signature=abc")
				r.Header.Set("x-amz-date", amzDate)
				r.Header.Set("x-amz-content-sha256", unsignedPayload)
			},
			want: apperr.ErrSignatureDoesNotMatch,
		},
		{
			name: "wrong signature",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
					"Credential=AKID/"+dateStamp+"/us-east-1/s3/aws4_request, "+
					"SignedHeaders=host, Signature=0000000000000000")
				r.Header.Set("x-amz-date", amzDate)
				r.Header.Set("x-amz-content-sha256", unsignedPayload)
			},
			want: apperr.ErrSignatureDoesNotMatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ns/key", nil)
			tc.prepare(r)
			_, err := verify(r, auth)
			if err != tc.want {
				t.Errorf("verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// signAt signs r as keyID/secret at the given time and scope service, the way
// a real client does: build the canonical request, sign it, and set the
// Authorization header. The payload hash is the x-amz-content-sha256 already on
// r, or UNSIGNED-PAYLOAD when it carries none.
func signAt(r *http.Request, keyID, secret string, at time.Time, service string) {
	payload := r.Header.Get("x-amz-content-sha256")
	if payload == "" {
		payload = unsignedPayload
	}
	amzDate := at.UTC().Format(amzDateFormat)
	dateStamp := amzDate[:8]

	r.Header.Set("x-amz-date", amzDate)
	r.Header.Set("x-amz-content-sha256", payload)

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + r.Host + "\n" +
		"x-amz-content-sha256:" + payload + "\n" +
		"x-amz-date:" + amzDate + "\n"

	sig := computeSignature(signatureInput{
		secret:           secret,
		method:           r.Method,
		canonicalURI:     r.URL.EscapedPath(),
		canonicalQuery:   canonicalQueryString(r.URL.RawQuery),
		signedHeaders:    signedHeaders,
		canonicalHeaders: canonicalHeaders,
		hashedPayload:    payload,
		amzDate:          amzDate,
		dateStamp:        dateStamp,
		region:           "us-east-1",
		service:          service,
	})
	r.Header.Set("Authorization", strings.Join([]string{
		sigV4Algorithm + " Credential=" + keyID + "/" + dateStamp + "/us-east-1/" + service + "/aws4_request",
		"SignedHeaders=" + signedHeaders,
		"Signature=" + sig,
	}, ", "))
}

var testAuth = config.AuthConfig{
	Enabled:         true,
	AccessKeyID:     "AKID",
	SecretAccessKey: "secret",
}

// A correctly signed request must actually pass, exercising the same path a
// real client takes: sign the canonical request, then verify it.
func TestVerifyAcceptsACorrectlySignedRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ns/key?list-type=2&prefix=a/b", nil)
	r.Host = "cas.example.com"
	signAt(r, "AKID", "secret", now(), "s3")

	if _, err := verify(r, testAuth); err != nil {
		t.Fatalf("a correctly signed request was rejected: %v", err)
	}
}

// x-amz-content-sha256 is what the signature holds the body to, so S3 requires
// it on every SigV4 request. Without it a signed request would say nothing
// about its body at all.
func TestVerifyRequiresThePayloadHash(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("abc"))
	r.Host = "cas.example.com"
	signAt(r, "AKID", "secret", now(), "s3")
	r.Header.Del("x-amz-content-sha256")

	_, err := verify(r, testAuth)
	if e := apperr.From(err); e == nil || e.S3Code() != "InvalidRequest" {
		t.Fatalf("verify without x-amz-content-sha256 = %v, want InvalidRequest", err)
	}
}

// A validly signed request is only good for maxClockSkew either side of the
// server's clock; past that, a captured request must stop verifying.
func TestVerifyEnforcesFreshness(t *testing.T) {
	tests := []struct {
		name    string
		at      time.Duration
		service string
		want    error
	}{
		{"within the window, behind", -14 * time.Minute, "s3", nil},
		{"within the window, ahead", 14 * time.Minute, "s3", nil},
		{"replayed after the window", -16 * time.Minute, "s3", apperr.ErrRequestTimeTooSkewed},
		{"a year old", -365 * 24 * time.Hour, "s3", apperr.ErrRequestTimeTooSkewed},
		{"signed for the future", 16 * time.Minute, "s3", apperr.ErrRequestTimeTooSkewed},
		{"scoped to another service", 0, "iam", apperr.ErrAccessDenied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ns/key", nil)
			r.Host = "cas.example.com"
			signAt(r, "AKID", "secret", now().Add(tc.at), tc.service)
			if _, err := verify(r, testAuth); err != tc.want {
				t.Errorf("verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// The credential scope's date must be x-amz-date's, so a signature cannot be
// re-dated by editing one of the two.
func TestVerifyRejectsMismatchedScopeDate(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ns/key", nil)
	r.Host = "cas.example.com"
	signAt(r, "AKID", "secret", now(), "s3")
	r.Header.Set("x-amz-date", now().Add(-48*time.Hour).UTC().Format(amzDateFormat))
	if _, err := verify(r, testAuth); err != apperr.ErrAccessDenied {
		t.Errorf("verify = %v, want AccessDenied", err)
	}

	r.Header.Set("x-amz-date", "not-a-date")
	if _, err := verify(r, testAuth); err != apperr.ErrAccessDenied {
		t.Errorf("verify with a malformed x-amz-date = %v, want AccessDenied", err)
	}
}

// presignAt presigns r as keyID/secret at the given time, valid for expires,
// the way a client builds a presigned URL: the signing parameters go in the
// query, the canonical request covers them and UNSIGNED-PAYLOAD, and the
// signature is appended last.
func presignAt(r *http.Request, keyID, secret string, at time.Time, expires time.Duration) {
	date := at.UTC().Format(amzDateFormat)
	dateStamp := date[:8]
	query := r.URL.Query()
	query.Set(amzAlgorithm, sigV4Algorithm)
	query.Set(amzCredential, keyID+"/"+dateStamp+"/us-east-1/s3/aws4_request")
	query.Set(amzDate, date)
	query.Set(amzExpires, strconv.Itoa(int(expires/time.Second)))
	query.Set(amzSignedHeaders, "host")

	sig := computeSignature(signatureInput{
		secret:           secret,
		method:           r.Method,
		canonicalURI:     r.URL.EscapedPath(),
		canonicalQuery:   canonicalQuery(query),
		signedHeaders:    "host",
		canonicalHeaders: "host:" + r.Host + "\n",
		hashedPayload:    unsignedPayload,
		amzDate:          date,
		dateStamp:        dateStamp,
		region:           "us-east-1",
		service:          "s3",
	})
	query.Set(amzSignature, sig)
	r.URL.RawQuery = query.Encode()
}

func presignedRequest(method, target string, at time.Time, expires time.Duration) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "cas.example.com"
	presignAt(r, "AKID", "secret", at, expires)
	return r
}

// A presigned URL verifies like a header-signed request, with no headers at
// all beyond Host, and its own query parameters still covered by it.
func TestVerifyAcceptsAPresignedRequest(t *testing.T) {
	r := presignedRequest(http.MethodGet, "/ns/some%20key?x-id=GetObject&response-cache-control=no-store", now(), time.Hour)
	signer, err := verify(r, testAuth)
	if err != nil {
		t.Fatalf("a correctly presigned request was rejected: %v", err)
	}
	if signer != nil {
		t.Error("a presigned request returned a chunk signing context")
	}
}

// A presigned URL is good from its X-Amz-Date (less the clock skew S3
// allows) until X-Amz-Expires after it, and not outside that.
func TestPresignedRequestsExpire(t *testing.T) {
	tests := []struct {
		name    string
		at      time.Duration
		expires time.Duration
		want    string
	}{
		{"fresh", 0, time.Hour, ""},
		{"near the end of its life", -59 * time.Minute, time.Hour, ""},
		{"a week old with a week's expiry", -maxPresignExpiry + time.Minute, maxPresignExpiry, ""},
		{"expired", -61 * time.Minute, time.Hour, "AccessDenied"},
		{"expired, though within the header skew", -2 * time.Minute, time.Minute, "AccessDenied"},
		{"signed slightly ahead of the clock", 14 * time.Minute, time.Hour, ""},
		{"not valid yet", 16 * time.Minute, time.Hour, "AccessDenied"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := presignedRequest(http.MethodGet, "/ns/key", now().Add(tc.at), tc.expires)
			_, err := verify(r, testAuth)
			if got := s3Code(err); got != tc.want {
				t.Errorf("verify = %v, want %q", err, tc.want)
			}
		})
	}
}

func s3Code(err error) string {
	if err == nil {
		return ""
	}
	return apperr.From(err).S3Code()
}

// A presigned URL whose parameters are missing, repeated, malformed or out of
// range is refused before any signature is computed.
func TestPresignedQueryParameters(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(q url.Values)
		want   string
	}{
		{"no signature", func(q url.Values) { q.Del(amzSignature) }, "AuthorizationQueryParametersError"},
		{"no credential", func(q url.Values) { q.Del(amzCredential) }, "AuthorizationQueryParametersError"},
		{"no date", func(q url.Values) { q.Del(amzDate) }, "AuthorizationQueryParametersError"},
		{"no expiry", func(q url.Values) { q.Del(amzExpires) }, "AuthorizationQueryParametersError"},
		{"no signed headers", func(q url.Values) { q.Del(amzSignedHeaders) }, "AuthorizationQueryParametersError"},
		{"a second signature", func(q url.Values) { q.Add(amzSignature, "00") }, "AuthorizationQueryParametersError"},
		{"a second expiry", func(q url.Values) { q.Add(amzExpires, "604800") }, "AuthorizationQueryParametersError"},
		{"another algorithm", func(q url.Values) { q.Set(amzAlgorithm, "AWS4-ECDSA-P256-SHA256") }, "AuthorizationQueryParametersError"},
		{"a malformed credential", func(q url.Values) { q.Set(amzCredential, "AKID/x/y") }, "AuthorizationQueryParametersError"},
		{"zero expiry", func(q url.Values) { q.Set(amzExpires, "0") }, "AuthorizationQueryParametersError"},
		{"negative expiry", func(q url.Values) { q.Set(amzExpires, "-5") }, "AuthorizationQueryParametersError"},
		{"expiry past a week", func(q url.Values) { q.Set(amzExpires, "604801") }, "AuthorizationQueryParametersError"},
		{"an expiry that overflows a duration", func(q url.Values) { q.Set(amzExpires, "9223372037") }, "AuthorizationQueryParametersError"},
		{"non-numeric expiry", func(q url.Values) { q.Set(amzExpires, "1h") }, "AuthorizationQueryParametersError"},
		{"host not signed", func(q url.Values) { q.Set(amzSignedHeaders, "x-amz-date") }, "AuthorizationQueryParametersError"},
		{"a session token", func(q url.Values) { q.Set(amzSecurityToken, "token") }, "AccessDenied"},
		{"a longer expiry than was signed", func(q url.Values) { q.Set(amzExpires, "7200") }, "SignatureDoesNotMatch"},
		{"another key", func(q url.Values) { q.Set("prefix", "elsewhere/") }, "SignatureDoesNotMatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := presignedRequest(http.MethodGet, "/ns/key", now(), time.Hour)
			q := r.URL.Query()
			tc.mutate(q)
			r.URL.RawQuery = q.Encode()
			_, err := verify(r, testAuth)
			if got := s3Code(err); got != tc.want {
				t.Errorf("verify = %v, want %q", err, tc.want)
			}
		})
	}
}

// The signature binds the method, path and host: a URL presigned for one
// object cannot be pointed at another, used to write, or replayed elsewhere.
func TestPresignedRequestCannotBeRetargeted(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *http.Request)
	}{
		{"another key", func(r *http.Request) { r.URL.Path, r.URL.RawPath = "/ns/other", "" }},
		{"another namespace", func(r *http.Request) { r.URL.Path, r.URL.RawPath = "/other/key", "" }},
		{"another method", func(r *http.Request) { r.Method = http.MethodPut }},
		{"another host", func(r *http.Request) { r.Host = "evil.example.com" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := presignedRequest(http.MethodGet, "/ns/key", now(), time.Hour)
			tc.mutate(r)
			if _, err := verify(r, testAuth); err != apperr.ErrSignatureDoesNotMatch {
				t.Errorf("verify = %v, want SignatureDoesNotMatch", err)
			}
		})
	}
}

// A presigned URL with an Authorization header too is refused, as on S3,
// rather than checked one way and trusted the other.
func TestPresignedAndHeaderAuthTogetherAreRefused(t *testing.T) {
	r := presignedRequest(http.MethodGet, "/ns/key", now(), time.Hour)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, "+
		"SignedHeaders=host, Signature=abc")
	if _, err := verify(r, testAuth); s3Code(err) != "InvalidArgument" {
		t.Errorf("verify = %v, want InvalidArgument", err)
	}
}

// A presigned signature has no chunk chain to seed, so a body that claims to
// be signed chunk by chunk is refused instead of decoded without checks.
func TestPresignedRequestRefusesASignedChunkedBody(t *testing.T) {
	for _, mode := range []string{streamingSigned, streamingSignedTrailer} {
		r := presignedRequest(http.MethodPut, "/ns/key", now(), time.Hour)
		r.Header.Set("x-amz-content-sha256", mode)
		if _, err := verify(r, testAuth); s3Code(err) != "InvalidRequest" {
			t.Errorf("%s: verify = %v, want InvalidRequest", mode, err)
		}
	}
}
