package s3

import (
	"net/http"
	"net/http/httptest"
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
	if err := verify(r, config.AuthConfig{Enabled: false}); err != nil {
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
			name: "presigned query auth is not supported",
			prepare: func(r *http.Request) {
				r.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef"
			},
			want: apperr.ErrAccessDenied,
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
			},
			want: apperr.ErrSignatureDoesNotMatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ns/key", nil)
			tc.prepare(r)
			err := verify(r, auth)
			if err != tc.want {
				t.Errorf("verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// signAt signs r with UNSIGNED-PAYLOAD as keyID/secret at the given time and
// scope service, the way a real client does: build the canonical request, sign
// it, and set the Authorization header.
func signAt(r *http.Request, keyID, secret string, at time.Time, service string) {
	const payload = "UNSIGNED-PAYLOAD"
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

	if err := verify(r, testAuth); err != nil {
		t.Fatalf("a correctly signed request was rejected: %v", err)
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
			if err := verify(r, testAuth); err != tc.want {
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
	if err := verify(r, testAuth); err != apperr.ErrAccessDenied {
		t.Errorf("verify = %v, want AccessDenied", err)
	}

	r.Header.Set("x-amz-date", "not-a-date")
	if err := verify(r, testAuth); err != apperr.ErrAccessDenied {
		t.Errorf("verify with a malformed x-amz-date = %v, want AccessDenied", err)
	}
}
