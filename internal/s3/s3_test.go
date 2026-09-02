package s3

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		namespace, key string
	}{
		{"service root", "/", "", ""},
		{"empty path", "", "", ""},
		{"namespace only", "/photos", "photos", ""},
		{"namespace with trailing slash", "/photos/", "photos", ""},
		{"simple key", "/photos/cat.jpg", "photos", "cat.jpg"},
		{"hierarchical key", "/photos/2024/06/cat.jpg", "photos", "2024/06/cat.jpg"},
		{"percent-encoded space", "/photos/my%20cat.jpg", "photos", "my cat.jpg"},
		{"encoded slash decodes into the key", "/photos/a%2Fb", "photos", "a/b"},
		{"encoded plus stays a plus", "/photos/a+b", "photos", "a+b"},
		{"unicode", "/photos/%C3%A9t%C3%A9.jpg", "photos", "été.jpg"},

		// S3 keys may contain these sequences, and http.ServeMux would clean
		// them away with a redirect — which is why the gateway routes itself.
		{"double slash inside a key", "/photos//nested.jpg", "photos", "/nested.jpg"},
		{"dot segment inside a key", "/photos/./cat.jpg", "photos", "./cat.jpg"},
		{"dotdot segment inside a key", "/photos/../cat.jpg", "photos", "../cat.jpg"},
		{"trailing double slash", "/photos/dir//", "photos", "dir//"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ns, key, err := splitPath(tc.path)
			if err != nil {
				t.Fatalf("splitPath(%q): %v", tc.path, err)
			}
			if ns != tc.namespace || key != tc.key {
				t.Errorf("splitPath(%q) = (%q, %q), want (%q, %q)",
					tc.path, ns, key, tc.namespace, tc.key)
			}
		})
	}
}

func TestSplitPathRejectsBadEscapes(t *testing.T) {
	for _, path := range []string{"/ns/%zz", "/%zz/key"} {
		if _, _, err := splitPath(path); err == nil {
			t.Errorf("splitPath(%q) should reject a malformed escape", path)
		}
	}
}

func TestValidNamespaceName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"typical", "my-namespace.01", true},
		{"minimum length", "abc", true},
		{"maximum length", strings.Repeat("a", 63), true},
		{"digits at both ends", "1a2", true},
		{"too short", "ab", false},
		{"too long", strings.Repeat("a", 64), false},
		{"leading hyphen", "-bad", false},
		{"trailing hyphen", "bad-", false},
		{"leading dot", ".bad", false},
		{"trailing dot", "bad.", false},
		{"uppercase", "Bad", false},
		{"underscore", "a_b", false},
		{"space", "a b", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validNamespaceName(tc.input); got != tc.want {
				t.Errorf("validNamespaceName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseRange(t *testing.T) {
	const size = 10

	tests := []struct {
		name       string
		header     string
		start, end int64
		present    bool
		wantErr    bool
	}{
		{name: "closed range", header: "bytes=0-4", start: 0, end: 4, present: true},
		{name: "open-ended", header: "bytes=5-", start: 5, end: 9, present: true},
		{name: "suffix", header: "bytes=-3", start: 7, end: 9, present: true},
		{name: "end beyond the object is clamped", header: "bytes=0-99", start: 0, end: 9, present: true},
		{name: "whole object", header: "bytes=0-9", start: 0, end: 9, present: true},
		{name: "single byte", header: "bytes=4-4", start: 4, end: 4, present: true},
		{name: "suffix longer than the object", header: "bytes=-99", start: 0, end: 9, present: true},
		{name: "surrounding whitespace", header: " bytes=1-2 ", start: 1, end: 2, present: true},

		// Recognised but unsatisfiable.
		{name: "start past the end", header: "bytes=10-", wantErr: true},
		{name: "zero-length suffix", header: "bytes=-0", wantErr: true},
		{name: "inverted", header: "bytes=5-2", wantErr: true},
		{name: "non-numeric start", header: "bytes=x-5", wantErr: true},
		{name: "non-numeric end", header: "bytes=0-x", wantErr: true},
		{name: "non-numeric suffix", header: "bytes=-x", wantErr: true},

		// Not honoured: serve the whole object instead (RFC 7233 permits this).
		{name: "multiple ranges", header: "bytes=0-1,3-4", present: false},
		{name: "unknown unit", header: "items=0-1", present: false},
		{name: "no dash", header: "bytes=5", present: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start, end, present, err := parseRange(tc.header, size)
			if tc.wantErr {
				if !errors.Is(err, apperr.ErrInvalidRange) {
					t.Fatalf("err = %v, want ErrInvalidRange", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if present != tc.present {
				t.Fatalf("present = %v, want %v", present, tc.present)
			}
			if present && (start != tc.start || end != tc.end) {
				t.Errorf("range = %d-%d, want %d-%d", start, end, tc.start, tc.end)
			}
		})
	}
}

func TestParseDelimiter(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    byte
		wantErr bool
	}{
		{name: "absent", raw: "", want: 0},
		{name: "slash", raw: "/", want: '/'},
		{name: "pipe", raw: "|", want: '|'},
		{name: "multi-byte string", raw: "//", wantErr: true},
		{name: "non-ascii", raw: "é", wantErr: true},
		{name: "control character", raw: "\x01", wantErr: true},
		// 0x7f would increment to 0x80, which is not valid UTF-8 for the
		// resume marker the listing writes back into Postgres.
		{name: "delete character", raw: "\x7f", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDelimiter(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseDelimiter(%q) should have failed", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDelimiter(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("parseDelimiter(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClampInt(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		max  int
		want int
	}{
		{"absent falls back to the maximum", "", 1000, 1000},
		{"in range", "50", 1000, 50},
		{"above the maximum is capped", "5000", 1000, 1000},
		{"zero floors to one", "0", 1000, 1},
		{"negative floors to one", "-5", 1000, 1},
		{"unparseable falls back to the maximum", "lots", 1000, 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampInt(tc.raw, tc.max); got != tc.want {
				t.Errorf("clampInt(%q, %d) = %d, want %d", tc.raw, tc.max, got, tc.want)
			}
		})
	}
}

func TestTimeFormats(t *testing.T) {
	// A non-UTC input must still render as UTC on the wire.
	loc := time.FixedZone("UTC+9", 9*3600)
	ts := time.Date(2026, 9, 2, 22, 4, 5, 123456789, loc)

	if got, want := iso8601(ts), "2026-09-02T13:04:05.123Z"; got != want {
		t.Errorf("iso8601 = %q, want %q", got, want)
	}
	if got, want := httpDate(ts), "Wed, 02 Sep 2026 13:04:05 GMT"; got != want {
		t.Errorf("httpDate = %q, want %q", got, want)
	}
	if got, want := quotedETag("abc"), `"abc"`; got != want {
		t.Errorf("quotedETag = %q, want %q", got, want)
	}
}

func TestParseUploadIDRejectsGarbageAsUnknown(t *testing.T) {
	if _, err := parseUploadID("not-a-uuid"); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("err = %v, want ErrNoSuchUpload so a typo is indistinguishable from someone else's upload", err)
	}
	if _, err := parseUploadID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"); err != nil {
		t.Errorf("a well-formed id should parse: %v", err)
	}
}
