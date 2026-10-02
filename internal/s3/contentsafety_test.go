package s3

import (
	"net/http"
	"testing"
)

func TestSetContentSafetyHeaders(t *testing.T) {
	tests := []struct {
		contentType string
		attachment  bool
		sandbox     bool
	}{
		{"text/html", true, true},
		{"TEXT/HTML; charset=utf-8", true, true},
		{"image/svg+xml", true, true},
		{"application/xhtml+xml", true, true},
		{"application/javascript", true, true},
		{"application/octet-stream", true, true},
		{"", true, true},
		{"not a media type;;", true, true},
		{"image/png", false, true},
		{"video/mp4", false, true},
		{"audio/mpeg", false, true},
		{"text/plain; charset=utf-8", false, true},
		// Browsers will not render a PDF inside a sandboxed document.
		{"application/pdf", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.contentType, func(t *testing.T) {
			h := http.Header{}
			setContentSafetyHeaders(h, tc.contentType)

			if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := h.Get("Content-Disposition") == "attachment"; got != tc.attachment {
				t.Errorf("attachment = %v, want %v", got, tc.attachment)
			}
			if got := h.Get("Content-Security-Policy") == "sandbox"; got != tc.sandbox {
				t.Errorf("sandbox = %v, want %v", got, tc.sandbox)
			}
		})
	}
}
