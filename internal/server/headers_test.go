package server

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSurfaceHeaders(t *testing.T) {
	handler := newRoutes(true)

	tests := []struct {
		path   string
		policy string
	}{
		{"/ui/", uiPolicy},
		{"/ui", uiPolicy},
		{"/ui/assets/index-abc123.js", uiPolicy},
		{"/api/stats", lockedPolicy},
		{"/auth/login", lockedPolicy},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			want := map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"Referrer-Policy":         "same-origin",
				"X-Frame-Options":         "DENY",
				"Content-Security-Policy": tc.policy,
			}
			for name, value := range want {
				if got := w.Header().Get(name); got != value {
					t.Errorf("%s = %q, want %q", name, got, value)
				}
			}
			if got := w.Header().Get("Strict-Transport-Security"); got != "" {
				t.Errorf("Strict-Transport-Security = %q on plain HTTP", got)
			}
		})
	}
}

// Every policy refuses framing outright, so the UI cannot be clickjacked even
// by a browser that ignores X-Frame-Options.
func TestPoliciesRefuseFraming(t *testing.T) {
	for _, policy := range []string{uiPolicy, lockedPolicy} {
		if !strings.Contains(policy, "frame-ancestors 'none'") {
			t.Errorf("policy %q allows framing", policy)
		}
	}
}

// The gateway sets its own headers on objects, and none of the surface headers
// may leak onto it: a namespace, an object, and /auth while sign-in is off.
func TestGatewayGetsNoSurfaceHeaders(t *testing.T) {
	for _, tc := range []struct {
		path     string
		withAuth bool
	}{
		{"/", true},
		{"/photos/cat.jpg", true},
		{"/auth/login", false},
		{"/%61pi/stats", true},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.TLS = &tls.ConnectionState{}
		newRoutes(tc.withAuth).ServeHTTP(w, r)
		if got := w.Header().Get("X-Handled-By"); got != "gateway" {
			t.Fatalf("%s was handled by %q", tc.path, got)
		}
		for _, name := range []string{
			"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
		} {
			if got := w.Header().Get(name); got != "" {
				t.Errorf("%s: %s = %q, want none", tc.path, name, got)
			}
		}
	}
}

func TestStrictTransportSecurity(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		https bool
		want  string
	}{
		{"plain http", false, false, ""},
		{"a request over tls", true, false, hstsPolicy},
		// TLS ends at a proxy, so the request is plain but the public URL is not.
		{"an https public url", false, true, hstsPolicy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := Routes{
				Gateway: marker("gateway"), API: marker("api"), UI: marker("ui"),
				HTTPS: tc.https,
			}.Handler(slog.New(slog.DiscardHandler))
			for _, path := range []string{"/ui/", "/api/stats"} {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				if tc.tls {
					r.TLS = &tls.ConnectionState{}
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if got := w.Header().Get("Strict-Transport-Security"); got != tc.want {
					t.Errorf("%s: Strict-Transport-Security = %q, want %q", path, got, tc.want)
				}
			}
		})
	}
}

// The headers are defaults: a surface that knows its page needs a different
// policy (the sign-in page's inline stylesheet) can replace it.
func TestSurfaceCanReplaceItsPolicy(t *testing.T) {
	const own = "default-src 'none'; style-src 'sha256-x'"
	handler := Routes{
		Gateway: marker("gateway"), API: marker("api"), UI: marker("ui"),
		Auth: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Security-Policy", own)
		}),
	}.Handler(slog.New(slog.DiscardHandler))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if got := w.Header().Get("Content-Security-Policy"); got != own {
		t.Errorf("Content-Security-Policy = %q, want the handler's own", got)
	}
}
