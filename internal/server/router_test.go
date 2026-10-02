package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// marker is a handler that identifies itself and echoes the path it saw, so a
// test can tell both which surface handled a request and what path reached it.
func marker(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handled-By", name)
		_, _ = io.WriteString(w, r.URL.Path)
	})
}

func newRoutes(withAuth bool) http.Handler {
	rt := Routes{
		Gateway: marker("gateway"),
		API:     marker("api"),
		UI:      marker("ui"),
	}
	if withAuth {
		rt.Auth = marker("auth")
	}
	return rt.Handler(slog.New(slog.DiscardHandler))
}

func TestFirstSegment(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/", ""},
		{"", ""},
		{"/api", "api"},
		{"/api/stats", "api"},
		{"/photos/cat.jpg", "photos"},
		{"/photos/", "photos"},
		// Not decoded, so an encoded spelling is a different segment.
		{"/%61pi/stats", "%61pi"},
	}
	for _, tc := range tests {
		if got := firstSegment(tc.path); got != tc.want {
			t.Errorf("firstSegment(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestRoutePrecedence(t *testing.T) {
	handler := newRoutes(true)

	tests := []struct {
		name    string
		path    string
		handled string
	}{
		{"service root goes to the gateway", "/", "gateway"},
		{"admin api", "/api/stats", "api"},
		{"admin api object route", "/api/namespaces/ns/objects/a/b", "api"},
		{"pwa root", "/ui/", "ui"},
		{"pwa asset", "/ui/assets/index-abc123.js", "ui"},
		{"bare pwa path", "/ui", "ui"},
		{"auth endpoints", "/auth/login", "auth"},
		{"a namespace", "/photos", "gateway"},
		{"an object", "/photos/cat.jpg", "gateway"},
		{"a namespace that merely starts with a reserved word", "/apifoo/key", "gateway"},
		{"a namespace named uix", "/uix", "gateway"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if got := w.Header().Get("X-Handled-By"); got != tc.handled {
				t.Errorf("%s was handled by %q, want %q", tc.path, got, tc.handled)
			}
		})
	}
}

// With sign-in disabled there are no /auth endpoints, so "auth" stops being a
// reserved name and behaves like any other namespace.
func TestAuthPrefixIsOnlyReservedWhenEnabled(t *testing.T) {
	w := httptest.NewRecorder()
	newRoutes(false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if got := w.Header().Get("X-Handled-By"); got != "gateway" {
		t.Errorf("/auth was handled by %q, want the gateway when OIDC is off", got)
	}

	w = httptest.NewRecorder()
	newRoutes(true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if got := w.Header().Get("X-Handled-By"); got != "auth" {
		t.Errorf("/auth was handled by %q, want auth when OIDC is on", got)
	}
}

// A percent-encoded reserved prefix must not reach the reserved surface.
func TestEncodedPrefixDoesNotReachReservedSurfaces(t *testing.T) {
	for _, path := range []string{"/%61pi/stats", "/%75i/"} {
		w := httptest.NewRecorder()
		newRoutes(true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Header().Get("X-Handled-By"); got != "gateway" {
			t.Errorf("%s was handled by %q, want the gateway", path, got)
		}
	}
}

// The router must not clean paths: S3 keys may contain "//" and dot segments,
// and the gateway has to see them exactly as sent.
func TestPathsReachTheGatewayUncleaned(t *testing.T) {
	handler := newRoutes(true)

	for _, path := range []string{
		"/photos//nested.jpg",
		"/photos/./cat.jpg",
		"/photos/../cat.jpg",
		"/photos/dir//",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (no redirect)", w.Code)
			}
			if got := w.Header().Get("X-Handled-By"); got != "gateway" {
				t.Errorf("handled by %q", got)
			}
			if got := w.Body.String(); got != path {
				t.Errorf("the gateway saw %q, want %q untouched", got, path)
			}
		})
	}
}

func TestRequestLogging(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rt := Routes{
		Gateway: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "hello")
		}),
		API: marker("api"), UI: marker("ui"),
	}
	w := httptest.NewRecorder()
	rt.Handler(log).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/photos/cat.jpg", nil))

	logged := buf.String()
	for _, want := range []string{"method=GET", "path=/photos/cat.jpg", "status=418", "bytes=5"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log line missing %q:\n%s", want, logged)
		}
	}
}

// A handler that writes a body without an explicit WriteHeader still produced
// a 200, and the log has to say so rather than 0.
func TestRequestLoggingImplicitStatus(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rt := Routes{Gateway: marker("gateway"), API: marker("api"), UI: marker("ui")}
	w := httptest.NewRecorder()
	rt.Handler(log).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/photos", nil))

	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("expected an implicit 200 in the log:\n%s", buf.String())
	}
}

// A handler that writes nothing at all is still a 200.
func TestRequestLoggingEmptyResponse(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rt := Routes{
		Gateway: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		API:     marker("api"), UI: marker("ui"),
	}
	w := httptest.NewRecorder()
	rt.Handler(log).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/photos", nil))

	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("expected status=200:\n%s", buf.String())
	}
}

// Server errors are promoted above debug so they show at the default level.
func TestServerErrorsAreLoggedAtWarn(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rt := Routes{
		Gateway: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}),
		API: marker("api"), UI: marker("ui"),
	}
	w := httptest.NewRecorder()
	rt.Handler(log).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/photos", nil))

	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "status=500") {
		t.Errorf("a 500 should be logged at warn level:\n%s", logged)
	}
}

// Every response carries a request ID, distinct per request, and the access
// log records it, so a client quoting the ID from an error finds its log line.
func TestRequestIDs(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var seenByHandler string
	rt := Routes{
		Gateway: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			seenByHandler = w.Header().Get(apperr.RequestIDHeader)
		}),
		API: marker("api"), UI: marker("ui"),
	}
	h := rt.Handler(log)

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/b/k", nil))
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/b/k", nil))

	id := first.Header().Get(apperr.RequestIDHeader)
	if len(id) != 16 {
		t.Fatalf("request ID = %q, want 16 hex digits", id)
	}
	if id == second.Header().Get(apperr.RequestIDHeader) {
		t.Error("two requests got the same ID")
	}
	if seenByHandler == "" {
		t.Error("the ID must be set before the handler runs, so error writers can echo it")
	}
	if !strings.Contains(buf.String(), "requestId="+id) {
		t.Errorf("access log lacks requestId=%s:\n%s", id, buf.String())
	}
}
