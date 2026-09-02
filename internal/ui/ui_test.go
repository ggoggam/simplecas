package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func builtAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":              {Data: []byte("<!doctype html>app shell")},
		"assets/index-abc123.js":  {Data: []byte("console.log(1)")},
		"assets/index-abc123.css": {Data: []byte("body{}")},
		"manifest.webmanifest":    {Data: []byte("{}")},
		"favicon.svg":             {Data: []byte("<svg/>")},
	}
}

func get(t *testing.T, assets fstest.MapFS, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	New(assets).Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// The bare /ui must redirect, or index.html's relative asset URLs would
// resolve against the site root.
func TestBareUIRedirects(t *testing.T) {
	w := get(t, builtAssets(), "/ui")

	if w.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/ui/" {
		t.Errorf("Location = %q, want /ui/", got)
	}
}

func TestServesTheAppShell(t *testing.T) {
	w := get(t, builtAssets(), "/ui/")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "app shell") {
		t.Errorf("body = %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestServesAssetsWithTheirOwnTypes(t *testing.T) {
	tests := []struct {
		path       string
		wantPrefix string
		body       string
	}{
		{"/ui/assets/index-abc123.js", "text/javascript", "console.log(1)"},
		{"/ui/assets/index-abc123.css", "text/css", "body{}"},
		{"/ui/favicon.svg", "image/svg+xml", "<svg/>"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			w := get(t, builtAssets(), tc.path)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			if w.Body.String() != tc.body {
				t.Errorf("body = %q, want %q", w.Body.String(), tc.body)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, tc.wantPrefix) {
				t.Errorf("Content-Type = %q, want a %s", ct, tc.wantPrefix)
			}
		})
	}
}

// Content-hashed bundles can cache forever; the shell must revalidate so a
// deploy is picked up on the next load.
func TestCacheHeaders(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/ui/assets/index-abc123.js", "public, max-age=31536000, immutable"},
		{"/ui/", "no-cache"},
		{"/ui/manifest.webmanifest", "no-cache"},
		{"/ui/files/photos", "no-cache"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := get(t, builtAssets(), tc.path).Header().Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}
}

// Unknown paths are client-side routes, so they get the app shell rather than
// a 404 — that is what makes deep links work on reload.
func TestSPAFallback(t *testing.T) {
	for _, path := range []string{
		"/ui/files",
		"/ui/files/photos/2024",
		"/ui/settings/teams",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, builtAssets(), path)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if !strings.Contains(w.Body.String(), "app shell") {
				t.Errorf("body = %q, want the app shell", w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html for a client route", ct)
			}
		})
	}
}

// A missing asset under assets/ also falls through to the shell, matching how
// the previous implementation behaved.
func TestMissingAssetFallsBackToTheShell(t *testing.T) {
	w := get(t, builtAssets(), "/ui/assets/gone-999.js")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "app shell") {
		t.Errorf("body = %q", w.Body.String())
	}
}

// A binary built without running the frontend build must explain itself
// instead of returning a bare error.
func TestNotBuiltPlaceholder(t *testing.T) {
	empty := fstest.MapFS{".gitkeep": {Data: []byte("")}}

	w := httptest.NewRecorder()
	New(empty).Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "UI not built") || !strings.Contains(body, "bun run build") {
		t.Errorf("placeholder should say what to run:\n%s", body)
	}
}

// Traversal attempts must not escape the asset tree.
func TestPathTraversalIsContained(t *testing.T) {
	for _, path := range []string{
		"/ui/../etc/passwd",
		"/ui/../../etc/passwd",
		"/ui/assets/../../index.html",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, builtAssets(), path)
			// The app shell, or a redirect to the cleaned path (which then
			// lands outside /ui and is somebody else's 404), are both fine.
			// Serving something from outside the asset tree is not.
			if w.Code != http.StatusOK && (w.Code < 300 || w.Code >= 400) {
				t.Fatalf("status = %d, want 200 or a redirect", w.Code)
			}
			if w.Code >= 300 && w.Code < 400 {
				if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "/ui/") {
					t.Errorf("redirected to %q, which is still inside the asset tree", loc)
				}
				return
			}
			if !strings.Contains(w.Body.String(), "app shell") {
				t.Errorf("traversal served %q, want the app shell", w.Body.String())
			}
		})
	}
}

func TestContentType(t *testing.T) {
	tests := []struct{ name, wantPrefix string }{
		{"index.html", "text/html"},
		{"app.js", "text/javascript"},
		{"app.css", "text/css"},
		{"icon.png", "image/png"},
		// Extensionless client routes serve the HTML shell.
		{"files", "text/html"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentType(tc.name); !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("contentType(%q) = %q, want a %s", tc.name, got, tc.wantPrefix)
			}
		})
	}
}
