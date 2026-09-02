// Package ui serves the bundled PWA, which package web compiles into the
// binary as an embedded filesystem.
//
// It is a single-page app, so any path under /ui that does not name a real file
// falls back to index.html and lets the client-side router take over.
package ui

import (
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

// indexFile is both the app shell and the SPA fallback.
const indexFile = "index.html"

// Handler serves the embedded assets.
type Handler struct {
	assets fs.FS
}

// New returns a Handler over an asset tree rooted where index.html lives.
func New(assets fs.FS) *Handler {
	return &Handler{assets: assets}
}

// Routes returns the UI's routes: a redirect for the bare /ui, and the asset
// tree under /ui/.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	// Without the trailing slash, relative asset URLs in index.html would
	// resolve against / instead of /ui/.
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("GET /ui/", h.serve)
	return mux
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/ui/")
	if name == "" || name == "/ui" || strings.HasPrefix(name, "..") {
		name = indexFile
	}

	data, err := fs.ReadFile(h.assets, name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "could not read asset", http.StatusInternalServerError)
			return
		}
		// Unknown paths are client-side routes, so hand back the app shell.
		name = indexFile
		data, err = fs.ReadFile(h.assets, indexFile)
		if err != nil {
			h.serveNotBuilt(w)
			return
		}
	}

	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("Cache-Control", cacheControl(name))
	if _, err := w.Write(data); err != nil {
		// The client went away mid-response; nothing useful to do.
		_ = err
	}
}

// contentType maps an asset's extension to its media type, defaulting to HTML
// because the SPA fallback serves index.html for extensionless routes.
func contentType(name string) string {
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		return ct
	}
	return "text/html; charset=utf-8"
}

// cacheControl lets Vite's content-hashed bundles cache forever while keeping
// index.html revalidating, so a deploy is picked up on the next load.
func cacheControl(name string) string {
	if strings.HasPrefix(name, "assets/") {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}

// serveNotBuilt explains the missing frontend build rather than returning a
// bare 404, which is otherwise a confusing first run.
func (h *Handler) serveNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, notBuiltPage)
}

const notBuiltPage = `<!doctype html><meta charset="utf-8"><title>simplecas</title>` +
	`<p style="font-family:system-ui,sans-serif;padding:2rem">` +
	`UI not built. Run <code>bun install &amp;&amp; bun run build</code> in <code>web/</code>, ` +
	`then rebuild the server.</p>`
