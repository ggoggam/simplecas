// Package server assembles the four surfaces simplecas exposes into one
// handler, and decides which of them a request belongs to.
//
// Route precedence is resolved here rather than by http.ServeMux, for two
// reasons. First, ServeMux cleans request paths — collapsing "//" and resolving
// "." and ".." segments with a redirect — and S3 object keys may legitimately
// contain those sequences, so the gateway has to see the path untouched.
// Second, making the precedence explicit is what documents which namespace
// names are reserved.
package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Routes are the surfaces to mount. Gateway is the fallback: anything not
// claimed by a reserved prefix is an S3 request.
type Routes struct {
	// Gateway is the S3-compatible gateway, serving "/" and "/{namespace}/…".
	Gateway http.Handler
	// API is the JSON admin API, serving "/api/…".
	API http.Handler
	// UI is the bundled PWA, serving "/ui" and "/ui/…".
	UI http.Handler
	// Auth serves "/auth/…". It is nil when OIDC is disabled, in which case
	// "auth" is not reserved and behaves like any other namespace name.
	Auth http.Handler
}

// Handler returns the composed handler.
//
// Because /api and /ui are literal first segments, the namespace names "api"
// and "ui" are reserved — and "auth" is too, whenever sign-in is enabled.
func (rt Routes) Handler(log *slog.Logger) http.Handler {
	return logRequests(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The comparison is against the raw path segment, so a
		// percent-encoded spelling like /%61pi cannot slip past the reserved
		// prefixes; it addresses a namespace named "api" instead.
		switch firstSegment(r.URL.EscapedPath()) {
		case "api":
			rt.API.ServeHTTP(w, r)
		case "ui":
			rt.UI.ServeHTTP(w, r)
		case "auth":
			if rt.Auth != nil {
				rt.Auth.ServeHTTP(w, r)
				return
			}
			rt.Gateway.ServeHTTP(w, r)
		default:
			rt.Gateway.ServeHTTP(w, r)
		}
	}))
}

// firstSegment returns the first path segment, without decoding it.
func firstSegment(escapedPath string) string {
	trimmed := strings.TrimPrefix(escapedPath, "/")
	segment, _, _ := strings.Cut(trimmed, "/")
	return segment
}

// statusRecorder captures the status and byte count for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

// Unwrap exposes the underlying writer to http.ResponseController, so features
// like flushing still reach it through this wrapper.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// logRequests emits one line per request at debug level, and promotes server
// errors to warnings so they surface at the default level.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		status := rec.status
		if status == 0 {
			// A handler that wrote nothing still produced a 200.
			status = http.StatusOK
		}
		level := slog.LevelDebug
		if status >= http.StatusInternalServerError {
			level = slog.LevelWarn
		}
		log.Log(r.Context(), level, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", rec.bytes,
			"duration", time.Since(start),
		)
	})
}
