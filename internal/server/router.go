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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
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
	// StallTimeout drops a connection whose request or response body goes
	// this long without moving a byte. Zero disables it.
	StallTimeout time.Duration
	// HTTPS says browsers reach this instance over HTTPS even though requests
	// arrive as plain HTTP from a TLS-terminating proxy, so /ui, /api and
	// /auth send Strict-Transport-Security. A request made over TLS gets it
	// either way.
	HTTPS bool
}

// Handler returns the composed handler.
//
// Because /api and /ui are literal first segments, the namespace names "api"
// and "ui" are reserved — and "auth" is too, whenever sign-in is enabled.
func (rt Routes) Handler(log *slog.Logger) http.Handler {
	return logRequests(log, stallDeadlines(rt.StallTimeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The comparison is against the raw path segment, so a
		// percent-encoded spelling like /%61pi cannot slip past the reserved
		// prefixes; it addresses a namespace named "api" instead.
		switch firstSegment(r.URL.EscapedPath()) {
		case "api":
			setSurfaceHeaders(w, r, lockedPolicy, rt.HTTPS)
			rt.API.ServeHTTP(w, r)
		case "ui":
			setSurfaceHeaders(w, r, uiPolicy, rt.HTTPS)
			rt.UI.ServeHTTP(w, r)
		case "auth":
			if rt.Auth != nil {
				setSurfaceHeaders(w, r, lockedPolicy, rt.HTTPS)
				rt.Auth.ServeHTTP(w, r)
				return
			}
			rt.Gateway.ServeHTTP(w, r)
		default:
			rt.Gateway.ServeHTTP(w, r)
		}
	})))
}

// stallDeadlines pushes the connection's read deadline out by timeout before
// every read of the request body, and its write deadline before every write of
// the response. A body that keeps moving can take as long as it needs; one that
// stops for timeout fails, and the handler sees the error.
//
// The server sets no ReadTimeout or WriteTimeout because a multi-gigabyte
// object outlasts any fixed deadline (see main.go). Without this, a client
// could open an upload or a download and then stall, holding a connection, a
// goroutine and a staging writer or blob reader open indefinitely.
func stallDeadlines(timeout time.Duration, next http.Handler) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &stallBody{ReadCloser: r.Body, rc: rc, timeout: timeout}
		}
		next.ServeHTTP(&stallWriter{ResponseWriter: w, rc: rc, timeout: timeout}, r)
		// The connection may serve another request, which must not inherit
		// a deadline set here. net/http only resets the write deadline itself
		// when WriteTimeout is set.
		_ = rc.SetWriteDeadline(time.Time{})
	})
}

// stallBody extends the read deadline before each read.
type stallBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
}

func (b *stallBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.timeout))
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		// Once the body is drained, net/http reads the connection in the
		// background to notice a client hanging up, and cancels the request
		// context when that read fails. It clears the deadline as that read
		// starts, but a reader that calls Read again after EOF re-arms it
		// above, and the background read would then time out and cancel a
		// commit that is still promoting a large blob.
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

// stallWriter extends the write deadline before each write.
type stallWriter struct {
	http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
}

func (s *stallWriter) Write(p []byte) (int, error) {
	_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
	return s.ResponseWriter.Write(p)
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (s *stallWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

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

// newRequestID returns a random ID in the 16-hex-digit shape S3 uses.
func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// logRequests tags every response with a request ID, emits one line per
// request at debug level, and promotes server errors to warnings so they
// surface at the default level.
//
// The ID is set on the response before any handler runs, so the error writers
// can echo it in the body and the handlers' own error logs can carry it: a
// client reporting a 500 has the ID, and the ID finds the cause in the log.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := newRequestID()
		w.Header().Set(apperr.RequestIDHeader, requestID)
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
			"requestId", requestID,
		)
	})
}
