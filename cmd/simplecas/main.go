// Command simplecas is a content-addressable storage server: an S3-compatible
// gateway with global file-level deduplication, pluggable storage backends, and
// a bundled PWA for managing objects.
//
// Every instance is stateless — all shared state lives in Postgres and the blob
// backend — so any number of them can run behind a load balancer.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ggoggam/simplecas/internal/api"
	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/s3"
	"github.com/ggoggam/simplecas/internal/server"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/ui"
	"github.com/ggoggam/simplecas/web"
)

// startupTimeout bounds the work done before the listener opens: connecting to
// Postgres, running migrations, checking the blob backend, OIDC discovery, and
// sealing stored S3 secrets.
const startupTimeout = 2 * time.Minute

// shutdownTimeout is how long in-flight requests get to finish on SIGTERM.
// Uploads stream, so this is deliberately generous.
const shutdownTimeout = 30 * time.Second

func main() {
	logger := slog.New(logHandler(&slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// logLevel reads LOG_LEVEL, defaulting to info. Debug turns on the per-request
// access log.
func logLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// logHandler reads LOG_FORMAT: "json" writes one JSON object per line;
// anything else, the default, writes logfmt key=value lines. Either is meant to
// be parsed, the audit lines especially (see db.SetAuditLogger).
func logHandler(opts *slog.HandlerOptions) slog.Handler {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LOG_FORMAT")), "json") {
		return slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.NewTextHandler(os.Stdout, opts)
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Signals cancel this context, which unwinds the background loops.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	defer cancelStartup()

	database, err := db.Connect(startupCtx, cfg.Database.URL, cfg.Database.MaxConnections)
	if err != nil {
		return err
	}
	defer database.Close()
	database.SetAuditLogger(logger)

	bucket, err := storage.Open(startupCtx, cfg.Storage)
	if err != nil {
		return err
	}
	defer func() { _ = bucket.Close() }()

	// Fail fast on unusable backend credentials or paths, rather than on the
	// first upload.
	if err := bucket.Check(startupCtx); err != nil {
		return err
	}

	// OIDC discovery (and the initial JWKS fetch) happens here so a broken auth
	// configuration fails startup instead of every login.
	registry, err := auth.NewRegistry(startupCtx, &cfg.OIDC, database, logger)
	if err != nil {
		return err
	}

	store := cas.New(database, bucket, cfg.GC, cfg.Limits, logger)
	gateway := s3.New(database, bucket, store, cfg, logger)

	// Seal any team S3 secret still in plaintext, or under a rotated-out
	// key, before the gateway verifies anything with it.
	if err := gateway.SealStoredCredentials(startupCtx); err != nil {
		return err
	}
	cancelStartup()

	// When OIDC is on, the guard wraps the /ui and /api surfaces only: the S3
	// gateway keeps its own SigV4 auth, and the /auth endpoints have to stay
	// reachable while signed out.
	guard := func(h http.Handler) http.Handler { return h }
	var authHandler http.Handler
	if registry != nil {
		guard = registry.Guard
		authHandler = registry.Handler()
	} else if !config.IsLoopbackBind(cfg.Server.Bind) {
		// Validate only lets this through with server.insecure_open_api set,
		// but an open admin plane should still be loud in the log.
		logger.Warn("/api is unauthenticated and listening beyond loopback",
			"bind", cfg.Server.Bind,
			"detail", "anyone who reaches this port controls every namespace; enable oidc or restrict access in front")
	}

	routes := server.Routes{
		Gateway: gateway,
		API:     guard(api.New(database, store, gateway, logger).Routes()),
		UI:      guard(ui.New(web.Dist()).Routes()),
		Auth:    authHandler,
		// Uploads and downloads have no total deadline (see srv below), so
		// this is what stops a stalled one from holding its connection.
		StallTimeout: time.Duration(cfg.Limits.StallTimeoutSecs) * time.Second,
		// Only the sign-in configuration records a public URL. Without it,
		// HSTS goes only on requests that themselves arrived over TLS.
		HTTPS: registry != nil && cfg.OIDC.PublicHTTPS(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.RunGC(ctx)
	}()
	if registry != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.RunRefresh(ctx)
		}()
	}

	srv := &http.Server{
		Addr:              cfg.Server.Bind,
		Handler:           routes.Handler(logger),
		ReadHeaderTimeout: 30 * time.Second,
		// No ReadTimeout or WriteTimeout: uploads and downloads stream, and a
		// multi-gigabyte object legitimately takes longer than any fixed
		// deadline would allow. ReadHeaderTimeout still bounds slow-header
		// attacks, IdleTimeout reaps abandoned keep-alive connections, and
		// the router's StallTimeout drops a body that stops moving.
		IdleTimeout: 120 * time.Second,
	}

	logger.Info("simplecas listening",
		"bind", cfg.Server.Bind,
		"region", cfg.Server.Region,
		"storage", cfg.Storage.Backend,
		"s3Auth", cfg.Auth.Enabled,
		"oidc", registry != nil,
		"gcInterval", time.Duration(cfg.GC.IntervalSecs)*time.Second,
		"detail", "S3 gateway at /, PWA at /ui/, admin API at /api/",
	)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		stop()
		wg.Wait()
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown timed out", "err", err)
	}
	wg.Wait()
	logger.Info("stopped")
	return nil
}
