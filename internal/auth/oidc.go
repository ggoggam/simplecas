package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ggoggam/simplecas/internal/config"
)

// refreshInterval is how often provider metadata (and with it the signing key
// set) is re-discovered, so IdP key rotation does not break logins on a
// long-running instance.
const refreshInterval = time.Hour

// defaultScopes are requested when a provider configures none. email and
// profile are included so the ID token carries an address for the allowlist and
// a display name for the UI.
var defaultScopes = []string{oidc.ScopeOpenID, "email", "profile"}

// Provider is one configured, discovered identity provider.
//
// The discovered metadata sits behind a mutex so the refresh loop can swap in
// freshly fetched signing keys without a restart, while requests read it
// concurrently.
type Provider struct {
	ID           string
	Name         string
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	// scopes always includes openid.
	scopes []string

	mu       sync.RWMutex
	provider *oidc.Provider
}

// oauthConfig builds the relying-party configuration from the current metadata.
func (p *Provider) oauthConfig() (*oauth2.Config, *oidc.Provider) {
	p.mu.RLock()
	discovered := p.provider
	p.mu.RUnlock()

	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     discovered.Endpoint(),
		RedirectURL:  p.redirectURL,
		Scopes:       p.scopes,
	}, discovered
}

// verifier validates ID tokens against this provider's current key set.
func (p *Provider) verifier() *oidc.IDTokenVerifier {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.provider.Verifier(&oidc.Config{ClientID: p.clientID})
}

// Registry holds every configured provider in declaration order, plus the HTTP
// client used to talk to them.
type Registry struct {
	cfg        *config.OidcConfig
	providers  []*Provider
	byID       map[string]*Provider
	httpClient *http.Client
	log        *slog.Logger
}

// Providers returns the configured providers in declaration order, which is the
// order the login page lists them in.
func (r *Registry) Providers() []*Provider { return r.providers }

func (r *Registry) provider(id string) (*Provider, bool) {
	p, ok := r.byID[id]
	return p, ok
}

// errNoRedirect refuses redirects. A relying party must never follow one from
// the token endpoint: doing so could replay the client credential to another
// host.
var errNoRedirect = errors.New("redirects are not followed")

// NewRegistry performs OIDC discovery for every configured provider, returning
// nil when OIDC is disabled.
//
// Misconfiguration and unreachable issuers are fatal here, so a broken auth
// setup fails at startup rather than on every login attempt.
func NewRegistry(ctx context.Context, cfg *config.OidcConfig, log *slog.Logger) (*Registry, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errNoRedirect
		},
	}
	discoveryCtx := oidc.ClientContext(ctx, httpClient)

	registry := &Registry{
		cfg:        cfg,
		byID:       make(map[string]*Provider, len(cfg.Providers)),
		httpClient: httpClient,
		log:        log,
	}
	publicURL := trimTrailingSlash(cfg.PublicURL)

	for _, pc := range cfg.Providers {
		if _, exists := registry.byID[pc.ID]; exists {
			return nil, fmt.Errorf("duplicate oidc provider id %q", pc.ID)
		}
		discovered, err := oidc.NewProvider(discoveryCtx, pc.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for provider %q failed: %w", pc.ID, err)
		}

		name := pc.Name
		if name == "" {
			name = pc.ID
		}
		p := &Provider{
			ID:           pc.ID,
			Name:         name,
			issuer:       pc.Issuer,
			clientID:     pc.ClientID,
			clientSecret: pc.ClientSecret,
			redirectURL:  fmt.Sprintf("%s/auth/oidc/%s/callback", publicURL, pc.ID),
			scopes:       effectiveScopes(pc.Scopes),
			provider:     discovered,
		}
		registry.providers = append(registry.providers, p)
		registry.byID[pc.ID] = p
	}

	log.Info("oidc enabled; /ui and /api require sign-in",
		"providers", len(registry.providers))
	return registry, nil
}

// validateConfig checks the settings a login cannot work without.
func validateConfig(cfg *config.OidcConfig) error {
	if trimSpace(cfg.PublicURL) == "" {
		return errors.New("oidc.enabled is set but oidc.public_url is empty (needed to derive redirect URIs)")
	}
	if len(cfg.SessionSecret) < 16 {
		return errors.New("oidc.session_secret must be at least 16 characters when oidc is enabled")
	}
	if len(cfg.Providers) == 0 {
		return errors.New("oidc.enabled is set but no [[oidc.providers]] are configured")
	}
	for _, p := range cfg.Providers {
		if p.ID == "" || p.Issuer == "" || p.ClientID == "" {
			return fmt.Errorf("oidc provider %q: id, issuer and client_id are all required", p.ID)
		}
	}
	return nil
}

// effectiveScopes normalises a provider's scope list, guaranteeing openid is
// present exactly once.
func effectiveScopes(configured []string) []string {
	if len(configured) == 0 {
		return defaultScopes
	}
	scopes := []string{oidc.ScopeOpenID}
	for _, s := range configured {
		if s != oidc.ScopeOpenID {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// RunRefresh re-discovers each provider on a schedule until ctx is cancelled,
// picking up rotated IdP signing keys without a restart.
//
// A failed refresh keeps the cached metadata: a transient discovery outage must
// not lock every user out.
func (r *Registry) RunRefresh(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		discoveryCtx := oidc.ClientContext(ctx, r.httpClient)
		for _, p := range r.providers {
			discovered, err := oidc.NewProvider(discoveryCtx, p.issuer)
			if err != nil {
				if ctx.Err() == nil {
					r.log.Warn("oidc metadata refresh failed; keeping cached keys",
						"provider", p.ID, "err", err)
				}
				continue
			}
			p.mu.Lock()
			p.provider = discovered
			p.mu.Unlock()
		}
	}
}

// randomToken returns an unguessable value for CSRF state and nonces.
func randomToken() string {
	var buf [32]byte
	// crypto/rand.Read never fails on any supported platform; it panics
	// internally rather than returning an error worth handling here.
	_, _ = rand.Read(buf[:])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}
