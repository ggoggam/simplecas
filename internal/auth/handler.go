package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// sessionContextKey carries the signed-in caller down to the handlers.
type sessionContextKey struct{}

// FromContext returns the caller the guard attached, or nil when the request
// was not guarded (OIDC disabled) or carried no session.
func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionContextKey{}).(*Session)
	return s
}

// WithSession attaches a caller to ctx. The guard uses this after verifying a
// session cookie; it is exported so an alternative authentication front-end —
// or a test — can establish a caller the same way.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, s)
}

// Handler serves the sign-in endpoints: the login page, logout, the identity
// probe, and the two halves of the OIDC authorization-code flow.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", r.handleLogin)
	mux.HandleFunc("GET /auth/logout", r.handleLogout)
	mux.HandleFunc("GET /auth/me", r.handleMe)
	mux.HandleFunc("GET /auth/oidc/{provider}/start", r.handleStart)
	mux.HandleFunc("GET /auth/oidc/{provider}/callback", r.handleCallback)
	return mux
}

// Guard protects the /ui and /api surfaces. An unauthenticated API call gets a
// 401 with a JSON body; an unauthenticated page load is redirected to the login
// page with its intended destination preserved.
func (r *Registry) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if session := CurrentSession(req, r.cfg); session != nil {
			next.ServeHTTP(w, req.WithContext(WithSession(req.Context(), session)))
			return
		}

		// The PWA distinguishes 401 (signed out) from 404 (OIDC not enabled),
		// so this must be a JSON 401 and not a redirect to an HTML page.
		if strings.HasPrefix(req.URL.Path, "/api") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"code":    "Unauthorized",
				"message": "sign-in required",
			})
			return
		}

		dest := req.URL.Path
		if req.URL.RawQuery != "" {
			dest += "?" + req.URL.RawQuery
		}
		http.Redirect(w, req, "/auth/login?"+url.Values{"redirect": {dest}}.Encode(),
			http.StatusSeeOther)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Login page, logout, identity
// ---------------------------------------------------------------------------

func (r *Registry) handleLogin(w http.ResponseWriter, req *http.Request) {
	dest := sanitizeRedirect(req.URL.Query().Get("redirect"))
	// Already signed in: nothing to do here.
	if CurrentSession(req, r.cfg) != nil {
		http.Redirect(w, req, dest, http.StatusSeeOther)
		return
	}

	redirectQuery := url.Values{"redirect": {dest}}.Encode()
	var buttons strings.Builder
	for _, p := range r.providers {
		fmt.Fprintf(&buttons,
			`<a class="btn" href="/auth/oidc/%s/start?%s">Continue with %s</a>`,
			html.EscapeString(url.PathEscape(p.ID)), redirectQuery, html.EscapeString(p.Name))
	}

	var errorHTML string
	if code := req.URL.Query().Get("oidc_error"); code != "" {
		errorHTML = `<p class="err">Sign-in failed: ` + html.EscapeString(code) + `</p>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, loginPageTemplate, errorHTML, buttons.String())
}

// loginPageTemplate is the standalone sign-in page. It is deliberately
// self-contained: it has to render before the PWA's assets are reachable.
const loginPageTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<title>Sign in · simplecas</title>` +
	`<style>body{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#0b0d10;color:#e7e9ea}` +
	`.card{display:flex;flex-direction:column;gap:12px;padding:32px;min-width:280px}` +
	`h1{font-size:20px;margin:0 0 8px;text-align:center}` +
	`.btn{display:block;padding:12px 16px;border-radius:8px;background:#1f6feb;color:#fff;text-decoration:none;text-align:center;font-weight:600}` +
	`.btn:hover{background:#388bfd}.err{color:#f85149;text-align:center;margin:0}</style></head>` +
	`<body><div class="card"><h1>simplecas</h1>%s%s</div></body></html>`

func (r *Registry) handleLogout(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, clearCookie(sessionCookie, secureCookies(r.cfg)))
	http.Redirect(w, req, "/auth/login", http.StatusSeeOther)
}

func (r *Registry) handleMe(w http.ResponseWriter, req *http.Request) {
	session := CurrentSession(req, r.cfg)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"code":    "Unauthorized",
			"message": "not signed in",
		})
		return
	}
	// Field names and the null-for-absent shape are the contract with the PWA.
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":      session.Subject,
		"email":    nullable(session.Email),
		"name":     nullable(session.Name),
		"provider": session.Provider,
	})
}

// nullable renders an empty string as JSON null, which is what the PWA's
// Identity type expects for an absent claim.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------------------------------------------------------------------------
// Authorization-code flow
// ---------------------------------------------------------------------------

// handleStart begins a login: it stashes the flow state in a signed cookie and
// redirects to the provider's authorization endpoint.
func (r *Registry) handleStart(w http.ResponseWriter, req *http.Request) {
	p, ok := r.provider(req.PathValue("provider"))
	if !ok {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}

	oauthCfg, _ := p.oauthConfig()
	csrf, nonce := randomToken(), randomToken()
	verifier := oauth2.GenerateVerifier()

	flow := flowState{
		Provider:      p.ID,
		CSRF:          csrf,
		Nonce:         nonce,
		PKCEVerifier:  verifier,
		RedirectAfter: sanitizeRedirect(req.URL.Query().Get("redirect")),
		Expires:       time.Now().Add(flowTTL).Unix(),
	}
	payload, err := json.Marshal(flow)
	if err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, setCookie(flowCookie,
		sign(r.cfg.SessionSecret, payload),
		int(flowTTL.Seconds()),
		secureCookies(r.cfg)))

	authURL := oauthCfg.AuthCodeURL(csrf,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, req, authURL, http.StatusSeeOther)
}

// handleCallback completes a login: it validates the flow state and CSRF token,
// exchanges the code, verifies the ID token's signature and nonce, applies the
// allowlist, and opens a session.
func (r *Registry) handleCallback(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	if providerErr := query.Get("error"); providerErr != "" {
		r.loginError(w, req, providerErr)
		return
	}

	providerID := req.PathValue("provider")
	p, ok := r.provider(providerID)
	if !ok {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}

	flow, ok := r.readFlow(req)
	if !ok {
		r.loginError(w, req, "state_missing")
		return
	}
	if flow.Expires < time.Now().Unix() || flow.Provider != providerID {
		r.loginError(w, req, "state_expired")
		return
	}

	code, state := query.Get("code"), query.Get("state")
	if code == "" || state == "" {
		r.loginError(w, req, "missing_code")
		return
	}
	if !constantTimeEqual(state, flow.CSRF) {
		r.loginError(w, req, "state_mismatch")
		return
	}

	session, failure := r.completeLogin(req.Context(), p, flow, code)
	if failure != "" {
		r.loginError(w, req, failure)
		return
	}

	payload, err := json.Marshal(session)
	if err != nil {
		r.loginError(w, req, "server_error")
		return
	}
	secure := secureCookies(r.cfg)
	http.SetCookie(w, setCookie(sessionCookie,
		sign(r.cfg.SessionSecret, payload),
		int(r.cfg.SessionTTLSecs), secure))
	http.SetCookie(w, clearCookie(flowCookie, secure))
	http.Redirect(w, req, flow.RedirectAfter, http.StatusSeeOther)
}

// readFlow recovers the per-login state from its signed cookie.
func (r *Registry) readFlow(req *http.Request) (flowState, bool) {
	cookie, err := req.Cookie(flowCookie)
	if err != nil {
		return flowState{}, false
	}
	payload := unsign(r.cfg.SessionSecret, cookie.Value)
	if payload == nil {
		return flowState{}, false
	}
	var flow flowState
	if err := json.Unmarshal(payload, &flow); err != nil {
		return flowState{}, false
	}
	return flow, true
}

// idTokenClaims is the slice of the ID token this server reads.
type idTokenClaims struct {
	Email string `json:"email"`
	// EmailVerified is a flexibleBool because providers disagree on whether it
	// is a JSON boolean or a string.
	EmailVerified flexibleBool `json:"email_verified"`
	Name          string       `json:"name"`
}

// flexibleBool accepts either a JSON boolean or a quoted "true"/"false", which
// some identity providers emit for email_verified. Without this, one such
// provider would fail every login with an unparseable-token error.
type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	var asBool bool
	if err := json.Unmarshal(data, &asBool); err == nil {
		*b = flexibleBool(asBool)
		return nil
	}
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		*b = flexibleBool(asString == "true")
		return nil
	}
	return errors.New("email_verified is neither a boolean nor a string")
}

// completeLogin performs the token exchange, ID-token verification and
// allowlist check. Failures come back as short machine codes, which the login
// page surfaces without leaking provider internals.
func (r *Registry) completeLogin(ctx context.Context, p *Provider, flow flowState, code string) (*Session, string) {
	oauthCfg, _ := p.oauthConfig()
	exchangeCtx := oidc.ClientContext(ctx, r.httpClient)

	token, err := oauthCfg.Exchange(exchangeCtx, code, oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		r.log.Warn("oidc code exchange failed", "provider", p.ID, "err", err)
		return nil, "exchange_failed"
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, "no_id_token"
	}
	idToken, err := p.verifier().Verify(exchangeCtx, rawIDToken)
	if err != nil {
		r.log.Warn("oidc id token verification failed", "provider", p.ID, "err", err)
		return nil, "token_invalid"
	}
	// The nonce binds this token to the login that started here, defeating a
	// replayed or injected token.
	if !constantTimeEqual(idToken.Nonce, flow.Nonce) {
		return nil, "nonce_mismatch"
	}

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, "token_invalid"
	}
	if !admitted(r.cfg, claims.Email, bool(claims.EmailVerified)) {
		return nil, "not_allowed"
	}

	return &Session{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: bool(claims.EmailVerified),
		Name:          claims.Name,
		Provider:      p.ID,
		Expires:       time.Now().Add(time.Duration(r.cfg.SessionTTLSecs) * time.Second).Unix(),
	}, ""
}

// loginError sends the browser back to the login page with a failure code, also
// clearing any stale flow cookie so a retry starts clean.
func (r *Registry) loginError(w http.ResponseWriter, req *http.Request, code string) {
	http.SetCookie(w, clearCookie(flowCookie, secureCookies(r.cfg)))
	http.Redirect(w, req, "/auth/login?"+url.Values{"oidc_error": {code}}.Encode(),
		http.StatusSeeOther)
}
