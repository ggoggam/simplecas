package auth

import (
	cryptoSHA256Import "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/config"
)

// testRegistry builds a Registry with no discovery, for the handlers that do
// not talk to a provider.
func testRegistry(t *testing.T, providers ...*Provider) *Registry {
	t.Helper()
	cfg := &config.OidcConfig{
		Enabled:        true,
		PublicURL:      "http://localhost:9000",
		SessionSecret:  testSecret,
		SessionTTLSecs: 3600,
	}
	reg := &Registry{
		cfg:        cfg,
		byID:       map[string]*Provider{},
		httpClient: &http.Client{Timeout: 5 * time.Second},
		store:      newMemStore(),
		log:        slog.New(slog.DiscardHandler),
	}
	for _, p := range providers {
		reg.providers = append(reg.providers, p)
		reg.byID[p.ID] = p
	}
	return reg
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

func TestGuard(t *testing.T) {
	reg := testRegistry(t)
	var reached bool
	var seen *Session
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		seen = FromContext(r.Context())
	})
	guarded := reg.Guard(next)

	t.Run("a valid session passes through and is attached", func(t *testing.T) {
		reached, seen = false, nil
		r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		r.AddCookie(reg.signIn(t, Session{
			Issuer: "https://idp.test", Subject: "sub-1", Email: "dev@example.com", EmailVerified: true,
			Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
		}))
		guarded.ServeHTTP(httptest.NewRecorder(), r)

		if !reached {
			t.Fatal("the guarded handler was not reached")
		}
		if seen == nil || seen.VerifiedEmail() != "dev@example.com" {
			t.Errorf("session in context = %+v", seen)
		}
		// The rows behind it are attached too, for the admin API.
		if seen != nil && (seen.ID == uuid.Nil || seen.UserID == 0) {
			t.Errorf("session in context = %+v, want its row ids", seen)
		}
	})

	// A genuine cookie is not enough: its session has to have a row.
	t.Run("a genuine cookie with no session row is refused", func(t *testing.T) {
		reached = false
		r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		r.AddCookie(issueSession(t, testSecret, Session{
			Issuer: "https://idp.test", Subject: "sub-1", Provider: "google",
			Expires: time.Now().Add(time.Hour).Unix(),
		}))
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		if reached || w.Code != http.StatusUnauthorized {
			t.Errorf("reached=%v status=%d, want a 401", reached, w.Code)
		}
	})

	// The PWA reads 401 as "signed out" and 404 as "OIDC disabled", so an
	// unauthenticated API call must be a JSON 401, never an HTML redirect.
	t.Run("unauthenticated API call gets a JSON 401", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/stats", nil))

		if reached {
			t.Error("the guarded handler should not have been reached")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("content-type = %q, want JSON", ct)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		if body["code"] != "Unauthorized" {
			t.Errorf("body = %#v", body)
		}
	})

	t.Run("unauthenticated page load redirects, preserving the destination", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ui/files?ns=photos", nil))

		if reached {
			t.Error("the guarded handler should not have been reached")
		}
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", w.Code)
		}
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if location.Path != "/auth/login" {
			t.Errorf("redirected to %q", location.Path)
		}
		if got := location.Query().Get("redirect"); got != "/ui/files?ns=photos" {
			t.Errorf("redirect param = %q, want the full destination", got)
		}
	})

	t.Run("an expired session is not a session", func(t *testing.T) {
		reached = false
		r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		r.AddCookie(issueSession(t, testSecret, Session{
			Issuer: "https://idp.test", Subject: "sub-1", Expires: time.Now().Add(-time.Hour).Unix(),
		}))
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)

		if reached || w.Code != http.StatusUnauthorized {
			t.Errorf("reached=%v status=%d, want a 401", reached, w.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Login page, logout, identity
// ---------------------------------------------------------------------------

func TestLoginPage(t *testing.T) {
	reg := testRegistry(t,
		&Provider{ID: "google", Name: "Google"},
		&Provider{ID: "okta", Name: "Okta <Test>"},
	)

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/ui/x", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "/auth/oidc/google/start?redirect=%2Fui%2Fx") {
		t.Errorf("missing google button with the preserved destination:\n%s", body)
	}
	if !strings.Contains(body, "Continue with Google") {
		t.Errorf("missing google label:\n%s", body)
	}
	// A provider name is operator-supplied, but escaping it costs nothing.
	if strings.Contains(body, "Okta <Test>") {
		t.Errorf("provider name was not HTML-escaped:\n%s", body)
	}
	if !strings.Contains(body, "Okta &lt;Test&gt;") {
		t.Errorf("expected an escaped provider name:\n%s", body)
	}
	if strings.Contains(body, "Sign-in failed") {
		t.Error("no error was requested, so none should be shown")
	}
}

// The page's policy admits its stylesheet by hash, so the hash has to be of the
// exact bytes served, and nothing else may load or frame it.
func TestLoginPagePolicyAdmitsOnlyItsStylesheet(t *testing.T) {
	reg := testRegistry(t, &Provider{ID: "google", Name: "Google"})

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	body := w.Body.String()
	_, rest, ok := strings.Cut(body, "<style>")
	if !ok {
		t.Fatalf("no inline stylesheet:\n%s", body)
	}
	style, _, ok := strings.Cut(rest, "</style>")
	if !ok {
		t.Fatalf("unterminated stylesheet:\n%s", body)
	}
	if strings.Count(body, "<style") != 1 || strings.Contains(body, "style=") {
		t.Errorf("the policy admits one stylesheet; the page has more:\n%s", body)
	}

	sum := sha256.Sum256([]byte(style))
	want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	policy := w.Header().Get("Content-Security-Policy")
	for _, directive := range []string{want, "default-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(policy, directive) {
			t.Errorf("policy %q lacks %q", policy, directive)
		}
	}
}

// The error code lands in the page via a query parameter, so it must be escaped.
func TestLoginPageEscapesErrorCode(t *testing.T) {
	reg := testRegistry(t, &Provider{ID: "google", Name: "Google"})

	w := httptest.NewRecorder()
	target := "/auth/login?oidc_error=" + url.QueryEscape(`<script>alert(1)</script>`)
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))

	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("error code was injected as markup:\n%s", body)
	}
	if !strings.Contains(body, "Sign-in failed") {
		t.Errorf("the failure was not surfaced:\n%s", body)
	}
}

func TestLoginPageRedirectsWhenAlreadySignedIn(t *testing.T) {
	reg := testRegistry(t, &Provider{ID: "google", Name: "Google"})

	r := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/ui/x", nil)
	r.AddCookie(reg.signIn(t, Session{
		Issuer: "https://idp.test", Subject: "s", Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/ui/x" {
		t.Errorf("Location = %q, want /ui/x", got)
	}
}

// A signed-in user who follows a crafted login link must not be bounced off
// the PWA.
func TestLoginPageRedirectStaysInThePWA(t *testing.T) {
	reg := testRegistry(t, &Provider{ID: "google", Name: "Google"})
	target := "/auth/login?" + url.Values{"redirect": {`/\evil.example`}}.Encode()

	t.Run("signed in", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.AddCookie(reg.signIn(t, Session{
			Issuer: "https://idp.test", Subject: "s", Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
		}))
		w := httptest.NewRecorder()
		reg.Handler().ServeHTTP(w, r)
		if got := w.Header().Get("Location"); got != "/ui/" {
			t.Errorf("Location = %q, want /ui/", got)
		}
	})

	t.Run("signed out", func(t *testing.T) {
		w := httptest.NewRecorder()
		reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		body := w.Body.String()
		if !strings.Contains(body, "/auth/oidc/google/start?redirect=%2Fui%2F") {
			t.Errorf("the provider button must carry the default landing:\n%s", body)
		}
		if strings.Contains(body, "evil.example") {
			t.Errorf("the rejected destination leaked into the page:\n%s", body)
		}
	})
}

// sessionCleared reports whether the response expires the named cookie.
func sessionCleared(w *httptest.ResponseRecorder, name string) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestLogoutClearsTheSession(t *testing.T) {
	reg := testRegistry(t)

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/auth/login" {
		t.Errorf("Location = %q", got)
	}
	if !sessionCleared(w, sessionCookie) {
		t.Errorf("the session cookie was not cleared: %v", w.Result().Cookies())
	}
}

// Over HTTPS the cookie to clear is the __Host- one the login set.
func TestLogoutClearsTheHostPrefixedSessionOverHTTPS(t *testing.T) {
	reg := testRegistry(t)
	reg.cfg.PublicURL = "https://cas.example.com"

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))

	if !sessionCleared(w, "__Host-"+sessionCookie) {
		t.Errorf("the __Host- session cookie was not cleared: %v", w.Result().Cookies())
	}
}

// Logging out is a state change, so a link or an image tag must not do it.
func TestLogoutRefusesGET(t *testing.T) {
	reg := testRegistry(t)

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if sessionCleared(w, sessionCookie) {
		t.Error("a GET must not clear the session")
	}
}

// Nor may a form on another site.
func TestLogoutRefusesCrossSitePOST(t *testing.T) {
	reg := testRegistry(t)

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if sessionCleared(w, sessionCookie) {
		t.Error("a cross-site POST must not clear the session")
	}
}

func TestRejectCrossSite(t *testing.T) {
	var reached bool
	handler := RejectCrossSite(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	tests := []struct {
		name          string
		method        string
		secFetchSite  string
		origin        string
		wantForbidden bool
	}{
		{name: "same-origin POST", method: http.MethodPost, secFetchSite: "same-origin"},
		{name: "same-origin DELETE", method: http.MethodDelete, secFetchSite: "same-origin"},
		{name: "cross-site POST", method: http.MethodPost, secFetchSite: "cross-site", wantForbidden: true},
		{name: "cross-site PUT", method: http.MethodPut, secFetchSite: "cross-site", wantForbidden: true},
		{name: "cross-site PATCH", method: http.MethodPatch, secFetchSite: "cross-site", wantForbidden: true},
		{name: "cross-site DELETE", method: http.MethodDelete, secFetchSite: "cross-site", wantForbidden: true},
		// A sibling subdomain is the same site, so SameSite=Lax alone would
		// still send it the cookie.
		{name: "same-site POST from a sibling subdomain", method: http.MethodPost, secFetchSite: "same-site", wantForbidden: true},
		{name: "user-initiated POST", method: http.MethodPost, secFetchSite: "none", wantForbidden: true},
		// Sec-Fetch-Site decides when present, whatever Origin says.
		{
			name: "cross-site despite a matching origin", method: http.MethodPost,
			secFetchSite: "cross-site", origin: "http://cas.test", wantForbidden: true,
		},

		// An older browser sends Origin but not Sec-Fetch-Site.
		{name: "matching origin", method: http.MethodPost, origin: "http://cas.test"},
		{name: "matching origin over https", method: http.MethodPost, origin: "https://cas.test"},
		{name: "matching origin, different case", method: http.MethodPost, origin: "http://CAS.test"},
		{name: "foreign origin", method: http.MethodPost, origin: "https://evil.example", wantForbidden: true},
		{name: "origin on another port", method: http.MethodPost, origin: "http://cas.test:8080", wantForbidden: true},
		{name: "lookalike origin", method: http.MethodPost, origin: "http://cas.test.evil.example", wantForbidden: true},
		{name: "opaque origin", method: http.MethodPost, origin: "null", wantForbidden: true},
		{name: "unparseable origin", method: http.MethodPost, origin: "http://%zz", wantForbidden: true},

		// A client that is not a browser sends neither.
		{name: "no browser headers", method: http.MethodPost},

		// Reads are never refused.
		{name: "cross-site GET", method: http.MethodGet, secFetchSite: "cross-site", origin: "https://evil.example"},
		{name: "cross-site HEAD", method: http.MethodHead, secFetchSite: "cross-site"},
		{name: "cross-site OPTIONS", method: http.MethodOptions, secFetchSite: "cross-site"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			r := httptest.NewRequest(tc.method, "http://cas.test/api/namespaces", nil)
			if tc.secFetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if tc.wantForbidden {
				if reached || w.Code != http.StatusForbidden {
					t.Errorf("reached=%v status=%d, want a 403", reached, w.Code)
				}
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["code"] != "AccessDenied" {
					t.Errorf("body = %s, want a JSON AccessDenied", w.Body.String())
				}
				return
			}
			if !reached {
				t.Errorf("status = %d; the request should have been let through", w.Code)
			}
		})
	}
}

func TestHandleMe(t *testing.T) {
	reg := testRegistry(t)

	t.Run("signed out", func(t *testing.T) {
		w := httptest.NewRecorder()
		reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("signed in", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		r.AddCookie(reg.signIn(t, Session{
			Issuer: "https://idp.test", Subject: "sub-1", Email: "dev@example.com", EmailVerified: true,
			Name: "Dev", Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
		}))
		w := httptest.NewRecorder()
		reg.Handler().ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		// These field names are the PWA's Identity type.
		for key, want := range map[string]any{
			"sub": "sub-1", "email": "dev@example.com", "name": "Dev", "provider": "google",
		} {
			if body[key] != want {
				t.Errorf("%s = %v, want %v", key, body[key], want)
			}
		}
	})

	// The PWA types email and name as `string | null`, so an absent claim has
	// to serialise as null rather than "".
	t.Run("absent claims serialise as null", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		r.AddCookie(reg.signIn(t, Session{
			Issuer: "https://idp.test", Subject: "sub-1", Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
		}))
		w := httptest.NewRecorder()
		reg.Handler().ServeHTTP(w, r)

		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["email"] != nil || body["name"] != nil {
			t.Errorf("email=%v name=%v, want both null", body["email"], body["name"])
		}
	})
}

// ---------------------------------------------------------------------------
// The authorization-code flow, against a fake identity provider
// ---------------------------------------------------------------------------

// fakeIdP is a minimal OIDC provider: a discovery document, a JWKS, and a
// token endpoint that mints RS256 ID tokens.
type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// nonce is echoed into the next ID token issued.
	nonce string
	// claims are merged into the next ID token.
	claims map[string]any
	// lastForm records what the relying party sent to the token endpoint.
	lastForm url.Values
	// omitIDToken makes the token endpoint answer without an id_token.
	omitIDToken bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, claims: map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/authorize",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{jwk(&key.PublicKey)}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.lastForm = r.PostForm

		body := map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if !idp.omitIDToken {
			body["id_token"] = idp.signIDToken(t)
		}
		writeJSON(w, http.StatusOK, body)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// jwk renders an RSA public key as a JSON Web Key.
func jwk(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": "test-key",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// signIDToken mints an RS256 JWT carrying the configured nonce and claims.
func (idp *fakeIdP) signIDToken(t *testing.T) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"}
	payload := map[string]any{
		"iss":   idp.server.URL,
		"aud":   "test-client",
		"sub":   "sub-abc",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": idp.nonce,
	}
	for k, v := range idp.claims {
		payload[k] = v
	}

	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, cryptoSHA256Import.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// flowRegistry discovers idp and returns a registry pointed at it, keeping
// sessions in memory.
func flowRegistry(t *testing.T, idp *fakeIdP, cfg *config.OidcConfig) *Registry {
	t.Helper()
	return flowRegistryWith(t, idp, cfg, newMemStore())
}

// flowRegistryWith is flowRegistry keeping sessions in store.
func flowRegistryWith(t *testing.T, idp *fakeIdP, cfg *config.OidcConfig, store SessionStore) *Registry {
	t.Helper()
	cfg.Enabled = true
	if cfg.PublicURL == "" {
		cfg.PublicURL = "http://localhost:9000"
	}
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = testSecret
	}
	if cfg.SessionTTLSecs == 0 {
		cfg.SessionTTLSecs = 3600
	}
	cfg.Providers = []config.ProviderConfig{{
		ID:           "fake",
		Name:         "Fake",
		Issuer:       idp.server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}}

	reg, err := NewRegistry(t.Context(), cfg, store, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("discovery against the fake provider failed: %v", err)
	}
	return reg
}

// start runs the first half of the flow and returns the provider redirect plus
// the flow cookie the browser would keep.
func start(t *testing.T, reg *Registry, redirect string) (*url.URL, *http.Cookie) {
	t.Helper()
	target := "/auth/oidc/fake/start"
	if redirect != "" {
		target += "?" + url.Values{"redirect": {redirect}}.Encode()
	}
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d, want 303\nbody: %s", w.Code, w.Body.String())
	}
	authURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var flow *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName(flowCookie, secureCookies(reg.cfg)) {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("start did not set the flow cookie")
	}
	return authURL, flow
}

// Served over HTTPS, the whole flow runs on __Host- cookies.
func TestFullLoginFlowOverHTTPS(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{PublicURL: "https://cas.example.com"})

	authURL, flow := start(t, reg, "/ui/files")
	if flow.Name != "__Host-"+flowCookie || !flow.Secure {
		t.Errorf("flow cookie = %+v, want a Secure __Host- cookie", flow)
	}
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{"email": "dev@example.com", "email_verified": true}

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	if got := w.Header().Get("Location"); got != "/ui/files" {
		t.Fatalf("Location = %q, want the stashed destination", got)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-"+sessionCookie && c.MaxAge > 0 {
			if !c.Secure || c.Path != "/" || c.Domain != "" {
				t.Errorf("session cookie = %+v, want Secure, Path=/, no Domain", c)
			}
			r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
			r.AddCookie(c)
			if got := mustSession(t, r, reg.cfg); got.Subject != "sub-abc" {
				t.Errorf("session = %+v", got)
			}
			return
		}
	}
	t.Fatalf("no __Host- session cookie was issued: %v", w.Result().Cookies())
}

func TestStartRedirectsWithPKCEAndNonce(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	authURL, flowCookieValue := start(t, reg, "/ui/files")

	if got, want := authURL.Path, "/authorize"; got != want {
		t.Errorf("authorize path = %q, want %q", got, want)
	}
	q := authURL.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:9000/auth/oidc/fake/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope = %q, want openid", q.Get("scope"))
	}
	// PKCE is mandatory here, not optional.
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("PKCE challenge = %q / %q", q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	if q.Get("state") == "" || q.Get("nonce") == "" {
		t.Errorf("state = %q, nonce = %q; both are required", q.Get("state"), q.Get("nonce"))
	}

	// The flow cookie is signed, short-lived, and carries the destination.
	payload := unsign(testSecret, flowCookieValue.Value)
	if payload == nil {
		t.Fatal("the flow cookie is not verifiable")
	}
	var flow flowState
	if err := json.Unmarshal(payload, &flow); err != nil {
		t.Fatal(err)
	}
	if flow.CSRF != q.Get("state") || flow.Nonce != q.Get("nonce") {
		t.Error("the flow cookie must carry the same state and nonce that were sent")
	}
	if flow.Type != typeFlow {
		t.Errorf("flow cookie typ = %q, want %q", flow.Type, typeFlow)
	}
	if flow.PKCEVerifier == "" {
		t.Error("the PKCE verifier must be stashed for the exchange")
	}
	if flow.RedirectAfter != "/ui/files" {
		t.Errorf("RedirectAfter = %q", flow.RedirectAfter)
	}
	if flowCookieValue.MaxAge != int(flowTTL.Seconds()) {
		t.Errorf("flow cookie MaxAge = %d, want %d", flowCookieValue.MaxAge, int(flowTTL.Seconds()))
	}
}

func TestStartUnknownProvider(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/oidc/nope/start", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// callback replays the provider's redirect back to the server.
func callback(t *testing.T, reg *Registry, flow *http.Cookie, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/fake/callback?"+query.Encode(), nil)
	if flow != nil {
		r.AddCookie(flow)
	}
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)
	return w
}

func TestFullLoginFlow(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	authURL, flow := start(t, reg, "/ui/files")
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{
		"email":          "dev@example.com",
		"email_verified": true,
		"name":           "Dev Eloper",
	}

	w := callback(t, reg, flow, url.Values{
		"code":  {"the-code"},
		"state": {authURL.Query().Get("state")},
	})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303\nLocation: %s",
			w.Code, w.Header().Get("Location"))
	}
	if got := w.Header().Get("Location"); got != "/ui/files" {
		t.Errorf("Location = %q, want the destination stashed at start", got)
	}

	// The exchange must have sent the PKCE verifier and the authorization code.
	if got := idp.lastForm.Get("code"); got != "the-code" {
		t.Errorf("token request code = %q", got)
	}
	if idp.lastForm.Get("code_verifier") == "" {
		t.Error("the token request must carry the PKCE verifier")
	}
	if got := idp.lastForm.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q", got)
	}

	// A session cookie is issued, and the flow cookie is cleared.
	var session, cleared *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch {
		case c.Name == sessionCookie && c.MaxAge > 0:
			session = c
		case c.Name == flowCookie && c.MaxAge < 0:
			cleared = c
		}
	}
	if session == nil {
		t.Fatalf("no session cookie was issued: %v", w.Result().Cookies())
	}
	if cleared == nil {
		t.Error("the flow cookie should have been cleared")
	}

	// And the session carries the verified identity.
	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.AddCookie(session)
	got := mustSession(t, r, reg.cfg)
	// Membership is keyed on (issuer, subject), so the issuer must be the
	// one the ID token was verified against.
	if got.Issuer != idp.server.URL || got.Subject != "sub-abc" || got.Provider != "fake" {
		t.Errorf("session = %+v", got)
	}
	if got.VerifiedEmail() != "dev@example.com" {
		t.Errorf("VerifiedEmail = %q, want dev@example.com", got.VerifiedEmail())
	}
	if got.Name != "Dev Eloper" {
		t.Errorf("Name = %q", got.Name)
	}
}

// An unverified email still signs in (with no allowlist), but carries no
// address to accept invitations with.
func TestLoginWithUnverifiedEmailCarriesNoVerifiedAddress(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	authURL, flow := start(t, reg, "")
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{"email": "dev@example.com", "email_verified": false}

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
			r.AddCookie(c)
			if email := cookieClaims(r, reg.cfg).VerifiedEmail(); email != "" {
				t.Errorf("VerifiedEmail = %q, want empty for an unverified address", email)
			}
			return
		}
	}
	t.Fatal("no session cookie was issued")
}

// A provider that sends email_verified as a string must still work.
func TestLoginWithStringEmailVerified(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	authURL, flow := start(t, reg, "")
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{"email": "dev@example.com", "email_verified": "true"}

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
			r.AddCookie(c)
			if email := cookieClaims(r, reg.cfg).VerifiedEmail(); email != "dev@example.com" {
				t.Errorf("VerifiedEmail = %q, want the verified address", email)
			}
			return
		}
	}
	t.Fatalf("no session cookie was issued; location = %s", w.Header().Get("Location"))
}

func TestLoginRejectedByAllowlist(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{
		AllowedDomains: []string{"allowed.example"},
	})

	authURL, flow := start(t, reg, "")
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{"email": "dev@blocked.example", "email_verified": true}

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	assertLoginError(t, w, "not_allowed")
}

// assertLoginError checks the callback bounced back to the login page with a
// given failure code, and issued no session.
func assertLoginError(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/auth/login" {
		t.Fatalf("redirected to %q, want /auth/login", location.Path)
	}
	if got := location.Query().Get("oidc_error"); got != wantCode {
		t.Errorf("oidc_error = %q, want %q", got, wantCode)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			t.Error("a failed login must not issue a session")
		}
	}
}

func TestCallbackFailureModes(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	t.Run("provider reported an error", func(t *testing.T) {
		w := callback(t, reg, nil, url.Values{"error": {"access_denied"}})
		assertLoginError(t, w, "access_denied")
	})

	t.Run("no flow cookie", func(t *testing.T) {
		w := callback(t, reg, nil, url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_missing")
	})

	t.Run("forged flow cookie", func(t *testing.T) {
		w := callback(t, reg, &http.Cookie{Name: flowCookie, Value: "nonsense"},
			url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_missing")
	})

	t.Run("expired flow", func(t *testing.T) {
		stale := &http.Cookie{Name: flowCookie, Value: signedJSON(t, flowState{
			Type: typeFlow, Provider: "fake", CSRF: "s", Nonce: "n", PKCEVerifier: "v",
			RedirectAfter: "/ui/", Expires: time.Now().Add(-time.Minute).Unix(),
		})}
		w := callback(t, reg, stale, url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_expired")
	})

	t.Run("flow belongs to another provider", func(t *testing.T) {
		mismatched := &http.Cookie{Name: flowCookie, Value: signedJSON(t, flowState{
			Type: typeFlow, Provider: "other", CSRF: "s", Nonce: "n", PKCEVerifier: "v",
			RedirectAfter: "/ui/", Expires: time.Now().Add(time.Hour).Unix(),
		})}
		w := callback(t, reg, mismatched, url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_expired")
	})

	// Flow state without its type tag is refused even when every field would
	// otherwise check out.
	t.Run("untagged flow state", func(t *testing.T) {
		untagged := &http.Cookie{Name: flowCookie, Value: signedJSON(t, flowState{
			Provider: "fake", CSRF: "s", Nonce: "n", PKCEVerifier: "v",
			RedirectAfter: "/ui/", Expires: time.Now().Add(time.Hour).Unix(),
		})}
		w := callback(t, reg, untagged, url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_missing")
	})

	// A session cookie is signed with the same key, and is not flow state.
	t.Run("session presented as flow state", func(t *testing.T) {
		session := issueSession(t, testSecret, Session{
			Issuer: "https://idp.test", Subject: "s", Provider: "fake",
			Expires: time.Now().Add(time.Hour).Unix(),
		})
		moved := &http.Cookie{Name: flowCookie, Value: session.Value}
		w := callback(t, reg, moved, url.Values{"code": {"c"}, "state": {"s"}})
		assertLoginError(t, w, "state_missing")
	})

	t.Run("missing code", func(t *testing.T) {
		_, flow := start(t, reg, "")
		w := callback(t, reg, flow, url.Values{"state": {"s"}})
		assertLoginError(t, w, "missing_code")
	})

	// The CSRF check: a state that does not match the flow cookie is an
	// injected callback.
	t.Run("state mismatch", func(t *testing.T) {
		_, flow := start(t, reg, "")
		w := callback(t, reg, flow, url.Values{"code": {"c"}, "state": {"attacker-state"}})
		assertLoginError(t, w, "state_mismatch")
	})

	// The nonce binds the ID token to this login; a token minted for a
	// different one must be refused even though it is validly signed.
	t.Run("nonce mismatch", func(t *testing.T) {
		authURL, flow := start(t, reg, "")
		idp.nonce = "a-nonce-from-some-other-login"
		idp.claims = map[string]any{"email": "dev@example.com", "email_verified": true}

		w := callback(t, reg, flow, url.Values{
			"code": {"c"}, "state": {authURL.Query().Get("state")},
		})
		assertLoginError(t, w, "nonce_mismatch")
	})

	t.Run("no id token in the response", func(t *testing.T) {
		authURL, flow := start(t, reg, "")
		idp.nonce = authURL.Query().Get("nonce")
		idp.omitIDToken = true
		defer func() { idp.omitIDToken = false }()

		w := callback(t, reg, flow, url.Values{
			"code": {"c"}, "state": {authURL.Query().Get("state")},
		})
		assertLoginError(t, w, "no_id_token")
	})
}

// An ID token signed by a key the provider does not publish must be refused,
// which is the check that makes the whole flow trustworthy.
func TestCallbackRejectsForeignSignature(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	authURL, flow := start(t, reg, "")
	idp.nonce = authURL.Query().Get("nonce")
	idp.claims = map[string]any{"email": "dev@example.com", "email_verified": true}

	// Swap in a key that was never published in the JWKS.
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp.key = foreign

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	assertLoginError(t, w, "token_invalid")
}

func TestRegistryRejectsDuplicateProviderIDs(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := &config.OidcConfig{
		Enabled:       true,
		PublicURL:     "http://localhost:9000",
		SessionSecret: testSecret,
		Providers: []config.ProviderConfig{
			{ID: "dup", Issuer: idp.server.URL, ClientID: "a"},
			{ID: "dup", Issuer: idp.server.URL, ClientID: "b"},
		},
	}
	if _, err := NewRegistry(t.Context(), cfg, newMemStore(), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("duplicate provider ids should be rejected at startup")
	}
}

// A broken issuer must fail at startup rather than on every login attempt.
func TestRegistryFailsOnUnreachableIssuer(t *testing.T) {
	cfg := &config.OidcConfig{
		Enabled:       true,
		PublicURL:     "http://localhost:9000",
		SessionSecret: testSecret,
		Providers: []config.ProviderConfig{
			{ID: "broken", Issuer: "http://127.0.0.1:1/nope", ClientID: "a"},
		},
	}
	if _, err := NewRegistry(t.Context(), cfg, newMemStore(), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("an unreachable issuer should fail discovery at startup")
	}
}

// Discovery must reach the provider through the registry's own client, and the
// resulting provider must be usable.
func TestRegistryDiscovers(t *testing.T) {
	idp := newFakeIdP(t)
	reg := flowRegistry(t, idp, &config.OidcConfig{})

	if len(reg.Providers()) != 1 {
		t.Fatalf("providers = %d, want 1", len(reg.Providers()))
	}
	p := reg.Providers()[0]
	if p.ID != "fake" || p.Name != "Fake" {
		t.Errorf("provider = %+v", p)
	}
	if p.redirectURL != "http://localhost:9000/auth/oidc/fake/callback" {
		t.Errorf("redirect URL = %q", p.redirectURL)
	}
	oauthCfg, discovered := p.oauthConfig()
	if oauthCfg.Endpoint.TokenURL != idp.server.URL+"/token" {
		t.Errorf("token endpoint = %q", oauthCfg.Endpoint.TokenURL)
	}
	if discovered == nil {
		t.Error("no discovered provider")
	}
	if p.verifier() == nil {
		t.Error("no ID token verifier")
	}
}
