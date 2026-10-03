package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/config"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestSignRoundTripAndTamper(t *testing.T) {
	token := sign(testSecret, []byte("hello world"))

	if got := unsign(testSecret, token); string(got) != "hello world" {
		t.Errorf("round trip = %q, want %q", got, "hello world")
	}
	if unsign("a-completely-different-secret", token) != nil {
		t.Error("a token must not verify under a different secret")
	}

	// Swap the payload but keep the tag.
	_, tag, _ := strings.Cut(token, ".")
	forged := signingEncoding.EncodeToString([]byte("goodbye")) + "." + tag
	if unsign(testSecret, forged) != nil {
		t.Error("a tampered payload must not verify")
	}

	for _, malformed := range []string{"", "no-dot", "!!!.!!!", ".", "abc."} {
		if unsign(testSecret, malformed) != nil {
			t.Errorf("malformed token %q must not verify", malformed)
		}
	}
}

func TestSessionVerifiedEmail(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		want    string
	}{
		{
			name:    "verified email is trimmed and lowercased",
			session: &Session{Email: "  Dev@Example.COM ", EmailVerified: true},
			want:    "dev@example.com",
		},
		{
			name:    "unverified email yields nothing",
			session: &Session{Email: "dev@example.com", EmailVerified: false},
			want:    "",
		},
		{
			name:    "absent email yields nothing",
			session: &Session{EmailVerified: true},
			want:    "",
		},
		{
			name:    "a nil session is safe to ask",
			session: nil,
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.session.VerifiedEmail(); got != tc.want {
				t.Errorf("VerifiedEmail() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeRedirect(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"the PWA root", "/ui/", "/ui/"},
		{"the PWA root without its slash", "/ui", "/ui"},
		{"a path in the PWA", "/ui/x", "/ui/x"},
		{"path with query", "/ui/x?a=1", "/ui/x?a=1"},
		{"path with fragment", "/ui/x#top", "/ui/x#top"},
		{"a dot inside a name is fine", "/ui/file..txt", "/ui/file..txt"},

		{"protocol-relative is an open redirect", "//evil.example", "/ui/"},
		{"absolute URL", "https://evil.example", "/ui/"},
		{"absolute URL to this site's PWA", "https://evil.example/ui/", "/ui/"},
		{"scheme-relative with path", "//evil.example/ui/", "/ui/"},
		{"javascript URL", "javascript:alert(1)", "/ui/"},
		{"empty", "", "/ui/"},
		{"relative without a leading slash", "ui/x", "/ui/"},

		// A browser reads a backslash as a slash, so each of these is
		// "//evil.example" by the time it is followed.
		{"backslash after the slash", `/\evil.example`, "/ui/"},
		{"two backslashes", `/\\evil.example`, "/ui/"},
		{"backslash first", `\\evil.example`, "/ui/"},
		{"backslash inside the PWA", `/ui/\evil.example`, "/ui/"},
		{"percent-encoded backslash", "/%5Cevil.example", "/ui/"},
		{"percent-encoded backslash inside the PWA", "/ui/%5Cevil.example", "/ui/"},

		// A browser strips tabs and newlines from a URL, closing up the
		// slashes around them.
		{"tab between the slashes", "/\t/evil.example", "/ui/"},
		{"newline between the slashes", "/\n/evil.example", "/ui/"},
		{"carriage return between the slashes", "/\r/evil.example", "/ui/"},
		{"control character inside the PWA", "/ui/\x00x", "/ui/"},
		{"percent-encoded newline inside the PWA", "/ui/%0Ax", "/ui/"},

		// Same-origin, but not the PWA.
		{"the API", "/api/tenants", "/ui/"},
		{"the logout endpoint", "/auth/logout", "/ui/"},
		{"a gateway namespace", "/photos/cat.jpg", "/ui/"},
		{"a lookalike prefix", "/uix", "/ui/"},
		{"a dot segment out of the PWA", "/ui/../api/tenants", "/ui/"},
		{"an encoded dot segment out of the PWA", "/ui/%2e%2e/api/tenants", "/ui/"},
		{"a single dot segment", "/ui/./x", "/ui/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRedirect(tc.in); got != tc.want {
				t.Errorf("sanitizeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAdmitted(t *testing.T) {
	open := &config.OidcConfig{}
	restricted := &config.OidcConfig{
		AllowedDomains: []string{"example.com"},
		AllowedEmails:  []string{"ceo@other.example"},
	}

	tests := []struct {
		name     string
		cfg      *config.OidcConfig
		email    string
		verified bool
		want     bool
	}{
		{"no allowlist admits anyone", open, "", false, true},
		{"no allowlist admits an unverified address", open, "x@any.example", false, true},

		{"allowed domain, verified", restricted, "dev@example.com", true, true},
		{"allowed domain is case-insensitive", restricted, "DEV@EXAMPLE.COM", true, true},
		{"explicitly allowed address", restricted, "ceo@other.example", true, true},
		{"wrong domain", restricted, "dev@evil.example", true, false},
		// An allowlist trusts the address, so it must be verified.
		{"right domain but unverified", restricted, "dev@example.com", false, false},
		{"no address at all", restricted, "", true, false},
		{"address with no domain", restricted, "malformed", true, false},
		// A domain must match the part after the LAST @, or
		// "evil@example.com@attacker.test" would sneak through.
		{"multiple at-signs uses the final domain", restricted, "evil@example.com@attacker.test", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := admitted(tc.cfg, tc.email, tc.verified); got != tc.want {
				t.Errorf("admitted(%q, verified=%v) = %v, want %v",
					tc.email, tc.verified, got, tc.want)
			}
		})
	}
}

// cookieClaims reads the claims of the caller's session cookie, without
// asking any store whether its session is live.
func cookieClaims(r *http.Request, cfg *config.OidcConfig) *Session {
	s, _ := sessionFromCookie(r, cfg)
	return s
}

// mustSession reads the caller's session cookie and fails if there isn't a
// genuine one, so the assertions that follow can dereference it directly.
func mustSession(t *testing.T, r *http.Request, cfg *config.OidcConfig) *Session {
	t.Helper()
	s := cookieClaims(r, cfg)
	if s == nil {
		t.Fatal("expected a valid session")
	}
	return s
}

// issueSession mints a signed session cookie shaped like the one a completed
// login sets, with a fresh token that no store has a row for. It is for the
// checks made on the cookie alone; Registry.signIn mints a live one.
func issueSession(t *testing.T, secret string, s Session) *http.Cookie {
	t.Helper()
	token, err := signSession(secret, s, randomToken())
	if err != nil {
		t.Fatal(err)
	}
	return setCookie(sessionCookie, token, 3600, false)
}

// signedJSON signs v as it marshals, for payloads a real login never mints.
func signedJSON(t *testing.T, v any) string {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return sign(testSecret, payload)
}

func TestSessionFromCookie(t *testing.T) {
	cfg := &config.OidcConfig{SessionSecret: testSecret, SessionTTLSecs: 3600}
	valid := Session{
		Issuer: "https://idp.test", Subject: "sub-1", Email: "dev@example.com", EmailVerified: true,
		Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
	}

	t.Run("valid cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, testSecret, valid))

		got := mustSession(t, r, cfg)
		if got.Subject != "sub-1" || got.VerifiedEmail() != "dev@example.com" {
			t.Errorf("session = %+v", got)
		}
	})

	t.Run("no cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if cookieClaims(r, cfg) != nil {
			t.Error("expected no session")
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired := valid
		expired.Expires = time.Now().Add(-time.Minute).Unix()
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, testSecret, expired))
		if cookieClaims(r, cfg) != nil {
			t.Error("an expired session must be rejected")
		}
	})

	t.Run("signed with another secret", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, "a-different-secret-entirely", valid))
		if cookieClaims(r, cfg) != nil {
			t.Error("a session signed elsewhere must be rejected")
		}
	})

	t.Run("garbage cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "nonsense"})
		if cookieClaims(r, cfg) != nil {
			t.Error("a malformed cookie must be rejected")
		}
	})

	// Sessions minted before they carried the issuer have no identity to
	// authorize, so they sign the holder out instead.
	t.Run("no issuer", func(t *testing.T) {
		legacy := valid
		legacy.Issuer = ""
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, testSecret, legacy))
		if cookieClaims(r, cfg) != nil {
			t.Error("a session without an issuer must be rejected")
		}
	})

	// The login flow's state is signed with the same key, so it must not be
	// accepted when moved into the session cookie.
	t.Run("flow state presented as a session", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: signedJSON(t, flowState{
			Type: typeFlow, Provider: "google", CSRF: "c", Nonce: "n", PKCEVerifier: "v",
			RedirectAfter: "/ui/", Expires: time.Now().Add(time.Hour).Unix(),
		})})
		if cookieClaims(r, cfg) != nil {
			t.Error("a flow-state token must not be accepted as a session")
		}
	})

	// The type tag decides, not the fields: a token tagged as flow state is
	// refused even when it carries everything a session needs.
	t.Run("a complete session tagged as flow state", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: signedJSON(t,
			sessionToken{Type: typeFlow, Token: randomToken(), Session: valid})})
		if cookieClaims(r, cfg) != nil {
			t.Error("a token of another type must not be accepted as a session")
		}
	})

	// A stateless session from before sessions had rows carries no token to
	// look one up by, so it signs its holder out.
	t.Run("pre-upgrade session without a token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: signedJSON(t,
			sessionToken{Type: typeSession, Session: valid})})
		if cookieClaims(r, cfg) != nil {
			t.Error("a session cookie without a token must not be accepted")
		}
	})

	// The row ids come from the database; a cookie that claims them gets no
	// say.
	t.Run("row ids are not read from the cookie", func(t *testing.T) {
		payload, err := json.Marshal(map[string]any{
			"typ": typeSession, "tok": randomToken(), "iss": valid.Issuer, "sub": valid.Subject,
			"provider": valid.Provider, "exp": valid.Expires,
			"ID": "6f1c1d9e-0000-4000-8000-000000000000", "UserID": 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sign(testSecret, payload)})
		got := mustSession(t, r, cfg)
		if got.ID != uuid.Nil || got.UserID != 0 {
			t.Errorf("session = %+v, want no row ids from the cookie", got)
		}
	})

	// A session minted before tokens were tagged signs its holder out.
	t.Run("untagged session", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: signedJSON(t, valid)})
		if cookieClaims(r, cfg) != nil {
			t.Error("an untagged token must not be accepted as a session")
		}
	})

	// A validly-signed but non-Session payload must not panic or half-succeed.
	t.Run("valid signature over a non-session payload", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{
			Name:  sessionCookie,
			Value: sign(testSecret, []byte(`"not an object"`)),
		})
		if cookieClaims(r, cfg) != nil {
			t.Error("a non-session payload must be rejected")
		}
	})
}

func TestCookieAttributes(t *testing.T) {
	c := setCookie("n", "v", 3600, true)
	if !c.HttpOnly {
		t.Error("session cookies must be HttpOnly so page scripts cannot read them")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("SameSite must be Lax so the provider's redirect back carries the cookie")
	}
	if !c.Secure || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}

	cleared := clearCookie("n", true)
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("cleared cookie = %+v, want an immediate expiry", cleared)
	}
}

// Over HTTPS both cookies carry the __Host- prefix, which a browser accepts
// only with Secure, Path=/ and no Domain; over plain HTTP, where a Secure
// cookie cannot be set, they keep their bare names.
func TestCookiesTakeTheHostPrefixOverHTTPS(t *testing.T) {
	for _, base := range []string{sessionCookie, flowCookie} {
		c := setCookie(base, "v", 3600, true)
		if c.Name != "__Host-"+base {
			t.Errorf("HTTPS cookie name = %q, want the __Host- prefix", c.Name)
		}
		if !c.Secure || c.Path != "/" || c.Domain != "" {
			t.Errorf("a __Host- cookie must be Secure, Path=/, with no Domain: %+v", c)
		}
		if cleared := clearCookie(base, true); cleared.Name != c.Name {
			t.Errorf("clearing %q names %q", c.Name, cleared.Name)
		}

		if plain := setCookie(base, "v", 3600, false); plain.Name != base || plain.Secure {
			t.Errorf("plain-HTTP cookie = %+v, want the bare name and no Secure", plain)
		}
	}
}

// Over HTTPS only the prefixed cookie is a session; a bare-named one, which a
// sibling subdomain or a plain-HTTP response could have planted, is ignored.
func TestSessionCookieIsHostPrefixedOverHTTPS(t *testing.T) {
	cfg := &config.OidcConfig{PublicURL: "https://cas.example.com", SessionSecret: testSecret}
	token, err := signSession(testSecret, Session{
		Issuer: "https://idp.test", Subject: "sub-1", Provider: "google",
		Expires: time.Now().Add(time.Hour).Unix(),
	}, randomToken())
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.AddCookie(setCookie(sessionCookie, token, 3600, true))
	if s := mustSession(t, r, cfg); s.Subject != "sub-1" {
		t.Errorf("session = %+v", s)
	}

	r = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if cookieClaims(r, cfg) != nil {
		t.Error("over HTTPS a cookie without the __Host- prefix must be ignored")
	}
}

func TestSecureCookiesFollowsPublicURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://cas.example.com", true},
		{"http://localhost:9000", false},
		{"", false},
	}
	for _, tc := range tests {
		got := secureCookies(&config.OidcConfig{PublicURL: tc.url})
		if got != tc.want {
			t.Errorf("secureCookies(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestEffectiveScopes(t *testing.T) {
	tests := []struct {
		name       string
		configured []string
		want       []string
	}{
		{"default", nil, []string{"openid", "email", "profile"}},
		{"explicit list gains openid", []string{"email"}, []string{"openid", "email"}},
		{"openid is not duplicated", []string{"openid", "email"}, []string{"openid", "email"}},
		{"custom scopes are preserved", []string{"groups"}, []string{"openid", "groups"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveScopes(tc.configured)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("effectiveScopes(%v) = %v, want %v", tc.configured, got, tc.want)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	valid := func() *config.OidcConfig {
		return &config.OidcConfig{
			Enabled:       true,
			PublicURL:     "https://cas.example.com",
			SessionSecret: testSecret,
			Providers: []config.ProviderConfig{{
				ID: "google", Issuer: "https://accounts.google.com", ClientID: "cid",
			}},
		}
	}
	if err := validateConfig(valid()); err != nil {
		t.Fatalf("a complete config should validate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*config.OidcConfig)
	}{
		{"no public url", func(c *config.OidcConfig) { c.PublicURL = "" }},
		{"blank public url", func(c *config.OidcConfig) { c.PublicURL = "   " }},
		{"short session secret", func(c *config.OidcConfig) { c.SessionSecret = "tooshort" }},
		{"no providers", func(c *config.OidcConfig) { c.Providers = nil }},
		{"provider without an id", func(c *config.OidcConfig) { c.Providers[0].ID = "" }},
		{"provider without an issuer", func(c *config.OidcConfig) { c.Providers[0].Issuer = "" }},
		{"provider without a client id", func(c *config.OidcConfig) { c.Providers[0].ClientID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			if err := validateConfig(cfg); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

// A disabled OIDC config yields no registry at all, which is what leaves the
// /auth endpoints unmounted and /ui and /api unguarded.
func TestNewRegistryDisabled(t *testing.T) {
	reg, err := NewRegistry(t.Context(), &config.OidcConfig{Enabled: false}, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("disabled OIDC should not error: %v", err)
	}
	if reg != nil {
		t.Error("disabled OIDC should produce no registry")
	}
}

func TestFlexibleBool(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    bool
		wantErr bool
	}{
		{name: "boolean true", json: `true`, want: true},
		{name: "boolean false", json: `false`, want: false},
		// Some providers send email_verified as a string; without this the
		// whole claims parse would fail and every login would break.
		{name: `string "true"`, json: `"true"`, want: true},
		{name: `string "false"`, json: `"false"`, want: false},
		{name: "number is neither", json: `1`, wantErr: true},
		{name: "object is neither", json: `{}`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b flexibleBool
			err := json.Unmarshal([]byte(tc.json), &b)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if bool(b) != tc.want {
				t.Errorf("got %v, want %v", bool(b), tc.want)
			}
		})
	}
}

// The claims struct as a whole must survive a string-valued email_verified.
func TestIDTokenClaimsToleratesStringEmailVerified(t *testing.T) {
	var claims idTokenClaims
	body := `{"email":"dev@example.com","email_verified":"true","name":"Dev"}`
	if err := json.Unmarshal([]byte(body), &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims.Email != "dev@example.com" || !bool(claims.EmailVerified) || claims.Name != "Dev" {
		t.Errorf("claims = %+v", claims)
	}
}
