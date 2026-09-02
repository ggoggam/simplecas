package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestSessionTenantEmail(t *testing.T) {
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
			name:    "unverified email yields no tenant identity",
			session: &Session{Email: "dev@example.com", EmailVerified: false},
			want:    "",
		},
		{
			name:    "absent email yields no tenant identity",
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
			if got := tc.session.TenantEmail(); got != tc.want {
				t.Errorf("TenantEmail() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeRedirect(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"same-site path", "/ui/x", "/ui/x"},
		{"path with query", "/ui/x?a=1", "/ui/x?a=1"},
		{"protocol-relative is an open redirect", "//evil.example", "/ui/"},
		{"absolute URL", "https://evil.example", "/ui/"},
		{"scheme-relative with path", "//evil.example/ui/", "/ui/"},
		{"empty", "", "/ui/"},
		{"relative without a leading slash", "ui/x", "/ui/"},
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

// mustSession reads the caller's session and fails if there isn't one, so the
// assertions that follow can dereference it directly.
func mustSession(t *testing.T, r *http.Request, cfg *config.OidcConfig) *Session {
	t.Helper()
	s := CurrentSession(r, cfg)
	if s == nil {
		t.Fatal("expected a valid session")
	}
	return s
}

// issueSession mints a signed session cookie the way a completed login does.
func issueSession(t *testing.T, secret string, s Session) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return setCookie(sessionCookie, sign(secret, payload), 3600, false)
}

func TestCurrentSession(t *testing.T) {
	cfg := &config.OidcConfig{SessionSecret: testSecret, SessionTTLSecs: 3600}
	valid := Session{
		Subject: "sub-1", Email: "dev@example.com", EmailVerified: true,
		Provider: "google", Expires: time.Now().Add(time.Hour).Unix(),
	}

	t.Run("valid cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, testSecret, valid))

		got := mustSession(t, r, cfg)
		if got.Subject != "sub-1" || got.TenantEmail() != "dev@example.com" {
			t.Errorf("session = %+v", got)
		}
	})

	t.Run("no cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if CurrentSession(r, cfg) != nil {
			t.Error("expected no session")
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired := valid
		expired.Expires = time.Now().Add(-time.Minute).Unix()
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, testSecret, expired))
		if CurrentSession(r, cfg) != nil {
			t.Error("an expired session must be rejected")
		}
	})

	t.Run("signed with another secret", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(issueSession(t, "a-different-secret-entirely", valid))
		if CurrentSession(r, cfg) != nil {
			t.Error("a session signed elsewhere must be rejected")
		}
	})

	t.Run("garbage cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "nonsense"})
		if CurrentSession(r, cfg) != nil {
			t.Error("a malformed cookie must be rejected")
		}
	})

	// A validly-signed but non-Session payload must not panic or half-succeed.
	t.Run("valid signature over a non-session payload", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		r.AddCookie(&http.Cookie{
			Name:  sessionCookie,
			Value: sign(testSecret, []byte(`"not an object"`)),
		})
		if CurrentSession(r, cfg) != nil {
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
	reg, err := NewRegistry(t.Context(), &config.OidcConfig{Enabled: false}, slog.New(slog.DiscardHandler))
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
