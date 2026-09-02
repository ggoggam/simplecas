// Package auth is OIDC single sign-on for the human-facing surface: the PWA at
// /ui and the JSON admin API at /api. The S3 gateway keeps its own SigV4 auth —
// OIDC is a browser flow and does not apply to machine clients.
//
// Everything here is stateless, which is what lets any number of instances sit
// behind a load balancer sharing only a session secret:
//
//   - Authentication has no users table. Any identity that authenticates at a
//     configured provider is admitted, optionally narrowed by an email
//     allowlist. Authorization is a separate layer — the tenants and
//     tenant_members tables scope each namespace to the team that owns it,
//     keyed on the caller's verified email.
//   - Sessions are HMAC-signed cookies carrying the identity and an expiry.
//     There is no session table and no server-side revocation; logging out
//     clears the cookie.
//   - Login flow state (the CSRF token, nonce and PKCE verifier) rides along in
//     a second short-lived signed cookie across the redirect to the provider
//     and back, so the callback needs no shared store either.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/config"
)

const (
	// sessionCookie holds the signed identity.
	sessionCookie = "scas_session"
	// flowCookie holds the per-login state across the provider round trip.
	flowCookie = "scas_oidc_flow"
	// flowTTL bounds how long a login ceremony may take.
	flowTTL = 10 * time.Minute
)

// Session is the identity carried in the session cookie.
type Session struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	// EmailVerified records whether the provider asserted the address. Tenancy
	// is keyed on email, so tenant access requires it.
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Provider      string `json:"provider"`
	// Expires is a Unix timestamp.
	Expires int64 `json:"exp"`
}

// TenantEmail is the caller's tenant identity: their verified address,
// normalised. It is empty when the email is absent or unverified, in which case
// the caller has no tenant access at all — an unverified address must never be
// enough to join a team, since membership is granted by email.
func (s *Session) TenantEmail() string {
	if s == nil || !s.EmailVerified {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s.Email))
}

// flowState is the per-login state that must survive the round trip to the
// provider.
type flowState struct {
	Provider      string `json:"provider"`
	CSRF          string `json:"csrf"`
	Nonce         string `json:"nonce"`
	PKCEVerifier  string `json:"pkce"`
	RedirectAfter string `json:"redirect"`
	Expires       int64  `json:"exp"`
}

// ---------------------------------------------------------------------------
// Signed cookies
// ---------------------------------------------------------------------------

// signingEncoding is URL-safe and unpadded, so a token is cookie-safe.
var signingEncoding = base64.RawURLEncoding

// sign renders payload as base64url(payload).base64url(HMAC-SHA256(payload)).
func sign(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return signingEncoding.EncodeToString(payload) + "." + signingEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies the tag in constant time and returns the payload, or nil if
// the token is malformed or the signature does not match.
func unsign(secret, token string) []byte {
	payloadB64, tagB64, ok := strings.Cut(token, ".")
	if !ok {
		return nil
	}
	payload, err := signingEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil
	}
	tag, err := signingEncoding.DecodeString(tagB64)
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil
	}
	return payload
}

// secureCookies reports whether cookies should carry the Secure attribute,
// inferred from whether this instance is served over TLS.
func secureCookies(cfg *config.OidcConfig) bool {
	return strings.HasPrefix(cfg.PublicURL, "https")
}

// setCookie builds a session-style cookie. HttpOnly keeps it away from page
// scripts; SameSite=Lax still allows the top-level redirect back from the
// provider to carry it.
func setCookie(name, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearCookie expires a cookie immediately.
func clearCookie(name string, secure bool) *http.Cookie {
	c := setCookie(name, "", -1, secure)
	c.Expires = time.Unix(0, 0)
	return c
}

// ---------------------------------------------------------------------------
// Session reading
// ---------------------------------------------------------------------------

// CurrentSession returns the caller's session if the cookie is present, signed
// with the configured secret, and unexpired.
func CurrentSession(r *http.Request, cfg *config.OidcConfig) *Session {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	payload := unsign(cfg.SessionSecret, cookie.Value)
	if payload == nil {
		return nil
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil
	}
	if s.Expires <= time.Now().Unix() {
		return nil
	}
	return &s
}

// sanitizeRedirect keeps a post-login destination on this site. A protocol-
// relative "//host" would otherwise be an open redirect.
func sanitizeRedirect(raw string) string {
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	return "/ui/"
}

// admitted decides whether an authenticated identity may sign in.
//
// Both allowlists empty admits anyone who authenticates at a configured
// provider. A configured allowlist trusts the email address, so an unverified
// or absent address is refused — otherwise a provider that lets users type any
// address would let them claim an allowlisted domain.
func admitted(cfg *config.OidcConfig, email string, verified bool) bool {
	if len(cfg.AllowedDomains) == 0 && len(cfg.AllowedEmails) == 0 {
		return true
	}
	if email == "" || !verified {
		return false
	}
	for _, allowed := range cfg.AllowedEmails {
		if strings.EqualFold(allowed, email) {
			return true
		}
	}
	// An address may contain more than one "@"; the domain is whatever follows
	// the last one, so "evil@example.com@attacker.test" is not an example.com
	// address.
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	for _, allowed := range cfg.AllowedDomains {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return false
}

// trimSpace and trimTrailingSlash keep the validation and URL assembly above
// readable.
func trimSpace(s string) string { return strings.TrimSpace(s) }

func trimTrailingSlash(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

// constantTimeEqual compares two tokens without leaking their contents through
// timing. Used for the CSRF state and the ID token nonce.
func constantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
