// Package auth is OIDC single sign-on for the human-facing surface: the PWA at
// /ui and the JSON admin API at /api. The S3 gateway keeps its own SigV4 auth —
// OIDC is a browser flow and does not apply to machine clients.
//
// Everything here is stateless, which is what lets any number of instances sit
// behind a load balancer sharing only a session secret:
//
//   - Authentication needs no database. Any identity that authenticates at a
//     configured provider is admitted, optionally narrowed by an email
//     allowlist. Authorization is a separate layer in the admin API: it maps
//     the session's (issuer, subject) to a users row and scopes each namespace
//     to the teams that user belongs to.
//   - Sessions are HMAC-signed cookies carrying the identity and an expiry.
//     There is no session table and no server-side revocation; logging out
//     clears the cookie.
//   - Login flow state (the CSRF token, nonce and PKCE verifier) rides along in
//     a second short-lived signed cookie across the redirect to the provider
//     and back, so the callback needs no shared store either.
//   - Cross-site requests are refused from the request's own Sec-Fetch-Site
//     and Origin headers (see RejectCrossSite), so state-changing calls need
//     no CSRF token either.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/ggoggam/simplecas/internal/config"
)

const (
	// sessionCookie holds the signed identity. Like flowCookie it is a base
	// name: served over HTTPS the cookie is stored with the __Host- prefix
	// (see cookieName).
	sessionCookie = "scas_session"
	// flowCookie holds the per-login state across the provider round trip.
	flowCookie = "scas_oidc_flow"
	// hostCookiePrefix is the prefix a browser accepts only on a cookie that
	// is Secure, has Path=/ and names no Domain.
	hostCookiePrefix = "__Host-"
	// flowTTL bounds how long a login ceremony may take.
	flowTTL = 10 * time.Minute
)

// Token types. Both cookies are signed with the same key, so each payload
// names what it is and is accepted only where that type is read: a flow-state
// token moved into the session cookie, or a session into the flow cookie, is
// refused for its type rather than for whichever fields it happens to lack.
const (
	typeSession = "session"
	typeFlow    = "oidc_flow"
)

// Session is the identity carried in the session cookie.
type Session struct {
	// Issuer and Subject together are the identity: the subject is the
	// provider's never-reassigned id for the account, and the issuer keeps two
	// providers' subjects apart. Team membership is keyed on the pair.
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	// EmailVerified records whether the provider asserted the address. Only a
	// verified address may accept an invitation addressed to it.
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Provider      string `json:"provider"`
	// Expires is a Unix timestamp.
	Expires int64 `json:"exp"`
}

// sessionToken is the signed form of a Session: its fields, tagged with their
// type.
type sessionToken struct {
	Type string `json:"typ"`
	Session
}

// VerifiedEmail is the caller's address, normalised, if their provider
// verified it, and empty otherwise. Invitations are addressed by email, so this
// is what decides which ones the caller may accept; an unverified address must
// never be enough to join a team.
func (s *Session) VerifiedEmail() string {
	if s == nil || !s.EmailVerified {
		return ""
	}
	return NormalizeEmail(s.Email)
}

// NormalizeEmail is the one canonical form of an address, so an invitation
// addressed to "Dev@Example.com " matches the login that presents
// "dev@example.com".
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// flowState is the per-login state that must survive the round trip to the
// provider.
type flowState struct {
	// Type is always typeFlow.
	Type          string `json:"typ"`
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
	return cfg.PublicHTTPS()
}

// cookieName is the name a cookie is stored under. Served over HTTPS it carries
// the __Host- prefix, which a browser honours only on a Secure cookie with
// Path=/ and no Domain, so neither a sibling subdomain nor a plain-HTTP
// response can plant or overwrite it. Over plain HTTP (local development) the
// cookie cannot be Secure, so it keeps the bare name.
func cookieName(base string, secure bool) string {
	if secure {
		return hostCookiePrefix + base
	}
	return base
}

// setCookie builds a session-style cookie under base's effective name (see
// cookieName). HttpOnly keeps it away from page scripts; SameSite=Lax still
// allows the top-level redirect back from the provider to carry it.
func setCookie(base, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName(base, secure),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearCookie expires a cookie immediately.
func clearCookie(base string, secure bool) *http.Cookie {
	c := setCookie(base, "", -1, secure)
	c.Expires = time.Unix(0, 0)
	return c
}

// ---------------------------------------------------------------------------
// Session reading
// ---------------------------------------------------------------------------

// CurrentSession returns the caller's session if the cookie is present, signed
// with the configured secret, and unexpired.
func CurrentSession(r *http.Request, cfg *config.OidcConfig) *Session {
	cookie, err := r.Cookie(cookieName(sessionCookie, secureCookies(cfg)))
	if err != nil {
		return nil
	}
	payload := unsign(cfg.SessionSecret, cookie.Value)
	if payload == nil {
		return nil
	}
	var token sessionToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil
	}
	if token.Type != typeSession {
		return nil
	}
	s := token.Session
	if s.Expires <= time.Now().Unix() {
		return nil
	}
	// Without both halves of the identity there is nobody to authorize.
	if s.Issuer == "" || s.Subject == "" {
		return nil
	}
	return &s
}

// signSession renders s as a session cookie value.
func signSession(secret string, s Session) (string, error) {
	payload, err := json.Marshal(sessionToken{Type: typeSession, Session: s})
	if err != nil {
		return "", err
	}
	return sign(secret, payload), nil
}

// defaultLanding is where a login lands when it names no acceptable
// destination.
const defaultLanding = "/ui/"

// sanitizeRedirect keeps a post-login destination inside the PWA: "/ui" itself
// or a path under "/ui/", and nothing else.
//
// Browsers read a Location more loosely than url.Parse does, so anything one
// might take for another host is refused outright: a backslash (a browser reads
// "/\evil.example" as "//evil.example") and a control character (a browser
// strips tabs and newlines, which can close "/\t/evil.example" up into
// "//evil.example"). The decoded path is checked for both as well, and for dot
// segments, since "/ui/../api/x" resolves outside the PWA and a browser treats
// "%2e" as a dot when resolving one.
func sanitizeRedirect(raw string) string {
	if strings.ContainsFunc(raw, unsafeInRedirect) {
		return defaultLanding
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return defaultLanding
	}
	if u.Path != "/ui" && !strings.HasPrefix(u.Path, "/ui/") {
		return defaultLanding
	}
	if strings.ContainsFunc(u.Path, unsafeInRedirect) {
		return defaultLanding
	}
	for segment := range strings.SplitSeq(u.Path, "/") {
		if segment == "." || segment == ".." {
			return defaultLanding
		}
	}
	return raw
}

// unsafeInRedirect reports a character a redirect target may never contain.
func unsafeInRedirect(c rune) bool {
	return c == '\\' || unicode.IsControl(c)
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
