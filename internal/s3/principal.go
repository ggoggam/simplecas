package s3

import (
	"context"
	"crypto/hmac"
	"net/http"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
)

// principal is who a verified S3 request belongs to.
//
// tenantID nil means the admin credential — the one in simplecas.toml, or no
// credential at all when auth is disabled — which addresses every namespace
// including unowned ones. A non-nil tenantID is a per-tenant credential, and
// it may address only that tenant's namespaces.
type principal struct {
	tenantID *int64
}

// principalKey types the context value, so nothing else can collide with it.
type principalKey struct{}

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// principalFrom returns the verified principal for a request.
//
// ok is false when the request never went through authenticate. That is a
// routing bug rather than an anonymous caller, and callers deny the request:
// defaulting a missing principal to admin scope is exactly the fail-open shape
// this indirection exists to prevent.
func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalKey{}).(principal)
	return p, ok
}

// authenticate verifies the request signature and resolves the tenant scope its
// credential grants. Signature checking and scope resolution are deliberately
// one call: a caller cannot obtain one without the other, so no handler can end
// up authenticated but unscoped. The signing context comes back too, for the
// body's chunk signatures (see verify).
func (g *Gateway) authenticate(r *http.Request) (principal, *chunkSigner, error) {
	// With auth disabled there are no credentials to distinguish, so the
	// gateway is the open admin plane it has always been — which is what lets
	// `aws s3 --no-sign-request` work against a dev instance. Tenanted S3
	// access requires auth.enabled.
	if !g.cfg.Auth.Enabled {
		return principal{}, nil, nil
	}

	parsed, ok := parseAuthHeader(r.Header.Get("Authorization"))
	if !ok {
		return principal{}, nil, apperr.ErrAccessDenied
	}

	// The configured admin credential is matched first, so a row in
	// tenant_credentials that somehow carried the same access key id could
	// never shadow the admin key into a narrower scope — or, worse, be
	// mistaken for it. The empty guard matters because an unset admin key
	// would otherwise match a request whose credential scope parsed empty.
	adminKey := g.cfg.Auth.AccessKeyID
	if adminKey != "" && hmac.Equal([]byte(parsed.accessKeyID), []byte(adminKey)) {
		signer, err := verify(r, g.cfg.Auth)
		if err != nil {
			return principal{}, nil, err
		}
		return principal{}, signer, nil
	}

	cred, found, err := g.db.LookupS3Credential(r.Context(), parsed.accessKeyID)
	if err != nil {
		return principal{}, nil, err
	}
	if !found {
		// An unknown or expired key is reported the same way a bad
		// signature is, so the gateway is not an oracle for which access
		// key ids exist.
		return principal{}, nil, apperr.ErrAccessDenied
	}
	secret, err := g.openSecret(cred)
	if err != nil {
		return principal{}, nil, err
	}

	// Reuse the single-credential path rather than reimplementing the
	// canonicalisation, so the tenanted and admin credentials cannot drift in
	// what they accept.
	signer, err := verify(r, config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: secret,
	})
	if err != nil {
		return principal{}, nil, err
	}
	g.touchCredential(r.Context(), cred)
	return principal{tenantID: &cred.TenantID}, signer, nil
}

// namespace resolves a namespace name within the caller's scope. Every handler
// goes through here rather than calling db.GetNamespace, which is what makes
// tenant scoping impossible to forget: there is no unscoped way to turn a
// namespace name from a request into a namespace row.
func (g *Gateway) namespace(r *http.Request, name string) (db.Namespace, error) {
	p, ok := principalFrom(r.Context())
	if !ok {
		return db.Namespace{}, apperr.Internalf("s3: request reached %s without authentication", r.URL.Path)
	}
	if p.tenantID != nil {
		return g.db.GetNamespaceForTenant(r.Context(), name, *p.tenantID)
	}
	return g.db.GetNamespace(r.Context(), name)
}
