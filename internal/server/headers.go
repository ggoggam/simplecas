// Response headers for the human-facing surfaces: the PWA at /ui, the JSON API
// at /api and the sign-in endpoints at /auth. The S3 gateway gets none of them;
// its object responses carry headers chosen for untrusted content instead (see
// internal/s3/contentsafety.go), and so do the object bytes /api hands back
// through the gateway, which drops the policy and framing headers set here.
//
// They are set before the surface's handler runs, so a handler that knows
// better can replace one: the sign-in page relaxes the policy to admit its own
// inline stylesheet.

package server

import "net/http"

const (
	// uiPolicy is what the built PWA needs and no more. Every script, style
	// sheet, worker and fetch is same-origin, and so are previews: images,
	// media and the PDF iframe all load object bytes from /api.
	//
	//   - 'wasm-unsafe-eval' lets the upload worker compile hash-wasm's
	//     BLAKE3 module; it permits WebAssembly compilation, not eval.
	//   - Styles need 'unsafe-inline': sonner, the Radix scroll lock and
	//     dnd-kit inject <style> elements at runtime. Scripts stay strictly same-origin, so
	//     an injected style cannot become an injected script.
	//   - frame-ancestors 'none' refuses any framing, the modern spelling of
	//     X-Frame-Options: DENY, which is still sent for older browsers.
	uiPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"

	// lockedPolicy is for responses that should never render anything: JSON,
	// redirects and plain-text errors. Should one be opened as a page anyway,
	// it can load nothing and be framed by nobody.
	lockedPolicy = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

	// hstsPolicy keeps browsers on HTTPS for a year. It leaves out
	// includeSubDomains and preload: this server cannot know what else is
	// served under its parent domain.
	hstsPolicy = "max-age=31536000"
)

// setSurfaceHeaders adds the headers every human-facing response carries, with
// policy as its Content-Security-Policy.
//
// Referrer-Policy is same-origin rather than strict-origin-when-cross-origin:
// nothing the PWA or the sign-in flow sends cross-origin needs a Referer, and
// these URLs name namespaces and object keys that should not leak to an
// identity provider or a linked site even as a bare origin.
//
// Strict-Transport-Security goes only on a request that came over TLS, or when
// the instance's configured public URL is https (TLS ending at a proxy in
// front). Browsers ignore it over plain HTTP anyway, but sending it there would
// claim something this server does not know.
func setSurfaceHeaders(w http.ResponseWriter, r *http.Request, policy string, https bool) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", policy)
	if r.TLS != nil || https {
		h.Set("Strict-Transport-Security", hstsPolicy)
	}
}
