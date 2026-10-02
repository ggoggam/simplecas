// Response headers for serving user content.
//
// Objects are served from the same origin as the PWA and its session cookie,
// with whatever Content-Type the uploader declared. Without these headers an
// uploaded text/html or image/svg+xml file is a page that runs script as the
// app: anyone who can get a signed-in user to open a link can act as them.
//
// A separate user-content domain is the complete fix. Until then, every object
// response is defused here:
//
//   - X-Content-Type-Options: nosniff stops a browser from upgrading a benign
//     declared type to an executable one by sniffing the bytes.
//   - Content-Security-Policy: sandbox gives a navigated-to object an opaque
//     origin with scripts disabled, so it can neither run nor reach the
//     session. PDF is exempt: browsers refuse to render a PDF in a sandboxed
//     document, and PDF viewers do not run script in the page's origin.
//   - Content-Disposition: attachment, for every type outside a short list
//     the PWA previews inline, makes a navigation download instead of render.
//     <img>, <video>, <audio> and fetch() ignore it, so previews still work.

package s3

import (
	"mime"
	"net/http"
	"strings"
)

// setContentSafetyHeaders adds the headers above for an object of the given
// declared content type.
func setContentSafetyHeaders(h http.Header, contentType string) {
	h.Set("X-Content-Type-Options", "nosniff")

	mediaType := normalizedMediaType(contentType)
	if mediaType != "application/pdf" {
		h.Set("Content-Security-Policy", "sandbox")
	}
	if !inlineSafe(mediaType) {
		h.Set("Content-Disposition", "attachment")
	}
}

// inlineSafe reports whether a browser can render the media type without
// running script in the document: raster images, audio, video, PDF and plain
// text. SVG and every other XML-based type are excluded, since they can carry
// script.
func inlineSafe(mediaType string) bool {
	switch {
	case mediaType == "application/pdf", mediaType == "text/plain":
		return true
	case strings.HasSuffix(mediaType, "+xml"):
		return false
	case strings.HasPrefix(mediaType, "image/"),
		strings.HasPrefix(mediaType, "video/"),
		strings.HasPrefix(mediaType, "audio/"):
		return true
	default:
		return false
	}
}

// normalizedMediaType lowercases the media type and drops its parameters. An
// unparseable value yields "", which is treated as unsafe.
func normalizedMediaType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return strings.ToLower(mediaType)
}
