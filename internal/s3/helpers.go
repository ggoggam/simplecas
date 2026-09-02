package s3

import (
	"encoding/xml"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/db"
)

// unmarshalXML parses a request body, reporting a parse failure as MalformedXML
// so the client sees a 400 rather than a 500.
func unmarshalXML(raw []byte, v any) error {
	if err := xml.Unmarshal(raw, v); err != nil {
		return apperr.MalformedXML("%v", err)
	}
	return nil
}

// encodeToken and decodeToken wrap the shared marker encoding, so V2
// continuation tokens stay opaque to clients.
func encodeToken(marker string) string { return db.EncodeMarker(marker) }

func decodeToken(token string) (string, error) { return db.DecodeMarker(token) }

// resolveManifest adapts the XML completion manifest to the shared validator.
func resolveManifest(requested []completePart, stored []db.PartMeta) ([]db.PartMeta, error) {
	parts := make([]cas.ManifestPart, 0, len(requested))
	for _, p := range requested {
		parts = append(parts, cas.ManifestPart{PartNumber: p.PartNumber, ETag: p.ETag})
	}
	return cas.ResolveManifest(parts, stored)
}
