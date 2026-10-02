// Subresource routing.
//
// S3 selects many operations by a bare query parameter on an ordinary path:
// PUT /b/k?tagging is PutObjectTagging, not PutObject. The dispatchers here
// route on the handful they implement and otherwise fall through to the plain
// object or bucket operation, so an unrecognised subresource used to act on
// the resource itself — PUT ?tagging overwrote the object with the tagging
// XML, DELETE ?tagging deleted the object, DELETE /b?cors deleted the bucket.
//
// unsupportedSubresource closes that gap before dispatch: a request carrying
// any S3 subresource that its level and method do not implement is answered
// 501 NotImplemented and never reaches a handler.

package s3

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
)

// s3Subresources are the query parameters S3 treats as selecting an operation
// rather than parameterising one. Ordinary parameters (prefix, max-keys, x-id,
// response-content-type, …) are not listed and never trigger a rejection.
var s3Subresources = map[string]bool{
	"accelerate": true, "acl": true, "analytics": true, "attributes": true,
	"cors": true, "delete": true, "encryption": true, "intelligent-tiering": true,
	"inventory": true, "legal-hold": true, "lifecycle": true, "location": true,
	"logging": true, "metadataConfiguration": true, "metrics": true,
	"notification": true, "object-lock": true, "ownershipControls": true,
	"partNumber": true, "policy": true, "policyStatus": true,
	"publicAccessBlock": true, "renameObject": true, "replication": true,
	"requestPayment": true, "restore": true, "retention": true, "select": true,
	"session": true, "tagging": true, "torrent": true, "uploadId": true,
	"uploads": true, "versionId": true, "versioning": true, "versions": true,
	"website": true,
}

// level is which kind of resource a request path addresses.
type level uint8

const (
	levelService level = iota
	levelNamespace
	levelObject
)

// implementedSubresources is, per level and method, the subresources the
// dispatchers route. It has to stay in step with serviceDispatch,
// namespaceDispatch and objectDispatch.
var implementedSubresources = map[level]map[string][]string{
	levelNamespace: {
		http.MethodGet:  {"location", "versioning", "uploads"},
		http.MethodPost: {"delete"},
	},
	levelObject: {
		http.MethodPut:    {"partNumber", "uploadId"},
		http.MethodGet:    {"uploadId", "versionId", "tagging"},
		http.MethodHead:   {"versionId"},
		http.MethodPost:   {"uploads", "uploadId"},
		http.MethodDelete: {"uploadId", "versionId"},
	},
}

// unsupportedSubresource returns the first subresource on the request that its
// level and method do not implement, or "" when every one is handled.
//
// versionId is accepted only as "null", which S3 defines as the current
// version of an object in an unversioned bucket — every object here. Any other
// value names a version this store cannot have kept.
func unsupportedSubresource(method string, lvl level, query url.Values) string {
	implemented := implementedSubresources[lvl][method]

	// Sorted so the error names the same parameter on every run.
	for _, name := range slices.Sorted(maps.Keys(query)) {
		if !s3Subresources[name] {
			continue
		}
		if name == "versionId" && query.Get(name) != "null" {
			return name
		}
		if !slices.Contains(implemented, name) {
			return name
		}
	}
	return ""
}
