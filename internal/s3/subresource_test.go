package s3

import (
	"net/http"
	"net/url"
	"testing"
)

func TestUnsupportedSubresource(t *testing.T) {
	tests := []struct {
		name   string
		method string
		level  level
		query  string
		want   string
	}{
		// Implemented operations pass.
		{"plain object PUT", http.MethodPut, levelObject, "", ""},
		{"upload part", http.MethodPut, levelObject, "partNumber=1&uploadId=u", ""},
		{"list parts", http.MethodGet, levelObject, "uploadId=u&max-parts=10", ""},
		{"initiate multipart", http.MethodPost, levelObject, "uploads", ""},
		{"abort multipart", http.MethodDelete, levelObject, "uploadId=u", ""},
		{"bucket location", http.MethodGet, levelNamespace, "location", ""},
		{"list uploads", http.MethodGet, levelNamespace, "uploads&prefix=a", ""},
		{"batch delete", http.MethodPost, levelNamespace, "delete", ""},
		{"listing parameters are not subresources", http.MethodGet, levelNamespace, "list-type=2&prefix=a&max-keys=5", ""},
		{"SDK operation hints are ignored", http.MethodPut, levelObject, "x-id=PutObject", ""},
		{"the null version is the current object", http.MethodGet, levelObject, "versionId=null", ""},

		// The review's reported cases: each used to act on the resource.
		{"PUT ?tagging overwrote the object", http.MethodPut, levelObject, "tagging", "tagging"},
		{"DELETE ?tagging deleted the object", http.MethodDelete, levelObject, "tagging", "tagging"},
		{"DELETE ?cors deleted the bucket", http.MethodDelete, levelNamespace, "cors", "cors"},
		{"PUT ?versioning created the bucket", http.MethodPut, levelNamespace, "versioning", "versioning"},

		// Implemented subresources only on their own method.
		{"POST ?delete is bucket-level only", http.MethodPost, levelObject, "delete", "delete"},
		{"GET ?partNumber is not implemented", http.MethodGet, levelObject, "partNumber=1", "partNumber"},
		{"a real version id", http.MethodGet, levelObject, "versionId=3HL4kqtJlcpXroDTDmJ", "versionId"},
		{"service-level subresource", http.MethodGet, levelService, "acl", "acl"},
		{"object acl", http.MethodGet, levelObject, "acl", "acl"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			query, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if got := unsupportedSubresource(tc.method, tc.level, query); got != tc.want {
				t.Errorf("unsupportedSubresource(%s %q) = %q, want %q", tc.method, tc.query, got, tc.want)
			}
		})
	}
}
