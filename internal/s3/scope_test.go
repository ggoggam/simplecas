package s3

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// mustScopedCredential mints a team key with a scope, the way the API does.
func mustScopedCredential(t *testing.T, f *tenantFixture, tenantID int64, label string, perms []Permission, namespaces []string) (id, secret string) {
	t.Helper()
	id = "SCASTESTKEY" + strings.ToUpper(strings.ReplaceAll(label, "-", ""))
	secret = "secret-for-" + label
	_, err := f.g.StoreCredential(t.Context(), Credential{
		AccessKeyID: id, Secret: secret, TenantID: tenantID, Description: label,
		Permissions: perms, Namespaces: namespaces,
	})
	if err != nil {
		t.Fatalf("create credential %s: %v", label, err)
	}
	return id, secret
}

// The zero principal can do nothing: a principal is only as capable as the
// code that built it said, never capable by default.
func TestZeroPrincipalAllowsNothing(t *testing.T) {
	all := []action{actionLocate, actionRead, actionList, actionWrite, actionDelete,
		actionCreateNamespace, actionDeleteNamespace}
	for _, a := range all {
		if (principal{}).allows(a) {
			t.Errorf("the zero principal may %s", a)
		}
		if !adminPrincipal().allows(a) {
			t.Errorf("the admin may not %s", a)
		}
	}
}

func TestReadOnlyKeyCannotChangeAnything(t *testing.T) {
	f := newTenantFixture(t)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-a/kept.txt", "abc"), http.StatusOK, "")
	id, secret := mustScopedCredential(t, f, f.tenantA, "reader", []Permission{PermRead, PermList}, nil)
	as := func(method, target, body string) int {
		return f.signed(t, id, secret, method, target, body).Code
	}

	if code := as(http.MethodGet, "/ns-a/kept.txt", ""); code != http.StatusOK {
		t.Errorf("read-only GetObject = %d, want 200", code)
	}
	if code := as(http.MethodGet, "/ns-a/?list-type=2", ""); code != http.StatusOK {
		t.Errorf("read-only ListObjects = %d, want 200", code)
	}
	for _, tc := range []struct {
		name, method, target, body string
	}{
		{"PutObject", http.MethodPut, "/ns-a/new.txt", "xyz"},
		{"overwrite", http.MethodPut, "/ns-a/kept.txt", "xyz"},
		{"CopyObject", http.MethodPut, "/ns-a/copy.txt", ""},
		{"DeleteObject", http.MethodDelete, "/ns-a/kept.txt", ""},
		{"DeleteObjects", http.MethodPost, "/ns-a/?delete", `<Delete><Object><Key>kept.txt</Key></Object></Delete>`},
		{"InitiateMultipart", http.MethodPost, "/ns-a/big.bin?uploads", ""},
		{"CreateBucket", http.MethodPut, "/ns-new/", ""},
		{"DeleteBucket", http.MethodDelete, "/ns-a/", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var headers []string
			if tc.name == "CopyObject" {
				headers = []string{"x-amz-copy-source", "/ns-a/kept.txt"}
			}
			mustCode(t, f.signed(t, id, secret, tc.method, tc.target, tc.body, headers...), http.StatusForbidden, "AccessDenied")
		})
	}

	if w := f.asA(t, http.MethodGet, "/ns-a/kept.txt", ""); w.Body.String() != "abc" {
		t.Fatalf("a read-only key changed the object to %q", w.Body.String())
	}
	if w := f.asAdmin(t, http.MethodHead, "/ns-new/", ""); w.Code != http.StatusNotFound {
		t.Fatalf("a read-only key created a bucket: HeadBucket = %d", w.Code)
	}
}

// A key that may only write can upload, by either route, and still not read
// back, list or delete what is there: an uploader from CI need not be able to
// exfiltrate the namespace.
func TestWriteOnlyKeyCannotReadListOrDelete(t *testing.T) {
	f := newTenantFixture(t)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-a/kept.txt", "abc"), http.StatusOK, "")
	id, secret := mustScopedCredential(t, f, f.tenantA, "writer", []Permission{PermWrite}, nil)

	mustCode(t, f.signed(t, id, secret, http.MethodPut, "/ns-a/upload.txt", "xyz"), http.StatusOK, "")

	var initiated initiateMultipartUploadResult
	decode(t, f.signed(t, id, secret, http.MethodPost, "/ns-a/big.bin?uploads", ""), &initiated)
	uploadQuery := "?uploadId=" + initiated.UploadID
	mustCode(t, f.signed(t, id, secret, http.MethodPut, "/ns-a/big.bin"+uploadQuery+"&partNumber=1", "part"), http.StatusOK, "")
	// Listing an upload's parts is listing, which this key may not do;
	// aborting its own upload is part of writing, which it may.
	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a/big.bin"+uploadQuery, ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodDelete, "/ns-a/big.bin"+uploadQuery, ""), http.StatusNoContent, "")

	// Locating the bucket needs no particular permission; the AWS CLI asks
	// before it uploads.
	mustCode(t, f.signed(t, id, secret, http.MethodHead, "/ns-a/", ""), http.StatusOK, "")

	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a/kept.txt", ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodHead, "/ns-a/kept.txt", ""), http.StatusForbidden, "")
	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a/kept.txt?tagging", ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a/?list-type=2", ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a/?uploads", ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodDelete, "/ns-a/kept.txt", ""), http.StatusForbidden, "AccessDenied")
}

// A key limited to some of its team's namespaces treats the rest the way it
// treats another team's: as missing. It cannot add or remove namespaces, since
// it could not reach one it created.
func TestNamespaceLimitedKey(t *testing.T) {
	f := newTenantFixture(t)
	mustCreateNamespace(t, f.g.db, "ns-a2", &f.tenantA)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-a/kept.txt", "abc"), http.StatusOK, "")
	id, secret := mustScopedCredential(t, f, f.tenantA, "limited", nil, []string{"ns-a2"})

	var listing listAllMyBucketsResult
	decode(t, f.signed(t, id, secret, http.MethodGet, "/", ""), &listing)
	if len(listing.Buckets.Bucket) != 1 || listing.Buckets.Bucket[0].Name != "ns-a2" {
		t.Fatalf("limited key lists %+v, want only ns-a2", listing.Buckets.Bucket)
	}

	mustCode(t, f.signed(t, id, secret, http.MethodPut, "/ns-a2/in.txt", "xyz"), http.StatusOK, "")
	mustCode(t, f.signed(t, id, secret, http.MethodGet, "/ns-a2/in.txt", ""), http.StatusOK, "")

	for _, tc := range []struct {
		name, method, target, body string
	}{
		{"HeadBucket", http.MethodHead, "/ns-a/", ""},
		{"GetBucketLocation", http.MethodGet, "/ns-a/?location", ""},
		{"ListObjects", http.MethodGet, "/ns-a/?list-type=2", ""},
		{"GetObject", http.MethodGet, "/ns-a/kept.txt", ""},
		{"PutObject", http.MethodPut, "/ns-a/planted.txt", "xyz"},
		{"DeleteObject", http.MethodDelete, "/ns-a/kept.txt", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := f.signed(t, id, secret, tc.method, tc.target, tc.body); w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
			}
		})
	}

	// Copying out of a namespace it does not reach fails as that namespace
	// missing, so copy is no way around the limit.
	mustCode(t, f.signed(t, id, secret, http.MethodPut, "/ns-a2/stolen.txt", "",
		"x-amz-copy-source", "/ns-a/kept.txt"), http.StatusNotFound, "NoSuchBucket")

	mustCode(t, f.signed(t, id, secret, http.MethodPut, "/ns-a3/", ""), http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, id, secret, http.MethodDelete, "/ns-a2/", ""), http.StatusForbidden, "AccessDenied")
}

// CopyObject reads its source and writes its destination, and needs both.
func TestCopyNeedsReadAndWrite(t *testing.T) {
	f := newTenantFixture(t)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-a/src.txt", "abc"), http.StatusOK, "")
	writer, writerSecret := mustScopedCredential(t, f, f.tenantA, "writer", []Permission{PermWrite}, nil)
	both, bothSecret := mustScopedCredential(t, f, f.tenantA, "both", []Permission{PermRead, PermWrite}, nil)
	source := []string{"x-amz-copy-source", "/ns-a/src.txt"}

	mustCode(t, f.signed(t, writer, writerSecret, http.MethodPut, "/ns-a/dst.txt", "", source...),
		http.StatusForbidden, "AccessDenied")
	mustCode(t, f.signed(t, both, bothSecret, http.MethodPut, "/ns-a/dst.txt", "", source...),
		http.StatusOK, "")
}

// A key minted for the whole team still reaches namespaces made after it.
func TestUnlimitedKeyReachesNewNamespaces(t *testing.T) {
	f := newTenantFixture(t)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-later/", ""), http.StatusOK, "")
	mustCode(t, f.asA(t, http.MethodPut, "/ns-later/x.txt", "abc"), http.StatusOK, "")
}

func TestStoreCredentialChecksTheScope(t *testing.T) {
	f := newTenantFixture(t)
	mustCreateNamespace(t, f.g.db, "ns-a2", &f.tenantA)

	scope, err := f.g.StoreCredential(t.Context(), Credential{
		AccessKeyID: "SCASNORMAL", Secret: "s", TenantID: f.tenantA,
		Permissions: []Permission{PermWrite, PermRead, PermWrite},
		Namespaces:  []string{"ns-a2", "ns-a", "ns-a2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(scope.Permissions, []string{"read", "write"}) || !slices.Equal(scope.Namespaces, []string{"ns-a", "ns-a2"}) {
		t.Errorf("stored scope %+v, want read+write on ns-a, ns-a2", scope)
	}
	full, err := f.g.StoreCredential(t.Context(), Credential{AccessKeyID: "SCASFULL", Secret: "s", TenantID: f.tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(full.Permissions, []string{"read", "list", "write", "delete"}) || full.Namespaces != nil {
		t.Errorf("unscoped key stored as %+v, want every permission on every namespace", full)
	}

	for name, c := range map[string]Credential{
		"no permissions":          {Permissions: []Permission{}},
		"unknown permission":      {Permissions: []Permission{"admin"}},
		"no namespaces":           {Namespaces: []string{}},
		"another team's":          {Namespaces: []string{"ns-b"}},
		"a namespace not there":   {Namespaces: []string{"ns-missing"}},
		"one good, one not there": {Namespaces: []string{"ns-a", "ns-missing"}},
	} {
		c.AccessKeyID, c.Secret, c.TenantID = "SCASBAD", "s", f.tenantA
		_, err := f.g.StoreCredential(t.Context(), c)
		var e *apperr.Error
		if !errors.As(err, &e) || e.Kind != apperr.KindInvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	if _, ok, _ := f.g.db.LookupS3Credential(t.Context(), "SCASBAD"); ok {
		t.Error("a key with a bad scope was stored")
	}
}
