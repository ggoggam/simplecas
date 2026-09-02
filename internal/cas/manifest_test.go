package cas

import (
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
)

func TestResolveManifest(t *testing.T) {
	stored := []db.PartMeta{
		{PartNumber: 1, StagingKey: "staging/a", Size: 2, ETag: "aaa"},
		{PartNumber: 2, StagingKey: "staging/b", Size: 1, ETag: "bbb"},
		{PartNumber: 5, StagingKey: "staging/e", Size: 4, ETag: "eee"},
	}
	etag := func(s string) *string { return &s }

	t.Run("orders by the manifest and returns the staged parts", func(t *testing.T) {
		got, err := ResolveManifest([]ManifestPart{
			{PartNumber: 1}, {PartNumber: 5},
		}, stored)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d parts, want 2", len(got))
		}
		// The staged record wins, not whatever the client claimed.
		if got[0].StagingKey != "staging/a" || got[1].StagingKey != "staging/e" {
			t.Errorf("parts = %+v", got)
		}
		if got[1].Size != 4 || got[1].ETag != "eee" {
			t.Errorf("part 5 = %+v, want the stored metadata", got[1])
		}
	})

	t.Run("gaps in part numbers are fine", func(t *testing.T) {
		if _, err := ResolveManifest([]ManifestPart{{PartNumber: 2}, {PartNumber: 5}}, stored); err != nil {
			t.Errorf("a manifest may skip staged parts: %v", err)
		}
	})

	t.Run("matching etags pass, quoted or bare", func(t *testing.T) {
		for _, tag := range []string{"aaa", `"aaa"`} {
			if _, err := ResolveManifest([]ManifestPart{{PartNumber: 1, ETag: etag(tag)}}, stored); err != nil {
				t.Errorf("etag %q should match: %v", tag, err)
			}
		}
	})

	tests := []struct {
		name      string
		requested []ManifestPart
	}{
		{"empty manifest", nil},
		{"part never uploaded", []ManifestPart{{PartNumber: 3}}},
		{"descending part numbers", []ManifestPart{{PartNumber: 2}, {PartNumber: 1}}},
		{"repeated part number", []ManifestPart{{PartNumber: 1}, {PartNumber: 1}}},
		{"etag mismatch", []ManifestPart{{PartNumber: 1, ETag: etag("wrong")}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveManifest(tc.requested, stored)
			if err == nil {
				t.Fatal("expected a validation failure")
			}
			e := apperr.From(err)
			if e.S3Code() != "InvalidPart" {
				t.Errorf("code = %q, want InvalidPart", e.S3Code())
			}
			if e.Status() != 400 {
				t.Errorf("status = %d, want 400", e.Status())
			}
		})
	}
}
