package s3

import (
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
)

func renderString(t *testing.T, v any) string {
	t.Helper()
	body, err := render(v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return string(body)
}

func TestRenderIncludesProlog(t *testing.T) {
	got := renderString(t, versioningConfiguration{Xmlns: xmlns})
	if !strings.HasPrefix(got, `<?xml version="1.0" encoding="UTF-8"?>`+"\n") {
		t.Errorf("missing XML prolog: %q", got)
	}
	if !strings.Contains(got, `xmlns="`+xmlns+`"`) {
		t.Errorf("missing namespace: %q", got)
	}
}

func TestListAllMyBucketsResult(t *testing.T) {
	got := renderString(t, listAllMyBucketsResult{
		Xmlns: xmlns,
		Owner: owner{ID: "simplecas", DisplayName: "simplecas"},
		Buckets: buckets{Bucket: []bucketEntry{
			{Name: "photos", CreationDate: "2026-09-02T13:04:05.123Z"},
		}},
	})

	for _, want := range []string{
		"<ListAllMyBucketsResult",
		"<Owner><ID>simplecas</ID><DisplayName>simplecas</DisplayName></Owner>",
		"<Buckets><Bucket><Name>photos</Name>",
		"<CreationDate>2026-09-02T13:04:05.123Z</CreationDate>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestListBucketResultOptionalElements(t *testing.T) {
	t.Run("absent optionals are omitted", func(t *testing.T) {
		got := renderString(t, listBucketResult{
			Xmlns:    xmlns,
			Name:     "photos",
			MaxKeys:  1000,
			KeyCount: 0,
		})
		for _, absent := range []string{
			"<Delimiter>", "<ContinuationToken>", "<NextContinuationToken>",
			"<Marker>", "<NextMarker>", "<Contents>", "<CommonPrefixes>",
		} {
			if strings.Contains(got, absent) {
				t.Errorf("unexpected %q in:\n%s", absent, got)
			}
		}
		// IsTruncated is not optional: clients read it on every response.
		if !strings.Contains(got, "<IsTruncated>false</IsTruncated>") {
			t.Errorf("IsTruncated must always be present:\n%s", got)
		}
		// So are MaxKeys and KeyCount, even at zero.
		if !strings.Contains(got, "<KeyCount>0</KeyCount>") {
			t.Errorf("KeyCount must be present even at zero:\n%s", got)
		}
	})

	t.Run("V1 emits an empty Marker rather than omitting it", func(t *testing.T) {
		empty := ""
		got := renderString(t, listBucketResult{Xmlns: xmlns, Name: "photos", Marker: &empty})
		if !strings.Contains(got, "<Marker>") {
			t.Errorf("a present-but-empty Marker must still be emitted:\n%s", got)
		}
	})

	t.Run("populated listing", func(t *testing.T) {
		delim, token := "/", "bmV4dA=="
		got := renderString(t, listBucketResult{
			Xmlns:                 xmlns,
			Name:                  "photos",
			Prefix:                "2024/",
			Delimiter:             &delim,
			MaxKeys:               2,
			KeyCount:              2,
			IsTruncated:           true,
			NextContinuationToken: &token,
			Contents: []contents{{
				Key:          "2024/cat.jpg",
				LastModified: "2026-09-02T13:04:05.123Z",
				ETag:         `"abc"`,
				Size:         42,
				StorageClass: "STANDARD",
			}},
			CommonPrefixes: []commonPrefix{{Prefix: "2024/raw/"}},
		})

		for _, want := range []string{
			"<Delimiter>/</Delimiter>",
			"<IsTruncated>true</IsTruncated>",
			"<NextContinuationToken>bmV4dA==</NextContinuationToken>",
			"<Key>2024/cat.jpg</Key>",
			"<ETag>&#34;abc&#34;</ETag>",
			"<Size>42</Size>",
			"<StorageClass>STANDARD</StorageClass>",
			"<CommonPrefixes><Prefix>2024/raw/</Prefix></CommonPrefixes>",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in:\n%s", want, got)
			}
		}
	})
}

func TestListPartsResultOmitsNextMarkerWhenComplete(t *testing.T) {
	got := renderString(t, listPartsResult{
		Xmlns: xmlns, Bucket: "ns", Key: "k", UploadID: "u",
		MaxParts: 1000,
		Parts:    []partEntry{{PartNumber: 1, ETag: `"abc"`, Size: 5}},
	})
	if strings.Contains(got, "<NextPartNumberMarker>") {
		t.Errorf("NextPartNumberMarker should be omitted when not truncated:\n%s", got)
	}
	if !strings.Contains(got, "<PartNumberMarker>0</PartNumberMarker>") {
		t.Errorf("PartNumberMarker must always be present:\n%s", got)
	}

	next := int32(3)
	got = renderString(t, listPartsResult{
		Xmlns: xmlns, IsTruncated: true, NextPartNumberMarker: &next,
	})
	if !strings.Contains(got, "<NextPartNumberMarker>3</NextPartNumberMarker>") {
		t.Errorf("missing NextPartNumberMarker:\n%s", got)
	}
}

func TestDeleteResultOmitsEmptySections(t *testing.T) {
	got := renderString(t, deleteResult{Xmlns: xmlns})
	if strings.Contains(got, "<Deleted>") || strings.Contains(got, "<Error>") {
		t.Errorf("empty sections should be omitted:\n%s", got)
	}

	got = renderString(t, deleteResult{
		Xmlns:   xmlns,
		Deleted: []deletedEntry{{Key: "a"}},
		Errors:  []deleteErrorEntry{{Key: "b", Code: "NoSuchKey", Message: "gone"}},
	})
	if !strings.Contains(got, "<Deleted><Key>a</Key></Deleted>") {
		t.Errorf("missing Deleted entry:\n%s", got)
	}
	if !strings.Contains(got, "<Error><Key>b</Key><Code>NoSuchKey</Code><Message>gone</Message></Error>") {
		t.Errorf("missing Error entry:\n%s", got)
	}
}

func TestLocationConstraintCarriesTheRegion(t *testing.T) {
	got := renderString(t, locationConstraint{Xmlns: xmlns, Region: "eu-west-1"})
	if !strings.Contains(got, ">eu-west-1</LocationConstraint>") {
		t.Errorf("region should be the element's text:\n%s", got)
	}
}

func TestUnmarshalDeleteRequest(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
		<Delete>
		  <Object><Key>a.txt</Key></Object>
		  <Object><Key>dir/b.txt</Key></Object>
		  <Quiet>true</Quiet>
		</Delete>`)

	var req deleteRequest
	if err := unmarshalXML(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req.Objects) != 2 || req.Objects[0].Key != "a.txt" || req.Objects[1].Key != "dir/b.txt" {
		t.Errorf("objects = %+v", req.Objects)
	}
	if !req.Quiet {
		t.Error("Quiet should have parsed as true")
	}
}

func TestUnmarshalDeleteRequestDefaults(t *testing.T) {
	var req deleteRequest
	if err := unmarshalXML([]byte(`<Delete></Delete>`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req.Objects) != 0 || req.Quiet {
		t.Errorf("empty request = %+v, want no objects and Quiet false", req)
	}
}

func TestUnmarshalCompleteMultipartUpload(t *testing.T) {
	body := []byte(`<CompleteMultipartUpload>
		  <Part><PartNumber>1</PartNumber><ETag>"aaa"</ETag></Part>
		  <Part><PartNumber>2</PartNumber></Part>
		</CompleteMultipartUpload>`)

	var manifest completeMultipartUpload
	if err := unmarshalXML(body, &manifest); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(manifest.Parts) != 2 {
		t.Fatalf("parts = %+v", manifest.Parts)
	}
	if manifest.Parts[0].ETag == nil || *manifest.Parts[0].ETag != `"aaa"` {
		t.Errorf("part 1 etag = %v, want the quoted digest", manifest.Parts[0].ETag)
	}
	// An omitted ETag stays nil, which means "do not check it".
	if manifest.Parts[1].ETag != nil {
		t.Errorf("part 2 etag = %v, want nil", *manifest.Parts[1].ETag)
	}
}

func TestUnmarshalXMLReportsMalformedBodyAsClientError(t *testing.T) {
	var req deleteRequest
	err := unmarshalXML([]byte("<Delete><Object>"), &req)
	if err == nil {
		t.Fatal("expected a parse failure")
	}
	if got := apperr.From(err).Status(); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
}
