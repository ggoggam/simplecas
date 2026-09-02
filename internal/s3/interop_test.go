package s3

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/ggoggam/simplecas/internal/config"
)

// These tests drive the gateway with the real AWS SDK, so the hand-written
// SigV4 verification is checked against an actual signing implementation rather
// than only against the published test vector.

const (
	interopKeyID  = "AKIAIOSFODNN7EXAMPLE"
	interopSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// awsClient starts the gateway with SigV4 required and returns a signing client
// pointed at it.
func awsClient(t *testing.T) *awss3.Client {
	t.Helper()
	gateway := newGateway(t)
	gateway.cfg.Auth = config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     interopKeyID,
		SecretAccessKey: interopSecret,
	}

	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)

	cfg, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(interopKeyID, interopSecret, ""),
		),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	return awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(server.URL)
		// The gateway is path-style only; virtual-host addressing would need
		// per-bucket DNS.
		o.UsePathStyle = true
	})
}

// A wrong secret must be rejected, which proves the signature is genuinely
// being checked rather than waved through.
func TestAWSSDKRejectsAWrongSecret(t *testing.T) {
	gateway := newGateway(t)
	gateway.cfg.Auth = config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     interopKeyID,
		SecretAccessKey: interopSecret,
	}
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)

	cfg, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(interopKeyID, "the-wrong-secret", ""),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(server.URL)
		o.UsePathStyle = true
	})

	_, err = client.CreateBucket(t.Context(), &awss3.CreateBucketInput{
		Bucket: aws.String("photos"),
	})
	if err == nil {
		t.Fatal("a request signed with the wrong secret was accepted")
	}
	if !containsAny(err.Error(), "SignatureDoesNotMatch", "403", "Forbidden") {
		t.Errorf("err = %v, want a signature rejection", err)
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if bytes.Contains([]byte(s), []byte(n)) {
			return true
		}
	}
	return false
}

// The core object lifecycle, driven entirely by the SDK.
func TestAWSSDKObjectLifecycle(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("photos"),
	}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	buckets, err := client.ListBuckets(ctx, &awss3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets.Buckets) != 1 || aws.ToString(buckets.Buckets[0].Name) != "photos" {
		t.Errorf("buckets = %+v", buckets.Buckets)
	}

	put, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:      aws.String("photos"),
		Key:         aws.String("cat.txt"),
		Body:        bytes.NewReader([]byte("abc")),
		ContentType: aws.String("text/plain"),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if got := aws.ToString(put.ETag); got != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want the content hash", got)
	}

	// The bytes must round-trip exactly. If the SDK framed the body (aws-chunked
	// transfer encoding) and the server stored it verbatim, this is where it
	// would show up as a length and content mismatch.
	get, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("photos"),
		Key:    aws.String("cat.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "abc" {
		t.Errorf("body = %q, want %q", body, "abc")
	}
	if aws.ToInt64(get.ContentLength) != 3 {
		t.Errorf("ContentLength = %d, want 3", aws.ToInt64(get.ContentLength))
	}
	if got := aws.ToString(get.ContentType); got != "text/plain" {
		t.Errorf("ContentType = %q", got)
	}

	head, err := client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String("photos"),
		Key:    aws.String("cat.txt"),
	})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if aws.ToInt64(head.ContentLength) != 3 {
		t.Errorf("HeadObject ContentLength = %d, want 3", aws.ToInt64(head.ContentLength))
	}

	// A range GET, which the SDK signs with the Range header included.
	ranged, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("photos"),
		Key:    aws.String("cat.txt"),
		Range:  aws.String("bytes=1-2"),
	})
	if err != nil {
		t.Fatalf("ranged GetObject: %v", err)
	}
	rangedBody, _ := io.ReadAll(ranged.Body)
	_ = ranged.Body.Close()
	if string(rangedBody) != "bc" {
		t.Errorf("ranged body = %q, want %q", rangedBody, "bc")
	}

	if _, err := client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String("photos"),
		Key:    aws.String("cat.txt"),
	}); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	var missing *types.NoSuchKey
	_, err = client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("photos"),
		Key:    aws.String("cat.txt"),
	})
	if !errors.As(err, &missing) {
		t.Errorf("err = %v, want the SDK to decode NoSuchKey", err)
	}
}

// Listing with a prefix and delimiter is where query-string canonicalisation in
// the signature matters most.
func TestAWSSDKListObjectsV2(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("photos"),
	}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"a.txt", "2024/one.jpg", "2024/two.jpg", "z.txt"} {
		if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String("photos"),
			Key:    aws.String(key),
			Body:   bytes.NewReader([]byte("abc")),
		}); err != nil {
			t.Fatalf("PutObject %s: %v", key, err)
		}
	}

	grouped, err := client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket:    aws.String("photos"),
		Delimiter: aws.String("/"),
	})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	if len(grouped.Contents) != 2 {
		t.Errorf("contents = %d, want 2", len(grouped.Contents))
	}
	if len(grouped.CommonPrefixes) != 1 ||
		aws.ToString(grouped.CommonPrefixes[0].Prefix) != "2024/" {
		t.Errorf("common prefixes = %+v", grouped.CommonPrefixes)
	}
	if aws.ToInt32(grouped.KeyCount) != 3 {
		t.Errorf("KeyCount = %d, want 3", aws.ToInt32(grouped.KeyCount))
	}

	// Paginate, which exercises the continuation token round trip through a
	// real client.
	pager := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket:  aws.String("photos"),
		MaxKeys: aws.Int32(2),
	})
	var seen []string
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("NextPage: %v", err)
		}
		for _, o := range page.Contents {
			seen = append(seen, aws.ToString(o.Key))
		}
	}
	want := []string{"2024/one.jpg", "2024/two.jpg", "a.txt", "z.txt"}
	if len(seen) != len(want) {
		t.Fatalf("paged through %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("page order = %v, want %v", seen, want)
			break
		}
	}
}

// The SDK's own multipart manifest and part signing, end to end.
func TestAWSSDKMultipart(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("files"),
	}); err != nil {
		t.Fatal(err)
	}

	created, err := client.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket:      aws.String("files"),
		Key:         aws.String("big.txt"),
		ContentType: aws.String("text/plain"),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	uploadID := created.UploadId

	var completed []types.CompletedPart
	for i, chunk := range []string{"ab", "c"} {
		partNumber := int32(i + 1)
		uploaded, err := client.UploadPart(ctx, &awss3.UploadPartInput{
			Bucket:     aws.String("files"),
			Key:        aws.String("big.txt"),
			UploadId:   uploadID,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader([]byte(chunk)),
		})
		if err != nil {
			t.Fatalf("UploadPart %d: %v", partNumber, err)
		}
		completed = append(completed, types.CompletedPart{
			ETag:       uploaded.ETag,
			PartNumber: aws.Int32(partNumber),
		})
	}

	listed, err := client.ListParts(ctx, &awss3.ListPartsInput{
		Bucket:   aws.String("files"),
		Key:      aws.String("big.txt"),
		UploadId: uploadID,
	})
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	if len(listed.Parts) != 2 {
		t.Errorf("parts = %+v", listed.Parts)
	}

	uploads, err := client.ListMultipartUploads(ctx, &awss3.ListMultipartUploadsInput{
		Bucket: aws.String("files"),
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(uploads.Uploads) != 1 {
		t.Errorf("uploads = %+v", uploads.Uploads)
	}

	done, err := client.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket:          aws.String("files"),
		Key:             aws.String("big.txt"),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	// The assembled object hashes as the whole content, so it dedups against a
	// single-shot upload of the same bytes.
	if got := aws.ToString(done.ETag); got != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want %s", got, `"`+abcHash+`"`)
	}

	get, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("files"),
		Key:    aws.String("big.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, _ := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if string(body) != "abc" {
		t.Errorf("assembled body = %q, want abc", body)
	}
}

func TestAWSSDKCopyAndBatchDelete(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()

	for _, name := range []string{"src", "dst"} {
		if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
			Bucket: aws.String(name),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("src"), Key: aws.String("orig.txt"),
		Body: bytes.NewReader([]byte("abc")),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CopyObject(ctx, &awss3.CopyObjectInput{
		Bucket:     aws.String("dst"),
		Key:        aws.String("copy.txt"),
		CopySource: aws.String("src/orig.txt"),
	}); err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	get, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("dst"), Key: aws.String("copy.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject after copy: %v", err)
	}
	body, _ := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if string(body) != "abc" {
		t.Errorf("copied body = %q", body)
	}

	deleted, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
		Bucket: aws.String("dst"),
		Delete: &types.Delete{Objects: []types.ObjectIdentifier{
			{Key: aws.String("copy.txt")},
			{Key: aws.String("never-existed.txt")},
		}},
	})
	if err != nil {
		t.Fatalf("DeleteObjects: %v", err)
	}
	if len(deleted.Errors) != 0 {
		t.Errorf("errors = %+v", deleted.Errors)
	}
	if len(deleted.Deleted) != 2 {
		t.Errorf("deleted = %+v, want both keys reported", deleted.Deleted)
	}
}

// Bucket-level operations the SDK exposes separately.
func TestAWSSDKBucketOperations(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("photos"),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := client.HeadBucket(ctx, &awss3.HeadBucketInput{
		Bucket: aws.String("photos"),
	}); err != nil {
		t.Errorf("HeadBucket: %v", err)
	}

	location, err := client.GetBucketLocation(ctx, &awss3.GetBucketLocationInput{
		Bucket: aws.String("photos"),
	})
	if err != nil {
		t.Fatalf("GetBucketLocation: %v", err)
	}
	if got := string(location.LocationConstraint); got != "us-east-1" {
		t.Errorf("LocationConstraint = %q, want us-east-1", got)
	}

	if _, err := client.DeleteBucket(ctx, &awss3.DeleteBucketInput{
		Bucket: aws.String("photos"),
	}); err != nil {
		t.Errorf("DeleteBucket: %v", err)
	}
}
