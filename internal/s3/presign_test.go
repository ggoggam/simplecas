package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

// These tests presign with the real AWS SDK and then use the URLs the way
// whoever they are handed to would: plain HTTP, with no credentials and only
// the headers the SDK says were signed.

// send issues a presigned request with body, returning the status, the body and
// the response headers.
func send(t *testing.T, req *v4.PresignedHTTPRequest, body string) (int, string, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r, err := http.NewRequestWithContext(t.Context(), req.Method, req.URL, reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range req.SignedHeader {
		if strings.EqualFold(name, "host") {
			continue
		}
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	if body != "" {
		r.ContentLength = int64(len(body))
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(got), resp.Header
}

// wantCode checks a presigned request failed with an S3 error code.
func wantCode(t *testing.T, what string, status int, body string, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || !strings.Contains(body, "<Code>"+code+"</Code>") {
		t.Errorf("%s = %d %s, want %d %s", what, status, body, wantStatus, code)
	}
}

func presignGet(t *testing.T, p *awss3.PresignClient, bucket, key string) *v4.PresignedHTTPRequest {
	t.Helper()
	req, err := p.PresignGetObject(t.Context(), &awss3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		t.Fatalf("presign GET %s/%s: %v", bucket, key, err)
	}
	return req
}

func presignPut(t *testing.T, p *awss3.PresignClient, bucket, key string) *v4.PresignedHTTPRequest {
	t.Helper()
	req, err := p.PresignPutObject(t.Context(), &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		t.Fatalf("presign PUT %s/%s: %v", bucket, key, err)
	}
	return req
}

// A presigned PUT, GET, HEAD and DELETE each do what the same call through the
// SDK would, for someone holding nothing but the URL.
func TestAWSSDKPresignedObjectLifecycle(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String("shared")}); err != nil {
		t.Fatal(err)
	}
	presigner := awss3.NewPresignClient(client, awss3.WithPresignExpires(10*time.Minute))
	const key = "reports/q3 final.txt"

	status, body, _ := send(t, presignPut(t, presigner, "shared", key), "quarterly numbers")
	if status != http.StatusOK {
		t.Fatalf("presigned PUT = %d %s", status, body)
	}

	status, body, header := send(t, presignGet(t, presigner, "shared", key), "")
	if status != http.StatusOK || body != "quarterly numbers" {
		t.Fatalf("presigned GET = %d %q", status, body)
	}
	// Served through the same path as any other download, defused alike.
	if header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("presigned GET served without nosniff: %v", header)
	}

	head, err := presigner.PresignHeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String("shared"), Key: aws.String(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status, _, header := send(t, head, ""); status != http.StatusOK || header.Get("Content-Length") != "17" {
		t.Errorf("presigned HEAD = %d, Content-Length %q", status, header.Get("Content-Length"))
	}

	del, err := presigner.PresignDeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String("shared"), Key: aws.String(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status, body, _ := send(t, del, ""); status != http.StatusNoContent {
		t.Fatalf("presigned DELETE = %d %s", status, body)
	}
	status, body, _ = send(t, presignGet(t, presigner, "shared", key), "")
	wantCode(t, "GET after the presigned DELETE", status, body, http.StatusNotFound, "NoSuchKey")
}

// A presigned URL is good for one request shape: pointed at another object or
// sent with another method, it no longer verifies.
func TestAWSSDKPresignedURLIsBoundToItsRequest(t *testing.T) {
	client := awsClient(t)
	ctx := t.Context()
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String("shared")}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"public.txt", "private.txt"} {
		if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String("shared"), Key: aws.String(key), Body: bytes.NewReader([]byte(key)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	presigner := awss3.NewPresignClient(client)
	get := presignGet(t, presigner, "shared", "public.txt")

	retargeted := *get
	retargeted.URL = strings.Replace(get.URL, "public.txt", "private.txt", 1)
	status, body, _ := send(t, &retargeted, "")
	wantCode(t, "GET retargeted at another key", status, body, http.StatusForbidden, "SignatureDoesNotMatch")

	overwrite := *get
	overwrite.Method = http.MethodPut
	status, body, _ = send(t, &overwrite, "overwritten")
	wantCode(t, "PUT through a GET URL", status, body, http.StatusForbidden, "SignatureDoesNotMatch")

	// Stretching the expiry is editing the signed query.
	u, err := url.Parse(get.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set(amzExpires, "604800")
	u.RawQuery = q.Encode()
	stretched := *get
	stretched.URL = u.String()
	status, body, _ = send(t, &stretched, "")
	wantCode(t, "GET with a stretched expiry", status, body, http.StatusForbidden, "SignatureDoesNotMatch")

	if status, body, _ := send(t, get, ""); status != http.StatusOK || body != "public.txt" {
		t.Errorf("the untouched URL = %d %q", status, body)
	}
}

// A team key's presigned URL carries that key's scope and nothing more: it
// cannot reach another team's bucket, cannot do what the key may not, and
// stops working when the key is deleted.
func TestAWSSDKPresignedURLCarriesTheKeysScope(t *testing.T) {
	gateway, clientA, clientB, tenantA := tenantClients(t)
	ctx := t.Context()
	if _, err := clientB.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("bucket-b"), Key: aws.String("secret.txt"), Body: bytes.NewReader([]byte("b's")),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("bucket-a"), Key: aws.String("ours.txt"), Body: bytes.NewReader([]byte("a's")),
	}); err != nil {
		t.Fatal(err)
	}
	presignerA := awss3.NewPresignClient(clientA)

	status, body, _ := send(t, presignGet(t, presignerA, "bucket-b", "secret.txt"), "")
	wantCode(t, "team A's URL for team B's object", status, body, http.StatusNotFound, "NoSuchBucket")

	own := presignGet(t, presignerA, "bucket-a", "ours.txt")
	if status, body, _ := send(t, own, ""); status != http.StatusOK || body != "a's" {
		t.Fatalf("team A's URL for its own object = %d %q", status, body)
	}

	// A read-only key presigns a PUT happily; the gateway refuses it.
	if _, err := gateway.StoreCredential(ctx, Credential{
		AccessKeyID: "SCASTEAMAREAD", Secret: "team-a-reader", TenantID: tenantA, Description: "reader",
		Permissions: []Permission{PermRead, PermList},
	}); err != nil {
		t.Fatal(err)
	}
	reader := awss3.NewPresignClient(awss3.New(clientA.Options(), func(o *awss3.Options) {
		o.Credentials = aws.NewCredentialsCache(staticCredentials{"SCASTEAMAREAD", "team-a-reader"})
	}))
	status, body, _ = send(t, presignPut(t, reader, "bucket-a", "ours.txt"), "overwritten")
	wantCode(t, "a read-only key's presigned PUT", status, body, http.StatusForbidden, "AccessDenied")
	if status, body, _ := send(t, presignGet(t, reader, "bucket-a", "ours.txt"), ""); status != http.StatusOK || body != "a's" {
		t.Errorf("a read-only key's presigned GET = %d %q", status, body)
	}

	if err := gateway.db.DeleteS3Credential(ctx, tenantA, "SCASTEAMAKEY"); err != nil {
		t.Fatal(err)
	}
	status, body, _ = send(t, own, "")
	wantCode(t, "a URL signed by a deleted key", status, body, http.StatusForbidden, "AccessDenied")
}

// staticCredentials is a credentials provider for one fixed key.
type staticCredentials struct{ id, secret string }

func (c staticCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: c.id, SecretAccessKey: c.secret, Source: "test"}, nil
}
