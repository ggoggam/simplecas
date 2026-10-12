// Package storage is simplecas's blob store: a thin wrapper over
// gocloud.dev/blob that fixes the logical layout and builds the configured
// backend.
//
// The layout is identical on every backend:
//
//	xorbs/<h[0:2]>/<h[2:4]>/<hash> – Xet xorbs of content-defined chunks; immutable
//	blobs/<h[0:2]>/<h[2:4]>/<hash> – whole files stored before chunking
//	staging/<uuid>                 – in-flight uploads and multipart parts
//
// A commit reads the staging file back and writes its new chunks into xorbs,
// each written in one request. Content stored before chunking was promoted
// whole through Bucket.Copy, which every driver implements with the backend's
// own copy operation, and still is when such a blob is revived from zero; that
// path inherits S3's 5GiB single-copy ceiling.
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3v2 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"golang.org/x/oauth2/google"

	"gocloud.dev/blob"
	"gocloud.dev/blob/azureblob"
	"gocloud.dev/blob/fileblob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
	"gocloud.dev/gcp"

	"github.com/ggoggam/simplecas/internal/config"
)

// Bucket is the blob store. It embeds *blob.Bucket, so the full portable API
// (NewWriter, NewRangeReader, Copy, Delete, List, Attributes) is available
// directly on it.
type Bucket struct {
	*blob.Bucket
	// put writes an object in one request where the driver would split it,
	// or is nil where WriteAll already sends one.
	put func(ctx context.Context, key string, data []byte, ifNew bool) error
}

// ErrExists is PutOnce refusing to replace an object.
var ErrExists = errors.New("object already exists")

// PutOnce writes data to key in a single request, which is what object stores
// bill. With ifNew, an object already at key is left as it is and the write
// fails with ErrExists.
//
// The S3 driver hands writes to the AWS transfer manager, which turns any
// object of 16 MiB or more into a multipart upload: three requests (create,
// part, complete) where one PutObject would do. PutOnce calls PutObject
// directly instead. On the other backends a write buffered whole is already
// one request, or a local file.
func (b *Bucket) PutOnce(ctx context.Context, key string, data []byte, ifNew bool) error {
	if b.put != nil {
		return b.put(ctx, key, data, ifNew)
	}
	err := b.WriteAll(ctx, key, data, &blob.WriterOptions{
		BufferSize:  len(data) + 1,
		ContentType: "application/octet-stream",
		IfNotExist:  ifNew,
	})
	if ifNew && gcerrors.Code(err) == gcerrors.FailedPrecondition {
		return ErrExists
	}
	return err
}

// BlobPrefix is the prefix every content-addressed blob lives under, and what
// the orphan sweep lists.
const BlobPrefix = "blobs/"

// XorbPrefix is the prefix every xorb lives under, and what the xorb orphan
// sweep lists.
const XorbPrefix = "xorbs/"

// BlobPath is where the bytes of a whole-file blob live. The two levels of
// two-hex-character fanout keep any single directory small on filesystem
// backends and spread the keyspace on object stores.
func BlobPath(hash string) string { return fanOut(BlobPrefix, hash) }

// XorbPath is where a xorb lives, named by its Xet hash and fanned out as
// BlobPath is.
func XorbPath(hash string) string { return fanOut(XorbPrefix, hash) }

func fanOut(prefix, hash string) string {
	if len(hash) < 4 {
		// Never reachable with a blake3 digest, but a short hash must not
		// panic its way out of a request handler.
		return prefix + hash
	}
	return fmt.Sprintf("%s%s/%s/%s", prefix, hash[0:2], hash[2:4], hash)
}

// HashFromBlobPath is the inverse of BlobPath for a BLAKE3 digest: it returns
// the hash whose bytes live at key, and false for any key BlobPath would not
// have produced from one. Anything else under blobs/ — a backend's temporary
// file, a key written by hand — is not a blob, and the orphan sweep must leave
// it alone rather than guess.
func HashFromBlobPath(key string) (string, bool) { return hashFromPath(key, BlobPath) }

// HashFromXorbPath is HashFromBlobPath for XorbPath.
func HashFromXorbPath(key string) (string, bool) { return hashFromPath(key, XorbPath) }

func hashFromPath(key string, path func(string) string) (string, bool) {
	hash := key[strings.LastIndexByte(key, '/')+1:]
	if len(hash) != 64 || path(hash) != key {
		return "", false
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return hash, true
}

// StagingPrefix is the prefix the staging sweeper lists.
const StagingPrefix = "staging/"

// StagingPath is where an in-flight upload or multipart part is buffered.
func StagingPath(id string) string { return StagingPrefix + id }

// Open builds the configured backend. The caller owns the returned Bucket and
// must Close it.
func Open(ctx context.Context, cfg config.StorageConfig) (*Bucket, error) {
	var (
		bucket *blob.Bucket
		client *s3v2.Client
		err    error
	)
	switch cfg.Backend {
	case "fs":
		bucket, err = openFS(cfg)
	case "s3":
		bucket, client, err = openS3(ctx, cfg)
	case "gcs":
		bucket, err = openGCS(ctx, cfg)
	case "azblob":
		bucket, err = openAzblob(ctx, cfg)
	default:
		// config.Validate rejects this first; belt and braces.
		return nil, fmt.Errorf("unknown storage backend %q", cfg.Backend)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s storage: %w", cfg.Backend, err)
	}

	// For fs the root is the directory itself; everywhere else it is a key
	// prefix. An empty or "/" root means no prefix at all.
	prefix := ""
	if cfg.Backend != "fs" {
		if prefix = keyPrefix(cfg.Root); prefix != "" {
			bucket = blob.PrefixedBucket(bucket, prefix)
		}
	}
	b := &Bucket{Bucket: bucket}
	if client != nil {
		b.put = s3Put(client, cfg.Bucket, prefix)
	}
	return b, nil
}

// s3Put writes an object with one PutObject. The key carries the bucket's
// prefix, which the blob.Bucket adds to every other call.
func s3Put(client *s3v2.Client, bucket, prefix string) func(context.Context, string, []byte, bool) error {
	return func(ctx context.Context, key string, data []byte, ifNew bool) error {
		in := &s3v2.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(prefix + key),
			Body:          bytes.NewReader(data),
			ContentLength: aws.Int64(int64(len(data))),
			ContentType:   aws.String("application/octet-stream"),
		}
		if ifNew {
			in.IfNoneMatch = aws.String("*")
		}
		_, err := client.PutObject(ctx, in)
		var apiErr smithy.APIError
		if ifNew && errors.As(err, &apiErr) && apiErr.ErrorCode() == "PreconditionFailed" {
			return ErrExists
		}
		if err != nil {
			return fmt.Errorf("put %s: %w", key, err)
		}
		return nil
	}
}

// gcsScope is the OAuth scope a GCS service account needs to read and write
// blobs.
const gcsScope = "https://www.googleapis.com/auth/devstorage.read_write"

// keyPrefix normalises a configured root into a key prefix. "/" and "" both
// mean "no prefix", which is what lets the dev stack neutralise the config
// file's fs root by setting the root to "/".
func keyPrefix(root string) string {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" {
		return ""
	}
	return root + "/"
}

// Check verifies the backend is reachable and the credentials work, so a
// misconfigured store fails at startup instead of on the first upload.
func (b *Bucket) Check(ctx context.Context) error {
	ok, err := b.IsAccessible(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("storage backend is not accessible")
	}
	return nil
}

func openFS(cfg config.StorageConfig) (*blob.Bucket, error) {
	root := cfg.Root
	if root == "" {
		root = "./data"
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create %s: %w", root, err)
	}
	return fileblob.OpenBucket(root, &fileblob.Options{
		// MetadataDontWrite suppresses the per-blob ".attrs" sidecars fileblob
		// writes by default. Object metadata lives in Postgres, and sidecars
		// would otherwise show up as extra entries in the staging sweep's
		// listing.
		Metadata: fileblob.MetadataDontWrite,

		// Write temporary files inside the bucket directory rather than in
		// os.TempDir. fileblob finalises a write by renaming its temp file into
		// place, and rename fails with EXDEV across mount points — which is
		// exactly the normal deployment, where the blob directory is a mounted
		// volume and /tmp is the container's own filesystem.
		NoTempDir: true,
	})
}

func openS3(ctx context.Context, cfg config.StorageConfig) (*blob.Bucket, *s3v2.Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	// Explicit keys win; without them the SDK's default chain (instance role,
	// env, shared config) applies.
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("load aws config: %w", err)
	}
	client := s3v2.NewFromConfig(awsCfg, func(o *s3v2.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			// S3-compatible stores (MinIO, RustFS, R2) are addressed
			// path-style; virtual-host addressing needs per-bucket DNS.
			o.UsePathStyle = true
		}
	})
	bucket, err := s3blob.OpenBucket(ctx, client, cfg.Bucket, nil)
	return bucket, client, err
}

func openGCS(ctx context.Context, cfg config.StorageConfig) (*blob.Bucket, error) {
	var (
		creds *google.Credentials
		err   error
	)
	if cfg.CredentialPath != "" {
		data, readErr := os.ReadFile(cfg.CredentialPath)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", cfg.CredentialPath, readErr)
		}
		// Pinning the credential type to a service account both matches what
		// storage.credential_path is documented to hold and avoids the
		// unvalidated-configuration loaders, which will honour an
		// externally-sourced config that names arbitrary token URLs.
		creds, err = google.CredentialsFromJSONWithTypeAndParams(ctx, data,
			google.ServiceAccount,
			google.CredentialsParams{Scopes: []string{gcsScope}})
	} else {
		creds, err = gcp.DefaultCredentials(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("gcs credentials: %w", err)
	}
	client, err := gcp.NewHTTPClient(gcp.DefaultTransport(), gcp.CredentialsTokenSource(creds))
	if err != nil {
		return nil, fmt.Errorf("gcs client: %w", err)
	}
	return gcsblob.OpenBucket(ctx, client, cfg.Bucket, nil)
}

func openAzblob(ctx context.Context, cfg config.StorageConfig) (*blob.Bucket, error) {
	// An explicit account key means shared-key auth against an explicit
	// container URL, which is also how an emulator (Azurite) is reached.
	if cfg.AccountName != "" && cfg.AccountKey != "" {
		cred, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("azblob shared key: %w", err)
		}
		client, err := container.NewClientWithSharedKeyCredential(
			containerURL(cfg), cred, nil,
		)
		if err != nil {
			return nil, fmt.Errorf("azblob container client: %w", err)
		}
		return azureblob.OpenBucket(ctx, client, nil)
	}

	// Otherwise fall back to the driver's ambient credential handling
	// (AZURE_STORAGE_* environment, managed identity).
	svcURL, err := azureblob.NewServiceURL(&azureblob.ServiceURLOptions{
		AccountName: cfg.AccountName,
	})
	if err != nil {
		return nil, fmt.Errorf("azblob service url: %w", err)
	}
	client, err := azureblob.NewDefaultClient(svcURL, azureblob.ContainerName(cfg.Container))
	if err != nil {
		return nil, fmt.Errorf("azblob default client: %w", err)
	}
	return azureblob.OpenBucket(ctx, client, nil)
}

// containerURL builds the container endpoint, honouring a configured endpoint
// (an emulator or a non-public Azure cloud) over the default service domain.
func containerURL(cfg config.StorageConfig) string {
	base := strings.TrimSuffix(cfg.Endpoint, "/")
	if base == "" {
		base = fmt.Sprintf("https://%s.blob.core.windows.net", cfg.AccountName)
	}
	return base + "/" + cfg.Container
}
