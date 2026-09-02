// Package storage is simplecas's blob store: a thin wrapper over
// gocloud.dev/blob that fixes the logical layout and builds the configured
// backend.
//
// The layout is identical on every backend:
//
//	blobs/<h[0:2]>/<h[2:4]>/<hash>  – content-addressed, immutable
//	staging/<uuid>                  – in-flight uploads and multipart parts
//
// Promoting a staged upload to its content-addressed home goes through
// Bucket.Copy, which every driver implements with the backend's own copy
// operation (S3 CopyObject, the GCS copier, Azure's copy API, a local file copy
// for fs) — so the bytes never travel back through the server. The one limit
// inherited from the drivers is S3's 5GiB single-copy ceiling, the same ceiling
// the previous OpenDAL-based implementation had.
package storage

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3v2 "github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/oauth2/google"

	"gocloud.dev/blob"
	"gocloud.dev/blob/azureblob"
	"gocloud.dev/blob/fileblob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcp"

	"github.com/ggoggam/simplecas/internal/config"
)

// Bucket is the blob store. It embeds *blob.Bucket, so the full portable API
// (NewWriter, NewRangeReader, Copy, Delete, List, Attributes) is available
// directly on it.
type Bucket struct {
	*blob.Bucket
}

// BlobPath is where the bytes for a content hash live. The two levels of
// two-hex-character fanout keep any single directory small on filesystem
// backends and spread the keyspace on object stores.
func BlobPath(hash string) string {
	if len(hash) < 4 {
		// Never reachable with a blake3 digest, but a short hash must not
		// panic its way out of a request handler.
		return "blobs/" + hash
	}
	return fmt.Sprintf("blobs/%s/%s/%s", hash[0:2], hash[2:4], hash)
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
		err    error
	)
	switch cfg.Backend {
	case "fs":
		bucket, err = openFS(cfg)
	case "s3":
		bucket, err = openS3(ctx, cfg)
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
	if cfg.Backend != "fs" {
		if prefix := keyPrefix(cfg.Root); prefix != "" {
			bucket = blob.PrefixedBucket(bucket, prefix)
		}
	}
	return &Bucket{Bucket: bucket}, nil
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

func openS3(ctx context.Context, cfg config.StorageConfig) (*blob.Bucket, error) {
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
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := s3v2.NewFromConfig(awsCfg, func(o *s3v2.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			// S3-compatible stores (MinIO, RustFS, R2) are addressed
			// path-style; virtual-host addressing needs per-bucket DNS.
			o.UsePathStyle = true
		}
	})
	return s3blob.OpenBucket(ctx, client, cfg.Bucket, nil)
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
