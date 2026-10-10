// Package testblob gives each test its own blob store.
//
// By default that is a scratch directory on the fs backend. When
// SIMPLECAS_TEST_S3_URL names an S3-compatible store (RustFS in CI), it is a
// scratch key prefix in that store's bucket instead, so the same suites that
// run on fs also run on the s3 backend: S3 CopyObject for promotion, listings
// with real modification times for the sweepers, ranged GETs, and the
// eventual 404s of an object store rather than a filesystem's.
//
// Each test gets a fresh prefix, emptied when it finishes, so tests across
// packages share one bucket without seeing each other's keys — the same
// arrangement testdb makes with one schema per test.
//
// It imports testing because it is only ever used from tests; nothing in the
// server binary references it.
package testblob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/storage"
)

// EnvVar names the S3 store the tests run against, as
// http://ACCESS_KEY:SECRET@host:port/bucket. When it is unset, tests use the fs
// backend and the S3-only tests skip.
const EnvVar = "SIMPLECAS_TEST_S3_URL"

// region is what the tests sign for. RustFS and MinIO accept any region;
// us-east-1 is what an S3 client assumes when it is told nothing.
const region = "us-east-1"

// Target is the S3 store EnvVar names.
type Target struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
}

// S3 returns the store EnvVar names, and false when it is unset.
func S3(t *testing.T) (Target, bool) {
	t.Helper()
	raw := os.Getenv(EnvVar)
	if raw == "" {
		return Target{}, false
	}
	target, err := parse(raw)
	if err != nil {
		t.Fatalf("%s: %v", EnvVar, err)
	}
	return target, true
}

func parse(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("scheme %q: want http or https", u.Scheme)
	}
	secret, _ := u.User.Password()
	target := Target{
		Endpoint:        u.Scheme + "://" + u.Host,
		Bucket:          strings.Trim(u.Path, "/"),
		AccessKeyID:     u.User.Username(),
		SecretAccessKey: secret,
	}
	if target.Bucket == "" || strings.Contains(target.Bucket, "/") {
		return Target{}, fmt.Errorf("path %q: want exactly one bucket name", u.Path)
	}
	if target.AccessKeyID == "" || target.SecretAccessKey == "" {
		return Target{}, errors.New("want ACCESS_KEY:SECRET@ before the host")
	}
	return target, nil
}

// Client is an SDK client for the store, path-style as S3-compatible stores
// are addressed.
func (target Target) Client() *awss3.Client {
	return awss3.New(awss3.Options{
		Region:       region,
		BaseEndpoint: aws.String(target.Endpoint),
		UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(
			target.AccessKeyID, target.SecretAccessKey, ""),
	})
}

// Open returns a scratch bucket: a prefix in the S3 store when EnvVar is set,
// otherwise a temporary directory.
func Open(t *testing.T) *storage.Bucket {
	t.Helper()
	if _, ok := S3(t); ok {
		return OpenS3(t)
	}
	return open(t, config.StorageConfig{Backend: "fs", Root: t.TempDir()})
}

// OpenS3 returns a scratch prefix in the S3 store, and skips the test when
// EnvVar is unset.
func OpenS3(t *testing.T) *storage.Bucket {
	t.Helper()
	target, ok := S3(t)
	if !ok {
		t.Skipf("set %s to run the S3 backend tests", EnvVar)
	}
	if err := ensureBucket(target); err != nil {
		t.Fatalf("create bucket %s: %v", target.Bucket, err)
	}

	bucket := open(t, config.StorageConfig{
		Backend:         "s3",
		Bucket:          target.Bucket,
		Region:          region,
		Endpoint:        target.Endpoint,
		AccessKeyID:     target.AccessKeyID,
		SecretAccessKey: target.SecretAccessKey,
		Root:            "test-" + randomSuffix(t),
	})
	// Registered after open's Close, so it runs first: empty the prefix while
	// the bucket is still open.
	t.Cleanup(func() {
		if err := empty(context.Background(), bucket); err != nil {
			t.Logf("could not empty the test prefix: %v", err)
		}
	})
	return bucket
}

func open(t *testing.T, cfg config.StorageConfig) *storage.Bucket {
	t.Helper()
	bucket, err := storage.Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open %s bucket: %v", cfg.Backend, err)
	}
	t.Cleanup(func() { _ = bucket.Close() })
	return bucket
}

// ensureBucket creates the shared bucket once per test binary. Packages run as
// separate binaries, possibly at the same time, so another may win the race;
// a bucket that already exists and is ours is what was wanted.
var ensureBucket = func() func(Target) error {
	var (
		mu   sync.Mutex
		done bool
	)
	return func(target Target) error {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return nil
		}
		_, err := target.Client().CreateBucket(context.Background(),
			&awss3.CreateBucketInput{Bucket: aws.String(target.Bucket)})
		var owned *types.BucketAlreadyOwnedByYou
		var exists *types.BucketAlreadyExists
		if err != nil && !errors.As(err, &owned) && !errors.As(err, &exists) {
			return err
		}
		done = true
		return nil
	}
}()

// empty deletes every key under the bucket's prefix.
func empty(ctx context.Context, bucket *storage.Bucket) error {
	it := bucket.List(&blob.ListOptions{})
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := bucket.Delete(ctx, obj.Key); err != nil {
			return fmt.Errorf("delete %s: %w", obj.Key, err)
		}
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return hex.EncodeToString(buf[:])
}
