// Package e2e drives a fully assembled simplecas server with the real AWS CLI,
// and checks it against a reference S3 with the AWS SDK (conformance_test.go).
//
// The SDK interop tests in internal/s3 check the wire protocol against one
// signing implementation. These check what users actually run: `aws s3` and
// `aws s3api`, whose transfer manager picks multipart thresholds, copies between
// buckets with UploadPartCopy, paginates listings, reads tags before copying,
// and frames streamed uploads as aws-chunked over TLS — none of which the SDK
// tests choose on their own.
//
// The tests skip unless SIMPLECAS_TEST_DATABASE_URL is set; the CLI tests also
// need AWS CLI v2 on PATH, and the conformance reference needs
// SIMPLECAS_TEST_S3_URL (`mise run test:s3` arranges all three).
package e2e

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/api"
	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/s3"
	"github.com/ggoggam/simplecas/internal/server"
	"github.com/ggoggam/simplecas/internal/testblob"
	"github.com/ggoggam/simplecas/internal/testdb"
	"github.com/ggoggam/simplecas/internal/ui"
	"github.com/ggoggam/simplecas/web"
)

// The superuser credential every authenticated stack is configured with.
const (
	adminKeyID  = "SCASE2EADMIN"
	adminSecret = "e2e-admin-secret"
)

// partSize is the multipart threshold and chunk size the CLI is configured
// with: S3's 5 MiB minimum, so a 12 MiB file goes up as three parts without
// the tests having to move the CLI's default 8 MiB worth of data per part.
const partSize = 5 << 20

// awsCLIPath finds AWS CLI v2 once per test binary. Version 1 has different
// defaults and output, so it is not accepted as a substitute.
var awsCLIPath = sync.OnceValues(func() (string, error) {
	path, err := exec.LookPath("aws")
	if err != nil {
		return "", err
	}
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(out), "aws-cli/2.") {
		return "", fmt.Errorf("need AWS CLI v2, found %s", strings.TrimSpace(string(out)))
	}
	return path, nil
})

// stack is one running server: the full router, as main.go assembles it, over
// a scratch schema and a scratch blob store (testblob).
type stack struct {
	url     string
	db      *db.DB
	gateway *s3.Gateway
	// caBundle is the PEM file the CLI must trust; set only over TLS.
	caBundle string
}

type stackOptions struct {
	tls     bool
	authOff bool
}

type stackOption func(*stackOptions)

// withTLS serves over HTTPS. The CLI only frames uploads as aws-chunked when
// the connection is encrypted.
func withTLS() stackOption { return func(o *stackOptions) { o.tls = true } }

// withAuthDisabled turns SigV4 off, leaving the gateway open to
// --no-sign-request.
func withAuthDisabled() stackOption { return func(o *stackOptions) { o.authOff = true } }

func newStack(t *testing.T, options ...stackOption) *stack {
	t.Helper()
	var opts stackOptions
	for _, option := range options {
		option(&opts)
	}

	ctx := t.Context()
	dsn := testdb.URL(t)

	database, err := db.Connect(ctx, dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)

	bucket := testblob.Open(t)

	cfg := config.Default()
	cfg.Database.URL = dsn
	cfg.Auth = config.AuthConfig{
		Enabled:         !opts.authOff,
		AccessKeyID:     adminKeyID,
		SecretAccessKey: adminSecret,
		CredentialKeys:  []string{"e2e:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	log := slog.New(slog.DiscardHandler)

	store := cas.New(database, bucket, cfg.GC, cfg.Limits, log)
	gateway := s3.New(database, bucket, store, &cfg, log)
	routes := server.Routes{
		Gateway:      gateway,
		API:          api.New(database, store, gateway, log).Routes(),
		UI:           ui.New(web.Dist()).Routes(),
		StallTimeout: time.Duration(cfg.Limits.StallTimeoutSecs) * time.Second,
	}

	srv := httptest.NewUnstartedServer(routes.Handler(log))
	s := &stack{db: database, gateway: gateway}
	if opts.tls {
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		srv.StartTLS()
		s.caBundle = filepath.Join(t.TempDir(), "ca.pem")
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(s.caBundle, block, 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// admin returns a CLI signed with the superuser credential.
func (s *stack) admin(t *testing.T) *awsCLI {
	return s.cli(t, adminKeyID, adminSecret)
}

// awsCLI runs the aws binary against one stack with one credential, isolated
// from the user's ~/.aws and environment.
type awsCLI struct {
	t   *testing.T
	env []string
}

func (s *stack) cli(t *testing.T, keyID, secret string) *awsCLI {
	t.Helper()
	if _, err := awsCLIPath(); err != nil {
		t.Skipf("AWS CLI v2 not available: %v", err)
	}
	home := t.TempDir()
	configFile := filepath.Join(home, "config")
	// The classic transfer client keeps transfers deterministic: "auto" would
	// switch to the CRT client on some hosts, with its own part sizing.
	const profile = `[default]
region = us-east-1
output = json
s3 =
  addressing_style = path
  preferred_transfer_client = classic
  multipart_threshold = 5MB
  multipart_chunksize = 5MB
`
	if err := os.WriteFile(configFile, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"TMPDIR=" + os.TempDir(),
		"AWS_CONFIG_FILE=" + configFile,
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(home, "credentials"),
		"AWS_ACCESS_KEY_ID=" + keyID,
		"AWS_SECRET_ACCESS_KEY=" + secret,
		"AWS_ENDPOINT_URL=" + s.url,
		"AWS_PAGER=",
		"AWS_CLI_AUTO_PROMPT=off",
		"AWS_EC2_METADATA_DISABLED=true",
		// A refusal should fail the command at once rather than after the
		// CLI's backoff, and a flaky success should not hide behind a retry.
		"AWS_MAX_ATTEMPTS=1",
	}
	if s.caBundle != "" {
		env = append(env, "AWS_CA_BUNDLE="+s.caBundle)
	}
	return &awsCLI{t: t, env: env}
}

// exec runs one command and returns its stdout, stderr and error.
func (c *awsCLI) exec(stdin io.Reader, args ...string) (stdout, stderr []byte, err error) {
	path, _ := awsCLIPath()
	ctx, cancel := context.WithTimeout(c.t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = c.env
	cmd.Stdin = stdin
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// run executes a command that must succeed and returns its stdout.
func (c *awsCLI) run(args ...string) string {
	c.t.Helper()
	return string(c.runBytes(nil, args...))
}

// runStdin is run with the given bytes on stdin.
func (c *awsCLI) runStdin(stdin []byte, args ...string) string {
	c.t.Helper()
	return string(c.runBytes(bytes.NewReader(stdin), args...))
}

func (c *awsCLI) runBytes(stdin io.Reader, args ...string) []byte {
	c.t.Helper()
	stdout, stderr, err := c.exec(stdin, args...)
	if err != nil {
		c.t.Fatalf("aws %s: %v\nstderr: %s", strings.Join(args, " "), err, stderr)
	}
	return stdout
}

// json runs a command that must succeed and decodes its JSON output into v.
func (c *awsCLI) json(v any, args ...string) {
	c.t.Helper()
	out := c.run(args...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		c.t.Fatalf("aws %s: decode output: %v\noutput: %s", strings.Join(args, " "), err, out)
	}
}

// fails runs a command that must exit non-zero with stderr naming want, and
// returns that stderr.
func (c *awsCLI) fails(want string, args ...string) string {
	c.t.Helper()
	_, stderr, err := c.exec(nil, args...)
	if err == nil {
		c.t.Fatalf("aws %s succeeded, want a failure mentioning %q", strings.Join(args, " "), want)
	}
	if !strings.Contains(string(stderr), want) {
		c.t.Fatalf("aws %s: stderr does not mention %q\nstderr: %s", strings.Join(args, " "), want, stderr)
	}
	return string(stderr)
}

// ---------------------------------------------------------------------------
// Local files and content
// ---------------------------------------------------------------------------

// randomBytes returns n deterministic pseudo-random bytes, so a failure
// reproduces with the same content.
func randomBytes(n int, seed uint64) []byte {
	var key [32]byte
	key[0] = byte(seed)
	key[1] = byte(seed >> 8)
	buf := make([]byte, n)
	_, _ = rand.NewChaCha8(key).Read(buf)
	return buf
}

// writeFile writes data to dir/name, creating parent directories, and returns
// the path.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// etagOf is the ETag S3 gives content the CLI uploads as configured here: its
// quoted MD5, or from partSize up, the multipart form over partSize parts —
// the MD5 of the parts' MD5s, then "-" and the part count.
func etagOf(data []byte) string {
	if len(data) < partSize {
		sum := md5.Sum(data)
		return `"` + hex.EncodeToString(sum[:]) + `"`
	}
	all, n := md5.New(), 0
	for rest := data; len(rest) > 0; n++ {
		part := rest[:min(partSize, len(rest))]
		sum := md5.Sum(part)
		all.Write(sum[:])
		rest = rest[len(part):]
	}
	return fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(all.Sum(nil)), n)
}

// sameBytes fails the test when got differs from want, without dumping
// megabytes of content into the log.
func sameBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %d bytes (etag %s), want %d bytes (etag %s)",
			what, len(got), etagOf(got), len(want), etagOf(want))
	}
}

// download fetches s3://bucket/key with get-object and returns its bytes.
func (c *awsCLI) download(bucket, key string) []byte {
	c.t.Helper()
	path := filepath.Join(c.t.TempDir(), "object")
	c.run("s3api", "get-object", "--bucket", bucket, "--key", key, path)
	return readFile(c.t, path)
}

// lsNames parses `aws s3 ls` output into the names it lists: keys, "PRE x/"
// common prefixes as "x/", or bucket names. Names must not contain spaces.
func lsNames(out string) []string {
	var names []string
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[len(fields)-1])
	}
	return names
}

type headObject struct {
	ContentLength int64
	ContentType   string
	ETag          string
	Metadata      map[string]string
}

func (c *awsCLI) head(bucket, key string) headObject {
	c.t.Helper()
	var h headObject
	c.json(&h, "s3api", "head-object", "--bucket", bucket, "--key", key)
	return h
}
