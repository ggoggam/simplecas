package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultsAreServiceable(t *testing.T) {
	c := Default()
	if c.Server.Bind != "0.0.0.0:9000" || c.Server.Region != "us-east-1" {
		t.Errorf("server defaults = %+v", c.Server)
	}
	if c.Database.MaxConnections != 16 {
		t.Errorf("max_connections = %d, want 16", c.Database.MaxConnections)
	}
	if c.Storage.Backend != "fs" {
		t.Errorf("storage backend = %q, want fs", c.Storage.Backend)
	}
	if c.GC.IntervalSecs != 60 || c.GC.GraceSecs != 300 || c.GC.MultipartExpirySecs != 86400 {
		t.Errorf("gc defaults = %+v", c.GC)
	}
	if c.OIDC.SessionTTLSecs != 86400 {
		t.Errorf("session_ttl_secs = %d, want 86400", c.OIDC.SessionTTLSecs)
	}
	want := LimitsConfig{MaxObjectBytes: 5 << 40, MaxPartBytes: 5 << 30, StallTimeoutSecs: 60}
	if c.Limits != want {
		t.Errorf("limits defaults = %+v, want %+v", c.Limits, want)
	}
}

func TestApplyEnvSetsNestedScalars(t *testing.T) {
	c := Default()
	err := ApplyEnv(&c, []string{
		"SIMPLECAS__DATABASE__URL=postgres://x/y",
		"SIMPLECAS__DATABASE__MAX_CONNECTIONS=32",
		"SIMPLECAS__SERVER__BIND=127.0.0.1:1234",
		"SIMPLECAS__AUTH__ENABLED=true",
		"SIMPLECAS__STORAGE__BACKEND=s3",
		"SIMPLECAS__STORAGE__SECRET_ACCESS_KEY=shh",
		"SIMPLECAS__GC__GRACE_SECS=900",
		"PATH=/unrelated",
	})
	if err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if c.Database.URL != "postgres://x/y" || c.Database.MaxConnections != 32 {
		t.Errorf("database = %+v", c.Database)
	}
	if c.Server.Bind != "127.0.0.1:1234" {
		t.Errorf("bind = %q", c.Server.Bind)
	}
	if !c.Auth.Enabled {
		t.Error("auth.enabled should be true")
	}
	if c.Storage.Backend != "s3" || c.Storage.SecretAccessKey != "shh" {
		t.Errorf("storage = %+v", c.Storage)
	}
	if c.GC.GraceSecs != 900 {
		t.Errorf("grace_secs = %d", c.GC.GraceSecs)
	}
	// Untouched fields keep their defaults.
	if c.Server.Region != "us-east-1" {
		t.Errorf("region should be untouched, got %q", c.Server.Region)
	}
}

// A typo'd variable must fail loudly: silently ignoring it could leave auth
// disabled on a deployment that believed it had switched auth on.
func TestApplyEnvRejectsUnknownSettings(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{"unknown section", "SIMPLECAS__DATABSE__URL=x"},
		{"unknown key", "SIMPLECAS__DATABASE__URLL=x"},
		{"descending into a scalar", "SIMPLECAS__SERVER__BIND__EXTRA=x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			if err := ApplyEnv(&c, []string{tc.env}); err == nil {
				t.Fatalf("expected an error for %s", tc.env)
			}
		})
	}
}

func TestApplyEnvRejectsBadTypes(t *testing.T) {
	tests := []struct{ name, env string }{
		{"non-numeric int", "SIMPLECAS__DATABASE__MAX_CONNECTIONS=lots"},
		{"non-boolean", "SIMPLECAS__AUTH__ENABLED=yesplease"},
		{"struct slice has no env spelling", "SIMPLECAS__OIDC__PROVIDERS=google"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			err := ApplyEnv(&c, []string{tc.env})
			if err == nil {
				t.Fatalf("expected an error for %s", tc.env)
			}
			if !strings.Contains(err.Error(), strings.Split(tc.env, "=")[0]) {
				t.Errorf("error should name the variable, got %v", err)
			}
		})
	}
}

func TestApplyEnvStringLists(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"comma separated", "a.com,b.com", []string{"a.com", "b.com"}},
		{"tolerates spaces", " a.com , b.com ", []string{"a.com", "b.com"}},
		{"tolerates toml array form", `["a.com", "b.com"]`, []string{"a.com", "b.com"}},
		{"empty clears the list", "", []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			if err := ApplyEnv(&c, []string{"SIMPLECAS__OIDC__ALLOWED_DOMAINS=" + tc.raw}); err != nil {
				t.Fatalf("ApplyEnv: %v", err)
			}
			if !reflect.DeepEqual(c.OIDC.AllowedDomains, tc.want) {
				t.Errorf("allowed_domains = %#v, want %#v", c.OIDC.AllowedDomains, tc.want)
			}
		})
	}
}

// The whole point of the layering: file first, environment wins.
func TestLoadLayersEnvOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "simplecas.toml")
	err := os.WriteFile(path, []byte(`
[server]
bind = "0.0.0.0:8080"
region = "eu-west-1"

[database]
url = "postgres://from-file/db"

[storage]
backend = "fs"
root = "./from-file"

[[oidc.providers]]
id = "google"
issuer = "https://accounts.google.com"
client_id = "cid"
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SIMPLECAS_CONFIG", path)
	t.Setenv("SIMPLECAS__DATABASE__URL", "postgres://from-env/db")
	t.Setenv("SIMPLECAS__SERVER__REGION", "us-west-2")
	// The file binds every interface with OIDC off, which needs the opt-in.
	t.Setenv("SIMPLECAS__SERVER__INSECURE_OPEN_API", "true")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Database.URL != "postgres://from-env/db" {
		t.Errorf("env should win: url = %q", c.Database.URL)
	}
	if c.Server.Region != "us-west-2" {
		t.Errorf("env should win: region = %q", c.Server.Region)
	}
	if !c.Server.InsecureOpenAPI {
		t.Error("env should set server.insecure_open_api")
	}
	// File values with no env override survive.
	if c.Server.Bind != "0.0.0.0:8080" {
		t.Errorf("file value lost: bind = %q", c.Server.Bind)
	}
	if c.Storage.Root != "./from-file" {
		t.Errorf("file value lost: root = %q", c.Storage.Root)
	}
	// Provider tables come from the file only.
	if len(c.OIDC.Providers) != 1 || c.OIDC.Providers[0].ID != "google" {
		t.Errorf("providers = %+v", c.OIDC.Providers)
	}
}

// An all-environment deployment is supported, so a missing default config file
// must not be fatal — but an explicitly named one must be.
func TestLoadMissingConfigFile(t *testing.T) {
	t.Setenv("SIMPLECAS_CONFIG", "")
	t.Setenv("SIMPLECAS__DATABASE__URL", "postgres://x/y")
	t.Setenv("SIMPLECAS__SERVER__BIND", "127.0.0.1:9000")
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := Load(); err != nil {
		t.Fatalf("a missing simplecas.toml should not be fatal: %v", err)
	}

	t.Setenv("SIMPLECAS_CONFIG", filepath.Join(dir, "nope.toml"))
	if _, err := Load(); err == nil {
		t.Fatal("an explicitly requested config file must be required to exist")
	}
}

func TestValidate(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Database.URL = "postgres://x/y"
		// OIDC is off, so only a loopback bind starts without the opt-in.
		c.Server.Bind = "127.0.0.1:9000"
		return c
	}

	t.Run("fs backend gets the default root", func(t *testing.T) {
		c := base()
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Storage.Root != "./data" {
			t.Errorf("root = %q, want ./data", c.Storage.Root)
		}
	})

	t.Run("an explicit root is kept", func(t *testing.T) {
		c := base()
		c.Storage.Root = "/mnt/blobs"
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Storage.Root != "/mnt/blobs" {
			t.Errorf("root = %q", c.Storage.Root)
		}
	})

	t.Run("oidc with a private gateway credential", func(t *testing.T) {
		c := base()
		c.OIDC.Enabled = true
		c.Auth = AuthConfig{Enabled: true, AccessKeyID: "admin", SecretAccessKey: "a-private-secret"}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("oidc on every interface", func(t *testing.T) {
		c := base()
		c.Server.Bind = "0.0.0.0:9000"
		c.OIDC.Enabled = true
		c.Auth = AuthConfig{Enabled: true, AccessKeyID: "admin", SecretAccessKey: "a-private-secret"}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an open api on every interface when asked for", func(t *testing.T) {
		c := base()
		c.Server.Bind = "0.0.0.0:9000"
		c.Server.InsecureOpenAPI = true
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the sample secret is fine without oidc", func(t *testing.T) {
		c := base()
		c.Auth = AuthConfig{Enabled: true, AccessKeyID: "simplecas", SecretAccessKey: SampleSecretAccessKey}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("non-fs backends get no root default", func(t *testing.T) {
		c := base()
		c.Storage.Backend = "s3"
		c.Storage.Bucket = "b"
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Storage.Root != "" {
			t.Errorf("root = %q, want empty for s3", c.Storage.Root)
		}
	})

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing database url", func(c *Config) { c.Database.URL = "" }},
		{"blank database url", func(c *Config) { c.Database.URL = "   " }},
		{"zero pool size", func(c *Config) { c.Database.MaxConnections = 0 }},
		{"unknown backend", func(c *Config) { c.Storage.Backend = "ipfs" }},
		{"s3 without a bucket", func(c *Config) { c.Storage.Backend = "s3" }},
		{"gcs without a bucket", func(c *Config) { c.Storage.Backend = "gcs" }},
		{"azblob without a container", func(c *Config) { c.Storage.Backend = "azblob" }},
		{"zero gc interval", func(c *Config) { c.GC.IntervalSecs = 0 }},
		{"zero object size limit", func(c *Config) { c.Limits.MaxObjectBytes = 0 }},
		{"zero part size limit", func(c *Config) { c.Limits.MaxPartBytes = 0 }},
		{"negative quota", func(c *Config) { c.Limits.TenantQuotaBytes = -1 }},
		{"zero stall timeout", func(c *Config) { c.Limits.StallTimeoutSecs = 0 }},
		// The shipped default: every interface, no sign-in.
		{"open api on the default bind", func(c *Config) { c.Server.Bind = Default().Server.Bind }},
		{"open api on every IPv6 interface", func(c *Config) { c.Server.Bind = "[::]:9000" }},
		{"open api with an empty host", func(c *Config) { c.Server.Bind = ":9000" }},
		{"open api on a LAN address", func(c *Config) { c.Server.Bind = "192.168.1.10:9000" }},
		{"oidc with an unauthenticated gateway", func(c *Config) {
			c.OIDC.Enabled = true
		}},
		{"oidc with the sample admin secret", func(c *Config) {
			c.OIDC.Enabled = true
			c.Auth = AuthConfig{Enabled: true, AccessKeyID: "simplecas", SecretAccessKey: SampleSecretAccessKey}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestIsLoopbackBind(t *testing.T) {
	tests := []struct {
		bind string
		want bool
	}{
		{"127.0.0.1:9000", true},
		{"127.0.0.2:9000", true},
		{"[::1]:9000", true},
		{"localhost:9000", true},
		{"LOCALHOST:9000", true},
		{"0.0.0.0:9000", false},
		{"[::]:9000", false},
		{":9000", false},
		{"10.0.0.5:9000", false},
		{"cas.internal:9000", false},
		// Not a listen address at all; the listener would refuse it anyway.
		{"127.0.0.1", false},
	}
	for _, tc := range tests {
		if got := IsLoopbackBind(tc.bind); got != tc.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tc.bind, got, tc.want)
		}
	}
}
