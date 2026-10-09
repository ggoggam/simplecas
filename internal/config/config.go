// Package config loads simplecas's layered configuration: simplecas.toml (or
// $SIMPLECAS_CONFIG) first, then SIMPLECAS__-prefixed environment variables,
// which win. The env path mirrors the TOML nesting with `__` as the separator,
// e.g. SIMPLECAS__DATABASE__URL sets database.url.
package config

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ggoggam/simplecas/internal/seal"
)

// EnvPrefix is the prefix every configuration environment variable carries.
const EnvPrefix = "SIMPLECAS__"

// Config is the whole server configuration.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Database DatabaseConfig `toml:"database"`
	Storage  StorageConfig  `toml:"storage"`
	Auth     AuthConfig     `toml:"auth"`
	OIDC     OidcConfig     `toml:"oidc"`
	GC       GcConfig       `toml:"gc"`
	Limits   LimitsConfig   `toml:"limits"`
}

// ServerConfig covers the listener and the S3 region the gateway advertises.
type ServerConfig struct {
	Bind string `toml:"bind"`
	// Region is reported in SigV4 scope validation and S3 responses.
	Region string `toml:"region"`
	// InsecureOpenAPI accepts an unauthenticated /api on a non-loopback bind,
	// which is otherwise refused while OIDC is off. Set it only when something
	// in front (ingress auth, a private network) decides who reaches the port.
	// It has no effect with OIDC on.
	InsecureOpenAPI bool `toml:"insecure_open_api"`
}

// DatabaseConfig points at the shared Postgres metadata store.
type DatabaseConfig struct {
	URL            string `toml:"url"`
	MaxConnections int32  `toml:"max_connections"`
}

// StorageConfig selects and configures the blob backend. The fields are flat
// rather than a per-backend union so every one of them can be set from a single
// environment variable; `Backend` decides which are read, and Validate rejects
// a backend whose required fields are missing.
//
// The logical layout inside the backend is identical everywhere:
//
//	blobs/<h[0:2]>/<h[2:4]>/<hash>  – content-addressed, immutable
//	staging/<uuid>                  – in-flight uploads and multipart parts
type StorageConfig struct {
	// Backend is one of fs, s3, gcs, azblob.
	Backend string `toml:"backend"`
	// Root prefixes every key. Applies to all backends; defaults to ./data
	// for fs and to no prefix elsewhere.
	Root string `toml:"root"`

	// fs — no fields beyond Root.

	// s3 (also MinIO / R2 via Endpoint).
	Bucket          string `toml:"bucket"`
	Region          string `toml:"region"`
	Endpoint        string `toml:"endpoint"`
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`

	// gcs. Bucket is shared with s3. CredentialPath points at a
	// service-account JSON file; empty means ambient credentials.
	CredentialPath string `toml:"credential_path"`

	// azblob. Endpoint is shared with s3.
	Container   string `toml:"container"`
	AccountName string `toml:"account_name"`
	AccountKey  string `toml:"account_key"`
}

// AuthConfig is the S3 gateway's SigV4 credential. Disabled means anonymous
// access, which is fine behind private ingress or for the bundled PWA.
type AuthConfig struct {
	Enabled         bool   `toml:"enabled"`
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`
	// CredentialKeys seal the per-team S3 secrets in the database, as
	// "id:base64key" entries of 32 random bytes each. The first seals new
	// secrets; the rest only open what was sealed under them, so a key is
	// rotated by adding the new one at the end, then moving it to the front.
	// Required with OIDC on, since only signed-in owners mint team keys.
	CredentialKeys []string `toml:"credential_keys"`
}

// Keyring parses CredentialKeys. It is nil, with no error, when none are set.
func (a *AuthConfig) Keyring() (*seal.Keyring, error) {
	if len(a.CredentialKeys) == 0 {
		return nil, nil
	}
	k, err := seal.Parse(a.CredentialKeys)
	if err != nil {
		return nil, fmt.Errorf("auth.credential_keys: %w", err)
	}
	return k, nil
}

// OidcConfig configures single sign-on for the human-facing surface (the PWA at
// /ui and the JSON admin API at /api). The S3 gateway keeps its own SigV4 auth —
// OIDC is a browser flow and does not apply to machine clients.
//
// A successful login records a row in the sessions table and sets an
// HMAC-signed cookie that refers to it, so a session can be revoked. Instances
// share sessions through the database and need the same SessionSecret.
type OidcConfig struct {
	Enabled bool `toml:"enabled"`
	// PublicURL is this instance's public base URL (e.g. https://cas.example.com),
	// used to derive each provider's redirect URI. Required when Enabled.
	PublicURL string `toml:"public_url"`
	// SessionSecret signs session and flow-state cookies. Every instance behind
	// the load balancer must share it. Required when Enabled.
	SessionSecret string `toml:"session_secret"`
	// SessionTTLSecs is how long a login stays valid before re-authentication.
	SessionTTLSecs int64 `toml:"session_ttl_secs"`
	// AllowedDomains and AllowedEmails form an optional allowlist: if either is
	// non-empty a login is accepted only when the verified email matches an
	// entry. Both empty admits any identity that authenticates.
	AllowedDomains []string `toml:"allowed_domains"`
	AllowedEmails  []string `toml:"allowed_emails"`
	// Providers can only be set from TOML — an array of tables has no
	// environment-variable spelling.
	Providers []ProviderConfig `toml:"providers"`
}

// ProviderConfig is one external identity provider.
type ProviderConfig struct {
	// ID is the stable slug used in the redirect URI and login URLs (e.g. google).
	ID string `toml:"id"`
	// Name is the label on the login button; defaults to ID.
	Name string `toml:"name"`
	// Issuer is the discovery base (<issuer>/.well-known/openid-configuration).
	Issuer   string `toml:"issuer"`
	ClientID string `toml:"client_id"`
	// ClientSecret is omitted for public (PKCE-only) clients.
	ClientSecret string `toml:"client_secret"`
	// Scopes defaults to openid, email, profile.
	Scopes []string `toml:"scopes"`
}

// GcConfig tunes the background reclamation loop.
type GcConfig struct {
	IntervalSecs int64 `toml:"interval_secs"`
	// GraceSecs is how long a blob may sit at refcount 0 before its bytes are
	// deleted. Also the expiry for orphaned staging files.
	GraceSecs int64 `toml:"grace_secs"`
	// MultipartExpirySecs is how long a multipart upload may go without
	// activity (initiation or a new part) before it is abandoned and its
	// staged parts reclaimed.
	MultipartExpirySecs int64 `toml:"multipart_expiry_secs"`
	// OrphanIntervalSecs is how often GC lists every stored blob to reclaim
	// bytes no blob row accounts for, which a failed commit leaves behind.
	// The listing touches every blob, so it runs far less often than the
	// other sweeps; such bytes are rare and harmless until then.
	OrphanIntervalSecs int64 `toml:"orphan_interval_secs"`
}

// LimitsConfig bounds what one request, and one team, can consume.
type LimitsConfig struct {
	// MaxObjectBytes caps a single PUT and the assembled size of a multipart
	// upload. Defaults to S3's 5 TiB.
	MaxObjectBytes int64 `toml:"max_object_bytes"`
	// MaxPartBytes caps one multipart part. Defaults to S3's 5 GiB.
	MaxPartBytes int64 `toml:"max_part_bytes"`
	// TenantQuotaBytes caps the logical bytes each team stores: the size of
	// every object in its namespaces, plus the parts of its unfinished
	// multipart uploads. Content deduplicated against another team still
	// counts in full, so usage reveals nothing about what other teams store.
	// 0 means no quota. Namespaces without a team are never charged.
	TenantQuotaBytes int64 `toml:"tenant_quota_bytes"`
	// StallTimeoutSecs is how long a request or response body may go without
	// moving a byte before the connection is dropped. There is no cap on the
	// total duration, since a large object legitimately streams for a long time.
	StallTimeoutSecs int64 `toml:"stall_timeout_secs"`
}

// Default returns the configuration before any file or environment layer is
// applied. Decoding only overwrites keys that are actually present, so these
// act as the defaults for everything left unset.
func Default() Config {
	return Config{
		Server:   ServerConfig{Bind: "0.0.0.0:9000", Region: "us-east-1"},
		Database: DatabaseConfig{MaxConnections: 16},
		Storage:  StorageConfig{Backend: "fs"},
		OIDC:     OidcConfig{SessionTTLSecs: 86400},
		GC: GcConfig{
			IntervalSecs:        60,
			GraceSecs:           300,
			MultipartExpirySecs: 86400,
			OrphanIntervalSecs:  86400,
		},
		Limits: LimitsConfig{
			MaxObjectBytes:   5 << 40,
			MaxPartBytes:     5 << 30,
			StallTimeoutSecs: 60,
		},
	}
}

// Load reads simplecas.toml (or $SIMPLECAS_CONFIG), applies SIMPLECAS__
// environment overrides on top, and validates the result. A missing config file
// is not an error — an all-environment deployment is a supported way to run.
func Load() (*Config, error) {
	path := os.Getenv("SIMPLECAS_CONFIG")
	explicit := path != ""
	if !explicit {
		path = "simplecas.toml"
	}

	cfg := Default()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		// Only an explicitly requested file is required to exist.
		if !os.IsNotExist(err) || explicit {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	if err := ApplyEnv(&cfg, os.Environ()); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ApplyEnv overlays SIMPLECAS__-prefixed entries of environ onto cfg. An entry
// naming a field that does not exist is an error rather than a silent no-op, so
// a typo can't quietly leave a setting (say, an auth toggle) at its default.
func ApplyEnv(cfg *Config, environ []string) error {
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		path := strings.Split(strings.TrimPrefix(name, EnvPrefix), "__")
		if err := setPath(reflect.ValueOf(cfg).Elem(), path, value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// setPath walks v by TOML field name (case-insensitively) and assigns raw to
// the field the path names.
func setPath(v reflect.Value, path []string, raw string) error {
	field, ok := fieldByTOMLName(v, path[0])
	if !ok {
		return fmt.Errorf("no such setting %q", strings.ToLower(path[0]))
	}
	if len(path) > 1 {
		if field.Kind() != reflect.Struct {
			return fmt.Errorf("%q is not a section", strings.ToLower(path[0]))
		}
		return setPath(field, path[1:], raw)
	}
	return setScalar(field, raw)
}

// fieldByTOMLName finds the struct field whose `toml` tag (or, lacking one, its
// lowercased Go name) equals name, ignoring case.
func fieldByTOMLName(v reflect.Value, name string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		key := f.Tag.Get("toml")
		if key == "" {
			key = f.Name
		}
		if strings.EqualFold(key, name) {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// setScalar parses raw into field. String slices accept a comma-separated list;
// slices of structs (only oidc.providers) have no environment spelling.
func setScalar(field reflect.Value, raw string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("expected a boolean, got %q", raw)
		}
		field.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected an integer, got %q", raw)
		}
		field.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(raw, 10, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected a non-negative integer, got %q", raw)
		}
		field.SetUint(n)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(raw, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected a number, got %q", raw)
		}
		field.SetFloat(f)
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("this setting can only be configured in the config file")
		}
		field.Set(reflect.ValueOf(splitList(raw)))
	default:
		return fmt.Errorf("this setting can only be configured in the config file")
	}
	return nil
}

// splitList parses a comma-separated list, tolerating the [a,b] form and
// surrounding whitespace. An empty string yields an empty list, which is how
// an allowlist is switched off.
func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Validate fills in backend-dependent defaults and rejects a configuration the
// server could not run with. OIDC provider details are validated separately,
// when the registry performs discovery at startup.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Database.URL) == "" {
		return fmt.Errorf("database.url is required (set it in simplecas.toml or %sDATABASE__URL)", EnvPrefix)
	}
	if c.Database.MaxConnections < 1 {
		return fmt.Errorf("database.max_connections must be at least 1")
	}

	switch c.Storage.Backend {
	case "fs":
		if c.Storage.Root == "" {
			c.Storage.Root = "./data"
		}
	case "s3":
		if c.Storage.Bucket == "" {
			return fmt.Errorf("storage.bucket is required for the s3 backend")
		}
	case "gcs":
		if c.Storage.Bucket == "" {
			return fmt.Errorf("storage.bucket is required for the gcs backend")
		}
	case "azblob":
		if c.Storage.Container == "" {
			return fmt.Errorf("storage.container is required for the azblob backend")
		}
	default:
		return fmt.Errorf("storage.backend %q is not one of fs, s3, gcs, azblob", c.Storage.Backend)
	}

	if c.GC.IntervalSecs < 1 || c.GC.GraceSecs < 0 || c.GC.MultipartExpirySecs < 1 || c.GC.OrphanIntervalSecs < 1 {
		return fmt.Errorf("gc intervals must be positive")
	}

	if c.Limits.MaxObjectBytes < 1 || c.Limits.MaxPartBytes < 1 {
		return fmt.Errorf("limits.max_object_bytes and limits.max_part_bytes must be positive")
	}
	if c.Limits.TenantQuotaBytes < 0 {
		return fmt.Errorf("limits.tenant_quota_bytes must not be negative (0 means no quota)")
	}
	if c.Limits.StallTimeoutSecs < 1 {
		return fmt.Errorf("limits.stall_timeout_secs must be positive")
	}

	// An enabled-but-blank admin credential would leave the gateway rejecting
	// every request while looking configured, and per-tenant credentials make
	// a blank admin key worse than useless: the admin branch is matched before
	// the tenant lookup, so it must be unmistakable.
	if c.Auth.Enabled {
		if strings.TrimSpace(c.Auth.AccessKeyID) == "" {
			return fmt.Errorf("auth.access_key_id is required when auth.enabled is true")
		}
		if strings.TrimSpace(c.Auth.SecretAccessKey) == "" {
			return fmt.Errorf("auth.secret_access_key is required when auth.enabled is true")
		}
	}
	if _, err := c.Auth.Keyring(); err != nil {
		return err
	}

	// Without OIDC nothing authenticates /api, which creates and deletes every
	// namespace and object and mints gateway credentials. That is a sensible
	// default only where nobody else can reach it, so listening beyond loopback
	// has to be asked for rather than be what a fresh install does.
	if !c.OIDC.Enabled && !c.Server.InsecureOpenAPI && !IsLoopbackBind(c.Server.Bind) {
		return fmt.Errorf("oidc.enabled must be true when server.bind (%s) is not a loopback address: "+
			"without sign-in /api gives anyone who can reach the port full control of every namespace; "+
			"bind to 127.0.0.1, or set server.insecure_open_api = true if ingress in front authenticates it",
			c.Server.Bind)
	}

	// Tenancy is only as strong as its weakest plane. OIDC scopes /ui and /api
	// to the caller's team, but an unauthenticated gateway serves every team's
	// buckets to anyone who can reach the port, and the sample admin secret is
	// public in this repository. Either one makes the team boundary decorative,
	// so a multi-tenant deployment refuses to start with them rather than warn.
	if c.OIDC.Enabled {
		if !c.Auth.Enabled {
			return fmt.Errorf("auth.enabled must be true when oidc.enabled is true: " +
				"an unauthenticated S3 gateway serves every team's namespaces to anyone")
		}
		if c.Auth.SecretAccessKey == SampleSecretAccessKey {
			return fmt.Errorf("auth.secret_access_key is still the sample value from simplecas.toml; " +
				"set a private secret before enabling oidc")
		}
		// Team owners mint S3 keys only once they can sign in, and those
		// secrets are stored recoverably, so they are sealed rather than
		// left readable to anyone with a database dump or a backup.
		if len(c.Auth.CredentialKeys) == 0 {
			return fmt.Errorf("auth.credential_keys is required when oidc.enabled is true: " +
				"it seals the teams' S3 secrets in the database; " +
				"set it to [\"k1:<output of openssl rand -base64 32>\"]")
		}
	}
	return nil
}

// IsLoopbackBind reports whether a listen address accepts connections from
// this host only. An empty host listens on every interface, and a host name
// other than localhost is not resolved here, so both count as reachable.
func IsLoopbackBind(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PublicHTTPS reports whether browsers reach this instance over HTTPS, judged
// by public_url's scheme. TLS usually terminates at a proxy in front, so the
// requests themselves arrive as plain HTTP and cannot say.
func (c *OidcConfig) PublicHTTPS() bool {
	return strings.HasPrefix(c.PublicURL, "https")
}

// SampleSecretAccessKey is the admin secret shipped in simplecas.toml. It is
// fine for a local instance and refused for a multi-tenant one.
const SampleSecretAccessKey = "simplecas-secret"
