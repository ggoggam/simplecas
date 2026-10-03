# simplecas

A distributed **content-addressable storage** server with an **S3-compatible
gateway**, **global file-level deduplication**, pluggable storage backends, and
a bundled **PWA** for managing objects.

- **Go** for the server, on the standard library's `net/http` — no web framework.
- **PostgreSQL** as the shared metadata store, so you can run many stateless
  server instances behind a load balancer.
- **[Go CDK blob](https://gocloud.dev/howto/blob/)** for storage, so blobs can
  live on the local filesystem, **S3** (incl. MinIO / R2), **GCS**, or **Azure
  Blob** with a one-line config change.
- **[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)** for hashing — chosen for
  its throughput (multi-GB/s, SIMD + internal parallelism), far ahead of
  SHA-256 while remaining cryptographically strong.

## How deduplication works

Every object's bytes are hashed with BLAKE3. The digest is the object's ETag and
the key into a global `blobs` table shared across **all namespaces**. Two objects
with identical content — in the same namespace or different ones — reference one
physical blob. A `refcount` tracks how many objects point at each blob; deleting
the last reference marks the blob for garbage collection, which removes the bytes
after a grace period.

```
objects (namespace, key) ──blob_hash──▶ blobs (hash, size, refcount) ──▶ backend: blobs/ab/cd/<hash>
```

The write path streams uploads to a `staging/<uuid>` file while hashing, then in
one transaction claims a blob reference (creating the blob row + copying bytes
only if the content is new) and points the key at it. Uploading duplicate
content costs a staging write + delete and **zero** additional stored bytes.

### Client-side dedup (PWA)

The PWA takes dedup one step further for large uploads. Before sending any
bytes, the browser hashes the file with BLAKE3 in a **Web Worker** and asks the
server whether that blob already exists. On a hit, the object is linked to the
existing blob with **no bytes transferred at all** — a multi-GB duplicate
"uploads" in milliseconds. On a miss it streams the file via **parallel
multipart**. See [Uploads (PWA)](#uploads-pwa).

## Quick start (Docker)

Self-contained stack (Postgres + simplecas with a local-fs backend):

```bash
mise run up          # docker compose -f docker/docker-compose.yml up --build
# open http://localhost:9000/ui/
mise run down        # tear down (add down:clean to wipe volumes)
```

No mise? `docker compose -f docker/docker-compose.yml up --build` works the same.

The stack is for one machine. Sign-in is off, so `/api` is open; the compose
file sets `server.insecure_open_api` to allow that and publishes port 9000 on
the host's loopback only. Postgres is not published at all: simplecas reaches
it on the compose network (`docker compose -f docker/docker-compose.yml exec
postgres psql -U postgres simplecas` for a shell).

## Development

Install [mise](https://mise.jdx.dev) — it provisions the toolchain (Go, Bun,
golangci-lint) and drives every workflow. Docker is used for a throwaway
Postgres and a local S3-compatible blob store.

```bash
mise install         # install pinned tools
mise run dev         # dev Postgres + auto-reloading backend + Vite dev server
```

`mise run dev` starts four things: a dev Postgres container on `:55432`, a
[RustFS](https://github.com/rustfs/rustfs) S3-compatible blob store on `:9200`,
the backend on `:9100`, and the Vite dev server with hot module reload. Open the
URL Vite prints — it proxies `/api` to the backend. Migrations run automatically
on backend startup.

| Task                | What it does                                             |
|---------------------|---------------------------------------------------------|
| `mise run dev`      | Full watch-dev loop (Postgres + backend + Vite)         |
| `mise run up`       | Full stack in Docker on `:9000`                          |
| `mise run down`     | Tear down the Docker stack (`down:clean` wipes volumes) |
| `mise run logs`     | Follow Docker stack logs                                 |
| `mise run db`       | Start just the dev Postgres (`db:stop` to remove it)    |
| `mise run build`    | Production build: PWA then the binary with the UI embedded |
| `mise run test`     | Unit tests (database-backed tests skip without a DB)     |
| `mise run test:integration` | Full suite against the dev Postgres              |
| `mise run test:e2e` | AWS CLI end-to-end suite against the dev Postgres        |
| `mise run check`    | `lint` + `test` (`fmt`, `vet`, `lint` also defined)      |
| `mise run web:build`| Build the PWA into `web/dist`                            |

Run `mise tasks` to list them all.

The server exposes three surfaces on one port (`:9000` in Docker, backend on
`:9100` in watch-dev):

| Path      | Surface                                            |
|-----------|----------------------------------------------------|
| `/`       | S3-compatible gateway (path-style addressing)      |
| `/api/`   | JSON admin API (used by the PWA)                   |
| `/ui/`    | Progressive Web App                                |
| `/auth/`  | OIDC sign-in endpoints (only mounted when enabled) |

## Configuration

`simplecas.toml`, overridable by `SIMPLECAS__SECTION__KEY` env vars
(e.g. `SIMPLECAS__DATABASE__URL`). See the file for all options. Switch backends
by changing the `[storage]` section:

```toml
[storage]
backend = "s3"          # fs | s3 | gcs | azblob
bucket = "my-bucket"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"   # or MinIO / R2
access_key_id = "…"
secret_access_key = "…"
```

### Binding without sign-in

With OIDC off nothing authenticates `/api`, which can create and delete every
namespace and object. So the server **refuses to start** with OIDC off unless
`server.bind` is a loopback address (`127.0.0.1`, `[::1]`, `localhost`) or the
open admin plane is accepted explicitly:

```toml
[server]
bind = "0.0.0.0:9000"
insecure_open_api = true    # SIMPLECAS__SERVER__INSECURE_OPEN_API=true
```

Set it only when something in front (ingress auth, a private network) decides
who reaches the port; the server logs a warning at startup while it is in
effect. The shipped `simplecas.toml` binds `0.0.0.0:9000` without it, so a bare
`go run ./cmd/simplecas` needs `SIMPLECAS__SERVER__BIND=127.0.0.1:9000`, the
opt-in, or `[oidc]`. `mise run dev` and the compose stack set the opt-in. With
OIDC on the setting has no effect.

### Limits and quotas

The `[limits]` section bounds what one request and one team can consume:

| Setting | Default | Over the limit |
| --- | --- | --- |
| `max_object_bytes` | 5 TiB | `400 EntityTooLarge` for a PUT, or a multipart completion whose parts add up past it |
| `max_part_bytes` | 5 GiB | `400 EntityTooLarge` for an upload part |
| `tenant_quota_bytes` | 0 (off) | `403 QuotaExceeded` |
| `stall_timeout_secs` | 60 | `400 RequestTimeout`, and the connection is dropped |

A body whose `Content-Length` (or `x-amz-decoded-content-length`) is already
over a size limit is refused before it is read. An undeclared one is cut off one
byte past the limit.

The quota charges each team the **logical** size of what it stores: every
object in its namespaces plus the parts of its unfinished multipart uploads.
Dedup stays global, but content another team also stores is charged in full, so
a team's usage never reveals what other teams hold. Overwriting a key charges the
difference; copies and dedup links are charged like uploads. Namespaces without a
team are never charged. Usage is summed from the rows on each write rather than
kept as a counter, which costs a scan of the team's objects per write while a
quota is set.

The stall timeout is on silence, not duration: a multi-gigabyte transfer may
take as long as it needs while bytes keep moving, but one that stops for
`stall_timeout_secs` is dropped instead of holding its connection open.

## Authentication

There are two independent auth mechanisms for the two kinds of client:

- **S3 gateway (`/`)** — AWS **SigV4**, for machine clients. Toggled by
  `[auth] enabled` (see above). Unaffected by OIDC.
- **Web surface (`/ui` + `/api`)** — optional **OIDC** single sign-on, for
  humans. When enabled, both are gated behind a login; the S3 gateway is not.

### OIDC single sign-on

*Authentication* is deliberately lean and stateless: **any identity that
authenticates at a configured provider is admitted** (optionally narrowed by an
email allowlist), and the session is a stateless **HMAC-signed cookie** carrying
the ID token's issuer and subject — no session table, no server-side revocation.
Every instance behind a load balancer only needs the same `session_secret`.
*Authorization* (who may see which namespaces) is layered on top via **teams** —
see below.

```toml
[oidc]
enabled = true
public_url = "https://cas.example.com"      # used to derive redirect URIs
session_secret = "…32+ random bytes…"        # shared across instances
session_ttl_secs = 86400
allowed_domains = ["example.com"]            # optional; empty = allow anyone
allowed_emails = []                          # optional exact allowlist

[[oidc.providers]]                           # one block per provider
id = "google"
name = "Google"
issuer = "https://accounts.google.com"
client_id = "…"
client_secret = "…"                          # omit for public (PKCE) clients
scopes = ["openid", "email", "profile"]
```

Register this **redirect URI** with each provider:
`<public_url>/auth/oidc/<id>/callback` (e.g.
`https://cas.example.com/auth/oidc/google/callback`).

The flow is standard OIDC authorization-code with **PKCE** and **nonce**;
per-login state rides in a short-lived signed cookie so the callback needs no
shared store. Provider discovery (and the signing JWKS) is fetched at startup
and **re-discovered hourly**, so IdP key rotation doesn't break logins without a
restart. When an allowlist is configured the email must be present **and
verified** — an unverified email is rejected.

Endpoints: `GET /auth/login` (provider buttons), `/auth/oidc/{id}/start`,
`/auth/oidc/{id}/callback`, `POST /auth/logout` (a `GET` is refused with `405`),
and `/auth/me` (current identity as JSON). Unauthenticated `/api` calls get
`401`; unauthenticated page loads redirect to `/auth/login`. The post-login
destination (`?redirect=`) must be `/ui` or a path under `/ui/`; anything else,
including one carrying a backslash, a control character or a `..` segment,
lands on `/ui/` instead.

When `public_url` is `https://…` the session and login-flow cookies are named
`__Host-scas_session` and `__Host-scas_oidc_flow`: `Secure`, `Path=/`, no
`Domain`, so no other subdomain can set or overwrite them. Over plain HTTP
(local development) they keep the bare names `scas_session` and
`scas_oidc_flow`. Changing `public_url` between the two signs everyone out.

**Cross-site requests.** Every `POST`, `PUT`, `PATCH` or `DELETE` (any method
but `GET`, `HEAD` and `OPTIONS`) to `/api` or `/auth` is refused with `403
AccessDenied` when the browser says it came from elsewhere: a `Sec-Fetch-Site`
other than `same-origin` or, from a browser too old to send that, an `Origin`
whose host is not the one requested. A request with neither header, such as
from `curl` or a script, is let through; it carries no browser cookies to
misuse. This applies with OIDC off as well, so a web page can't drive the open
`/api` plane through a visitor's browser. A reverse proxy must pass the `Host`
header through unchanged for the `Origin` fallback to match.

> **Note:** OIDC gates the bundled PWA and admin API only, so with OIDC on the
> server **refuses to start** unless `[auth] enabled = true` with a secret other
> than the sample `simplecas-secret` — an unauthenticated gateway would serve
> every team's namespaces to anyone who can reach the port. With OIDC off, it
> refuses a non-loopback bind instead; see
> [Binding without sign-in](#binding-without-sign-in).

### Browser security headers

Every response from `/ui`, `/api` and `/auth` carries
`X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` (URLs here
name namespaces and keys, and nothing cross-origin needs a `Referer`),
`X-Frame-Options: DENY`, and a `Content-Security-Policy` with
`frame-ancestors 'none'`. The PWA's policy allows only same-origin scripts,
workers and fetches, plus `'wasm-unsafe-eval'` for the BLAKE3 hasher and inline
styles that its UI libraries inject; `/api` and `/auth` get `default-src
'none'`, and the sign-in page admits its one inline stylesheet by hash.
`Strict-Transport-Security` is added when the request came over TLS or
`oidc.public_url` is `https://`. Object bytes, at `/` or through `/api`, keep
the gateway's own headers instead (see [S3 gateway](#s3-gateway)).

### Teams (multi-tenancy)

When OIDC is enabled the human plane (`/ui` + `/api`) is **multi-tenant**: each
namespace is owned by a **team**, and a signed-in user sees and touches only the
namespaces of teams they belong to. Isolation is enforced per request; a
namespace a caller can't access is reported as *not found*, so reads, writes and
listings never reveal another team's namespaces.

The one exception is creation. Namespace names are **global** (they are S3
bucket names), so creating one whose name is taken fails `409` even when another
team holds it, and that answer necessarily confirms the name is in use. It says
nothing more: another team's namespace and an unowned one get the same
`BucketAlreadyExists`, and only a namespace the caller can already reach comes
back `BucketAlreadyOwnedByYou`. Real S3 behaves the same way. Don't put anything
secret in a namespace name.

- **Users** are keyed by the provider's **(issuer, subject)** — the ID token's
  `iss` and `sub`, which a provider never reassigns. A `users` row is created
  the first time an identity calls `/api`. Email and name are stored for
  display only; nothing authorizes on them.
- **Membership** belongs to a user. Owners **invite by email**; an invitation
  grants nothing until a signed-in user whose provider has **verified** that
  address accepts it, and the membership then belongs to that user's account,
  not to the address. An invitation lapses after **7 days**; inviting the same
  address again replaces it with a fresh one. So another provider that vouches
  for the same address, or whoever holds a recycled mailbox later, inherits
  nothing that has already been accepted.
- Two roles: `owner` (manage membership and invitations, mint S3 keys, delete
  the team) and `member` (read/write the team's namespaces). A team always keeps
  at least one owner: demoting or removing the last one is refused, including
  when two owners try it on each other at the same moment. Any member may leave.
- **Self-serve**: any signed-in user can create a team and becomes its owner.
- **Dedup stays global** across all content, but the client-side dedup "link"
  fast path is scoped to your own team, so it can't be used to probe whether
  another team holds a given blob: linking a hash only another team stores
  returns the same `404 NoSuchKey` as a hash nobody stores. A genuine re-upload of identical bytes is
  still physically de-duplicated (nothing new is stored).
- **Quota**: `limits.tenant_quota_bytes` caps each team's logical usage; see
  [Limits and quotas](#limits-and-quotas).

No config is required — tenancy is automatic whenever OIDC is on. There is no
users/teams state when OIDC is off; then `/api` is the unauthenticated
full-access plane it has always been, which is why it only listens beyond
loopback when told to ([Binding without sign-in](#binding-without-sign-in)).

API (JSON, cookie-authenticated):

| Endpoint | Who | |
| --- | --- | --- |
| `GET/POST /api/tenants`, `DELETE /api/tenants/{team}` | any user; delete is owner-only | list, create, delete teams |
| `GET /api/tenants/{team}/members` | members | roster; `id` addresses a member, `you` marks the caller |
| `PATCH /api/tenants/{team}/members/{id}` | owners | change a role: `{"role":"owner"}` |
| `DELETE /api/tenants/{team}/members/{id}` | owners, or the member themselves | remove, or leave |
| `GET/POST /api/tenants/{team}/invitations` | owners | list pending, or invite `{"email","role"}` |
| `DELETE /api/tenants/{team}/invitations/{email}` | owners | withdraw |
| `GET /api/invitations` | any user | invitations addressed to your verified email |
| `POST /api/invitations/{team}/accept`, `…/decline` | the invitee | answer one |

Creating a namespace (`POST /api/namespaces`) takes a `tenant` field naming the
owning team.

> **Upgrading from email-keyed membership:** migration `0004_users` cannot
> attach existing memberships to users that do not exist yet, so it turns each
> into a pending invitation with the same role and no expiry. After upgrading,
> every existing member, owners included, signs in and accepts once from the
> **team invitations** button in the PWA. Sessions issued before the upgrade
> lack the issuer and are signed out once.

### Per-team S3 credentials

The S3 gateway is tenant-scoped too, via access keys minted per team. A request
signed with one of them can address **only that team's namespaces**; every other
name — another team's, an unowned one, or one that doesn't exist — comes back
`NoSuchBucket`, so the gateway never confirms that a namespace it won't serve
is there, except that `CreateBucket` on a taken name answers
`BucketAlreadyExists` (see [Teams](#teams-multi-tenancy)). `CopyObject` resolves
*both* source and destination in that scope, so it can't be used to pull another
team's object into your own namespace.

| Endpoint | |
| --- | --- |
| `GET /api/tenants/{team}/credentials` | list keys (no secrets) |
| `POST /api/tenants/{team}/credentials` | mint one; **the secret is returned once and never again** |
| `DELETE /api/tenants/{team}/credentials/{accessKeyId}` | revoke |

All three are **owner-only**: a key is unrestricted read/write over everything
the team owns, so issuing one is closer to adding an owner than adding a member.
There are no per-namespace or read-only keys.

Buckets created with a team key are **owned by that team**, so they show up in
`/ui` and `/api` for its members — unlike buckets created with the admin
credential, which stay unowned (`tenant_id NULL`) and are invisible to every
team key.

The credential in `simplecas.toml` remains a **superuser**: it is matched before
the per-team lookup (so a database row can never shadow or impersonate it) and
it addresses every namespace, owned or not, so a `CreateBucket` clash is always
`BucketAlreadyOwnedByYou` for it. Treat it as a root key.

> Secrets in `tenant_credentials` are stored **recoverably, not hashed**. SigV4
> is symmetric HMAC — the server has to re-derive the signing key from the
> secret to check a signature, so a one-way hash cannot work. Treat that table
> as equivalent to the objects it grants access to.

Tenanted S3 access requires `[auth] enabled = true`, and with OIDC on the server
will not start without it. With auth off (and OIDC off) there are no credentials
to tell apart, so the gateway is the open admin plane it has always been
(`aws s3 --no-sign-request`).

## S3 gateway

Path-style, e.g. `PUT http://host:9000/mybucket/path/to/key`. Over the S3 wire a
*bucket* is a simplecas *namespace* — the gateway speaks S3's vocabulary, the DB,
JSON API and PWA call the same thing a namespace. Supported:

- Service: `ListBuckets`
- Bucket: `CreateBucket`, `DeleteBucket` (must be empty), `HeadBucket`,
  `GetBucketLocation`, `ListObjects` (V1) and `ListObjectsV2` — prefix,
  delimiter, pagination, `DeleteObjects` (batch)
- Object: `PutObject`, `GetObject` (incl. **range** requests), `HeadObject`,
  `DeleteObject`, `CopyObject` (metadata-only — no bytes moved; keeps the
  source's `Content-Type`, or takes the request's with
  `x-amz-metadata-directive: REPLACE`)
- Multipart: initiate, upload part, upload part copy (`x-amz-copy-source`,
  optionally with `x-amz-copy-source-range`), list parts, list uploads,
  complete, abort
- Tagging: `GetObjectTagging` answers an empty tag set. Tags are not stored, but
  the AWS CLI reads them before every `aws s3 cp` between buckets.

Auth is AWS **SigV4** (header-signed), toggled by `[auth] enabled`. When
disabled, anonymous access works (`aws s3 --no-sign-request`, or put the server
behind your own ingress auth). Two kinds of credential verify here: the
superuser key from `simplecas.toml`, and per-team keys that see only their own
team's buckets — see [Per-team S3 credentials](#per-team-s3-credentials).

A signed request is good for **15 minutes** either side of the server's clock
(`RequestTimeTooSkewed` past that), and its credential scope must carry the same
date as `x-amz-date` and the `s3` service, so a captured request cannot be
replayed later. Keep server clocks synced.

A signature covers the headers, so the body is held to what they claim about it,
in the same pass that stages it: nothing is committed, and the staged bytes are
discarded, unless every claim holds.

- `x-amz-content-sha256` is required on a signed request (`InvalidRequest`
  without it). A hex digest must match the body (`XAmzContentSHA256Mismatch`);
  `UNSIGNED-PAYLOAD` leaves the body unsigned, as on S3.
- `Content-MD5` (`InvalidDigest` if malformed) and `x-amz-checksum-crc32`,
  `-crc32c`, `-crc64nvme`, `-sha1` and `-sha256`, as headers or as an
  `aws-chunked` trailer announced in `x-amz-trailer`, must match the body
  (`BadDigest`). A matching checksum is echoed on the `PutObject` and
  `UploadPart` response. The AWS CLI sends CRC64NVME by default.

Request bodies framed as **`aws-chunked`** are decoded before hashing. The AWS
SDKs use that framing whenever they cannot hash a payload up front — an
unseekable stream, or a request carrying a trailing checksum — so a server that
ignored it would store the chunk headers as part of the object. Under
`STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]` every chunk signature, and the
trailer signature, is verified in a chain from the request's
(`SignatureDoesNotMatch`); `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, which the CLI
sends over TLS, is held to its trailing checksum instead. The decoded body must
match `x-amz-decoded-content-length` and end with the final zero-length chunk,
so a cut-off upload is rejected rather than stored short.

S3 subresources the gateway does not implement (`PUT`/`DELETE ?tagging`, `?acl`, `?cors`,
`?lifecycle`, …) are answered **`501 NotImplemented`** instead of falling through
to the plain object or bucket operation.

Objects are served with `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox` (PDF excepted), and with
`Content-Disposition: attachment` unless they are a raster image, audio, video,
PDF or plain text. Uploads share the PWA's origin and session cookie, so an
uploaded HTML or SVG file must never render there as a page.

Every response carries an `X-Amz-Request-Id`. Internal errors return a generic
message plus that ID (`<RequestId>` in XML, `request_id` in JSON); the cause is
logged server-side under the same ID.

**Deliberately unsupported:** versioning, ACLs/bucket policies, presigned URLs,
POST-policy uploads, virtual-host-style addressing. ETags are BLAKE3 digests,
not MD5.

### Example with the AWS CLI

```bash
export AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x
E="--endpoint-url http://localhost:9000 --no-sign-request"
aws $E s3 mb s3://demo
aws $E s3 cp ./bigfile s3://demo/bigfile      # multipart handled automatically
aws $E s3 ls s3://demo/
aws $E s3 cp s3://demo/bigfile ./out
```

## Uploads (PWA)

The bundled PWA uploads through the JSON admin API (`/api`), not the S3 gateway,
and picks a strategy by file size — all orchestrated in a dedicated Web Worker so
the UI thread never blocks:

- **Small files** (< 16 MiB) — a single `PUT`. The server hashes and dedups on
  arrival, so nothing extra is needed client-side.
- **Large files** (≥ 16 MiB) — the worker BLAKE3-hashes the file, then attempts a
  zero-byte **link** (`PUT …/{key}?link=<hash>`). If the content already exists
  in your team the object is created without transferring a byte; otherwise
  (`404`) the worker streams
  it as **parallel multipart** (initiate → upload parts with bounded concurrency
  and per-part retries → complete), auto-aborting on failure. Part size scales up
  automatically so the part count stays within S3's 10 000 limit.

The admin API mirrors the S3 multipart verbs: `POST …?uploads` (initiate),
`PUT …?uploadId&partNumber` (upload part), `GET …?uploadId` (list parts, for
resume), `POST …?uploadId` (complete, JSON manifest), `DELETE …?uploadId`
(abort).

Abandoned uploads (initiated but never completed or aborted) are reclaimed by a
background sweeper after `[gc] multipart_expiry_secs` of inactivity — this is the
only thing that frees their staged part bytes, which are otherwise protected from
the ordinary staging sweeper.

## Architecture notes

- **Stateless servers.** All coordination is in Postgres; blob bytes are in the
  backend. Scale horizontally by running more instances.
- **GC safety under concurrency.** The blob refcount row is the serialization
  point: `claim_blob` and the GC sweep both take `FOR UPDATE` on it, so a blob
  being swept cannot be re-referenced mid-delete, and a newly-referenced blob is
  never collected.
- **Crash safety.** A committed object row always has backing bytes (bytes are
  copied from staging before the transaction commits). Orphaned staging files
  from interrupted uploads are cleaned up by the staging sweeper, and abandoned
  multipart uploads (with their staged parts) by the multipart sweeper.

## Source layout

```
cmd/simplecas/       entrypoint: config, pool, bucket, routes, GC task, shutdown
internal/
  apperr/            error type carrying an S3 code + HTTP status; XML and JSON rendering
  config/            layered TOML + SIMPLECAS__ env config; backend selection
  storage/           blob backend construction + the blobs/ and staging/ layout
  db/                all SQL: namespaces, users, tenants + invitations, blobs/refcounts, objects, multipart, GC
  db/migrations/     embedded SQL migrations (run automatically on boot)
  cas/               content-addressed write path (stage → claim → commit) and the GC loop
  s3/                S3 gateway: handlers, XML wire types, SigV4 verification
  api/               JSON admin API for the PWA
  auth/              OIDC sign-in: discovery, signed-cookie sessions, guard middleware
  ui/                serves the embedded PWA
  server/            route precedence across the four surfaces + request logging
  reserved/          namespace names kept back from creation (routed segments, health probes)
  testdb/            per-test Postgres schemas (test-only)
e2e/                 AWS CLI end-to-end tests against the assembled server
web/                 Vite + React + Tailwind PWA (shadcn/ui, ggoggam/shadcn-treeview)
web/embed.go         go:embed of web/dist, so the PWA ships inside the binary
mise.toml            toolchain pins + dev/build/test tasks (`mise tasks`)
```

### A note on routing

Requests are dispatched on their first path segment rather than by
`http.ServeMux`, because `ServeMux` cleans request paths — collapsing `//` and
resolving `.` and `..` segments with a redirect — and S3 object keys may
legitimately contain those sequences. The routed first segments are therefore
`api` and `ui`, plus `auth` whenever sign-in is enabled. Creating a namespace
named `api`, `ui`, `auth`, `healthz` or `readyz` is refused with
`InvalidBucketName` whether or not sign-in is on (the last two are held for
health endpoints); the list lives in `internal/reserved`. A namespace created
with one of these names before it was reserved is left as it is.

### Tests

`go test ./...` runs everything, skipping the database-backed tests unless
`SIMPLECAS_TEST_DATABASE_URL` is set (`mise run test:integration` starts the dev
Postgres and sets it). Each such test provisions its own Postgres schema and
drops it afterwards, so packages can run concurrently without interfering.

`e2e/` runs the real AWS CLI v2 (`aws s3` and `aws s3api`) against an in-process
server assembled the way `main.go` does: buckets, `cp` up, down and between
buckets, `mv`, `sync`, `rm`, listings and pagination, multipart (including
`UploadPartCopy`), signatures, team keys, and aws-chunked uploads over TLS. It
skips unless the database variable is set and `aws` v2 is on `PATH`; mise
installs the CLI, and `mise run test:e2e` runs just this suite.
