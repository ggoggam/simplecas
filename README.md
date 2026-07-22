# simplecas

A distributed **content-addressable storage** server with an **S3-compatible
gateway**, **global file-level deduplication**, pluggable storage backends, and
a bundled **PWA** for managing objects.

- **Rust** (axum + tokio) for the server.
- **PostgreSQL** as the shared metadata store, so you can run many stateless
  server instances behind a load balancer.
- **[OpenDAL](https://opendal.apache.org/)** for storage, so blobs can live on
  the local filesystem, **S3** (incl. MinIO / R2), **GCS**, or **Azure Blob**
  with a one-line config change.
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

## Development

Install [mise](https://mise.jdx.dev) — it provisions the toolchain (Rust, Bun,
cargo-watch) and drives every workflow. Docker is used for a throwaway Postgres.

```bash
mise install         # install pinned tools
mise run dev         # dev Postgres + auto-reloading backend + Vite dev server
```

`mise run dev` starts three things: a dev Postgres container on `:55432`, the
backend on `:9100` (rebuilt on Rust changes via cargo-watch), and the Vite dev
server with hot module reload. Open the URL Vite prints — it proxies `/api` to
the backend. Migrations run automatically on backend startup.

| Task                | What it does                                             |
|---------------------|---------------------------------------------------------|
| `mise run dev`      | Full watch-dev loop (Postgres + backend + Vite)         |
| `mise run up`       | Full stack in Docker on `:9000`                          |
| `mise run down`     | Tear down the Docker stack (`down:clean` wipes volumes) |
| `mise run logs`     | Follow Docker stack logs                                 |
| `mise run db`       | Start just the dev Postgres (`db:stop` to remove it)    |
| `mise run build`    | Production build: PWA then release binary                |
| `mise run test`     | Rust test suite (`check`, `fmt`, `clippy` also defined) |
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

## Authentication

There are two independent auth mechanisms for the two kinds of client:

- **S3 gateway (`/`)** — AWS **SigV4**, for machine clients. Toggled by
  `[auth] enabled` (see above). Unaffected by OIDC.
- **Web surface (`/ui` + `/api`)** — optional **OIDC** single sign-on, for
  humans. When enabled, both are gated behind a login; the S3 gateway is not.

### OIDC single sign-on

*Authentication* is deliberately lean and stateless: **any identity that
authenticates at a configured provider is admitted** (optionally narrowed by an
email allowlist), and the session is a stateless **HMAC-signed cookie** — no
session table, no server-side revocation. Every instance behind a load balancer
only needs the same `session_secret`. *Authorization* (who may see which
namespaces) is layered on top via **teams** — see below.

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
`/auth/oidc/{id}/callback`, `/auth/logout`, and `/auth/me` (current identity as
JSON). Unauthenticated `/api` calls get `401`; unauthenticated page loads
redirect to `/auth/login`.

> **Note:** OIDC gates the bundled PWA and admin API only. If you expose the S3
> gateway publicly, protect it with `[auth]` SigV4 or your own ingress.

### Teams (multi-tenancy)

When OIDC is enabled the human plane (`/ui` + `/api`) is **multi-tenant**: each
namespace is owned by a **team**, and a signed-in user sees and touches only the
namespaces of teams they belong to. Isolation is enforced per request; a
namespace a caller can't access is reported as *not found*, so existence never
leaks across teams.

- **Membership** is keyed by **verified email** — you invite by email, and the
  invitee gains access on their next sign-in. Two roles: `owner` (manage
  membership, delete the team) and `member` (read/write the team's namespaces).
  A team always keeps at least one owner. Tenancy requires a verified email; an
  identity whose provider doesn't assert `email_verified` gets no team access.
- **Self-serve**: any signed-in user can create a team and becomes its owner.
- **Dedup stays global** across all content, but the client-side dedup "link"
  fast path is scoped to your own team, so it can't be used to probe whether
  another team holds a given blob. A genuine re-upload of identical bytes is
  still physically de-duplicated (nothing new is stored).

No config is required — tenancy is automatic whenever OIDC is on. There is no
users/teams state when OIDC is off; then `/api` is the unauthenticated
full-access plane it has always been.

API (JSON, cookie-authenticated): `GET/POST /api/tenants`,
`DELETE /api/tenants/{team}`, `GET/POST /api/tenants/{team}/members`,
`DELETE /api/tenants/{team}/members/{email}`. Creating a namespace
(`POST /api/namespaces`) takes a `tenant` field naming the owning team.

> **The S3 gateway is a single trusted admin plane** and is *not* tenant-scoped:
> its one credential has full access, and namespaces it creates are unowned
> (`tenant_id NULL`) and hidden from the team-scoped UI. Machine-client tenancy
> (per-team S3 keys) is intentionally out of scope.

## S3 gateway

Path-style, e.g. `PUT http://host:9000/mybucket/path/to/key`. Over the S3 wire a
*bucket* is a simplecas *namespace* — the gateway speaks S3's vocabulary, the DB,
JSON API and PWA call the same thing a namespace. Supported:

- Service: `ListBuckets`
- Bucket: `CreateBucket`, `DeleteBucket` (must be empty), `HeadBucket`,
  `GetBucketLocation`, `ListObjects` (V1) and `ListObjectsV2` — prefix,
  delimiter, pagination, `DeleteObjects` (batch)
- Object: `PutObject`, `GetObject` (incl. **range** requests), `HeadObject`,
  `DeleteObject`, `CopyObject` (metadata-only — no bytes moved)
- Multipart: initiate, upload part, list parts, list uploads, complete, abort

Auth is AWS **SigV4** (header-signed), toggled by `[auth] enabled`. When
disabled, anonymous access works (`aws s3 --no-sign-request`, or put the server
behind your own ingress auth).

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
  the object is created without transferring a byte; otherwise the worker streams
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
src/
  main.rs      entrypoint: config, pool, operator, router, GC task
  config.rs    layered TOML + env config; backend selection
  db.rs        all SQL: namespaces, objects, blobs/refcounts, multipart, listing, GC
  cas.rs       content-addressed write path (stage → claim → commit), GC loop
  storage.rs   OpenDAL operator construction + blob path layout
  s3/          S3 gateway: mod.rs (handlers), xml.rs (wire types), sigv4.rs (auth)
  api.rs       JSON admin API for the PWA
  auth.rs      OIDC sign-in: discovery, signed-cookie sessions, guard middleware
  ui.rs        serves the embedded PWA
migrations/    sqlx migrations (run automatically on boot)
web/           Vite + React + Tailwind PWA (shadcn/ui, ggoggam/shadcn-treeview)
mise.toml      toolchain pins + dev/build/test tasks (`mise tasks`)
```
