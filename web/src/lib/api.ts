// Client for the simplecas admin JSON API (served under /api by the same
// origin that serves this PWA).

import type {
  UploadJob,
  UploadPhase,
  WorkerMessage,
} from "./upload-protocol";

export interface Stats {
  namespace_count: number;
  object_count: number;
  blob_count: number;
  logical_bytes: number;
  physical_bytes: number;
  dedup_ratio: number;
  saved_bytes: number;
}

export interface Namespace {
  name: string;
  created_at: string;
}

export interface Identity {
  sub: string;
  email: string | null;
  name: string | null;
  provider: string;
}

export type Role = "owner" | "member";

export interface Tenant {
  name: string;
  role: Role;
  created_at: string;
}

export interface Member {
  /** Addresses the member in the role-change and removal calls. */
  id: number;
  /** Display only; empty when the member's provider verified no address. */
  email: string;
  name: string;
  role: Role;
  created_at: string;
  /** The signed-in caller's own row — the one they may remove to leave. */
  you: boolean;
}

/**
 * A pending offer of team membership, addressed to an email. It grants nothing
 * until the signed-in holder of that verified address accepts it.
 */
export interface Invitation {
  tenant: string;
  email: string;
  role: Role;
  invited_by: string | null;
  created_at: string;
  /** null only for a membership carried over from before invitations. */
  expires_at: string | null;
}

/**
 * One of the signed-in user's sessions: a browser they signed in from. It
 * stays live until it expires, signs out, or is revoked from here.
 */
export interface Session {
  /** Addresses the session in the revoke call. */
  id: string;
  created_at: string;
  /** Moved forward at most every few minutes, so "now" means "recently". */
  last_seen_at: string;
  expires_at: string;
  /** What the browser sent when it signed in; display only. */
  user_agent: string;
  /** The connection's address; behind a reverse proxy, the proxy's. */
  ip: string;
  /** The session making this request. */
  current: boolean;
}

/** An S3 access key belonging to a team. Never carries the secret. */
export interface Credential {
  access_key_id: string;
  description: string;
  created_at: string;
  /** Null for a key that never expires. Expired keys stay listed. */
  expires_at: string | null;
  /** Null for a key that has never signed a request. */
  last_used_at: string | null;
  /** The minting owner's address, or "" when it is not known. */
  created_by: string;
}

/**
 * The response to minting a key — the only time the secret is ever sent, so
 * the UI has to show it before this value is discarded.
 */
export interface CreatedCredential {
  access_key_id: string;
  secret_access_key: string;
  description: string;
  expires_at: string | null;
}

export interface ObjectEntry {
  key: string;
  size: number;
  etag: string;
  content_type: string;
  last_modified: string;
}

export interface ListResponse {
  objects: ObjectEntry[];
  common_prefixes: string[];
  next_token: string | null;
}

async function req(input: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(input, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.message ?? detail;
    } catch {
      // non-JSON error body; keep statusText
    }
    throw new Error(detail);
  }
  return res;
}

// Send the browser to the sign-in page, coming back here afterwards. Never
// resolves: the page is going away, and a loader awaiting this must not go on
// to render as though signed out in the meantime.
function redirectToLogin(): Promise<never> {
  const here = window.location.pathname + window.location.search;
  window.location.assign(
    `/auth/login?${new URLSearchParams({ redirect: here })}`,
  );
  return new Promise<never>(() => {});
}

export const api = {
  async stats(): Promise<Stats> {
    return (await req("/api/stats")).json();
  },

  // The signed-in identity, or null when sign-in genuinely isn't in effect:
  //   * 401 — OIDC is enabled but there's no valid session (not signed in).
  //   * 404 — the /auth endpoints aren't mounted (OIDC disabled).
  // Any *other* outcome (network failure, 5xx, or a non-JSON body — e.g. a proxy
  // or stale service worker returning HTML) is a genuine load failure and is
  // thrown, so the route loader can surface it and retry instead of silently
  // hiding the signed-in UI (which is what made the logout button vanish).
  async me(): Promise<Identity | null> {
    let res: Response;
    try {
      res = await fetch("/auth/me", { headers: { accept: "application/json" } });
    } catch (e) {
      throw new Error(`identity request failed: ${(e as Error).message}`);
    }
    if (res.status === 401 || res.status === 404) return null;
    if (!res.ok) throw new Error(`identity request failed: ${res.status}`);
    if (!res.headers.get("content-type")?.includes("application/json")) {
      throw new Error("identity request returned a non-JSON response");
    }
    return res.json();
  },

  // Probe multi-tenancy from `/api/tenants`:
  //   * 200 — OIDC is enabled and the caller is signed in: teams mode.
  //   * 403 — OIDC is disabled, so there is nobody for a team to belong to:
  //     the untenanted admin view.
  //   * 401 — OIDC is enabled but the session is gone (expired, or signed out
  //     in another tab): off to the login page, never the untenanted view.
  // Anything else (network failure, 5xx, a non-JSON body) is a load failure
  // and is thrown, like `me()`, rather than passed off as "untenanted".
  async tenancy(): Promise<
    { mode: "teams"; teams: Tenant[] } | { mode: "untenanted"; teams: [] }
  > {
    let res: Response;
    try {
      res = await fetch("/api/tenants", {
        headers: { accept: "application/json" },
      });
    } catch (e) {
      throw new Error(`team request failed: ${(e as Error).message}`);
    }
    if (res.status === 401) return redirectToLogin();
    if (res.status === 403) return { mode: "untenanted", teams: [] };
    if (!res.ok) throw new Error(`team request failed: ${res.status}`);
    if (!res.headers.get("content-type")?.includes("application/json")) {
      throw new Error("team request returned a non-JSON response");
    }
    return { mode: "teams", teams: await res.json() };
  },

  // Sign out: POST to the logout endpoint, which clears the session cookie,
  // then go to the login page. Logout is POST-only so that another site can't
  // sign the user out with a link. A failure is thrown for the caller to
  // report: navigating anyway would land on a login page that, with the
  // session still valid, bounces straight back.
  async logout(): Promise<void> {
    let res: Response;
    try {
      res = await fetch("/auth/logout", { method: "POST" });
    } catch (e) {
      throw new Error(`sign-out failed: ${(e as Error).message}`);
    }
    if (!res.ok) throw new Error(`sign-out failed: ${res.status}`);
    window.location.assign("/auth/login");
  },

  // The caller's own sessions. Like the team calls, these need sign-in, and
  // reject with 403 when OIDC is off.
  async listSessions(): Promise<Session[]> {
    return (await req("/api/me/sessions")).json();
  },

  // Revoking a session signs that browser out on its next request.
  async revokeSession(id: string): Promise<void> {
    await req(`/api/me/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  },

  // Sign out everywhere but here. Resolves to how many sessions ended.
  async revokeOtherSessions(): Promise<number> {
    const res = await req("/api/me/sessions/revoke-others", { method: "POST" });
    return (await res.json()).revoked;
  },

  // Sign out everywhere, here included: end every session, then log out so
  // this browser drops its now-dead cookie and lands on the login page.
  async signOutEverywhere(): Promise<void> {
    await req("/api/me/sessions/revoke-all", { method: "POST" });
    await this.logout();
  },

  // Teams (multi-tenancy). These succeed only when OIDC is enabled and the
  // caller is signed in; otherwise they reject (e.g. 403). `tenancy()` decides
  // which view to show. See README "Teams".
  async listTenants(): Promise<Tenant[]> {
    return (await req("/api/tenants")).json();
  },

  async createTenant(name: string): Promise<void> {
    await req("/api/tenants", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name }),
    });
  },

  async deleteTenant(name: string): Promise<void> {
    await req(`/api/tenants/${encodeURIComponent(name)}`, { method: "DELETE" });
  },

  async listMembers(tenant: string): Promise<Member[]> {
    return (
      await req(`/api/tenants/${encodeURIComponent(tenant)}/members`)
    ).json();
  },

  // Owner-only. A team keeps at least one owner, so demoting the last one is
  // refused.
  async setMemberRole(tenant: string, id: number, role: Role): Promise<void> {
    await req(`/api/tenants/${encodeURIComponent(tenant)}/members/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ role }),
    });
  },

  // Owners remove anyone; a member may remove only themselves (leaving).
  async removeMember(tenant: string, id: number): Promise<void> {
    await req(`/api/tenants/${encodeURIComponent(tenant)}/members/${id}`, {
      method: "DELETE",
    });
  },

  // Invitations, from the team's side. All three are owner-only.
  async listInvitations(tenant: string): Promise<Invitation[]> {
    return (
      await req(`/api/tenants/${encodeURIComponent(tenant)}/invitations`)
    ).json();
  },

  async invite(tenant: string, email: string, role: Role): Promise<void> {
    await req(`/api/tenants/${encodeURIComponent(tenant)}/invitations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, role }),
    });
  },

  async revokeInvitation(tenant: string, email: string): Promise<void> {
    await req(
      `/api/tenants/${encodeURIComponent(tenant)}/invitations/${encodeURIComponent(email)}`,
      { method: "DELETE" },
    );
  },

  // Invitations addressed to the caller's verified email.
  async myInvitations(): Promise<Invitation[]> {
    return (await req("/api/invitations")).json();
  },

  async acceptInvitation(tenant: string): Promise<void> {
    await req(`/api/invitations/${encodeURIComponent(tenant)}/accept`, {
      method: "POST",
    });
  },

  async declineInvitation(tenant: string): Promise<void> {
    await req(`/api/invitations/${encodeURIComponent(tenant)}/decline`, {
      method: "POST",
    });
  },

  // S3 access keys. All three are owner-only server-side; a member gets 403.
  async listCredentials(tenant: string): Promise<Credential[]> {
    return (
      await req(`/api/tenants/${encodeURIComponent(tenant)}/credentials`)
    ).json();
  },

  // The resolved value carries the secret, which the server will not repeat.
  // `expiresInDays` null mints a key that never expires.
  async createCredential(
    tenant: string,
    description: string,
    expiresInDays: number | null,
  ): Promise<CreatedCredential> {
    return (
      await req(`/api/tenants/${encodeURIComponent(tenant)}/credentials`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          expiresInDays === null
            ? { description }
            : { description, expires_in_days: expiresInDays },
        ),
      })
    ).json();
  },

  async deleteCredential(tenant: string, accessKeyId: string): Promise<void> {
    await req(
      `/api/tenants/${encodeURIComponent(tenant)}/credentials/${encodeURIComponent(accessKeyId)}`,
      { method: "DELETE" },
    );
  },

  // `tenant` scopes the listing to one team; omit for the untenanted view.
  async listNamespaces(tenant?: string): Promise<Namespace[]> {
    const q = tenant ? `?tenant=${encodeURIComponent(tenant)}` : "";
    return (await req(`/api/namespaces${q}`)).json();
  },

  // `tenant` names the owning team; required when signed in, ignored otherwise.
  async createNamespace(name: string, tenant?: string): Promise<void> {
    await req("/api/namespaces", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(tenant ? { name, tenant } : { name }),
    });
  },

  async deleteNamespace(name: string): Promise<void> {
    await req(`/api/namespaces/${encodeURIComponent(name)}`, { method: "DELETE" });
  },

  async list(
    namespace: string,
    prefix: string,
    delimiter: string | null,
    token?: string,
  ): Promise<ListResponse> {
    const params = new URLSearchParams({ prefix });
    if (delimiter) params.set("delimiter", delimiter);
    if (token) params.set("token", token);
    return (
      await req(`/api/namespaces/${encodeURIComponent(namespace)}/objects?${params}`)
    ).json();
  },

  // Path segments must not URL-encode "/" (keys are hierarchical), so encode
  // each segment individually.
  objectUrl(namespace: string, key: string): string {
    const encKey = key.split("/").map(encodeURIComponent).join("/");
    return `/api/namespaces/${encodeURIComponent(namespace)}/objects/${encKey}`;
  },

  async deleteObject(namespace: string, key: string): Promise<void> {
    await req(this.objectUrl(namespace, key), { method: "DELETE" });
  },

  // Smart upload: offloads hashing + transfer to a Web Worker. Large files are
  // hashed and, if the content already exists, linked with zero bytes uploaded;
  // otherwise they stream via parallel multipart. Small files take a single PUT.
  uploadSmart(
    namespace: string,
    key: string,
    file: File,
    onProgress?: (p: UploadProgress) => void,
  ): Promise<UploadResult> {
    const id = nextJobId++;
    return new Promise<UploadResult>((resolve, reject) => {
      jobs.set(id, { resolve, reject, onProgress });
      const job: UploadJob = {
        id,
        namespace,
        key,
        contentType: file.type,
        file,
      };
      getWorker().postMessage(job);
    });
  },
};

export interface UploadProgress {
  fraction: number;
  phase: UploadPhase;
}

export interface UploadResult {
  etag: string;
  size: number;
  deduped: boolean;
}

interface PendingJob {
  resolve: (r: UploadResult) => void;
  reject: (e: Error) => void;
  onProgress?: (p: UploadProgress) => void;
}

const jobs = new Map<number, PendingJob>();
let nextJobId = 1;
let worker: Worker | null = null;

function getWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL("./upload-worker.ts", import.meta.url), {
    type: "module",
  });
  worker.onmessage = (e: MessageEvent<WorkerMessage>) => {
    const msg = e.data;
    const job = jobs.get(msg.id);
    if (!job) return;
    if (msg.type === "progress") {
      job.onProgress?.({ fraction: msg.fraction, phase: msg.phase });
    } else if (msg.type === "done") {
      jobs.delete(msg.id);
      job.resolve({ etag: msg.etag, size: msg.size, deduped: msg.deduped });
    } else {
      jobs.delete(msg.id);
      job.reject(new Error(msg.message));
    }
  };
  return worker;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
