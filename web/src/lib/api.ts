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

export const api = {
  async stats(): Promise<Stats> {
    return (await req("/api/stats")).json();
  },

  async listNamespaces(): Promise<Namespace[]> {
    return (await req("/api/namespaces")).json();
  },

  async createNamespace(name: string): Promise<void> {
    await req("/api/namespaces", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name }),
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
