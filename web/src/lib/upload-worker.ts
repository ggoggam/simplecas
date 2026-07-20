// Dedicated module Web Worker: hashes files off the main thread, tries a
// zero-byte dedup "link", and otherwise uploads — single-PUT for small files,
// parallel multipart for large ones. All heavy work (hashing, byte transfer,
// retry orchestration) happens here so the UI thread stays responsive.

import { createBLAKE3 } from "hash-wasm";
import {
  MAX_PARTS,
  MULTIPART_THRESHOLD,
  PART_CONCURRENCY,
  PART_SIZE,
  objectUrl,
  type UploadJob,
  type WorkerMessage,
} from "./upload-protocol";

const HASH_CHUNK = 8 * 1024 * 1024;
const RETRIES = 3;

function post(msg: WorkerMessage) {
  self.postMessage(msg);
}

/** PUT/POST a blob with upload-progress via XHR (fetch can't report it). */
function xhrSend(
  method: "PUT" | "POST",
  url: string,
  body: Blob | string | null,
  contentType: string | null,
  onProgress?: (loaded: number) => void,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    if (contentType) xhr.setRequestHeader("content-type", contentType);
    if (onProgress)
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(e.loaded);
      };
    xhr.onload = () => resolve({ status: xhr.status, text: xhr.responseText });
    xhr.onerror = () => reject(new Error("network error"));
    xhr.send(body);
  });
}

async function okJson<T>(p: Promise<{ status: number; text: string }>): Promise<T> {
  const { status, text } = await p;
  if (status < 200 || status >= 300) {
    let msg = `HTTP ${status}`;
    try {
      msg = JSON.parse(text).message ?? msg;
    } catch {
      // keep the status-based message
    }
    throw new Error(msg);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

async function hashFile(job: UploadJob): Promise<string> {
  const hasher = await createBLAKE3();
  hasher.init();
  let offset = 0;
  while (offset < job.file.size) {
    const slice = job.file.slice(offset, offset + HASH_CHUNK);
    hasher.update(new Uint8Array(await slice.arrayBuffer()));
    offset += slice.size;
    post({
      id: job.id,
      type: "progress",
      phase: "hashing",
      fraction: job.file.size ? offset / job.file.size : 1,
    });
  }
  return hasher.digest("hex");
}

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < RETRIES; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
    }
  }
  throw lastErr;
}

async function multipartUpload(
  job: UploadJob,
  base: string,
): Promise<{ etag: string; size: number }> {
  const partSize = Math.max(PART_SIZE, Math.ceil(job.file.size / MAX_PARTS));
  const count = Math.ceil(job.file.size / partSize);

  const { upload_id } = await okJson<{ upload_id: string }>(
    xhrSend("POST", `${base}?uploads`, null, job.contentType),
  );

  try {
    const loaded = new Array<number>(count).fill(0);
    const emit = () => {
      const sum = loaded.reduce((a, b) => a + b, 0);
      post({
        id: job.id,
        type: "progress",
        phase: "uploading",
        fraction: job.file.size ? sum / job.file.size : 1,
      });
    };

    const etags = new Array<string>(count);
    let next = 0;
    const worker = async () => {
      for (let i = next++; i < count; i = next++) {
        const start = i * partSize;
        const slice = job.file.slice(start, Math.min(start + partSize, job.file.size));
        const res = await withRetry(() =>
          okJson<{ etag: string }>(
            xhrSend(
              "PUT",
              `${base}?uploadId=${upload_id}&partNumber=${i + 1}`,
              slice,
              "application/octet-stream",
              (n) => {
                loaded[i] = n;
                emit();
              },
            ),
          ),
        );
        etags[i] = res.etag;
        loaded[i] = slice.size;
        emit();
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(PART_CONCURRENCY, count) }, worker),
    );

    const parts = etags.map((etag, i) => ({ part_number: i + 1, etag }));
    const done = await okJson<{ etag: string; size: number }>(
      xhrSend("POST", `${base}?uploadId=${upload_id}`, JSON.stringify({ parts }), "application/json"),
    );
    return done;
  } catch (e) {
    // Best-effort abort so the server can reclaim staged parts promptly
    // (the expiry sweeper would eventually catch them regardless).
    try {
      await fetch(`${base}?uploadId=${upload_id}`, { method: "DELETE" });
    } catch {
      // ignore
    }
    throw e;
  }
}

async function handle(job: UploadJob) {
  const base = objectUrl(job.namespace, job.key);

  // Small files: single PUT, let the server dedup. No client hash.
  if (job.file.size < MULTIPART_THRESHOLD) {
    const done = await okJson<{ etag: string; size: number }>(
      xhrSend("PUT", base, job.file, job.contentType || "application/octet-stream", (n) =>
        post({
          id: job.id,
          type: "progress",
          phase: "uploading",
          fraction: job.file.size ? n / job.file.size : 1,
        }),
      ),
    );
    post({ id: job.id, type: "done", etag: done.etag, size: done.size, deduped: false });
    return;
  }

  // Large files: hash, try a zero-byte link, else multipart.
  const hash = await hashFile(job);
  const linked = await okJson<{ linked: boolean; etag?: string; size?: number }>(
    xhrSend("PUT", `${base}?link=${hash}`, null, job.contentType),
  );
  if (linked.linked) {
    post({
      id: job.id,
      type: "done",
      etag: linked.etag ?? hash,
      size: linked.size ?? job.file.size,
      deduped: true,
    });
    return;
  }

  const done = await multipartUpload(job, base);
  post({ id: job.id, type: "done", etag: done.etag, size: done.size, deduped: false });
}

self.onmessage = (e: MessageEvent<UploadJob>) => {
  handle(e.data).catch((err) =>
    post({ id: e.data.id, type: "error", message: (err as Error).message }),
  );
};
