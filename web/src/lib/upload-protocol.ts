// Shared contract between the main thread (api.ts) and the upload Web Worker.

/** Files at or above this size are hashed client-side and uploaded via
 *  multipart; smaller files take the plain single-PUT path (the server dedups
 *  them anyway, and the extra client hash isn't worth it). */
export const MULTIPART_THRESHOLD = 16 * 1024 * 1024;
/** Target part size. Scaled up automatically so part count stays ≤ 10000. */
export const PART_SIZE = 8 * 1024 * 1024;
/** Max concurrent part uploads per file. */
export const PART_CONCURRENCY = 4;
/** S3's hard cap on parts per upload — the server enforces 1..=10000 too. */
export const MAX_PARTS = 10_000;

export interface UploadJob {
  id: number;
  namespace: string;
  key: string;
  contentType: string;
  file: File;
}

export type UploadPhase = "hashing" | "uploading";

export type WorkerMessage =
  | { id: number; type: "progress"; phase: UploadPhase; fraction: number }
  | { id: number; type: "done"; etag: string; size: number; deduped: boolean }
  | { id: number; type: "error"; message: string };

/** A non-2xx response, keeping its status so callers can tell a refusal from
 *  a transient failure. */
export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Whether a failed request is worth sending again. Network errors, server
 *  errors, timeouts and rate limits may pass on a retry; any other 4xx (over
 *  quota, too large, not found) is the server's answer and will not change. */
export function isRetryable(err: unknown): boolean {
  if (!(err instanceof HttpError)) return true;
  return err.status >= 500 || err.status === 408 || err.status === 429;
}

/** Encode a hierarchical key without escaping the "/" separators. */
export function encodeKey(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

export function objectUrl(namespace: string, key: string): string {
  return `/api/namespaces/${encodeURIComponent(namespace)}/objects/${encodeKey(key)}`;
}
