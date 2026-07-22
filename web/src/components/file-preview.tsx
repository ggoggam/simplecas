import { useEffect, useState } from "react";
import { FileQuestion, Loader2 } from "lucide-react";
import { formatBytes } from "@/lib/api";

export type PreviewKind = "image" | "video" | "audio" | "pdf" | "text" | "none";

// Read at most this many bytes for a text preview; the fetch uses a Range
// request so we never pull a whole multi-gigabyte object over the wire.
const TEXT_CAP = 512 * 1024;

const TEXT_CT =
  /^(text\/|application\/(json|ld\+json|xml|javascript|ecmascript|x-yaml|yaml|x-sh|x-httpd-php|graphql|csv|x-ndjson))/;
const IMG_EXT = /\.(png|jpe?g|gif|webp|avif|svg|bmp|ico)$/i;
const VIDEO_EXT = /\.(mp4|webm|ogv|mov|m4v)$/i;
const AUDIO_EXT = /\.(mp3|wav|ogg|oga|flac|aac|m4a|opus)$/i;
const TEXT_EXT =
  /\.(txt|md|markdown|mdx|json|jsonc|ya?ml|toml|ini|cfg|conf|log|csv|tsv|xml|svg|html?|css|s[ac]ss|less|jsx?|tsx?|mjs|cjs|vue|svelte|py|rb|rs|go|java|kt|c|h|cpp|hpp|cc|cs|php|sh|bash|zsh|fish|sql|env|lock|gitignore|dockerfile|makefile|properties|gradle)$/i;

/** Decide how (if at all) an object can be previewed, from its content-type
 *  with a filename-extension fallback when the type is generic/unknown. */
export function previewKind(contentType: string, name: string): PreviewKind {
  const c = (contentType || "").toLowerCase();
  if (c.startsWith("image/")) return "image";
  if (c.startsWith("video/")) return "video";
  if (c.startsWith("audio/")) return "audio";
  if (c === "application/pdf") return "pdf";
  if (TEXT_CT.test(c)) return "text";

  const generic =
    c === "" ||
    c === "application/octet-stream" ||
    c === "binary/octet-stream";
  if (generic) {
    if (IMG_EXT.test(name)) return "image";
    if (VIDEO_EXT.test(name)) return "video";
    if (AUDIO_EXT.test(name)) return "audio";
    if (TEXT_EXT.test(name)) return "text";
  }
  return "none";
}

export function canPreview(contentType: string, name: string): boolean {
  return previewKind(contentType, name) !== "none";
}

/** Renders an object inline according to its preview kind. Fills the height of
 *  its container, so give it a sized parent. */
export function FilePreview({
  url,
  name,
  contentType,
}: {
  url: string;
  name: string;
  contentType: string;
}) {
  const kind = previewKind(contentType, name);

  switch (kind) {
    case "image":
      return (
        <div className="flex h-full w-full items-center justify-center overflow-auto p-2">
          <img
            src={url}
            alt={name}
            className="max-h-full max-w-full object-contain"
          />
        </div>
      );
    case "video":
      return (
        <div className="flex h-full w-full items-center justify-center bg-black/60 p-2">
          <video src={url} controls className="max-h-full max-w-full" />
        </div>
      );
    case "audio":
      return (
        <div className="flex h-full w-full items-center justify-center p-6">
          <audio src={url} controls className="w-full max-w-md" />
        </div>
      );
    case "pdf":
      return (
        <iframe
          src={url}
          title={name}
          className="h-full w-full border-0 bg-white"
        />
      );
    case "text":
      return <TextPreview url={url} />;
    default:
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center text-sm text-muted-foreground">
          <FileQuestion className="size-8" />
          <p>No inline preview for this file type.</p>
          <p className="text-xs">Use Download to open it locally.</p>
        </div>
      );
  }
}

function TextPreview({ url }: { url: string }) {
  const [state, setState] = useState<{
    loading: boolean;
    text?: string;
    error?: string;
    truncated?: boolean;
  }>({ loading: true });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true });
    (async () => {
      try {
        const res = await fetch(url, {
          headers: { Range: `bytes=0-${TEXT_CAP - 1}` },
        });
        if (!res.ok && res.status !== 206) throw new Error(res.statusText);
        const buf = await res.arrayBuffer();
        // content-range is "bytes 0-N/TOTAL"; fall back to content-length.
        const total = Number(
          res.headers.get("content-range")?.split("/")[1] ??
            res.headers.get("content-length") ??
            buf.byteLength,
        );
        const text = new TextDecoder().decode(buf);
        if (!cancelled)
          setState({
            loading: false,
            text,
            truncated: Number.isFinite(total) && total > buf.byteLength,
          });
      } catch (e) {
        if (!cancelled)
          setState({ loading: false, error: (e as Error).message });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [url]);

  if (state.loading)
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="size-5 animate-spin text-muted-foreground" />
      </div>
    );
  if (state.error)
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-sm text-destructive">
        Failed to load preview: {state.error}
      </div>
    );

  return (
    <div className="flex h-full flex-col">
      {state.truncated && (
        <div className="shrink-0 border-b bg-muted/50 px-4 py-1.5 text-xs text-muted-foreground">
          Preview truncated to the first {formatBytes(TEXT_CAP)}.
        </div>
      )}
      <pre className="min-h-0 flex-1 overflow-auto p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
        {state.text}
      </pre>
    </div>
  );
}
