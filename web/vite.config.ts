import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// Built assets are embedded into the Rust binary and served under /ui/.
export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  // hash-wasm is imported only inside the upload Web Worker, so Vite's startup
  // scanner never sees it and would otherwise discover it at runtime on the
  // first upload — forcing a mid-interaction re-optimize + full page reload.
  // Pre-bundling it here keeps the first upload instant.
  optimizeDeps: { include: ["hash-wasm"] },
  server: {
    // `bun dev` proxies API + auth calls to a locally running simplecas.
    // NOTE: full OIDC sign-in still can't complete through the Vite origin —
    // the provider's redirect_uri and the session cookie both belong to the
    // backend's public_url origin — so exercise auth against the backend
    // directly at http://localhost:9100/ui/. Proxying /auth here just keeps
    // /auth/me reachable so the app doesn't mistake Vite's HTML for a response.
    proxy: {
      "/api": "http://localhost:9100",
      "/auth": "http://localhost:9100",
    },
  },
});
