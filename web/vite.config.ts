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
    // `bun dev` proxies API calls to a locally running simplecas.
    proxy: {
      "/api": "http://localhost:9100",
    },
  },
});
