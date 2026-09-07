import { defineConfig } from "vite";

/**
 * Production CSP delivered via <meta http-equiv>. Dev server omits this so Vite HMR can run.
 *
 * Not included: frame-ancestors — CSP Level 3 requires that directive on an HTTP
 * response header; browsers ignore it in a meta element. GitHub Pages cannot set
 * CSP headers, so clickjacking is not a claimed control on that host. If Aegis is
 * later fronted by a proxy/CDN that can inject headers, add:
 *   Content-Security-Policy: …; frame-ancestors 'none'
 *
 * connect-src allows only the exact local origins used by optional modes:
 *   http://127.0.0.1:8787  — ?mode=dev (aegis-dev-vault-server)
 *   ws://127.0.0.1:7509    — ?mode=freenet WebSocket (freenet local)
 * Default browser-vault mode uses IndexedDB + same-origin WASM ('self' only).
 */
export const PRODUCTION_CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "form-action 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' http://127.0.0.1:8787 ws://127.0.0.1:7509",
  "worker-src 'self'",
  "manifest-src 'self'",
  "upgrade-insecure-requests",
].join("; ");

export default defineConfig({
  // Relative base for Freenet web-container packaging
  base: "./",
  server: {
    port: 5173,
    proxy: {
      // Freenet peer (when installed)
      "/v1/contract": {
        target: "http://127.0.0.1:7509",
        ws: true,
        changeOrigin: true,
      },
      // Optional: proxy dev vault through same origin
      "/dev-vault": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/dev-vault/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  optimizeDeps: {
    include: ["@freenetorg/freenet-stdlib", "cbor-x"],
  },
  plugins: [
    {
      name: "aegis-production-csp",
      transformIndexHtml: {
        order: "pre",
        handler(html, ctx) {
          if (ctx.server) return html;
          if (html.includes("Content-Security-Policy")) return html;
          return html.replace(
            '<meta charset="UTF-8" />',
            `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${PRODUCTION_CSP}" />`,
          );
        },
      },
    },
  ],
});
