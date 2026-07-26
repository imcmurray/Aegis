import { defineConfig } from "vite";

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
});
