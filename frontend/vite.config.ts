/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Development: `mizar serve` on 8730 with MIZAR_API_TOKEN set, and
// MIZAR_EXTRA_ALLOWED_ORIGINS='["http://localhost:5173"]' so the proxied browser origin is accepted.
const backend = process.env.MIZAR_BACKEND ?? "http://127.0.0.1:8730";
const devToken = process.env.MIZAR_API_TOKEN ?? "";

export default defineConfig({
  plugins: [
    react(),
    {
      name: "mizar-dev-token",
      apply: "serve",
      // In production the backend fills this meta tag when it serves index.html.
      transformIndexHtml: (html) => html.replace('content="__MIZAR_TOKEN__"', `content="${devToken}"`),
    },
  ],
  server: { port: 5173, proxy: { "/api": { target: backend, changeOrigin: true } } },
  build: { outDir: "dist", sourcemap: false, assetsDir: "assets" },
  test: { environment: "jsdom", include: ["src/**/*.test.tsx", "src/**/*.test.ts"] },
});
