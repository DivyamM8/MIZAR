import { defineConfig } from "@playwright/test";

// Drives the installed Google Chrome against a running `mizar serve` (MIZAR_URL).
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: process.env.MIZAR_URL ?? "http://127.0.0.1:8730",
    channel: "chrome",
    headless: true,
    viewport: { width: 1440, height: 900 },
  },
});
