import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The dev server proxies /api to the loopback backend so the browser never needs CORS wildcards.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: process.env.OSINTCC_BACKEND ?? "http://127.0.0.1:8791", changeOrigin: false } } },
  test: { exclude: ["e2e/**", "node_modules/**"], environment: "jsdom", setupFiles: ["./src/test-setup.ts"], globals: true },
});
