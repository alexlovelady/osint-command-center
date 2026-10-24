import { defineConfig } from "@playwright/test";

// Uses the system Microsoft Edge (no browser download). The backend is the real app with a mocked network (scripts/e2e_server.py).
const API = 8792;
const WEB = 5174;
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: `http://127.0.0.1:${WEB}`, channel: "msedge", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: [
    { command: `uv run python ../../scripts/e2e_server.py ${API} ${WEB}`, url: `http://127.0.0.1:${API}/api/v1/health/live`, reuseExistingServer: false, timeout: 60_000 },
    { command: `pnpm exec vite --host 127.0.0.1 --port ${WEB} --strictPort`, url: `http://127.0.0.1:${WEB}`, reuseExistingServer: false, timeout: 60_000,
      env: { OSINTCC_BACKEND: `http://127.0.0.1:${API}` } },
  ],
});
