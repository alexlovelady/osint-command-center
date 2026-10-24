import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import Overview from "./Overview";

function mock(egress: unknown) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input).replace("/api/v1", "");
    const body = url.startsWith("/overview") ? { open_cases: 1, pending_jobs: 0, findings: 0, offline: false, adapters: {}, storage_bytes: 0 } : egress;
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
}
const wrap = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Overview go={() => {}} /></QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

describe("start-up egress self-check card", () => {
  it("reports a clean result", async () => {
    mock({ enabled: true, state: "finished", verdict: "clean", note: "No outside connections from the app's processes during the start-up window.", samples: 45, window_s: 90, offenders: [], engine_connections: [] });
    wrap();
    await waitFor(() => screen.getByText(/no outside connections from this app/));
  });
  it("names the browser engine separately and shouts when our own process connects", async () => {
    mock({ enabled: true, state: "finished", verdict: "engine_only", note: "n", samples: 45, window_s: 90, offenders: [], engine_connections: [{ process: "msedgewebview2.exe", remote: "52.96.1.1:443" }] });
    wrap();
    await waitFor(() => screen.getByText(/the app made none; its browser engine did/));
    expect(screen.getByText("52.96.1.1:443")).toBeInTheDocument();
    vi.restoreAllMocks();
    mock({ enabled: true, state: "finished", verdict: "offending", note: "n", samples: 45, window_s: 90, offenders: [{ process: "osintcc-backend.exe", remote: "8.8.8.8:443" }], engine_connections: [] });
    wrap();
    await waitFor(() => screen.getAllByText(/OUTSIDE CONNECTIONS DETECTED/));
  });
  it("shows nothing when the check is disabled", async () => {
    mock({ enabled: false, state: "disabled", verdict: null, note: "" });
    wrap();
    await waitFor(() => screen.getByText("Overview"));
    expect(screen.queryByText(/Start-up network self-check/)).toBeNull();
  });
});
