import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import UpdatesCard from "./UpdatesCard";

function mockApi(routes: Record<string, unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    return new Response(JSON.stringify(key ? routes[key] : { code: "nf", message: "x", request_id: "r", retryable: false, details_safe: {} }), { status: key ? 200 : 404, headers: { "content-type": "application/json" } });
  });
  return calls;
}
afterEach(() => vi.restoreAllMocks());
const wrap = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><UpdatesCard /></QueryClientProvider>);

describe("UpdatesCard", () => {
  it("checks, shows the signed hash, and only downloads after confirmation", async () => {
    const calls = mockApi({
      "/settings": { update_manifest_url: "http://192.168.1.10:8800/manifest.json" },
      "/updates/check": { configured: true, current: "0.1.0", latest: "0.2.0", update_available: true, signature: "verified", released: "2026-11-01", notes: "fixes",
        artifact: { name: "setup.exe", size: 55000000, sha256: "ab".repeat(32) }, note: "n" },
      "/updates/download": { version: "0.2.0", file: "C:/data/updates/setup.exe", sha256: "ab".repeat(32), bytes: 55000000, next: "Run this file yourself." },
    });
    wrap();
    await waitFor(() => expect(screen.getByLabelText("Update server manifest URL")).toHaveValue("http://192.168.1.10:8800/manifest.json"));
    fireEvent.click(screen.getByText("Check for updates"));
    await waitFor(() => screen.getByText(/an update is available/));
    expect(screen.getByText(/setup.exe/)).toBeInTheDocument();
    expect(calls.some((c) => c.url === "/updates/download")).toBe(false);          // a check downloads nothing
    const btn = screen.getByText("Download and verify");
    expect(btn).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/download this file/));
    fireEvent.click(btn);
    await waitFor(() => screen.getByText(/Verified and saved to/));
    expect(JSON.parse(String(calls.find((c) => c.url === "/updates/download")!.init!.body))).toEqual({ confirm: true });
    expect(screen.getByText(/Run this file yourself/)).toBeInTheDocument();
  });
  it("explains when no server is configured", async () => {
    mockApi({ "/settings": { update_manifest_url: "" }, "/updates/check": { configured: false, current: "0.1.0", note: "No update server is configured." } });
    wrap();
    await waitFor(() => screen.getByText("Check for updates"));
    fireEvent.click(screen.getByText("Check for updates"));
    await waitFor(() => screen.getByText(/No update server is configured/));
  });
});
