import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import Setup from "./Setup";

type Handler = (url: string, init?: RequestInit) => unknown;
function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    if (!key) return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
    const v = routes[key];
    return new Response(JSON.stringify(typeof v === "function" ? (v as Handler)(url, init) : v), { headers: { "content-type": "application/json" } });
  });
  return calls;
}
afterEach(() => vi.restoreAllMocks());

const status = {
  platform: "win32-x86_64", ram_gb: 32, tools_dir: "C:/data/tools", completed: false, ollama_found: true, ai_profiles: [],
  recommended_model: { id: "m/8b", label: "Model 8B", download_gb: 5, min_ram_gb: 12 }, models: [{ id: "m/8b", label: "Model 8B", download_gb: 5, min_ram_gb: 12 }],
  tools: [
    { id: "subfinder", name: "Subfinder", version: "2.17.0", license: "MIT", homepage: "", installed: false, managed: false, path: null, installable: true, reason: null, download_mb: 10.6 },
    { id: "exiftool", name: "ExifTool", version: "13.59", license: "GPL", homepage: "", installed: true, managed: true, path: "x", installable: true, reason: null, download_mb: 11 },
    { id: "theharvester", name: "theHarvester", version: "4", license: "GPL", homepage: "", installed: false, managed: false, path: null, installable: false, reason: "does not support native Windows", download_mb: null }],
};

describe("Setup", () => {
  it("shows exact sources, refuses to start until confirmed, then sends confirm=true for tools and model", async () => {
    const calls = mockApi({
      "/setup/status": status,
      "/setup/plan": { items: [{ id: "subfinder", name: "Subfinder", version: "2.17.0", urls: ["https://github.com/projectdiscovery/subfinder/releases/x.zip"], size_mb: 10.6 }] },
      "/setup/install": { task_id: "t1", plan: [] }, "/setup/model": { task_id: "t2", model: "m/8b" },
      "/setup/tasks/t1": { id: "t1", kind: "tools", status: "done", events: [{ phase: "done", id: "subfinder" }], results: [{ id: "subfinder", reported_version: "v2.17.0" }], error: null },
      "/setup/tasks/t2": { id: "t2", kind: "model", status: "done", events: [{ phase: "model", status: "success" }], results: [], error: null },
    });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Setup /></QueryClientProvider>);
    await waitFor(() => screen.getByLabelText("Install Subfinder"));
    expect(screen.queryByLabelText("Install ExifTool")).toBeNull();                      // already installed: not offered again
    expect(screen.getByText("does not support native Windows")).toBeInTheDocument();     // unavailable tools say why
    await waitFor(() => screen.getByText("Exact sources that will be contacted"));
    expect(screen.getByText(/abliterated/)).toBeInTheDocument();                          // honest about what the model is
    const go = screen.getByText("Install selected");
    expect(go).toBeDisabled();
    expect(calls.some((c) => c.url.includes("/setup/install"))).toBe(false);
    fireEvent.click(screen.getByLabelText(/I have reviewed the sources/));
    expect(go).toBeEnabled();
    fireEvent.click(go);
    await waitFor(() => expect(calls.some((c) => c.url.includes("/setup/model"))).toBe(true));
    const inst = calls.find((c) => c.url.includes("/setup/install"))!;
    expect(JSON.parse(String(inst.init!.body))).toEqual({ ids: ["subfinder"], confirm: true });
    expect(JSON.parse(String(calls.find((c) => c.url.includes("/setup/model"))!.init!.body))).toEqual({ model_id: "m/8b", enable_ai: true, confirm: true });
    await waitFor(() => expect(screen.getAllByText("done").length).toBe(2));
  });
});
