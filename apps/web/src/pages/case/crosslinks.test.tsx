import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import CrossLinksTab from "./CrossLinksTab";
import PlansTab from "./PlansTab";

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
const wrap = (el: ReactElement) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{el}</QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

const side = (id: string, discipline: string) => ({ id, discipline, kind: "k", observed_at: "2025-03-01T12:00:00Z", evidence_id: "e" + id, access_class: "IMPORTED", quality_hint: "medium: supplied file" });

describe("CrossLinksTab", () => {
  it("shows a suggestion as a coincidence, sends nothing until accepted, and the slider changes the query", async () => {
    const calls = mockApi({
      "/cases/c1/cross-links/decision": { id: "cor1", status: "accepted" },
      "/cases/c1/cross-links": { total: 1, truncated: false, caveat: "Coincidence in time or place is not a relationship.",
        items: [{ key: "k1", type: "both", a: side("a", "GEOINT"), b: side("b", "CYBINT"), delta_s: 60, distance_m: 120, warnings: ["accuracy unknown for at least one position"], status: "suggested", correlation_id: null }] },
      "/cases/c1/timeline/unified": { note: "Every row states which of its times is shown", items: [{ source: "observation", id: "a", time: "2025-03-01T12:00:00Z", time_basis: "observed", discipline: "GEOINT", label: "photo.exif", evidence_id: "ea", located: true }] },
    });
    wrap(<CrossLinksTab id="c1" />);
    await waitFor(() => screen.getByText("Accept"));
    expect(screen.getAllByText(/not a relationship/).length).toBeGreaterThan(0);
    expect(screen.getByText(/accuracy unknown/)).toBeInTheDocument();
    expect(screen.getByText("observed")).toBeInTheDocument();                         // the timeline names the time it uses
    expect(calls.some((c) => c.url.includes("/decision"))).toBe(false);
    expect(calls.find((c) => c.url.includes("/cross-links?"))!.url).toContain("include_restricted=false");
    fireEvent.change(screen.getByLabelText("Time window"), { target: { value: "6" } });
    await waitFor(() => expect(calls.some((c) => c.url.includes("window_s=86400"))).toBe(true));
    await waitFor(() => screen.getByText("Accept"));
    fireEvent.click(screen.getByText("Accept"));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/decision"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.includes("/decision"))!.init!.body))).toEqual({ obs_a: "a", obs_b: "b", kind: "both", decision: "accept" });
  });

  it("an accepted link can be revoked", async () => {
    const calls = mockApi({
      "/correlations/cor1/revoke": { id: "cor1", status: "revoked" },
      "/cases/c1/cross-links": { total: 1, truncated: false, caveat: "c", items: [{ key: "k1", type: "temporal", a: side("a", "GEOINT"), b: side("b", "CYBINT"), delta_s: 5, distance_m: null, warnings: [], status: "accepted", correlation_id: "cor1" }] },
      "/cases/c1/timeline/unified": { note: "", items: [] },
    });
    wrap(<CrossLinksTab id="c1" />);
    await waitFor(() => screen.getByText("Revoke"));
    fireEvent.click(screen.getByText("Revoke"));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/revoke"))).toBe(true));
  });
});

describe("PlansTab", () => {
  const plan = (status?: string) => ({ target: { type: "domain", canonical: "example.com" }, warnings: [], offline: false, reason: "r", data_sensitivity: "INTERNAL",
    cache_policy: "raw responses stored in the evidence vault", recursion: "none: results never trigger follow-up collection automatically",
    budget: { paid_requests: 0, estimated_requests: 1, currency: "none" }, ...(status ? { policy_status: status } : {}),
    steps: [{ adapter_id: "rdap", name: "RDAP", runnable: true, reason: "ok", endpoints: ["https://rdap.example"], operation_class: "passive" },
      { adapter_id: "sherlock", name: "Sherlock", runnable: false, reason: "not installed" }] });

  it("previews without saving, then saves, and only approves on click", async () => {
    const calls = mockApi({
      "/collection-plans/preview": plan(),
      "/collection-plans/p1/approve": { id: "p1", status: "approved", run_id: "r1" },
      "/collection-plans/p1": { id: "p1", status: "draft", policy_status: "allowed", steps: [{ adapter_id: "rdap", status: "planned", error_code: null }] },
      "/collection-plans": { id: "p1", policy_status: "allowed", status: "draft", plan: plan("allowed") },
    });
    wrap(<PlansTab id="c1" />);
    fireEvent.change(screen.getByLabelText("Plan target"), { target: { value: "example.com" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "ownership check" } });
    fireEvent.click(screen.getByText("Preview plan"));
    await waitFor(() => screen.getByText(/Plan for example.com/));
    expect(screen.getByText(/preview \(not saved\)/)).toBeInTheDocument();
    expect(screen.getByText("not installed")).toBeInTheDocument();                     // blocked sources are shown with the reason
    expect(calls.filter((c) => c.url === "/collection-plans").length).toBe(0);         // preview created nothing
    fireEvent.click(screen.getByText("Save plan"));
    await waitFor(() => screen.getByText("Approve and run"));
    expect(calls.some((c) => c.url.includes("/approve"))).toBe(false);                 // saving does not run anything
    fireEvent.click(screen.getByText("Approve and run"));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/approve"))).toBe(true));
  });
});
