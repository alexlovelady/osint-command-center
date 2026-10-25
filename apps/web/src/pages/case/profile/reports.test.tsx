import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import TargetProfile from "./TargetProfile";

type Handler = (url: string, init?: RequestInit) => unknown;
function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => url.startsWith(k));
    if (!key) return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
    const v = routes[key];
    return new Response(JSON.stringify(typeof v === "function" ? (v as Handler)(url, init) : v), { headers: { "content-type": "application/json" } });
  });
  return calls;
}
const wrap = (el: ReactElement) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{el}</QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

const subject = { id: "s1", case_id: "c1", type: "person", display_name: "Jane Example", mode: "self", purpose: "self audit", status: "active", owner: "u", sensitivity: "RESTRICTED", retention_days: null };
const profile = { subject, case: { id: "c1", title: "Jane", category: "people" }, role: "owner", notice: "x", sections: [], identifiers: [], unresolved_leads: [], image_matches: { total: 0, unreviewed: 0 },
  exposure: [], remediation: [], risk_summary: { confirmed_exposures: 0, highest_risk: "none", not_assessed: 0 }, counts: { identifiers: 0, claims: 0, candidates: 0, verified: 0 },
  authorization: { status: "active", mode: "self", consent_id: "k", expires_at: "2026-12-01T00:00:00Z", source_classes: [], receipt: null, message: "Authorization is current." } };
const preview = (ok: boolean) => ({ exported: false, markdown: "# Target profile report: Jane Example\n- Employer: Acme Corp (verified) [E1]", report: { header: { status: "DRAFT" }, manifest_sha256: "a".repeat(64) },
  citation_check: { ok, problems: ok ? [] : ["S1: evidence 1a2b3c4d failed its integrity check (IntegrityError)"], warnings: [], statements_checked: 1, evidence_checked: 1 } });
const routes = (ok: boolean, extra: Record<string, unknown> = {}) => ({
  "/cases/c1/subjects": { total: 1, items: [subject] }, "/subjects/s1/profile": profile, "/subjects/s1/timeline": { items: [] },
  "/subjects/s1/coverage": { categories: [], totals: {}, approved_tasks: 0, completed_tasks: 0, label: "x", next_action: "", last_collected: null },
  "/subjects/s1/report/preview": preview(ok), "/subjects/s1/report/create": { id: "r1", file: "profile.md.enc", sha256: "b".repeat(64) },
  "/subjects/s1/reports": { items: [{ id: "r1", audience: "subject", file: "profile.md.enc", sha256: "b".repeat(64), generated_at: "2026-01-01T00:00:00Z", status: "done" }] }, ...extra });

describe("Reports", () => {
  it("cannot create a report whose citation check fails, and says why", async () => {
    const calls = mockApi(routes(false));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Reports" }));
    await waitFor(() => screen.getByRole("button", { name: "Preview draft" }));
    expect(screen.getByRole("button", { name: /Create and seal/ })).toBeDisabled();     // nothing to create before a preview
    fireEvent.click(screen.getByRole("button", { name: "Preview draft" }));
    await waitFor(() => screen.getByLabelText("Report preview"));
    expect(screen.getByText("citation check failed")).toBeInTheDocument();
    expect(screen.getByText(/failed its integrity check/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create and seal/ })).toBeDisabled();
    expect(calls.some((c) => c.url.endsWith("/report/create"))).toBe(false);
  });

  it("creates only after a passing check, with the chosen audience and format", async () => {
    const calls = mockApi(routes(true));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Reports" }));
    await waitFor(() => screen.getByLabelText("Audience"));
    fireEvent.change(screen.getByLabelText("Audience"), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText("Format"), { target: { value: "html" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview draft" }));
    await waitFor(() => screen.getByText("citation check passed"));
    expect(screen.getByLabelText("Report preview")).toHaveTextContent("Employer: Acme Corp (verified) [E1]");
    fireEvent.click(screen.getByRole("button", { name: /Create and seal/ }));
    await waitFor(() => screen.getByText(/Report created and sealed/));
    expect(JSON.parse(String(calls.find((c) => c.url.endsWith("/report/create"))!.init!.body))).toEqual({ audience: "analyst", format: "html" });
    expect(screen.getByLabelText("Exported reports")).toHaveTextContent("profile.md.enc");
  });

  it("viewers get no report tools", async () => {
    mockApi(routes(true, { "/subjects/s1/profile": { ...profile, role: "viewer" } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Reports" }));
    await waitFor(() => screen.getByText(/Reports are prepared by editors and owners/));
    expect(screen.queryByRole("button", { name: "Preview draft" })).toBeNull();
  });
});
