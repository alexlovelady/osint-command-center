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
const profile = (over: object = {}) => ({
  subject, case: { id: "c1", title: "Jane", category: "people" }, role: "owner", notice: "Findings are leads, not facts.",
  authorization: { status: "active", mode: "self", consent_id: "k1", expires_at: "2026-12-01T00:00:00Z", source_classes: ["exposure_check"], receipt: null, message: "Authorization is current." },
  sections: [], identifiers: [{ id: "i-mail", kind: "email", value: "jane.doe@example.com", masked: false, status: "active" }], unresolved_leads: [], image_matches: { total: 0, unreviewed: 0 },
  exposure: [], remediation: [], risk_summary: { confirmed_exposures: 0, highest_risk: "none", not_assessed: 0 }, counts: { identifiers: 1, claims: 0, candidates: 0, verified: 0 }, ...over });
const base = (extra: Record<string, unknown> = {}) => ({
  "/cases/c1/subjects": { total: 1, items: [subject] }, "/subjects/s1/profile": profile(), "/subjects/s1/timeline": { items: [] }, "/cases/c1/evidence": { items: [] },
  "/subjects/s1/coverage": { categories: [], totals: {}, approved_tasks: 0, completed_tasks: 0, label: "x", next_action: "", last_collected: null },
  "/profile/exposure/providers": { providers: { hibp: { name: "Have I Been Pwned", cost: "paid API key", note: "Needs the owner's consent.", maturity: "mocked_only", terms: "" } },
    classes: { breach_account: { label: "Account found in a known data breach", guidance: ["Change the password."] } }, never_stored: [] },
  "/subjects/s1/exposure/password-range": { suffixes: ["1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493", "0018A45C4D1DEF81644B54AB7F969B88D65:1"], padded: true, note: "x" },
  "/subjects/s1/exposure/preview": { provider_name: "Have I Been Pwned", allowed: true, reason: "authorized", cost: "paid API key (per-month subscription)", note: "n", maturity: "mocked_only", requires_key: "hibp",
    will_send: { to: "https://haveibeenpwned.com/api/v3/breachedaccount/", data: "jane.doe@example.com", also_sent: "your API key (header)" }, will_store: "Names, dates and categories only." },
  "/subjects/s1/exposure/approve": { status: "confirmed_exposure", message: "1 breach record(s) summarised." },
  "/subjects/s1/exposure": { redacted: false, total: 3, items: [
    { id: "x1", class: "breach_account", class_label: "Account found in a known data breach", status: "confirmed_exposure", status_label: "confirmed exposure", risk: "high", descriptor: "Breach: ExampleService (2023-05)", provider: "manual", verification_basis: "owner_confirmed", last_checked: "2026-01-01T00:00:00Z" },
    { id: "x2", class: "data_broker_listing", class_label: "Listing on a data-broker site", status: "not_found_in_checked_sources", status_label: "not found in checked sources", risk: "unknown", descriptor: "Checked one site", provider: "manual",
      caveat: "'Not found in checked sources' only describes the sources that were checked. It does not show the subject was never exposed.", last_checked: "2026-01-01T00:00:00Z" },
    { id: "x3", class: "social_oversharing", class_label: "Profile shows more detail than intended", status: "not_assessed", status_label: "not assessed", risk: "unknown", descriptor: "", provider: "manual", last_checked: "2026-01-01T00:00:00Z" }] },
  ...extra,
});

describe("Exposure", () => {
  it("keeps the three results distinct; the password check sends only five characters and clears the field", async () => {
    const calls = mockApi(base());
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Exposure" }));
    await waitFor(() => screen.getByLabelText("Exposure indicators"));
    const t = screen.getByLabelText("Exposure indicators");
    expect(t).toHaveTextContent("confirmed exposure");
    expect(t).toHaveTextContent("not found in checked sources");
    expect(t).toHaveTextContent("not assessed");
    expect(t).toHaveTextContent(/does not show the subject was never exposed/);
    expect(screen.getByText(/never requested or stored/)).toBeInTheDocument();
    const pw = screen.getByLabelText("Password to check") as HTMLInputElement;
    expect(pw.type).toBe("password");
    fireEvent.change(pw, { target: { value: "password" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => screen.getByText(/appears 3,861,493 time/));
    expect(pw.value).toBe("");
    const sent = calls.filter((c) => c.url.endsWith("/password-range"));
    expect(sent).toHaveLength(1);
    expect(JSON.parse(String(sent[0].init!.body))).toEqual({ prefix: "5BAA6" });
    const everything = JSON.stringify(calls.map((c) => [c.url, String(c.init?.body ?? "")]));
    expect(everything).not.toContain("1E4C9B93F3F0682250B6CF8331B7EE68FD8");           // the rest of the hash never leaves the page
    expect(everything.toLowerCase()).not.toContain('"password"');
  });

  it("shows exactly what the provider check would send and needs a confirmation first", async () => {
    const calls = mockApi(base());
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Exposure" }));
    await waitFor(() => screen.getByLabelText("Email to check"));
    expect(screen.getByText(/tested only against recorded responses, not against the live service/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Preview what would be sent" }));
    await waitFor(() => screen.getByLabelText("Data preview"));
    expect(screen.getByLabelText("Data preview")).toHaveTextContent(/jane\.doe@example\.com/);
    expect(calls.some((c) => c.url.endsWith("/exposure/approve"))).toBe(false);
    expect(screen.getByRole("button", { name: "Run the check" })).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I understand this address will be sent/));
    fireEvent.click(screen.getByRole("button", { name: "Run the check" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/exposure/approve"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.endsWith("/exposure/approve"))!.init!.body))).toEqual({ identifier_id: "i-mail", confirm: true });
  });

  it("a viewer sees that records exist but not their contents, and has no password check", async () => {
    mockApi(base({ "/subjects/s1/profile": profile({ role: "viewer" }),
      "/subjects/s1/exposure": { redacted: true, total: 1, items: [{ id: "x1", class: "breach_account", class_label: "Account found in a known data breach", redacted: true }] } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Exposure" }));
    await waitFor(() => screen.getByText(/Your role shows that exposure records exist/));
    expect(screen.getByText("hidden for your role")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password to check")).toBeNull();
  });
});

describe("Remediation and privacy", () => {
  it("resolving needs evidence; purging needs the typed confirmation", async () => {
    const calls = mockApi(base({
      "/subjects/s1/remediations": { items: [{ id: "t1", issue: "Change reused password", priority: "high", guidance: "1. Change the password.", owner: "u", state: "open", due_at: null, recheck_due: true, indicator_id: null, resolution_evidence_id: null }] },
      "/cases/c1/evidence": { items: [{ id: "ev1", title: "retest screenshot" }] },
      "/subjects/s1/corrections": { items: [] },
      "/subjects/s1/retention/preview": { will_delete: { claims: 2, images: 1, identifiers: 0 }, kept: ["The tamper-evident audit log"], confirm_with: "PURGE Jane Example", note: "Irreversible.", evidence_objects_redacted: 1 },
      "/subjects/s1/retention/purge": { purged: {} } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Remediation" }));
    await waitFor(() => screen.getByLabelText(/Task Change reused/));
    expect(screen.getByText("recheck due")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mark resolved" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Evidence for t1/), { target: { value: "ev1" } });
    fireEvent.click(screen.getByRole("button", { name: "Mark resolved" }));
    await waitFor(() => expect(calls.some((c) => c.init?.method === "PATCH")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.init?.method === "PATCH")!.init!.body))).toEqual({ state: "resolved", resolution_evidence_id: "ev1" });
    fireEvent.click(screen.getByRole("tab", { name: "Privacy & data" }));
    await waitFor(() => screen.getByRole("button", { name: "Preview what a purge would remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview what a purge would remove" }));
    await waitFor(() => screen.getByLabelText("Purge preview"));
    expect(screen.getByLabelText("Purge preview")).toHaveTextContent(/2 claims, 1 images/);
    expect(screen.getByRole("button", { name: "Purge this subject" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Type to confirm"), { target: { value: "purge jane" } });
    expect(screen.getByRole("button", { name: "Purge this subject" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Type to confirm"), { target: { value: "PURGE Jane Example" } });
    expect(screen.getByRole("button", { name: "Purge this subject" })).toBeEnabled();
  });
});
