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
const candidate = { id: "k1", canonical_url: "https://github.com/jane_e", site: "GitHub", hypothesis: "", adapters: ["sherlock", "maigret"], independent_signals: 1, state: "candidate",
  reviewed_by: null, reviewed_at: null, review_basis: "", first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z", observation_count: 2, evidence: [], note: "Lead only: more than one tool agreeing on a handle is still one signal." };
const profile = (over: object = {}) => ({
  subject, case: { id: "c1", title: "Jane", category: "people" }, role: "owner", notice: "Findings are leads, not facts. Absent results are never proof that information does not exist.",
  authorization: { status: "none", mode: "self", consent_id: null, expires_at: null, source_classes: [], receipt: null, message: "No authorization on record: collection about this person is blocked until one is added." },
  sections: [{ key: "identity", title: "Identity and aliases", identifiers: [], claims: [], state_note: "Not assessed. No claim recorded; this does not mean the information does not exist." },
    { key: "work", title: "Work and education", identifiers: [], claims: [{ id: "cl1", field: "employer", value: { text: "Acme" }, state: "verified", state_label: "verified", evidence: [{ id: "e1234567", title: "staff page", kind: "note", sha256: "a".repeat(64), url: null, retrieved_at: "2026-01-01T00:00:00Z" }] }], state_note: "" }],
  identifiers: [], unresolved_leads: [candidate], image_matches: { total: 0, unreviewed: 0 }, exposure: [], remediation: [],
  risk_summary: { confirmed_exposures: 0, highest_risk: "none", not_assessed: 0 }, counts: { identifiers: 1, claims: 1, candidates: 1, verified: 1 }, ...over });

const coverage = {
  label: "Coverage shows which approved research methods have run. It is not a measure of how much information exists about this subject.",
  approved_tasks: 1, completed_tasks: 1, totals: {}, next_action: "Approve the next collection (DNS records is eligible and has not run).", last_collected: null,
  categories: [{ key: "domain_infrastructure", title: "Owned domains and infrastructure", cells: [
    { source_id: "rdap", name: "RDAP registration data", maturity: "live_tested", status: "completed", detail: "5 result(s)", last_success: "2026-01-01T00:00:00Z" },
    { source_id: "dns", name: "DNS records", maturity: "live_tested", status: "not_run", detail: "eligible but not yet approved or run", last_success: null },
    { source_id: "sherlock", name: "Sherlock", maturity: "live_tested", status: "unavailable", detail: "tool state: not installed", last_success: null },
    { source_id: "sec_edgar", name: "SEC EDGAR", maturity: "mocked_only", status: "unsupported", detail: "needs a organization input, which this subject does not have", last_success: null }] }],
};
const entry = (over: object) => ({ key: "i1:rdap", identifier_id: "i1", identifier_kind: "domain", identifier: "example.com", source_id: "rdap", name: "RDAP registration data", category: "domain_infrastructure",
  consent_class: "public_passive", privacy: "public_org", maturity: "live_tested", legal_note: "Public registry data.", commercial_use: "x", runnable: true, reason: "passive source",
  requires_confirmation: false, warnings: [], endpoints: ["https://data.iana.org/rdap/dns.json"], rate_limit_per_minute: 30, cost: "free", needs_key: null, previous: null, ...over });
const routes = (extra: Record<string, unknown> = {}) => ({
  "/cases/c1/subjects": { total: 1, items: [subject] }, "/subjects/s1/profile": profile(), "/subjects/s1/timeline": { items: [] },
  "/cases/c1/evidence": { items: [] }, "/subjects/s1/candidates": { items: [candidate] }, "/subjects/s1/review-history": { items: [] },
  "/subjects/s1/consent": { current: profile().authorization, history: [] },
  "/subjects/s1/coverage": coverage, "/subjects/s1/research/runs": { items: [] }, ...extra,
});

describe("TargetProfile", () => {
  it("shows header, authorization status, evidence-backed state labels and 'not assessed' wording", async () => {
    mockApi(routes());
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => expect(screen.getByText("Jane Example")).toBeInTheDocument());
    expect(screen.getByRole("status", { name: "Authorization status" })).toHaveTextContent(/none.*blocked/i);
    expect(screen.getByText("exposure not assessed")).toBeInTheDocument();
    expect(screen.getByText(/this does not mean the information does not exist/i)).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();          // the claim state is a text label, not only a colour
    expect(screen.getByText(/e1234567/)).toBeInTheDocument();           // evidence reference
    expect(screen.getByLabelText("Target header")).toHaveTextContent(/Next: Record an authorization/);
    expect(screen.getByRole("button", { name: "Refresh approved checks" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Generate report" })).toBeNull();   // actions appear only for features that exist
  });

  it("offers to create a target (mode + purpose) when the case has none", async () => {
    const calls = mockApi({ "/cases/c1/subjects": { total: 0, items: [] } });
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByLabelText("Display label"));
    expect(screen.getByRole("button", { name: "Create target" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Display label"), { target: { value: "Jane" } });
    fireEvent.change(screen.getByLabelText("Purpose"), { target: { value: "my own audit" } });
    fireEvent.change(screen.getByLabelText("Assessment mode"), { target: { value: "client" } });
    fireEvent.click(screen.getByRole("button", { name: "Create target" }));
    await waitFor(() => expect(calls.some((c) => c.init?.method === "POST")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.init?.method === "POST")!.init!.body))).toMatchObject({ display_name: "Jane", mode: "client", purpose: "my own audit" });
  });

  it("review queue: needs a reason; sends one bulk decision with the subject attestation; nothing is preselected", async () => {
    const calls = mockApi(routes({ "/subjects/s1/candidates/bulk-review": { updated: 1, bulk_id: null, state: "confirmed" } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: /Review queue/ }));
    await waitFor(() => screen.getByLabelText("Select https://github.com/jane_e"));
    expect(screen.getByText(/2 observation\(s\) · 1 independent signal/)).toBeInTheDocument();
    expect(screen.getByLabelText("Select https://github.com/jane_e")).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Mine / Confirmed" })).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Select https://github.com/jane_e"));
    fireEvent.change(screen.getByLabelText("Reason or method"), { target: { value: "this is my account" } });
    fireEvent.click(screen.getByLabelText(/the subject attests/));
    fireEvent.click(screen.getByRole("button", { name: "Mine / Confirmed" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/candidates/bulk-review"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.endsWith("/candidates/bulk-review"))!.init!.body)))
      .toEqual({ candidate_ids: ["k1"], state: "confirmed", basis: "this is my account", attestation: "subject", evidence_ids: [] });
  });

  it("viewers cannot select or decide", async () => {
    mockApi(routes({ "/subjects/s1/profile": profile({ role: "viewer" }) }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: /Review queue/ }));
    await waitFor(() => screen.getByLabelText("Select https://github.com/jane_e"));
    expect(screen.getByLabelText("Select https://github.com/jane_e")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Mine / Confirmed" })).toBeNull();
  });

  it("authorization panel: only an owner can record; shows the mode rules", async () => {
    mockApi(routes());
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Authorization" }));
    await waitFor(() => screen.getByLabelText("Verified by"));
    expect(screen.getByText(/never authorises testing unrelated systems/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Record authorization" })).toBeDisabled();
  });

  it("research: coverage uses honest state words; nothing is preselected; public-site tools need their own confirmation before approval", async () => {
    const plan = { subject_id: "s1", budget: { max_per_approval: 40, runnable: 2, paid_requests: 0 }, offline: false, note: "Nothing has been sent.", stop_rules: ["No recursion: results never become new research inputs on their own."],
      entries: [entry({}), entry({ key: "i2:sherlock", identifier_id: "i2", identifier_kind: "username", identifier: "jane_e", source_id: "sherlock", name: "Sherlock", consent_class: "public_site_query",
        privacy: "public_personal", requires_confirmation: true, warnings: ["Tool contacts many public websites using the supplied handle."], endpoints: ["hundreds of third-party public websites"] }),
        entry({ key: "i1:crtsh", source_id: "crtsh", name: "Certificate transparency (crt.sh)", runnable: false, reason: "authorization: no live authorization covers 'public_passive'" })] };
    const calls = mockApi(routes({ "/subjects/s1/research/preview": plan, "/subjects/s1/research/approve": { run_ids: ["r1"], tasks: 2 } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Research" }));
    await waitFor(() => screen.getByLabelText("Coverage grid"));
    const grid = screen.getByLabelText("Coverage grid");
    expect(grid).toHaveTextContent(/completed.*RDAP registration data/);
    expect(grid).toHaveTextContent(/not run.*DNS records/);
    expect(grid).toHaveTextContent(/unavailable.*Sherlock.*not installed/);
    expect(grid).toHaveTextContent(/unsupported.*SEC EDGAR/);
    expect(grid).toHaveTextContent(/integration only tested against fixtures/);
    expect(screen.getByText(/not a measure of how much information exists/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Preview what would be contacted/ }));
    await waitFor(() => screen.getByLabelText("Run Sherlock on jane_e"));
    expect(screen.getByLabelText("Run Sherlock on jane_e")).not.toBeChecked();
    expect(screen.getByLabelText("Run Certificate transparency (crt.sh) on example.com")).toBeDisabled();
    expect(screen.getByText(/Blocked: authorization: no live authorization covers/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve and run 0 source(s)" })).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Run Sherlock on jane_e"));
    fireEvent.click(screen.getByLabelText("Run RDAP registration data on example.com"));
    expect(screen.getByRole("button", { name: "Approve and run 2 source(s)" })).toBeDisabled();          // Sherlock selected but not confirmed
    fireEvent.click(screen.getByLabelText("Confirm Sherlock contacts third-party sites"));
    expect(screen.getByRole("button", { name: "Approve and run 2 source(s)" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Approve and run 2 source(s)" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/research/approve"))).toBe(true));
    const sent = JSON.parse(String(calls.find((c) => c.url.endsWith("/research/approve"))!.init!.body));
    expect([...sent.keys].sort()).toEqual(["i1:rdap", "i2:sherlock"]);
    expect(sent.confirmed_sources).toEqual(["sherlock"]);
  });

  it("workflows: templates are described as disabled drafts with their real availability and gaps", async () => {
    mockApi(routes({ "/subjects/s1/templates": { items: [
      { slug: "tp-01-self-digital-footprint-baseline", key: "TP-01", name: "Self Digital Footprint Baseline", description: "Baseline.", maturity: "fixture_tested", trigger: "manual", quota_note: "About 2 source request(s) per run",
        capability_gaps: ["Published profile pages are entered by hand."], dependencies: ["sherlock"], optional_dependencies: [],
        availability: { state: "setup_required", gaps: [], missing: [{ adapter: "sherlock", status: "not_installed", setup: "Install with `uv tool install sherlock-project`." }] } }] } }));
    wrap(<TargetProfile caseId="c1" />);
    await waitFor(() => screen.getByText("Jane Example"));
    fireEvent.click(screen.getByRole("tab", { name: "Workflows" }));
    await waitFor(() => screen.getByLabelText("TP-01 Self Digital Footprint Baseline"));
    expect(screen.getByText(/Templates ship as/)).toHaveTextContent(/disabled drafts/);
    expect(screen.getByText(/Needs sherlock/)).toBeInTheDocument();
    expect(screen.getByText(/Gap: Published profile pages are entered by hand/)).toBeInTheDocument();
    expect(screen.getByText("setup required")).toBeInTheDocument();
  });
});
