import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Manifest, ManifestRow, PrepareOut, RunRow, Summary } from "../../lib/investigationApi";
import Home from "./Home";
import Investigation from "./Investigation";
import NewInvestigation from "./NewInvestigation";
import Review from "./Review";

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

const row = (o: Partial<ManifestRow>): ManifestRow => ({ key: "k", source_id: "gravatar_email", source: "Gravatar", module: "OSINT", identifier_id: "i1", identifier_kind: "email", identifier: "j***@gmail.com", status: "needs_approval",
  status_label: "", reason: "", third_party: true, recipients: ["api.gravatar.com"], maturity: "mocked_only", verified_live: false, category: "email_discovery", data_classes: [], depth: 0, ...o });
const manifest = (rows: ManifestRow[]): Manifest => ({ rows, counts: {}, third_parties: ["Gravatar"], authorization: { status: "active" }, stop_reason: "", approvable: ["gravatar_email"] });
const run = (o: Partial<RunRow>): RunRow => ({ id: "r1", case_id: "c1", subject_id: "s1", name: "Jane", kind: "person", status: "collecting", stop_reason: "", updated_at: "2026-10-27T00:00:00Z", created_at: "2026-10-27T00:00:00Z",
  units: { done: 2, running: 1, failed: 0, waiting_approval: 0, not_run: 3 }, pending_decisions: 0, ...o });

describe("Home", () => {
  it("shows the empty state with an example and one prominent way to start", async () => {
    mockApi({ "/investigations/review": { total: 0, subjects: [] }, "/investigations": { items: [] } });
    const go = vi.fn();
    wrap(<Home go={go} />);
    await waitFor(() => screen.getByText("No investigations yet"));
    expect(screen.getByText(/Example: start with one email address you own/)).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: /New investigation|Start your first/ })[0]);
    expect(go).toHaveBeenCalledWith("new");
  });

  it("lists running work first, with the truthful counts and waiting decisions", async () => {
    mockApi({ "/investigations/review": { total: 4, subjects: [] }, "/investigations": { items: [run({}), run({ id: "r2", name: "Old", status: "complete_with_limits", pending_decisions: 2 })] } });
    wrap(<Home go={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Investigation Jane"));
    expect(screen.getByText(/4 decision\(s\) waiting for you/)).toBeInTheDocument();
    expect(screen.getByLabelText("Investigation Jane")).toHaveTextContent("Collecting");
    expect(screen.getByLabelText("Investigation Old")).toHaveTextContent("Complete, with limits");
    expect(screen.getByLabelText("Investigation Old")).toHaveTextContent("2 decision(s) waiting");
  });
});

describe("New investigation", () => {
  it("needs the authorization confirmation before anything is prepared, then shows who would receive what", async () => {
    const prepared: PrepareOut = { case_id: "c1", subject_id: "s1", added: [{ kind: "email", id: "i1" }], skipped: [], run: null,
      manifest: manifest([row({}), row({ key: "k2", source_id: "web_search_email", source: "Brave web search", status: "needs_key", reason: "No 'brave_search' key is stored.", recipients: [], third_party: false }),
        row({ key: "k3", source_id: "", source: "No supported source", identifier_kind: "phone", identifier: "••• 42", status: "unsupported_input", reason: "No approved phone-discovery source is configured.", recipients: [], third_party: false })]) };
    const calls = mockApi({ "/investigations/detect": { inputs: [{ value: "jane@gmail.com", kind: "email", alternatives: ["name"] }] }, "/investigations": prepared, "/subjects/s1/investigations": { id: "r9", status: "queued" } });
    const go = vi.fn();
    wrap(<NewInvestigation go={go} />);
    fireEvent.change(screen.getByLabelText("Add an identifier"), { target: { value: "jane@gmail.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => screen.getByLabelText("Identifiers to investigate"));
    expect(screen.getByLabelText("Identifiers to investigate")).toHaveTextContent("jane@gmail.com");
    expect(screen.getByRole("button", { name: "Review plan" })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm this is my own information/ }));
    fireEvent.click(screen.getByRole("button", { name: "Review plan" }));
    await waitFor(() => screen.getByLabelText("Plan"));
    expect(screen.getByLabelText("Plan")).toHaveTextContent("Inputs would be sent to: Gravatar");
    expect(screen.getByLabelText("Plan")).toHaveTextContent("Needs an API key");
    expect(screen.getByLabelText("Plan")).toHaveTextContent("No approved phone-discovery source is configured.");
    fireEvent.click(screen.getByRole("checkbox", { name: "Include Gravatar for j***@gmail.com" }));       // opt a provider out
    fireEvent.click(screen.getByRole("button", { name: "Investigate" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("investigation/r9"));
    const start = calls.find((c) => c.url === "/subjects/s1/investigations");
    expect(JSON.parse(String(start?.init?.body))).toMatchObject({ approved_sources: [], excluded_sources: ["gravatar_email"] });   // only what stayed ticked is approved
  });

  it("splits a pasted list into typed chips that can be corrected", async () => {
    mockApi({ "/investigations/detect": { inputs: [{ value: "a@b.example", kind: "email", alternatives: [] }, { value: "janedoe", kind: "username", alternatives: [] }] } });
    wrap(<NewInvestigation go={() => undefined} />);
    fireEvent.change(screen.getByLabelText("Add an identifier"), { target: { value: "a@b.example, @janedoe" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => screen.getByLabelText("Type of janedoe"));
    expect(screen.getByLabelText("Type of janedoe")).toHaveValue("username");
    fireEvent.change(screen.getByLabelText("Type of janedoe"), { target: { value: "alias" } });
    expect(screen.getByLabelText("Type of janedoe")).toHaveValue("alias");
    fireEvent.click(screen.getByLabelText("Remove a@b.example"));
    expect(screen.queryByText("a@b.example")).toBeNull();
  });
});

const summary = (o: Partial<Summary> = {}): Summary => ({
  run: { id: "r1", status: "awaiting_review", kind: "person", policy: {}, approved_sources: [], excluded_sources: [], stop_reason: "needs_approval", created_at: "", requested_by: "me" },
  subject: { id: "s1", case_id: "c1", display_name: "Jane", type: "person", mode: "self", purpose: "self audit" }, authorization: { status: "active" },
  progress: { id: "r1", status: "awaiting_review", phase: "", pass: 1, stop_reason: "needs_approval", updated_at: "", started_at: null, finished_at: null, units: { done: 2, running: 0, failed: 0, waiting_approval: 1, not_run: 2 },
    label: "Counts are checks the investigation knows about. They are not a percentage of everything that exists about the subject.", pending_decisions: 3, policy: {}, last_error: "" },
  facts: { self_provided: [{ category: "contact", type: "Email address", value: "jane@gmail.com", state: "unassessed", state_label: "", evidence: 0 }], self_attested: [], independently_corroborated: [], conflicting: [] },
  fact_counts: { self_provided: 1, self_attested: 0, independently_corroborated: 0, conflicting: 0 }, possible_associations: 5, coverage: [],
  accounting: { sources: [], accounts: { tool_hits: 47, unique_accounts: 37, seen_by_more_than_one_tool: 10, by_review_state: {}, confirmed_by: {}, explain: "47 stored sightings became 37 unique account pages (10 repeats and URL variants merged). Two tools agreeing on a handle is one signal, not two." },
    profile_items: { discovered: 0, by_type: {} } },
  decisions: { open: 3, top: [{ id: "account:1", kind: "account", title: "GitHub", detail: "https://github.com/x", claim: "This account belongs to the subject", signals: 1, tools: ["sherlock"], evidence: 0, state: "candidate", note: "" }] },
  limits: [{ code: "needs_key", source: "Brave web search", input: "email: j***@gmail.com", text: "No 'brave_search' key is stored. Add it in Settings; nothing was sent." }],
  next_actions: [], email_first: { has_email: true, message: "x" }, invite: "Want better coverage? Add another email, username, business name or owned domain.",
  manifest: { counts: {}, rows: [row({})], third_parties: ["Gravatar"] }, ...o });

describe("Investigation", () => {
  it("separates confirmed from possible, lists what could not be done, and offers one bounded approval", async () => {
    const calls = mockApi({ "/investigations/r1/approve": { id: "r1", status: "queued" }, "/investigations/r1/summary": summary() });
    wrap(<Investigation id="r1" go={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Progress"));
    expect(screen.getByLabelText("Progress")).toHaveTextContent("Needs your decision");
    expect(screen.getByLabelText("Progress")).toHaveTextContent("not a percentage of everything");
    expect(screen.getByLabelText("Key facts")).toHaveTextContent("Possible, unverified");
    expect(screen.getByLabelText("Limits")).toHaveTextContent("Brave web search");
    expect(screen.getByLabelText("Limits")).toHaveTextContent("nothing was sent");
    expect(screen.getByLabelText("Next decisions")).toHaveTextContent("Review 3 item(s)");
    expect(screen.getByLabelText("Approval needed")).toHaveTextContent("api.gravatar.com");
    fireEvent.click(screen.getByRole("button", { name: "Approve these providers and continue" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/investigations/r1/approve")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url === "/investigations/r1/approve")?.init?.body))).toEqual({ sources: ["gravatar_email"] });
  });

  it("shows how raw hits become unique accounts on the Activity tab", async () => {
    mockApi({ "/investigations/r1/events": { events: [{ seq: 1, kind: "created", message: "Investigation created", detail: {}, at: "2026-10-27T00:00:00Z" }], last: 1, status: "awaiting_review" }, "/investigations/r1/summary": summary() });
    wrap(<Investigation id="r1" go={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Progress"));
    fireEvent.click(screen.getByRole("tab", { name: /Activity/ }));
    await waitFor(() => screen.getByLabelText("Activity log"));
    expect(screen.getByText(/47 stored sightings became 37 unique account pages/)).toBeInTheDocument();
    expect(screen.getByLabelText("Needs approval")).toHaveTextContent("Gravatar");
    expect(screen.getByLabelText("Needs approval")).toHaveTextContent("fixture-tested");
  });
});

describe("Review", () => {
  it("needs a reason, previews the impact, and records Mine as a self-attestation", async () => {
    const calls = mockApi({
      "/subjects/s1/review-inbox/decide": (_u: string, init?: RequestInit) => (JSON.parse(String(init?.body)).preview
        ? { preview: true, counts: { account: 1 }, total: 1, sites: ["GitHub"], exceptions: [], effect: "Recorded as the owner's own attestation. It is not independent corroboration and does not make an account verified." }
        : { preview: false, applied: 1, bulk_id: "b1", counts: { account: 1 }, total: 1, sites: ["GitHub"], exceptions: [], effect: "" }),
      "/cases/c1/evidence": { items: [{ id: "e1", title: "Screenshot of profile", kind: "screenshot", original_url: null }, { id: "e2", title: "github.raw", kind: "github_public.raw", original_url: "https://api.github.com/x" }] },
      "/investigations/review": { total: 1, subjects: [{ subject_id: "s1", case_id: "c1", name: "Jane", role: "owner", total: 1, items: [summary().decisions.top[0]] }] },
    });
    wrap(<Review go={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Review for Jane"));
    fireEvent.click(screen.getByLabelText("Select GitHub"));
    expect(screen.getByRole("button", { name: "Mine / confirmed" })).toBeDisabled();
    const sel = screen.getByLabelText("Independent evidence") as HTMLSelectElement;
    expect(sel.value).toBe("");                                                       // no evidence is attached unless picked
    await waitFor(() => expect(Array.from(sel.options).map((o) => o.text)).toEqual(["None (self-attested only)", "Screenshot of profile"]));   // raw tool captures are not offered as independent evidence
    fireEvent.change(screen.getByLabelText("Reason or method"), { target: { value: "my own account" } });
    fireEvent.click(screen.getByRole("button", { name: "Mine / confirmed" }));
    await waitFor(() => screen.getByLabelText("Impact preview"));
    expect(screen.getByLabelText("Impact preview")).toHaveTextContent("not independent corroboration");
    fireEvent.click(screen.getByRole("button", { name: "Apply to 1" }));
    await waitFor(() => screen.getByText(/Undo this batch/));
    const applied = calls.filter((c) => c.url === "/subjects/s1/review-inbox/decide").map((c) => JSON.parse(String(c.init?.body)));
    expect(applied.map((a) => a.preview)).toEqual([true, false]);
    expect(applied[1]).toMatchObject({ ids: ["account:1"], action: "mine", evidence_ids: [] });
  });

  it("says plainly when there is nothing to decide", async () => {
    mockApi({ "/investigations/review": { total: 0, subjects: [] } });
    wrap(<Review go={() => undefined} />);
    await waitFor(() => screen.getByText("Nothing waiting for you"));
  });
});
