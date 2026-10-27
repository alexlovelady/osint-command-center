import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import EdgarContact, { contactProblem } from "../../components/EdgarContact";
import type { RunRow } from "../../lib/investigationApi";
import Home from "./Home";
import ProviderUsage, { type ProviderEntry, type UsageOut } from "./ProviderUsage";

type Handler = (url: string, init?: RequestInit) => { status?: number; body: unknown } | unknown;
function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => url.startsWith(k));
    if (!key) return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
    const v = routes[key];
    const out = typeof v === "function" ? (v as Handler)(url, init) : v;
    const wrapped = out && typeof out === "object" && "body" in (out as object) && "status" in (out as object) ? (out as { status: number; body: unknown }) : { status: 200, body: out };
    return new Response(JSON.stringify(wrapped.body), { status: wrapped.status, headers: { "content-type": "application/json" } });
  });
  return calls;
}
const wrap = (el: ReactElement) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{el}</QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

describe("EdgarContact", () => {
  const saved = { edgar_contact: "Jane Analyst jane@example.org", edgar_contact_saved_at: "2026-10-27T12:00:00+00:00" };

  it("shows the saved contact after a reload, marks edits as unsaved, and says Saved with the time once it is read back", async () => {
    let current: Record<string, unknown> = { ...saved };
    const calls = mockApi({ "/settings": (_u: string, init?: RequestInit) => {
      if (init?.method === "PUT") { current = { edgar_contact: JSON.parse(String(init.body)).values.edgar_contact, edgar_contact_saved_at: "2026-10-27T12:30:00+00:00", edgar_contact_verified_readback: true }; }
      return current;
    } });
    wrap(<EdgarContact />);
    const input = (await waitFor(() => screen.getByLabelText(/SEC EDGAR contact/, { selector: "input" }))) as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe("Jane Analyst jane@example.org"));                       // rehydrated from the server, not blank
    expect(screen.getByRole("status")).toHaveTextContent("Saved at 2026-10-27 12:00 UTC");
    fireEvent.change(input, { target: { value: "Jane Q Analyst jane@example.org" } });
    expect(screen.getByRole("status")).toHaveTextContent("Unsaved changes");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Saved at 2026-10-27 12:30 UTC"));
    expect(input.value).toBe("Jane Q Analyst jane@example.org");                                           // the field is NOT cleared after saving
    expect(screen.getByRole("status")).toHaveTextContent("Read back from the database");
    expect(calls.filter((c) => c.init?.method === "PUT")).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();                                    // nothing left to save
  });

  it("blocks an unusable contact before sending, and reports a failed save with what happened", async () => {
    mockApi({ "/settings": (_u: string, init?: RequestInit) => (init?.method === "PUT" ? { status: 422, body: { code: "invalid_contact", message: "'jane@@x' is not a valid email address.", request_id: "r", retryable: false, details_safe: {} } } : { edgar_contact: "" }) });
    wrap(<EdgarContact />);
    const input = (await waitFor(() => screen.getByLabelText(/SEC EDGAR contact/, { selector: "input" }))) as HTMLInputElement;
    expect(screen.getByRole("status")).toHaveTextContent("blocked until you save a contact");
    fireEvent.change(input, { target: { value: "jane@example.org" } });
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByText(/Add your name before the email address|Enter your name and then your email/)).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "Jane Analyst jane@example.org" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Failed to save. Nothing was changed."));
    expect(screen.getByText(/not a valid email address/)).toBeInTheDocument();                              // actionable reason from the server
    expect(input.value).toBe("Jane Analyst jane@example.org");                                              // the edit is kept so it can be corrected
  });

  it("validates names and addresses the same way the server does", () => {
    expect(contactProblem("Jane Analyst jane@example.org")).toBeNull();
    expect(contactProblem("jane@example.org")).not.toBeNull();
    expect(contactProblem("Jane Analyst")).not.toBeNull();
    expect(contactProblem("J jane@example.org")).not.toBeNull();
  });
});

const entry = (o: Partial<ProviderEntry>): ProviderEntry => ({
  provider: "virustotal", label: "VirusTotal", plan: "public (free) API", credential_name: "virustotal", stored: true, paid_only: false, disabled: false, disabled_reason: "", verified_state: "verified", verified_at: "2026-10-27T11:00:00+00:00",
  last_status: 200, last_error: "", last_response_at: "2026-10-27T11:00:00+00:00", blocked_until: null,
  operations: [{ id: "lookup", label: "Reputation lookup", concurrency: null, blocked: "", restricted: false,
    windows: [{ window: "rolling:60", unit: "requests", limit: 4, used: 1, remaining: 3, resets_at: null, basis: "documented" }, { window: "utc_day", unit: "requests", limit: 500, used: 12, remaining: 488, resets_at: "2026-10-28T00:00:00+00:00", basis: "documented" }] }],
  queued: { deferred_rate_limit: 2 }, reset_note: "", limitations: [], state: { code: "verified", label: "Verified by a real call", hint: "The provider answered a real request made with this credential." },
  axes: { stored_credential: "yes", live_authentication: "yes", endpoint_supported: "yes", quota_available: "yes" }, test: { what: "Looks up example.com.", cost: "1 request of the daily quota", url_host: "www.virustotal.com" }, ...o });
const usage = (providers: ProviderEntry[], paused = false): UsageOut => ({ providers, paused, waiting: 2, enforced: true, timezone: "UTC", spend_guard: { paid_spend_usd: 0, text: "Fusion never buys credits, upgrades a plan or enables paid overflow." },
  note: "Counts are Fusion's own estimate from requests it made." });

describe("Provider usage", () => {
  it("keeps stored, verified, supported and available apart, shows remaining and reset times, and the $0 guard", async () => {
    mockApi({ "/providers/usage": usage([
      entry({}),
      entry({ provider: "censys", label: "Censys", stored: true, verified_state: "", verified_at: null, last_response_at: null, last_status: null, queued: {},
        state: { code: "stored", label: "Stored (not yet tested)", hint: "A value is saved, but Fusion has not yet seen the provider accept it." },
        axes: { stored_credential: "yes", live_authentication: "not_tested", endpoint_supported: "yes", quota_available: "unknown" },
        operations: [{ id: "asset_lookup", label: "Asset lookup", concurrency: 1, blocked: "", restricted: false, windows: [{ window: "utc_month", unit: "credits", limit: 100, used: 0, remaining: 100, resets_at: "2026-11-01T00:00:00+00:00", basis: "operator" }] }] }),
      entry({ provider: "shodan", label: "Shodan", plan: "not used", stored: false, paid_only: true, disabled: true, verified_state: "", queued: {}, operations: [], test: null, last_response_at: null,
        state: { code: "disabled_paid", label: "Disabled — paid provider", hint: "Not used because the capability needed is paid." }, axes: { stored_credential: "no", live_authentication: "not_tested", endpoint_supported: "no", quota_available: "unknown" } }),
    ]) });
    wrap(<ProviderUsage />);
    await waitFor(() => screen.getByLabelText("Provider usage table"));
    const vt = screen.getByLabelText("Provider VirusTotal");
    expect(vt).toHaveTextContent("Verified by a real call");
    expect(vt).toHaveTextContent("last 60 s: 3 of 4 requests left");
    expect(vt).toHaveTextContent("today (UTC): 488 of 500 requests left");
    expect(vt).toHaveTextContent("resets 2026-10-28 00:00 UTC");
    expect(vt).toHaveTextContent("2 waiting");
    const ce = screen.getByLabelText("Provider Censys");
    expect(ce).toHaveTextContent("Stored (not yet tested)");                                                // a stored key is not a verified key
    expect(ce).toHaveTextContent("verified by a real call: not tested");
    expect(ce).toHaveTextContent("this month (UTC): 100 of 100 credits left");
    expect(ce).toHaveTextContent("One request at a time");
    const sh = screen.getByLabelText("Provider Shodan");
    expect(sh).toHaveTextContent("Disabled — paid provider");
    expect(within(sh).queryByRole("button", { name: "Turn on" })).toBeNull();                               // a paid provider has no casual switch
    expect(screen.getByText(/Spend guard: \$0/)).toBeInTheDocument();
    expect(screen.getByText(/2 check\(s\) are waiting for a provider’s limit to reset/)).toBeInTheDocument();
  });

  it("asks before sending a test, naming where it goes and what it costs", async () => {
    const calls = mockApi({ "/providers/virustotal/test": { state: "verified", detail: "" }, "/providers/usage": usage([entry({})]) });
    wrap(<ProviderUsage />);
    await waitFor(() => screen.getByLabelText("Provider VirusTotal"));
    fireEvent.click(screen.getByRole("button", { name: "Test" }));
    expect(screen.getByRole("alert")).toHaveTextContent("1 request of the daily quota");
    expect(screen.getByRole("alert")).toHaveTextContent("www.virustotal.com");
    expect(calls.some((c) => c.url.startsWith("/providers/virustotal/test"))).toBe(false);                  // nothing is sent until confirmed
    fireEvent.click(screen.getByRole("button", { name: "Send the test" }));
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/providers/virustotal/test"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.startsWith("/providers/virustotal/test"))?.init?.body))).toEqual({ confirm: true });
  });

  it("asks for a licence confirmation for business use of the public VirusTotal API, and cancels queued work only after confirmation", async () => {
    const calls = mockApi({ "/providers/virustotal/licence": usage([entry({})]), "/providers/cancel-queued": { ...usage([entry({})]), cancelled: 2 },
      "/providers/usage": usage([entry({ licence: { needed_for: "business or client use", confirmed: false } })]) });
    wrap(<ProviderUsage />);
    await waitFor(() => screen.getByLabelText("Provider VirusTotal"));
    const box = screen.getByLabelText(/I hold a VirusTotal licence that covers business or client use/);
    expect(box).not.toBeChecked();
    fireEvent.click(box);
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/providers/virustotal/licence"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.startsWith("/providers/virustotal/licence"))?.init?.body))).toEqual({ commercial_licensed: true });
    fireEvent.click(screen.getByRole("button", { name: "Cancel queued work" }));
    expect(screen.getByRole("alert")).toHaveTextContent("cancels every queued or waiting provider check");
    expect(calls.some((c) => c.url.startsWith("/providers/cancel-queued"))).toBe(false);                   // nothing is cancelled until confirmed
    fireEvent.click(screen.getByRole("button", { name: /Cancel 2 queued check/ }));
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/providers/cancel-queued"))).toBe(true));
  });

  it("can pause and resume all provider work", async () => {
    const calls = mockApi({ "/providers/pause": usage([entry({})], true), "/providers/usage": usage([entry({})], true) });
    wrap(<ProviderUsage />);
    await waitFor(() => screen.getByText(/Provider work is paused/));
    fireEvent.click(screen.getByRole("button", { name: "Resume all provider work" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/providers/resume")).toBe(true));
  });
});

const run = (o: Partial<RunRow>): RunRow => ({ id: "r1", case_id: "c1", subject_id: "s1", name: "Acme", kind: "business", status: "waiting_limits", stop_reason: "provider_limits", updated_at: "2026-10-27T00:00:00Z", created_at: "2026-10-27T00:00:00Z",
  units: { done: 3, running: 0, failed: 0, waiting_approval: 0, not_run: 1, waiting_limits: 9, blocked: 1, no_match: 1, queued: 0, remaining: 9 }, pending_decisions: 0, ...o });

describe("Investigations waiting for limits", () => {
  it("never calls an investigation complete while permitted checks are waiting", async () => {
    mockApi({ "/investigations/review": { total: 0, subjects: [] }, "/investigations": { items: [run({})] } });
    wrap(<Home go={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Investigation Acme"));
    const card = screen.getByLabelText("Investigation Acme");
    expect(card).toHaveTextContent("Waiting for provider limits");
    expect(card).not.toHaveTextContent(/Complete/);
    expect(card).toHaveTextContent("9 waiting for limits");
    expect(card).toHaveTextContent("1 blocked");
    expect(within(card).getByRole("button")).toHaveTextContent("Watch");
  });
});

