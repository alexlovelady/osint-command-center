import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ProfileT } from "../../../lib/profileApi";
import DarkintDashboard from "../../Darkint";
import Darkint from "./Darkint";

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

const prof = (role: string) => ({ subject: { id: "s1", display_name: "Jane" }, case: { id: "c1" }, role }) as unknown as ProfileT;
const source = (id: string, name: string, state: string, automated = true) => ({ provider_id: id, name, state, reason: state === "disabled" ? "Not enabled." : "ok", verification: "fixture_tested", last_verified: null, licence: "",
  terms_url: "https://t.example", authentication: "", scope_policy: "", source_type: "breach_aggregator", cost_tier: "paid", quota: "", coverage_limitations: "Limited coverage.", terms_note: "", enabled: state === "live",
  automated, monitorable: true, identifier_kinds: ["email"], credential_present: null, terms_acknowledged_at: null });
const NOTICE = "There is no universal 'not leaked' indicator.";
const cov = (state: string, label: string) => ({ coverage: { items: [{ identifier_id: "i1", kind: "email", identifier: "j***@example.com", state, label,
  meaning: state === "not_checked" ? "No provider has been asked about this identifier yet. This is not the same as no exposure." : "x",
  providers: [{ provider_id: "hibp", provider: "Have I Been Pwned", state, checked_at: state === "not_checked" ? null : "2026-10-01T00:00:00Z", last_outcome: null, events: 0 }], checked_sources: [] }], labels: {}, notice: NOTICE },
  groups: [], reviews: {}, actions: [], suggested: {} });

describe("DARKINT tab", () => {
  it("never renders 'not checked' as 'no exposure' and says what is missing", async () => {
    mockApi({ "/darkint/sources": { items: [source("hibp", "Have I Been Pwned", "disabled")], notice: "n" }, "/cases/c1/darkint/exposures": cov("not_checked", "Not checked"), "/subjects/s1/identifiers": { items: [] } });
    wrap(<Darkint p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Exposure coverage"));
    expect(screen.getAllByText("Not checked").length).toBeGreaterThan(0);
    expect(screen.getByText(/not the same as no exposure/)).toBeInTheDocument();
    expect(screen.queryByText(/no exposure found/i)).toBeNull();
    expect(screen.getByText(/no universal 'not leaked' indicator/i)).toBeInTheDocument();
  });

  it("names the provider and time for a negative result", async () => {
    mockApi({ "/darkint/sources": { items: [source("hibp", "Have I Been Pwned", "live")], notice: "n" }, "/cases/c1/darkint/exposures": cov("no_match_checked_sources", "No match from checked sources"), "/subjects/s1/identifiers": { items: [] } });
    wrap(<Darkint p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Exposure coverage"));
    expect(screen.getByText("No match from checked sources")).toBeInTheDocument();
    expect(screen.getByText(/Have I Been Pwned: No match from checked sources \(/)).toBeInTheDocument();
  });

  it("shows each provider's honest state and sends nothing until the preview is confirmed", async () => {
    const preview = { items: [{ identifier_id: "i1", kind: "email", identifier: "j***@example.com", provider_id: "hibp", provider: "Have I Been Pwned", operation: "account_breaches", allowed: false, code: "CREDENTIAL_MISSING",
      reason: "CREDENTIAL_MISSING: add the 'hibp' API key in Settings.", will_send: { to: "https://haveibeenpwned.com/api/v3/", data: "the email", credentials: "the provider API key is sent as a header" },
      will_store: "Provider incident names only.", terms_url: "", cost: "paid", quota: "", terms_note: "", mocked: false }], runnable: 0, note: "" };
    const calls = mockApi({ "/darkint/sources": { items: [source("hibp", "Have I Been Pwned", "disabled"), source("intelligence_x", "Intelligence X", "manual_only", false)], notice: "n" },
      "/cases/c1/darkint/exposures": cov("not_checked", "Not checked"), "/subjects/s1/identifiers": { items: [{ id: "i1", kind: "email", value: "jane.doe@example.com" }] }, "/cases/c1/darkint/preview": preview });
    wrap(<Darkint p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Exposure providers"));
    expect(screen.getByText("manual only")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("option", { name: /^email: ja…/ })).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Input to check"), { target: { value: "i1" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /Have I Been Pwned/ }));
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => screen.getByLabelText("Check preview"));
    expect(screen.getAllByText(/CREDENTIAL_MISSING/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Confirm and check" })).toBeDisabled();
    expect(calls.some((c) => c.url.startsWith("/cases/c1/darkint/check"))).toBe(false);
  });

  it("is hidden from viewers", () => {
    mockApi({ "/darkint/sources": { items: [], notice: "" } });
    wrap(<Darkint p={prof("viewer")} />);
    expect(screen.getByText(/hidden for your role/)).toBeInTheDocument();
  });
});

describe("DARKINT dashboard", () => {
  it("shows four distinct states with counts and no identifiers", async () => {
    mockApi({ "/darkint/dashboard": { items: [{ case_id: "c1", case: "Jane", subject_id: "s1", subject: "Jane Example", mode: "self", states: { unknown: 1, not_checked: 2, no_match_checked_sources: 0, match_reported: 1 },
      unreviewed_events: 3, open_remediation: 1, monitors_active: 0, monitors_stopped: 1, last_checked: null }], totals: { unknown: 1, not_checked: 2, no_match_checked_sources: 0, match_reported: 1 }, notice: "n" },
      "/darkint/sources": { items: [source("hibp", "Have I Been Pwned", "disabled")], mock_mode: false } });
    wrap(<DarkintDashboard openCase={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Totals"));
    const totals = screen.getByLabelText("Totals");
    for (const label of ["Unknown", "Not checked", "No match from checked sources", "Match reported"]) expect(totals).toHaveTextContent(label);
    expect(screen.getByText(/1 stopped/)).toBeInTheDocument();
    expect(screen.getByText(/Enable and accept its terms/)).toBeInTheDocument();
  });
});
