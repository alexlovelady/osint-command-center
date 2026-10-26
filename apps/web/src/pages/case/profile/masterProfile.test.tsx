import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { MasterDoc, MasterItem, MasterSection } from "../../../lib/masterApi";
import type { ProfileT } from "../../../lib/profileApi";
import MasterProfile from "./MasterProfile";

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

const item = (o: Partial<MasterItem>): MasterItem => ({ id: "item:1", category: "contact", type: "email", type_label: "Email address", value: "jane@acme-example.com", masked: false, restricted: false, evidence: [],
  origin: "analyst_supplied", confidence: "unknown", verification_state: "unassessed", state_label: "Unassessed", is_input: true, feeds_research: true, caveat: "", ...o });
const sec = (key: string, title: string, items: MasterItem[], types: string[]): MasterSection => ({ key, title, items, types, empty_note: items.length ? "" : "Not researched. An empty section is unknown, never evidence that nothing exists.",
  counts: { unassessed: items.length, candidate: 0, corroborated: 0, conflicting: 0, rejected: 0, not_available: 0 } });
const doc = (role: string, over: Partial<MasterDoc> = {}): MasterDoc => ({
  subject_id: "s1", role, restricted_hidden: 0, notice: "Inputs are what you provided. An empty field means not researched.", restricted_note: "Restricted: shown masked.",
  states: [{ key: "unassessed", label: "Unassessed" }, { key: "candidate", label: "Candidate" }, { key: "corroborated", label: "Corroborated" }, { key: "conflicting", label: "Conflicting" }, { key: "rejected", label: "Rejected" }, { key: "not_available", label: "Not available" }],
  sections: [sec("identity", "Identity", [item({ id: "item:d", category: "identity", type: "date_of_birth", type_label: "Date of birth", value: "1990-••-••", masked: true, restricted: true, is_input: false, feeds_research: false })], ["date_of_birth", "full_name"]),
    sec("contact", "Contact", [item({})], ["email", "phone"]), sec("education", "Education", [], ["employer"])],
  types: [{ type: "email", category: "contact", label: "Email address", restricted: false, reference_only: false, single_valued: false, feeds_research: true, backed_by: "input" },
    { type: "phone", category: "contact", label: "Phone number", restricted: true, reference_only: false, single_valued: false, feeds_research: false, backed_by: "item" },
    { type: "date_of_birth", category: "identity", label: "Date of birth", restricted: true, reference_only: false, single_valued: true, feeds_research: false, backed_by: "item" },
    { type: "full_name", category: "identity", label: "Full name", restricted: false, reference_only: false, single_valued: false, feeds_research: true, backed_by: "input" }],
  duplicates: [], subject: { id: "s1", display_name: "Jane" },
  gaps: { categories: [{ key: "identity", title: "Identity", status: "manual_only", label: "Needs manual entry", why: "Add full and alternate names.", items: 0, sources: [] }],
    next_actions: [{ priority: 90, kind: "integration_gap", text: "No supported email-first discovery source configured. Add a key in Settings.", go: "Settings" }],
    email_first: { has_email: true, message: "No supported email-first discovery source configured.", configured: 0, sources: [{ source_id: "web_search_email", name: "Web search", state: "needs_key", needs_key: "brave_search", sends: "the address", cost: "your own key" }] },
    coverage: { attempted_categories: 1, of: 13, label: "Coverage counts categories where an authorized method was attempted. It is not a percentage of all information that exists." }, plan_stop_reason: "" }, ...over });

describe("Master profile editor", () => {
  it("shows unknown as not researched, the email-first message, masked restricted values and the gaps panel", async () => {
    mockApi({ "/subjects/s1/master": doc("owner") });
    wrap(<MasterProfile p={prof("owner")} onGo={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Master profile"));
    expect(screen.getByLabelText("Email-first discovery")).toHaveTextContent("No supported email-first discovery source configured.");
    expect(screen.queryByText(/Nothing found|Research complete/)).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: /Education/ }));
    expect(screen.getByText(/never evidence that nothing exists/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Identity/ }));
    expect(screen.getByText("1990-••-••")).toBeInTheDocument();
    expect(screen.queryByText("1990-04-12")).toBeNull();
    expect(screen.getByLabelText("Research gaps and next actions")).toHaveTextContent("not a percentage of all information");
  });

  it("adds an item through the single write path and requires a reason before reveal", async () => {
    const calls = mockApi({ "/subjects/s1/master/items/item%3Ad/reveal": { value: "1990-04-12" }, "/subjects/s1/master/items": { id: "item:2", created: true }, "/subjects/s1/master": doc("owner") });
    wrap(<MasterProfile p={prof("owner")} onGo={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Master profile"));
    fireEvent.click(screen.getByRole("tab", { name: /Contact/ }));
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "jane2@acme-example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/subjects/s1/master/items" && c.init?.method === "POST")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url === "/subjects/s1/master/items")!.init!.body))).toMatchObject({ type: "email", value: "jane2@acme-example.com", origin: "analyst_supplied" });
    fireEvent.click(screen.getByRole("tab", { name: /Identity/ }));
    fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
    expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason for revealing"), { target: { value: "confirming with the owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => screen.getByText("1990-04-12"));
  });

  it("hides editing controls from viewers", async () => {
    mockApi({ "/subjects/s1/master": doc("viewer", { gaps: null, restricted_hidden: 2 }) });
    wrap(<MasterProfile p={prof("viewer")} onGo={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Master profile"));
    expect(screen.getByText(/2 restricted value\(s\) are hidden/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Corroborate" })).toBeNull();
    expect(screen.queryByLabelText("Add to Identity")).toBeNull();
    expect(screen.queryByLabelText("Research gaps and next actions")).toBeNull();
  });

  it("explains that self-attestation is not corroboration and reports import errors row by row", async () => {
    mockApi({ "/subjects/s1/master/items/batch": { created: 1, existing: 0, errors: [{ row: 2, code: "invalid_type", message: "unknown type" }] }, "/subjects/s1/master": doc("editor") });
    wrap(<MasterProfile p={prof("editor")} onGo={() => undefined} />);
    await waitFor(() => screen.getByLabelText("Master profile"));
    fireEvent.click(screen.getByRole("tab", { name: /Contact/ }));
    fireEvent.click(screen.getByRole("button", { name: "Corroborate" }));
    expect(screen.getByText(/not corroboration/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Rows to import"), { target: { value: "type,value\nemail,a@b.example\nnonsense,x" } });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => screen.getByText(/1 added, 0 already present, 1 not imported/));
    expect(screen.getByText(/Row 2: unknown type/)).toBeInTheDocument();
  });
});
