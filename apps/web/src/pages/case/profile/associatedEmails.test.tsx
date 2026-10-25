import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AssociatedEmailT, EmailList, ExpansionPlan } from "../../../lib/emailApi";
import type { ProfileT } from "../../../lib/profileApi";
import AssociatedEmails from "./AssociatedEmails";

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

const mail = (id: string, address: string, cls: AssociatedEmailT["classification"], extra: Partial<AssociatedEmailT> = {}): AssociatedEmailT => ({
  id, address, masked: false, classification: cls, label: cls[0].toUpperCase() + cls.slice(1), state: cls === "confirmed" ? "confirmed" : "candidate", origin: "observed", origin_label: "Observed in a source",
  explanation: [cls === "likely" ? "2 independent sources explicitly tie this address to the subject (github, web:jane-example.org)." : "One source ties it to the subject explicitly (github)."],
  confirmation_kind: null, conflicts: [], associations: { usernames: ["janedoe"], domains: ["github.com"], documents: [], accounts: [] }, aliases: [], depth: 1, origin_path: ["subject input", "github_public on janedoe shows j***@acme-example.com"],
  discovered_at: "2026-10-01T00:00:00Z", last_verified_at: null, reviewed_by: null, review_basis: "", note: "", is_input: false,
  exposure: { state: "not_an_input", label: "Not checked", note: "A candidate is not an authorized input." },
  sources: [{ id: "x", kind: "profile_field", group: "github", explicit: true, evidence_id: "e1e1e1e1-0000", url: "https://github.com/janedoe", context: "Contact address listed on the public GitHub profile", adapter: "github_public", basis: "listed on the public profile", observed_at: "2026-10-01T00:00:00Z", via: "janedoe" }],
  evidence: [{ id: "e1e1e1e1-0000", title: "github profile", kind: "github_public.raw", sha256: "a".repeat(64), url: null }], ...extra });
const list = (items: AssociatedEmailT[]): EmailList => ({ items, counts: { confirmed: 0, likely: items.filter((i) => i.classification === "likely").length, possible: items.filter((i) => i.classification === "possible").length, rejected: 0 },
  duplicates: [], legend: { confirmed: "", likely: "", possible: "", rejected: "" }, notice: "An address found in a source is a candidate, never a fact.", role: "owner" });
const plan: ExpansionPlan = { policy: { max_depth: 2, max_runs: 20, max_per_pass: 6, auto_passive: false }, budget: { used: 1, max_runs: 20, remaining: 19, max_per_pass: 6 }, stop_reason: "",
  rules: ["Only your inputs and addresses a person confirmed are used as starting points.", "Likely and possible addresses are listed, never researched."], history: [],
  seeds: { proposals: [{ label: "j***@acme-example.com", state: "likely", action: "confirm_first", reason: "Likely, not confirmed: a person must confirm before anything is researched from it." }], skipped: { rejected_emails: 1 } },
  steps: [{ key: "i1:github_public", module: "OSINT", identifier: "janedoe", source_id: "github_public", source: "GitHub profile and commit authors", depth: 0, origin_path: [], priority: 90, runnable: true, needs: "confirmation", reason: "", executable_now: false, endpoints: [], privacy: "public_personal" },
    { key: "i1:darkint", module: "DARKINT", identifier: "j***@example.com", source_id: "darkint", source: "Exposure check (breach and mention providers)", depth: 0, origin_path: [], priority: 5, runnable: false, needs: "explicit_approval", reason: "Needs its own preview and approval in the DARKINT tab.", executable_now: false, endpoints: [], privacy: "personal_sensitive" }] };

describe("Associated emails", () => {
  it("shows the classification, why, evidence and conflicts, and never presents a candidate as a fact", async () => {
    mockApi({ "/subjects/s1/associated-emails": list([mail("m1", "jane.work@acme-example.com", "likely"), mail("m2", "bob@builder.example", "possible", { conflicts: [{ kind: "different_name", detail: "a source attributes the address to 'Robert Builder'" }], explanation: ["Conflict: a source attributes the address to 'Robert Builder'."] })]), "/subjects/s1/expansion": plan });
    wrap(<AssociatedEmails p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Associated emails"));
    expect(screen.getByText("Likely")).toBeInTheDocument();
    expect(screen.getByText(/never a fact/)).toBeInTheDocument();
    expect(screen.queryByText("Confirmed", { selector: "b" })).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: "Why" })[1]);
    expect(screen.getByText(/Conflicting evidence/)).toBeInTheDocument();
    expect(screen.getAllByText(/Robert Builder/).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /Possible \(1\)/ }));
    expect(screen.queryByText("jane.work@acme-example.com")).toBeNull();
  });

  it("confirming needs a reason, states the rule, and bulk decisions go through one request", async () => {
    const calls = mockApi({ "/subjects/s1/associated-emails/review": { updated: 2, bulk_id: "b", state: "rejected" }, "/subjects/s1/associated-emails": list([mail("m1", "a@x.example", "likely"), mail("m2", "b@x.example", "possible")]), "/subjects/s1/expansion": plan });
    wrap(<AssociatedEmails p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Associated emails"));
    fireEvent.click(screen.getByLabelText("Select a@x.example"));
    fireEvent.click(screen.getByLabelText("Select b@x.example"));
    const confirm = screen.getByRole("button", { name: "Confirm" });
    expect(confirm).toBeDisabled();
    expect(screen.getByText(/needs the owner’s attestation or independent corroboration/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Reason for the decision"), { target: { value: "both belong to her employer" } });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/review"))).toBe(true));
    const body = JSON.parse(String(calls.find((c) => c.url.endsWith("/review"))!.init!.body));
    expect(body).toMatchObject({ ids: ["m1", "m2"], to_state: "rejected", attestation: "none" });
  });

  it("the plan marks what needs a person, lists candidates as not researched, and runs only ticked steps", async () => {
    const calls = mockApi({ "/subjects/s1/expansion/run": { status: "executed", stop_reason: "", started_runs: 1 }, "/subjects/s1/associated-emails": list([]), "/subjects/s1/expansion": plan });
    wrap(<AssociatedEmails p={prof("owner")} />);
    await waitFor(() => screen.getByLabelText("Cross-INT research plan"));
    expect(screen.getByText(/needs its own approval/)).toBeInTheDocument();
    expect(screen.getByText(/nothing is researched from these until you confirm them/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Include Exposure check/)).toBeNull();                          // an exposure check cannot be ticked here
    const run = screen.getByRole("button", { name: /Run the 0 selected/ });
    expect(run).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/Include GitHub profile and commit authors on janedoe/));
    fireEvent.click(screen.getByLabelText(/I confirm this contacts that public site/));
    fireEvent.click(screen.getByRole("button", { name: /Run the 1 selected/ }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/expansion/run"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.endsWith("/expansion/run"))!.init!.body))).toMatchObject({ keys: ["i1:github_public"], confirmed_sources: ["github_public"] });
  });

  it("viewers see masked addresses and no decision controls or plan", async () => {
    mockApi({ "/subjects/s1/associated-emails": { ...list([mail("m1", "j***@acme-example.com", "likely", { masked: true })]), role: "viewer" } });
    wrap(<AssociatedEmails p={prof("viewer")} />);
    await waitFor(() => screen.getByLabelText("Associated emails"));
    expect(screen.getByText(/masked for your role/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Confirm" })).toBeNull();
    expect(screen.queryByLabelText("Cross-INT research plan")).toBeNull();
    expect(screen.queryByLabelText("Add an address")).toBeNull();
  });
});
