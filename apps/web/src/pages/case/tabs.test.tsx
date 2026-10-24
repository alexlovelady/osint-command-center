import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AdminPanel from "../AdminPanel";
import AiTab from "./AiTab";
import AnalysisTab from "./AnalysisTab";
import HumintTab from "./HumintTab";

type Handler = (url: string, init?: RequestInit) => unknown;
function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    if (!key) return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
    const v = routes[key];
    const body = typeof v === "function" ? (v as Handler)(url, init) : v;
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  return calls;
}
const wrap = (el: ReactElement) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{el}</QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

describe("AiTab", () => {
  it("explains that AI is off and does not offer to ask", async () => {
    mockApi({ "/ai/profiles": { ai_enabled: false, items: [] }, "/cases/c1/ai-policy": { allow_cloud: false, require_preview: true, deny_sensitive_cloud: true } });
    wrap(<AiTab id="c1" />);
    await waitFor(() => expect(screen.getByText(/AI is/)).toBeInTheDocument());
    expect(screen.queryByLabelText("Question")).toBeNull();
  });

  it("cloud: shows the exact preview, sends nothing until approved, then re-sends with the token", async () => {
    const asks: unknown[] = [];
    mockApi({
      "/ai/profiles": { ai_enabled: true, items: [{ id: "p1", name: "cloudy", model_id: "big", kind: "cloud", provider_type: "openai_compat" }] },
      "/cases/c1/ai-policy": { allow_cloud: true, require_preview: true, deny_sensitive_cloud: true },
      "/ai/ask": (_u: string, init?: RequestInit) => {
        const b = JSON.parse(String(init?.body)); asks.push(b);
        return b.transfer_token ? { status: "answered", structured: true, local: false, model: "big", verified_evidence: [{ statement: "grounded fact", evidence_ids: ["11111111-1111-1111-1111-111111111111"] }],
          inferences: ["an inference"], contradictions: [], unknowns: [], next_steps: [], proposed_actions: [{ type: "search", target: "10.0.0.1", adapters: null }],
          rejected_citations: [{ statement: "made up", reason: "cites missing, unretrieved or other-case evidence" }], sensitive_items_withheld: 0 }
          : { status: "approval_required", transfer_token: "tok123", preview: { provider: "https://api.cloud.example", model: "big", chunks: 3, approx_tokens: 120, estimated_cost: "unknown", retention_warning: "Content leaves this machine", sensitive_items_withheld: 1 } };
      },
    });
    wrap(<AiTab id="c1" />);
    await waitFor(() => screen.getByLabelText("Question"));
    fireEvent.change(screen.getByLabelText("Question"), { target: { value: "who runs it?" } });
    fireEvent.click(screen.getByText("Ask"));
    await waitFor(() => expect(screen.getByRole("alertdialog")).toBeInTheDocument());
    expect(screen.getByText(/api.cloud.example/)).toBeInTheDocument();
    expect(asks).toHaveLength(1);
    expect((asks[0] as { transfer_token?: string }).transfer_token).toBeUndefined();   // first call carries no approval
    fireEvent.click(screen.getByText("Approve and send exactly this"));
    await waitFor(() => expect(screen.getByText("grounded fact")).toBeInTheDocument());
    expect((asks[1] as { transfer_token?: string }).transfer_token).toBe("tok123");
    expect(screen.getByText(/made up/)).toBeInTheDocument();                           // rejected citations are shown, not hidden
    expect(screen.getByText("Proposed actions (not executed)")).toBeInTheDocument();
    expect(screen.queryByText("Run")).toBeNull();                                      // there is no run button for model proposals
  });
});

describe("AdminPanel", () => {
  it("enabling a plugin submits the exact hash shown and nothing else is auto-enabled", async () => {
    const hash = "a".repeat(64);
    const calls = mockApi({
      "/settings": { ai_enabled: false, edgar_contact: null }, "/ai/profiles": { items: [] }, "/mcp/approvals": { items: [] },
      "/system/vault": { mode: "required", key_available: true, objects: 4, encrypted_objects: 3, plaintext_objects: 1, database_encrypted: false, note: "DB not encrypted" },
      "/plugins/example-robots/1.0.0/enable": { ok: 1 },
      "/plugins": { items: [{ plugin_id: "example-robots", version: "1.0.0", name: "robots", enabled: false, active: false, health: "installed_disabled", tree_sha256: hash, maintainer: "m", license: "MIT",
        permissions: { network_domains: ["{target}"], max_requests: 1 }, compatibility: { hash_ok: true }, network_isolation: "x" }] },
    });
    wrap(<AdminPanel />);
    await waitFor(() => screen.getByText(/I reviewed it/));
    expect(screen.getByText(hash)).toBeInTheDocument();                                // the reviewer sees the hash they are accepting
    expect(screen.getByText(/Encrypt the 1 older object/)).toBeInTheDocument();
    expect(screen.getByText(/DB not encrypted/)).toBeInTheDocument();                  // honesty about the database is visible
    expect(calls.some((c) => c.url.includes("/enable"))).toBe(false);
    fireEvent.click(screen.getByText(/I reviewed it/));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/enable"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.includes("/enable"))!.init!.body))).toEqual({ accept_hash: hash });
  });

  it("an unencrypted backup is clearly labelled", async () => {
    mockApi({ "/settings": { ai_enabled: false }, "/ai/profiles": { items: [] }, "/mcp/approvals": { items: [] }, "/plugins": { items: [] },
      "/system/vault": { mode: "off", key_available: false, objects: 0, encrypted_objects: 0, plaintext_objects: 0, database_encrypted: false, note: "n" } });
    wrap(<AdminPanel />);
    await waitFor(() => expect(screen.getByText("Create UNENCRYPTED backup")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Backup passphrase"), { target: { value: "long enough pass" } });
    expect(screen.getByText("Create encrypted backup")).toBeInTheDocument();
  });
});

describe("HumintTab", () => {
  it("shows aliases only, grade as the analyst's judgement, and asks before deleting content", async () => {
    const calls = mockApi({
      "/cases/c1/human-sources": { items: [{ id: "s1", alias: "Witness A", status: "active", reliability_assessment: null, reports: 2,
        consent: { basis: "informed_consent", authorizing_party: "the source", scope: ["interview"], expires_at: null, revoked_at: null } }] },
      "/cases/c1/humint/corroboration": { items: [{ subject: "van", predicate: "colour", single_source: true, groups: ["human:s1"] }] },
      "/human-sources/s1/revoke": { ok: 1 },
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    wrap(<HumintTab id="c1" />);
    await waitFor(() => screen.getByText("Witness A"));
    expect(screen.getByText(/never scores a source/)).toBeInTheDocument();
    expect(screen.getByLabelText("Reliability for Witness A")).toHaveValue("");     // unrated until the analyst decides
    fireEvent.click(screen.getByText("Withdraw and delete content"));
    expect(confirm).toHaveBeenCalled();
    expect(calls.some((c) => c.url.includes("/revoke"))).toBe(false);               // declined => nothing sent
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByText("Withdraw and delete content"));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/revoke"))).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url.includes("/revoke"))!.init!.body))).toMatchObject({ delete_content: true, confirm: true });
  });
});

describe("AnalysisTab", () => {
  it("renders conflicting claims side by side with labels and does not offer to delete either", async () => {
    mockApi({
      "/claims?case_id=c1": { total: 2, items: [] }, "/cases/c1/gaps": { summary: "1 open requirement(s)", unanswered_requirements: [{ id: "r1", question: "Who hosts it?", priority: "high" }], stale_findings: 0, disputed_claims: 0, unverified_claims: 2, contradictions: 1 },
      "/cases/c1/contradictions": { items: [{ subject: "example.com", predicate: "registrar", note: "", positions: [
        { id: "a", value: "Registrar A", confidence_label: "low", verification_status: "unverified", independent_source_groups: 1, sources: [] },
        { id: "b", value: "Registrar B", confidence_label: "medium", verification_status: "unverified", independent_source_groups: 2, sources: [] }] }] },
      "/requirements?case_id=c1": { items: [] }, "/hypotheses?case_id=c1": { items: [] },
    });
    wrap(<AnalysisTab id="c1" />);
    await waitFor(() => screen.getByText("Registrar A"));
    expect(screen.getByText("Registrar B")).toBeInTheDocument();
    expect(screen.getByText(/open: Who hosts it/)).toBeInTheDocument();
    expect(screen.queryByText(/Delete/)).toBeNull();
  });
});
