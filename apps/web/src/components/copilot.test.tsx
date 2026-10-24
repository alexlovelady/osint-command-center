import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Markdown } from "../lib/markdown";
import CopilotPanel from "./CopilotPanel";
import TourOverlay from "./TourOverlay";

afterEach(() => { vi.restoreAllMocks(); localStorage.clear(); });

describe("Markdown", () => {
  it("renders structure and citation chips as elements, never as HTML or links", () => {
    const onCite = vi.fn();
    const { container } = render(<Markdown text={"**Facts**\n- RDAP shows two nameservers [c1]\n- docs say so [d2]\n\n<script>alert(1)</script> [evil](http://x.test)"} onCite={onCite} />);
    expect(container.querySelector("strong")?.textContent).toBe("Facts");
    expect(container.querySelectorAll("li")).toHaveLength(2);
    fireEvent.click(screen.getByLabelText("Source c1"));
    expect(onCite).toHaveBeenCalledWith("c1");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");   // shown as text
  });
});

const ndjson = (events: object[]) => events.map((e) => JSON.stringify(e)).join("\n") + "\n";
type Calls = { url: string; init?: RequestInit }[];

function mockBackend(chatEvents: object[], extra: Record<string, unknown> = {}): Calls {
  const calls: Calls = [];
  const saved: object[] = [];   // what the backend would have stored: the panel reloads it after every reply
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
    if (url.startsWith("/copilot/chat")) {
      const fin = chatEvents.find((e) => (e as { type: string }).type === "final") as { text: string; sources?: unknown[]; warnings?: string[] } | undefined;
      if (fin) saved.push({ role: "user", mode: "general", content: JSON.parse(String(init?.body)).text }, { role: "assistant", mode: "general", content: fin.text, meta: { sources: fin.sources, warnings: fin.warnings } });
    }
    if (url.startsWith("/copilot/chat")) return new Response(ndjson(chatEvents), { headers: { "content-type": "application/x-ndjson" } });
    for (const [k, v] of Object.entries(extra)) if (url.startsWith(k)) return json(typeof v === "function" ? (v as (u: string, i?: RequestInit) => unknown)(url, init) : v);
    if (url.startsWith("/copilot/status")) return json({ ai_enabled: true, ready: true, reason: "", fallback: "", active: { id: "p1", name: "local", model: "qwen3-test", type: "ollama", local: true }, profiles: [{ id: "p1", name: "local", model: "qwen3-test", type: "ollama", local: true }] });
    if (url.startsWith("/copilot/suggestions")) return json({ items: [{ label: "What is this page for?", prompt: "What is this page for?" }] });
    if (url.startsWith("/copilot/conversation")) return json({ conversation: null, messages: saved, proposals: [], skipped_corrupt: 0 });
    if (url.startsWith("/copilot/tutorials")) return json({ items: [] });
    return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
  });
  return calls;
}

function panel() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><CopilotPanel open setOpen={() => {}} /></QueryClientProvider>);
}

describe("CopilotPanel", () => {
  it("shows the active model, streams the reply and lists its sources", async () => {
    mockBackend([
      { type: "meta", conversation_id: "c", mode: "general", intent: null, skipped_corrupt: 0, model: { active: { id: "p1", name: "local", model: "qwen3-test", type: "ollama", local: true }, ready: true, reason: "", local: true } },
      { type: "delta", text: "RDAP is a registration " }, { type: "delta", text: "lookup protocol [d1]." },
      { type: "final", text: "RDAP is a registration lookup protocol [d1].", sources: [{ ref: "d1", id: "glossary:RDAP", source: "glossary:RDAP", title: "RDAP" }], warnings: [], message_id: "m1" },
      { type: "done", conversation_id: "c", message_id: "m1", proposals: [] },
    ]);
    panel();
    await waitFor(() => expect(screen.getByText("qwen3-test")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Ask the Copilot"), { target: { value: "What is RDAP?" } });
    await act(async () => { fireEvent.click(screen.getByText("Send")); });
    await waitFor(() => expect(screen.getByText(/lookup protocol/)).toBeInTheDocument());
    expect(screen.getByText("What is RDAP?")).toBeInTheDocument();
    expect(await screen.findByLabelText("Sources")).toHaveTextContent("RDAP");
  });

  it("shows an action as a proposal that cannot be approved until required confirmations are ticked, and approves with confirm=true", async () => {
    const proposal = {
      id: "pr1", tool: "start_search", case_id: "case1", status: "pending", args: { target: "example.net", adapters: ["rdap", "sherlock"] },
      preview: { steps: [{ adapter_id: "rdap", name: "RDAP", runnable: true, reason: "passive", endpoints: ["rdap.org"] }, { adapter_id: "sherlock", name: "Sherlock", runnable: true, reason: "many sites", requires_confirmation: true }], needs_confirmation: ["sherlock"] },
      result: {}, sensitive: "Sends requests to the listed external services.", description: "Start a collection run",
    };
    const calls = mockBackend([
      { type: "meta", conversation_id: "c", mode: "general", intent: null, skipped_corrupt: 0, model: { active: null, ready: false, reason: "", local: true } },
      { type: "proposal", proposal },
      { type: "final", text: "I can run that once you approve.", sources: [], warnings: [], message_id: "m2" },
      { type: "done", conversation_id: "c", message_id: "m2", proposals: ["pr1"] },
    ], { "/copilot/proposals/pr1/approve": { proposal: { ...proposal, status: "executed", result: { run_id: "abcdef123456" } }, result: { run_id: "abcdef123456" } },
         "/copilot/conversation": () => ({ conversation: { id: "c", mode: "general" }, messages: [
           { role: "user", mode: "general", content: "search example.net" },
           { role: "assistant", mode: "general", content: "I can run that once you approve.", meta: { proposals: ["pr1"] } }], proposals: [proposal], skipped_corrupt: 0 }) });
    panel();
    fireEvent.change(screen.getByLabelText("Ask the Copilot"), { target: { value: "search example.net" } });
    await act(async () => { fireEvent.click(screen.getByText("Send")); });
    const approve = await screen.findByText("Approve and run");
    expect(approve).toBeDisabled();                                       // Sherlock needs its own confirmation
    expect(screen.getByText("Reject")).toBeEnabled();
    fireEvent.click(screen.getByLabelText(/I confirm sherlock/));
    expect(approve).toBeEnabled();
    await act(async () => { fireEvent.click(approve); });
    await waitFor(() => expect(calls.some((c) => c.url === "/copilot/proposals/pr1/approve")).toBe(true));
    const body = JSON.parse(String(calls.find((c) => c.url === "/copilot/proposals/pr1/approve")!.init!.body));
    expect(body).toEqual({ confirm: true, confirmed_adapters: ["sherlock"] });
  });

  it("asks for approval of the exact payload before anything goes to a cloud model", async () => {
    const calls = mockBackend([
      { type: "meta", conversation_id: "c", mode: "general", intent: null, skipped_corrupt: 0, model: { active: { id: "p2", name: "cloud", model: "big", type: "openai_compat", local: false }, ready: true, reason: "", local: false } },
      { type: "approval_required", transfer_token: "tok", preview: { provider: "https://api.example.com", model: "big", approx_tokens: 900, case_records_included: 3, restricted_items_withheld: 1,
        warning: "This text and the case records listed will leave this computer for the provider's servers.", messages: [{ role: "user", content: "hello" }] } },
    ]);
    panel();
    fireEvent.change(screen.getByLabelText("Ask the Copilot"), { target: { value: "hello" } });
    await act(async () => { fireEvent.click(screen.getByText("Send")); });
    expect(await screen.findByText(/leave this computer/)).toBeInTheDocument();
    expect(screen.getByText("Send this once")).toBeInTheDocument();
    expect(calls.filter((c) => c.url.startsWith("/copilot/chat"))).toHaveLength(1);   // nothing re-sent without the click
  });

  it("says plainly when no model is available", async () => {
    mockBackend([], { "/copilot/status": { ai_enabled: false, ready: false, reason: "AI is switched off (Settings -> AI)", fallback: "Without a working model the Copilot still answers from the built-in documentation.", active: null, profiles: [] } });
    panel();
    expect(await screen.findByText(/No AI model: documentation and stored data only/)).toBeInTheDocument();
    expect(screen.getByText(/AI is switched off/)).toBeInTheDocument();
  });
});

describe("TourOverlay", () => {
  it("highlights the real element and does not pretend when it is missing", async () => {
    render(<><input data-tour="here" aria-label="here" /><TourOverlay title="T" steps={[{ n: 1, go: { route: "cases" }, target: "here", text: "Fill this in" }, { n: 2, go: { route: "cases" }, target: "nope", text: "Then this" }]} onClose={() => {}} /></>);
    expect(await screen.findByText("Fill this in")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Next"));
    expect(await screen.findByText("Then this")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/can't find that control/)).toBeInTheDocument(), { timeout: 6000 });
  }, 10000);
});
