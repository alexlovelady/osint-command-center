import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import Library from "../pages/automations/Library";
import { edges, fromModel, layout, levels, neighbour, removeNode, toModel, uniqueId, type WfDef, type WfNode } from "../lib/workflowGraph";
import WorkflowCanvas from "./WorkflowCanvas";

afterEach(() => vi.restoreAllMocks());

const def: WfDef = {
  schema_version: 1, workflow_key: "t", name: "T", description: "", owner_scope: "investigation", status: "draft", tags: ["a"],
  trigger: { type: "schedule", schedule: "0 8 * * *", timezone: "America/New_York", enabled: false, missed_run_policy: "coalesce", event: null },
  inputs: { domain: "example.org", other: null }, policy: { network_mode: "passive_only", max_requests_per_provider_per_run: 50 }, error_policy: { transient_retries: 2 },
  nodes: [
    { id: "scope", type: "authorization_check", depends_on: [], config: { target_ref: "$inputs.domain", mode: "passive_only", target_type: null } },
    { id: "rdap", type: "adapter_query", depends_on: ["scope"], config: { adapter: "rdap", target_ref: "$inputs.domain" } },
    { id: "dns", type: "adapter_query", depends_on: ["scope"], config: { adapter: "dns", target_ref: "$inputs.domain" }, optional: true },
    { id: "merged", type: "transform", depends_on: ["rdap", "dns"], config: { ref: "$nodes.rdap.output", extra_refs: ["$nodes.dns.output"], op: "merge" } },
    { id: "diff", type: "snapshot_diff", depends_on: ["merged"], config: { dataset_ref: "$nodes.merged.output" }, when: { ref: "$nodes.merged.output.count", op: "gt", value: 0 } },
  ],
};

describe("workflow graph helpers", () => {
  it("a visual round trip never changes the definition", () => {
    expect(fromModel(toModel(def))).toEqual(def);
    const shuffled = { ...def, nodes: [...def.nodes].reverse() };
    expect(layout(shuffled.nodes).pos).toEqual(layout(def.nodes).pos);               // positions are derived from structure, not from the order of the list
    expect(layout(def.nodes)).toEqual(layout(structuredClone(def.nodes)));
  });
  it("layers nodes left to right and rejects cycles", () => {
    expect(levels(def.nodes)).toEqual({ scope: 1, rdap: 2, dns: 2, merged: 3, diff: 4 });
    const cyc: WfNode[] = [{ id: "a", type: "delay", depends_on: ["b"], config: {} }, { id: "b", type: "delay", depends_on: ["a"], config: {} }];
    expect(levels(cyc)).toBeNull();
    expect(edges(def.nodes)).toHaveLength(5);
  });
  it("removing a node also removes the dependencies on it", () => {
    const n = removeNode(def.nodes, "rdap");
    expect(n.find((x) => x.id === "merged")!.depends_on).toEqual(["dns"]);
    expect(uniqueId(def.nodes, "scope")).toBe("scope_2");
    expect(uniqueId(def.nodes, "fresh")).toBe("fresh");
  });
  it("arrow keys follow the graph", () => {
    const { pos } = layout(def.nodes);
    expect(neighbour(def.nodes, pos, "scope", "right")).toBe("rdap");
    expect(neighbour(def.nodes, pos, "rdap", "left")).toBe("scope");
    expect(neighbour(def.nodes, pos, "dns", "down")).toBe("rdap");        // columns are ordered by id: dns above rdap
    expect(neighbour(def.nodes, pos, "rdap", "up")).toBe("dns");
    expect(neighbour(def.nodes, pos, "rdap", "down")).toBeNull();
    expect(neighbour(def.nodes, pos, "scope", "left")).toBeNull();
  });
});

describe("WorkflowCanvas", () => {
  it("is keyboard operable, labels every step and shows validation markers", () => {
    const onSelect = vi.fn();
    render(<WorkflowCanvas nodes={def.nodes} selected={null} onSelect={onSelect} issues={[{ code: "INVALID_GRAPH", node: "dns", message: "x" }]} titles={{ adapter_query: "Source query" }} networkTypes={new Set(["adapter_query"])} />);
    expect(screen.getByRole("application")).toHaveAccessibleName(/5 steps/);
    const dns = screen.getByRole("button", { name: /dns, Source query, 1 problem, optional/ });
    expect(dns).toHaveAttribute("tabindex", "0");
    fireEvent.keyDown(screen.getByRole("button", { name: /^scope,/ }), { key: "ArrowRight" });
    expect(onSelect).toHaveBeenCalledWith("rdap");
    fireEvent.keyDown(dns, { key: "Enter" });
    expect(onSelect).toHaveBeenLastCalledWith("dns");
    expect(screen.getByRole("button", { name: "Zoom in" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Minimap" })).toBeInTheDocument();
  });
  it("shows run states on the nodes", () => {
    render(<WorkflowCanvas nodes={def.nodes} selected="rdap" onSelect={() => {}} states={{ rdap: "succeeded", dns: "failed" }} />);
    expect(screen.getByRole("button", { name: /rdap.*succeeded/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /dns.*failed/ })).toBeInTheDocument();
  });
  it("deletes the focused step on Delete", () => {
    const onDelete = vi.fn();
    render(<WorkflowCanvas nodes={def.nodes} selected={null} onSelect={() => {}} onDelete={onDelete} />);
    fireEvent.keyDown(screen.getByRole("button", { name: /^diff,/ }), { key: "Delete" });
    expect(onDelete).toHaveBeenCalledWith("diff");
  });
});

describe("Library", () => {
  it("shows availability honestly, lists what is missing and creates only a disabled draft", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const tpl = (key: string, state: string, extra: object = {}) => ({ slug: key.toLowerCase(), key, category: "Cyber", name: `Template ${key}`, description: "desc", catalog_trigger: "Manual", trigger: "manual", tags: [],
      dependencies: ["rdap"], optional_dependencies: [], quota_note: "About 3 source request(s) per run", maturity: "fixture_tested", capability_gaps: [], checksum: "x", installed_disabled: true,
      availability: { state, missing: state === "setup_required" ? [{ adapter: "sherlock", status: "not_installed", setup: "Install Sherlock from Setup." }] : [], optional_missing: [], gaps: [] }, ...extra });
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input).replace("/api/v1", "");
      calls.push({ url, init });
      const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
      if (url.startsWith("/automations/templates/")) return json({ ...tpl("ID-01", "setup_required"), instructions: "Check many sites.", legal_notes: "Consent needed.", example_output: "Candidates.", inputs: [{ name: "username", label: "Username", type: "username", required: true, example: "alice" }] });
      if (url.startsWith("/automations/templates")) return json({ total: 2, categories: ["Cyber"], note: "All templates are installed disabled.", items: [tpl("CY-01", "ready"), tpl("ID-01", "setup_required")] });
      if (url.startsWith("/automations/from-template")) return json({ id: "w1" });
      if (url.startsWith("/cases")) return json({ items: [] });
      return new Response("{}", { status: 404 });
    });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Library /></QueryClientProvider>);
    expect(await screen.findByText("Template CY-01")).toBeInTheDocument();
    expect(screen.getByText("ready")).toBeInTheDocument();
    expect(screen.getByText("setup required")).toBeInTheDocument();
    fireEvent.click(screen.getAllByText("Details")[1]);
    expect(await screen.findByText(/Install Sherlock from Setup/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "bob" } });
    fireEvent.click(screen.getByText("Create from template"));
    await waitFor(() => expect(calls.some((c) => c.url === "/automations/from-template")).toBe(true));
    const body = JSON.parse(String(calls.find((c) => c.url === "/automations/from-template")!.init!.body));
    expect(body).toEqual({ slug: "id-01", case_id: null, inputs: { username: "bob" } });                // nothing about scheduling or activation is sent
  });
});
