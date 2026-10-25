import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import BrandingCard from "../../../components/BrandingCard";
import type { AivCaps, AssetAuth, BrandingT, PlanPreview } from "../../../lib/aivApi";
import Verification from "../profile/Verification";
import Workbench from "./Workbench";

type Handler = (url: string, init?: RequestInit) => unknown;
function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input).replace("/api/v1", "");
    calls.push({ url, init });
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => url.startsWith(k));
    if (!key) return new Response(JSON.stringify({ code: "nf", message: "no route " + url, request_id: "r", retryable: false, details_safe: {} }), { status: 404 });
    const v = routes[key];
    const body = typeof v === "function" ? (v as Handler)(url, init) : v;
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  return calls;
}
const wrap = (el: ReactElement) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{el}</QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

const caps = (enabled: boolean): AivCaps => ({ enabled, offline: false, classes: ["http_metadata", "tls_handshake", "tcp_connect", "service_detect", "signature_check"], lab_class: "lab_network",
  asset_types: ["fqdn"], attestation_kinds: ["owner_statement", "signed_document"], default_limits: {}, forbidden: ["exploitation or payload delivery", "credential testing, guessing or brute force"],
  boundary: "AIV verifies assets someone has authorized.", tools: [
    { id: "nmap", name: "Nmap", status: "not_installed", version: null, detail: "Install Nmap", role: "ports", license: "NPSL", install_hint: "", source_url: "" },
    { id: "http_metadata", name: "http metadata", status: "healthy", version: "built-in", detail: "built in", role: "", license: "in-house", install_hint: "", source_url: "" }] });
const auth: AssetAuth = { id: "a1", asset_type: "fqdn", scope: ["www.example.org"], ports: [443], paths: ["/"], allowed_classes: ["http_metadata", "tls_handshake"], exclusions: [], limits: {},
  authorized_by: "Owner", authority_role: "owner", source_of_authority: "I own it", attestation_kind: "owner_statement", starts_at: "2026-01-01T00:00:00Z", expires_at: "2026-12-01T00:00:00Z",
  revoked_at: null, state: "live", state_reason: "", owner_subject_id: null, scope_snapshot_hash: "h" };

describe("Verification workbench", () => {
  it("says plainly that it is off and offers nothing active until it is switched on", async () => {
    mockApi({ "/aiv/capabilities": caps(false), "/cases/c1/asset-authorizations": { items: [] } });
    wrap(<Workbench caseId="c1" />);
    await waitFor(() => expect(screen.getByText(/Active verification is OFF/)).toBeInTheDocument());
    expect(screen.getByText(/Nothing active can run/)).toBeInTheDocument();
    expect(screen.getAllByText(/not installed/i).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("tab", { name: "Plans" }));
    expect(screen.getByText("Verification is switched off")).toBeInTheDocument();
    expect(screen.queryByLabelText("Build a verification plan")).toBeNull();
  });

  it("lists what is never done and reports tool status honestly", async () => {
    mockApi({ "/aiv/capabilities": caps(true), "/cases/c1/asset-authorizations": { items: [auth] } });
    wrap(<Workbench caseId="c1" />);
    await waitFor(() => screen.getByLabelText("Tool status"));
    expect(screen.getByText("exploitation or payload delivery")).toBeInTheDocument();
    expect(screen.getAllByText(/not installed/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/exercised against local lab servers, not third-party systems/)).toBeInTheDocument();
  });

  it("recording an authorization keeps person-consent separate and needs the proof fields", async () => {
    const calls = mockApi({ "/aiv/capabilities": caps(true), "/cases/c1/asset-authorizations": (_u: string, init?: RequestInit) => (init?.method === "POST" ? auth : { items: [] }) });
    wrap(<Workbench caseId="c1" />);
    await waitFor(() => screen.getByRole("tab", { name: "Authorizations" }));
    fireEvent.click(screen.getByRole("tab", { name: "Authorizations" }));
    await waitFor(() => screen.getByLabelText("Record an asset authorization"));
    expect(screen.getByText(/consent to be researched/)).toBeInTheDocument();
    const submit = screen.getByRole("button", { name: "Record authorization" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Hosts in scope"), { target: { value: "www.example.org" } });
    fireEvent.change(screen.getByLabelText("Authorized by"), { target: { value: "Owner" } });
    fireEvent.change(screen.getByLabelText("Source of authority"), { target: { value: "I own and operate this server" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.init?.method === "POST")).toBe(true));
    const body = JSON.parse(String(calls.find((c) => c.init?.method === "POST")!.init!.body));
    expect(body.scope).toEqual(["www.example.org"]);
    expect(body.allowed_classes).not.toContain("lab_network");
  });

  it("previews a plan without sending, blocks a denied plan from being saved, and approval needs an explicit tick", async () => {
    const denied: PlanPreview = { ok: false, steps: [{ index: 0, kind: "tls_handshake", target: "other.test", detail: {}, allowed: false, code: "host_out_of_scope", reason: "host is not in the authorization", estimated_requests: 5, impact: "low" }],
      problems: [], estimated_requests: 5, limits: {}, hosts: ["other.test"], impact: "low", tools: {}, plan_hash: "0".repeat(64), normalized_steps: [], disclosure: { external_services: [], data_retention: "kept", what_is_sent: "Only the requests listed." } };
    const calls = mockApi({ "/aiv/capabilities": caps(true), "/cases/c1/asset-authorizations": { items: [auth] }, "/cases/c1/aiv/plans/preview": denied,
      "/cases/c1/aiv/plans": { items: [{ id: "p1234567", asset_authorization_id: "a1", plan_hash: "a".repeat(64), version: 1, steps: [{ kind: "tls_handshake", host: "www.example.org", port: 443 }], limits: {}, status: "draft", created_by: "u", created_at: "2026-01-01T00:00:00Z", supersedes_id: null, target_profile_id: null }] },
      "/aiv/plans/p1234567/approve": { approval_id: "ap1" } });
    wrap(<Workbench caseId="c1" />);
    await waitFor(() => screen.getByRole("tab", { name: "Plans" }));
    fireEvent.click(screen.getByRole("tab", { name: "Plans" }));
    await waitFor(() => screen.getByLabelText("Build a verification plan"));
    fireEvent.click(screen.getByRole("button", { name: /Preview/ }));
    await waitFor(() => screen.getByLabelText("Plan preview"));
    expect(screen.getByText(/host is not in the authorization/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save as draft plan" })).toBeDisabled();
    expect(calls.filter((c) => c.init?.method === "POST").every((c) => c.url.includes("/preview"))).toBe(true);     // preview posted nothing else
    const approve = await screen.findByRole("button", { name: "Approve this plan" });
    expect(approve).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I read this exact plan/));
    expect(approve).toBeEnabled();
  });
});

describe("Target profile verification", () => {
  const profile = (role: string) => ({ subject: { id: "s1", display_name: "Jane" }, role }) as never;
  it("shows only explicitly linked assets and repeats that consent is not asset authorization", async () => {
    mockApi({ "/subjects/s1/verification": { enabled: true, subject_id: "s1", authorizations: [auth], plans: [], runs: [], observations: [], unlinked_case_authorizations: 2,
      notice: "Consent from this person is not authorization to test a domain or server that merely carries their name." } });
    wrap(<Verification p={profile("owner")} />);
    await waitFor(() => screen.getByText(/not authorization to test/));
    expect(screen.getByText("www.example.org")).toBeInTheDocument();
    expect(screen.getByText(/2 other asset authorization\(s\)/)).toBeInTheDocument();
  });
  it("is hidden from viewers", () => {
    wrap(<Verification p={profile("viewer")} />);
    expect(screen.getByText(/hidden for your role/)).toBeInTheDocument();
  });
});

describe("Product name", () => {
  const branding: BrandingT = { active: { productName: "OSINT Command Center", shortName: "OSINT Command Center", tagline: "t", edition: "Community", legacyNames: [] }, preset: "current",
    notice: "This changes the text shown inside the application. It is not a trademark clearance.", unchanged: ["Python package `osintcc`"],
    presets: { current: { label: "Current name (default)", status: "in use", branding: { productName: "OSINT Command Center", shortName: "OSINT Command Center", tagline: "t" } },
      fusion: { label: "Fusion Intelligence Command Center (provisional)", status: "provisional: not a cleared trademark; the owner has not approved it", branding: { productName: "Fusion Intelligence Command Center", shortName: "Fusion Command Center", tagline: "t2" } } } };
  it("previews first, and applying needs the approval tick", async () => {
    const calls = mockApi({ "/branding": (_u: string, init?: RequestInit) => (init?.method === "PUT" ? (JSON.parse(String(init.body)).preview_only ? { preview: branding.presets.fusion.branding, applied: false } : { applied: true }) : branding) });
    wrap(<BrandingCard />);
    await waitFor(() => screen.getByLabelText("Product name"));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "fusion" } });
    expect(screen.getAllByText(/provisional/).length).toBeGreaterThan(0);
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => screen.getByLabelText("Name preview"));
    expect(calls.filter((c) => c.init?.method === "PUT").every((c) => JSON.parse(String(c.init!.body)).preview_only === true)).toBe(true);
    fireEvent.click(screen.getByLabelText(/I approve changing the name/));
    expect(apply).toBeEnabled();
  });
});
