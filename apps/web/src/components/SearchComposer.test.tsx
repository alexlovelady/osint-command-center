import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import SearchComposer from "./SearchComposer";

const plan = {
  target: { type: "domain", canonical: "example.com", ambiguous_with: [] }, warnings: [], offline: false, note: "Nothing has been sent.",
  steps: [
    { adapter_id: "rdap", name: "RDAP domain registration", runnable: true, operation_class: "passive", endpoints: ["https://data.iana.org/rdap/dns.json"] },
    { adapter_id: "sherlock", name: "Sherlock", runnable: true, requires_confirmation: true, operation_class: "public_site_query", endpoints: ["many sites"] },
  ],
};
const wrap = () => render(<QueryClientProvider client={new QueryClient()}><SearchComposer caseId="c1" /></QueryClientProvider>);
afterEach(() => vi.restoreAllMocks());

describe("SearchComposer", () => {
  it("sends nothing while typing; preview shows endpoints; public-site sources are not preselected", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(plan), { headers: { "content-type": "application/json" } }));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "example.com" } });
    expect(f).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => expect(screen.getByText("https://data.iana.org/rdap/dns.json")).toBeInTheDocument());
    expect(f).toHaveBeenCalledTimes(1);
    expect(String(f.mock.calls[0][0])).toContain("/searches/preview");
    expect(screen.getByLabelText("Run RDAP domain registration")).toBeChecked();
    expect(screen.getByLabelText("Run Sherlock")).not.toBeChecked();
    expect(screen.getByText(/contacts third-party public sites/)).toBeInTheDocument();
    expect(screen.getByText(/Confirm and run 1 source/)).toBeEnabled();
  });

  const userPlan = {
    target: { type: "username", canonical: "someone", ambiguous_with: [] }, warnings: [], offline: false, note: "Nothing has been sent.", notices: [],
    steps: [
      { adapter_id: "sherlock", name: "Sherlock", runnable: true, requires_confirmation: true, offered: true, health: "healthy", operation_class: "public_site_query",
        endpoints: ["many sites"], warnings: ["Tool contacts many public websites using the supplied handle."] },
      { adapter_id: "maigret", name: "Maigret", runnable: true, requires_confirmation: true, offered: true, health: "not_installed", operation_class: "public_site_query",
        endpoints: ["many sites"], warnings: ["Tool state: not installed; it will be skipped."] },
    ],
  };
  const json = (b: unknown) => new Response(JSON.stringify(b), { headers: { "content-type": "application/json" } });

  it("username preview lists Sherlock/Maigret unselected; selection and confirmation are required before launch", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockImplementation(async (u) => json(String(u).endsWith("/preview") ? userPlan : { id: "r1", status: "queued", jobs: [] }));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "someone" } });
    fireEvent.change(screen.getByLabelText("Target type"), { target: { value: "username" } });
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => expect(screen.getByLabelText("Run Sherlock")).toBeInTheDocument());
    expect(screen.getByText("installed · healthy")).toBeInTheDocument();
    expect(screen.getByText(/contact many public websites|contacts many public websites/)).toBeInTheDocument();
    expect(screen.getByLabelText("Run Sherlock")).not.toBeChecked();
    expect(screen.getByLabelText("Run Maigret")).toBeDisabled();                       // not installed: cannot be selected
    expect(screen.getByText(/Confirm and run 0 source/)).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Run Sherlock"));
    expect(screen.getByText(/Confirm and run 1 source/)).toBeDisabled();               // selected but not confirmed
    fireEvent.click(screen.getByLabelText("Confirm Sherlock contacts third-party sites"));
    expect(screen.getByText(/Confirm and run 1 source/)).toBeEnabled();
    fireEvent.click(screen.getByText(/Confirm and run 1 source/));
    const launched = () => f.mock.calls.find((c) => String(c[0]).endsWith("/searches"));
    await waitFor(() => expect(launched()).toBeTruthy());
    const sent = JSON.parse(String(launched()![1]!.body));
    expect(sent).toMatchObject({ adapters: ["sherlock"], confirmed_adapters: ["sherlock"], mode: "public_site_query", target_type: "username" });
  });

  it("changing the target or type resets the preview, selections and confirmations", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => json(userPlan));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "someone" } });
    fireEvent.change(screen.getByLabelText("Target type"), { target: { value: "username" } });
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => screen.getByLabelText("Run Sherlock"));
    fireEvent.click(screen.getByLabelText("Run Sherlock"));
    fireEvent.click(screen.getByLabelText("Confirm Sherlock contacts third-party sites"));
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "someone-else" } });
    expect(screen.queryByLabelText("Run Sherlock")).toBeNull();
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => screen.getByLabelText("Run Sherlock"));
    expect(screen.getByLabelText("Run Sherlock")).not.toBeChecked();
    expect(screen.getByLabelText("Confirm Sherlock contacts third-party sites")).not.toBeChecked();
    fireEvent.click(screen.getByLabelText("Run Sherlock"));
    fireEvent.click(screen.getByLabelText("Confirm Sherlock contacts third-party sites"));
    fireEvent.change(screen.getByLabelText("Target type"), { target: { value: "domain" } });
    expect(screen.queryByLabelText("Run Sherlock")).toBeNull();
  });

  it("explains when no username tool is available", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ ...userPlan, steps: [], notices: ["No username tools (Sherlock, Maigret) are installed and enabled."] }));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "someone" } });
    fireEvent.change(screen.getByLabelText("Target type"), { target: { value: "username" } });
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => expect(screen.getByText(/No username tools/)).toBeInTheDocument());
  });

  it("shows an actionable error for an invalid target", async () => {
    const err = { code: "invalid_target", message: "invalid domain", request_id: "r", retryable: false, details_safe: {} };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(err), { status: 422 }));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "a b" } });
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid domain"));
  });
});
