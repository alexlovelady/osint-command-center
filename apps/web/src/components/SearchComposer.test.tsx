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

  it("shows an actionable error for an invalid target", async () => {
    const err = { code: "invalid_target", message: "invalid domain", request_id: "r", retryable: false, details_safe: {} };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(err), { status: 422 }));
    wrap();
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "a b" } });
    fireEvent.click(screen.getByText("Preview"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid domain"));
  });
});
