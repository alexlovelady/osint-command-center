import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, getToken } from "./api";

afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); window.location.hash = ""; });

describe("api client", () => {
  it("sends the bearer token and parses JSON", async () => {
    sessionStorage.setItem("osintcc.token", "tok123");
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: 1 }), { headers: { "content-type": "application/json" } }));
    expect(await api("/cases")).toEqual({ ok: 1 });
    const headers = (f.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer tok123");
    expect(f.mock.calls[0][0]).toBe("/api/v1/cases");
  });

  it("surfaces the error envelope as ApiError", async () => {
    const body = { code: "invalid_target", message: "bad", request_id: "r", retryable: false, details_safe: {} };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status: 422 }));
    await expect(api("/x")).rejects.toMatchObject({ status: 422, body: { code: "invalid_target" } });
  });

  it("reports an unreachable backend distinctly", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
    const err = (await api("/x").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.body.code).toBe("backend_unreachable");
    expect(err.body.retryable).toBe(true);
  });

  it("moves a #token= fragment into sessionStorage and scrubs it from the URL", () => {
    window.location.hash = "#token=abc&x=1";
    expect(getToken()).toBe("abc");
    expect(window.location.hash).toBe("");
    expect(sessionStorage.getItem("osintcc.token")).toBe("abc");
    expect(localStorage.getItem("osintcc.token")).toBeNull(); // never persisted beyond the tab
  });
});
