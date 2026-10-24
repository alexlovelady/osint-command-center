// Where the user is, shared between the app shell, the case view and the Copilot. The Copilot only reads this; the backend re-checks every id.
import { useSyncExternalStore } from "react";

export interface AppCtx { route: string; tab: string | null; case_id: string | null; tool_id: string | null }

let ctx: AppCtx = { route: "overview", tab: null, case_id: null, tool_id: null };
const subs = new Set<() => void>();

export function setAppCtx(p: Partial<AppCtx>): void {
  const next = { ...ctx, ...p };
  if (next.route === ctx.route && next.tab === ctx.tab && next.case_id === ctx.case_id && next.tool_id === ctx.tool_id) return;
  ctx = next;
  subs.forEach((f) => f());
}

export function getAppCtx(): AppCtx { return ctx; }

export function useAppCtx(): AppCtx {
  return useSyncExternalStore((f) => { subs.add(f); return () => { subs.delete(f); }; }, () => ctx);
}

export interface Dest { route: string; tab?: string | null; case_id?: string | null }

/** One-click navigation used by the Copilot: pages are hash routes; case tabs are switched by an event the case view listens for. */
export function navigateTo(d: Dest): void {
  const cid = d.case_id ?? ctx.case_id;
  if (d.route === "case") {
    if (!cid) return;
    if (ctx.route !== "case" || ctx.case_id !== cid) window.location.hash = `/case/${cid}`;
    if (d.tab) window.setTimeout(() => window.dispatchEvent(new CustomEvent("osintcc:tab", { detail: d.tab })), ctx.case_id === cid && ctx.route === "case" ? 0 : 250);
    return;
  }
  window.location.hash = `/${d.route}`;
}
