import type { ReactNode } from "react";
import { ApiError } from "../lib/api";

export const Badge = ({ v }: { v: string }) => <span className={`badge ${v}`}>{v.replace(/_/g, " ")}</span>;

export function Loading({ what }: { what: string }) {
  return <div className="muted" role="status">Loading {what}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const e = error instanceof ApiError ? error : null;
  return (
    <div className="banner err" role="alert">
      <b>{e ? e.body.code.replace(/_/g, " ") : "Error"}</b>: {e ? e.message : String(error)}
      {e?.status === 401 && <div>Session token missing or wrong — open the app from the launcher, or paste a token in Settings.</div>}
      {e?.body.retryable && <div className="muted">This may be temporary; try again.</div>}
    </div>
  );
}

export function Empty({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div><b>{title}</b></div>
      {hint && <div>{hint}</div>}
      {children}
    </div>
  );
}

export const fmt = (s?: string | null) => (s ? new Date(s).toISOString().replace("T", " ").slice(0, 19) + "Z" : "unknown");
export const val = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));
