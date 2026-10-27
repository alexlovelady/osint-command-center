import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import { useAdvanced } from "../../lib/mode";

export interface UsageWindow { window: string; unit: string; limit: number | null; used: number | null; remaining: number | null; resets_at: string | null; basis: string }
export interface UsageOp { id: string; label: string; windows: UsageWindow[]; concurrency: number | null; blocked: string; restricted: boolean }
export interface ProviderEntry {
  provider: string; label: string; plan: string; credential_name: string | null; stored: boolean; paid_only: boolean; disabled: boolean; disabled_reason: string; verified_state: string; verified_at: string | null;
  last_status: number | null; last_error: string; last_response_at: string | null; blocked_until: string | null; operations: UsageOp[]; queued: Record<string, number>; reset_note: string; limitations: string[];
  state: { code: string; label: string; hint: string }; axes: { stored_credential: string; live_authentication: string; endpoint_supported: string; quota_available: string };
  test: { what: string; cost: string; url_host: string } | null; licence?: { needed_for: string; confirmed: boolean } | null;
}
export interface UsageOut { providers: ProviderEntry[]; paused: boolean; waiting: number; enforced: boolean; spend_guard: { text: string; paid_spend_usd: number }; note: string; timezone: string }
interface QueueRow { job_id: string; case: string | null; source: string; provider: string | null; operation: string | null; status: string; attempts: number; next_eligible_at: string | null; reason: string }
interface LedgerRow { id: string; provider: string; operation: string; state: string; http_status: number | null; classification: string; reserved_at: string; consumption_known: boolean | null; job_id: string | null }

const when = (iso?: string | null) => (iso ? `${iso.slice(0, 16).replace("T", " ")} UTC` : "—");
const BADGE: Record<string, string> = { verified: "st-ok", stored: "st-warn", no_key_needed: "st-mute", not_configured: "st-mute", rejected: "st-bad", wrong_format: "st-bad", plan_restricted: "st-bad", quota_exhausted: "st-warn", disabled: "st-mute", disabled_paid: "st-mute" };
const AXIS_TEXT: Record<string, string> = { yes: "yes", no: "no", unknown: "unknown", not_tested: "not tested", rejected: "rejected", not_needed: "not needed" };
const WINDOW_NAME: Record<string, string> = { utc_minute: "this minute", utc_hour: "this hour", utc_day: "today (UTC)", utc_month: "this month (UTC)" };
const winName = (w: string) => WINDOW_NAME[w] ?? (w.startsWith("rolling:") ? `last ${w.slice(8)} s` : w);
const unitText = (w: UsageWindow) => (w.unit === "credits" ? "credits" : "requests");

function Row({ p, advanced }: { p: ProviderEntry; advanced: boolean }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const done = () => qc.invalidateQueries({ queryKey: ["provider-usage"] });
  const test = useMutation({ mutationFn: () => api<{ state: string; detail: string }>(`/providers/${p.provider}/test`, { method: "POST", json: { confirm: true } }), onSuccess: () => { setConfirm(false); done(); qc.invalidateQueries({ queryKey: ["secrets"] }); } });
  const recheck = useMutation({ mutationFn: () => api(`/providers/${p.provider}/recheck`, { method: "POST" }), onSuccess: done });
  const licence = useMutation({ mutationFn: (v: boolean) => api(`/providers/${p.provider}/licence`, { method: "POST", json: { commercial_licensed: v } }), onSuccess: done });
  const toggle = useMutation({ mutationFn: (on: boolean) => api(`/providers/${p.provider}/${on ? "enable" : "disable"}`, { method: "POST", json: on ? { confirm: false, entitlement_verified: false } : undefined }), onSuccess: done });
  const queued = Object.entries(p.queued).filter(([k]) => k !== "running").reduce((a, [, n]) => a + n, 0);
  const wins = p.operations.filter((o) => !o.blocked).flatMap((o) => o.windows.map((w) => ({ ...w, op: o.label })));
  return (
    <tr aria-label={`Provider ${p.label}`}>
      <td><b>{p.label}</b><div className="muted">{p.plan}</div></td>
      <td><span className={`badge ${BADGE[p.state.code] ?? "st-mute"}`}>{p.state.label}</span><div className="muted">{p.state.hint}</div>
        <div className="muted" aria-label="Credential checks">stored: {AXIS_TEXT[p.axes.stored_credential]} · verified by a real call: {AXIS_TEXT[p.axes.live_authentication]}{p.verified_at ? ` (${when(p.verified_at)})` : ""} · endpoint supported: {AXIS_TEXT[p.axes.endpoint_supported]} · quota available: {AXIS_TEXT[p.axes.quota_available]}</div></td>
      <td>{wins.length === 0 ? <span className="muted">No limit known{p.operations.some((o) => o.blocked) ? "; paid operations are never used" : ""}</span> : (
        <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>{wins.map((w, i) => (
          <li key={`${w.op}${w.window}${i}`}>{p.operations.length > 1 ? `${w.op}, ` : ""}{winName(w.window)}: <b>{w.remaining === null ? "?" : w.remaining}</b> of {w.limit ?? "?"} {unitText(w)} left{w.resets_at ? <span className="muted"> · resets {when(w.resets_at)}</span> : null}
            {advanced && <span className="muted"> ({w.basis})</span>}</li>))}</ul>)}
        {p.operations.some((o) => o.concurrency) && <div className="muted">One request at a time.</div>}</td>
      <td>{queued > 0 ? <b>{queued} waiting</b> : "none"}{p.blocked_until && <div className="muted">paused until {when(p.blocked_until)}</div>}</td>
      <td>{p.last_response_at ? <>HTTP {p.last_status ?? "—"} <span className="muted">{when(p.last_response_at)}</span></> : <span className="muted">no request yet</span>}{p.last_error && <div className="muted">{p.last_error}</div>}</td>
      <td>
        <div className="row">
          {p.test && !p.disabled && !confirm && <button onClick={() => setConfirm(true)}>Test</button>}
          {(p.state.code === "rejected" || p.state.code === "plan_restricted" || p.blocked_until) && <button onClick={() => recheck.mutate()} title="Forget the earlier refusal after you changed the key or plan. Sends nothing.">Try again</button>}
          {!p.paid_only && !p.disabled && <button onClick={() => toggle.mutate(false)}>Turn off</button>}
          {!p.paid_only && p.disabled && <button onClick={() => toggle.mutate(true)}>Turn on</button>}
        </div>
        {confirm && p.test && <div className="banner" role="alert">{p.test.what} It uses {p.test.cost} and sends one request to {p.test.url_host}.
          <div className="row"><button className="primary" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? "Testing…" : "Send the test"}</button><button onClick={() => setConfirm(false)}>Cancel</button></div></div>}
        {p.licence && (
          <label className="muted" style={{ display: "block", marginTop: 6 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={p.licence.confirmed} onChange={(e) => licence.mutate(e.target.checked)} /> I hold a {p.label} licence that covers {p.licence.needed_for} (Fusion cannot check this)
          </label>)}
        {test.data && <div className="muted" role="status">{test.data.state === "verified" ? "The provider accepted the request." : test.data.detail}</div>}
        {(test.isError || recheck.isError || toggle.isError) && <ErrorBox error={test.error ?? recheck.error ?? toggle.error} />}
      </td>
    </tr>
  );
}

function Queue() {
  const q = useQuery({ queryKey: ["provider-queue"], queryFn: () => api<{ items: QueueRow[] }>("/providers/queue"), refetchInterval: 15000, retry: false });
  const l = useQuery({ queryKey: ["provider-ledger"], queryFn: () => api<{ items: LedgerRow[] }>("/providers/ledger?limit=60"), refetchInterval: 30000, retry: false });
  return (
    <details aria-label="Provider activity ledger"><summary>Advanced: queue and activity ledger</summary>
      <h4>Queue ({q.data?.items.length ?? 0})</h4>
      {q.data && q.data.items.length > 0 ? (
        <table aria-label="Queued provider work"><thead><tr><th>Source</th><th>Case</th><th>Status</th><th>Attempts</th><th>Earliest run (estimate)</th><th>Reason</th></tr></thead>
          <tbody>{q.data.items.map((r) => <tr key={r.job_id}><td>{r.source}</td><td>{r.case ?? "—"}</td><td>{r.status.replace(/_/g, " ")}</td><td>{r.attempts}</td><td>{when(r.next_eligible_at)}</td><td>{r.reason}</td></tr>)}</tbody></table>) : <div className="muted">Nothing is queued.</div>}
      <h4>Recent requests</h4>
      {l.data && l.data.items.length > 0 ? (
        <table aria-label="Request ledger"><thead><tr><th>When</th><th>Provider</th><th>Action</th><th>State</th><th>HTTP</th><th>Result</th><th>Counted by the provider</th></tr></thead>
          <tbody>{l.data.items.map((r) => <tr key={r.id}><td>{when(r.reserved_at)}</td><td>{r.provider}</td><td>{r.operation}</td><td>{r.state}</td><td>{r.http_status ?? "—"}</td><td>{r.classification.replace(/_/g, " ")}</td>
            <td>{r.consumption_known === null ? "unknown" : r.consumption_known ? "yes" : "no"}</td></tr>)}</tbody></table>) : <div className="muted">No requests have been made.</div>}
      <div className="muted">The ledger holds no keys and no searched identifiers.</div>
    </details>
  );
}

/** Settings → Provider usage: what each provider will allow, what is used, what is waiting, and the $0 guard. Reads never contact a provider. */
export default function ProviderUsage() {
  const qc = useQueryClient();
  const [advanced] = useAdvanced();
  const q = useQuery({ queryKey: ["provider-usage"], queryFn: () => api<UsageOut>("/providers/usage"), refetchInterval: 15000, retry: false });
  const pause = useMutation({ mutationFn: (p: boolean) => api(`/providers/${p ? "pause" : "resume"}`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["provider-usage"] }) });
  const [confirmCancel, setConfirmCancel] = useState(false);
  const cancel = useMutation({ mutationFn: () => api<{ cancelled: number }>("/providers/cancel-queued", { method: "POST" }), onSuccess: () => { setConfirmCancel(false); qc.invalidateQueries({ queryKey: ["provider-usage"] }); qc.invalidateQueries({ queryKey: ["investigations"] }); } });
  if (q.isLoading) return <Loading what="provider usage" />;
  if (q.isError || !q.data) return <div className="card" aria-label="Provider usage"><h3 style={{ marginTop: 0 }}>Provider usage</h3><div className="muted">Provider usage could not be loaded.</div></div>;
  const u = q.data;
  return (
    <div className="card" aria-label="Provider usage">
      <div className="row"><h3 style={{ margin: 0 }}>Provider usage</h3><span className="grow" />
        <button onClick={() => pause.mutate(!u.paused)} title="Holds all queued provider work without losing it">{u.paused ? "Resume all provider work" : "Pause all provider work"}</button>
        {u.waiting > 0 && !confirmCancel && <button onClick={() => setConfirmCancel(true)}>Cancel queued work</button>}</div>
      {confirmCancel && <div className="banner warn" role="alert">This cancels every queued or waiting provider check, in all investigations. Finished results are kept; the checks can be started again with Refresh results.
        <div className="row"><button className="primary" onClick={() => cancel.mutate()} disabled={cancel.isPending}>Cancel {u.waiting} queued check(s)</button><button onClick={() => setConfirmCancel(false)}>Keep them</button></div></div>}
      {u.paused && <div className="banner warn" role="status">Provider work is paused. Queued checks are kept and continue when you resume.</div>}
      {u.waiting > 0 && !u.paused && <div className="banner" role="status">{u.waiting} check(s) are waiting for a provider’s limit to reset. They continue by themselves; nothing needs you.</div>}
      <div className="banner" role="note"><b>Spend guard: $0.</b> {u.spend_guard.text}</div>
      <table aria-label="Provider usage table">
        <thead><tr><th>Provider</th><th>Credential</th><th>Remaining (reset times in {u.timezone})</th><th>Queued</th><th>Last response</th><th>Actions</th></tr></thead>
        <tbody>{u.providers.map((p) => <Row key={p.provider} p={p} advanced={advanced} />)}</tbody>
      </table>
      <div className="muted">{u.note}</div>
      {!u.enforced && <div className="banner warn">Provider budgets are switched off for this run (test mode).</div>}
      {advanced && <Queue />}
    </div>
  );
}
