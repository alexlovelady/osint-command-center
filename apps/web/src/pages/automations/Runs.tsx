import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { RUN_STATES, type DiagnoseResult, type RunDetail, type RunT } from "../../lib/automationsApi";

const tone = (s: string) => (s === "completed" ? "succeeded" : s === "completed_with_warnings" ? "partial" : s === "failed" ? "failed" : s === "cancelled" ? "skipped" : s === "running" ? "queued" : "unknown");

export function RunList({ workflowId }: { workflowId?: string }) {
  const [state, setState] = useState("");
  const [dry, setDry] = useState("");
  const [source, setSource] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [cmp, setCmp] = useState<string | null>(null);
  const qs = new URLSearchParams({ limit: "100", ...(workflowId ? { workflow_id: workflowId } : {}), ...(state ? { state } : {}), ...(dry ? { dry_run: dry } : {}), ...(source ? { source } : {}) });
  const q = useQuery({ queryKey: ["auto-runs", qs.toString()], queryFn: () => api<{ total: number; items: RunT[] }>(`/automations/runs?${qs}`), refetchInterval: 4000 });
  return (
    <div data-tour="auto-runs">
      <div className="row" role="search" aria-label="Filter runs">
        <select aria-label="State" value={state} onChange={(e) => setState(e.target.value)} style={{ width: 210 }}><option value="">any state</option>{RUN_STATES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}</select>
        <select aria-label="Real or simulated" value={dry} onChange={(e) => setDry(e.target.value)} style={{ width: 170 }}><option value="">real and simulated</option><option value="false">real runs only</option><option value="true">dry runs only</option></select>
        <input aria-label="Source" placeholder="source (e.g. crtsh)" value={source} onChange={(e) => setSource(e.target.value)} style={{ maxWidth: 190 }} />
        <span className="muted">{q.data?.total ?? 0} runs</span>
      </div>
      {q.isLoading && <Loading what="runs" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data?.items.length === 0 && <Empty title="No runs yet" hint="Dry-run a template, or run a published workflow. Simulated runs are always labelled." />}
      {!!q.data?.items.length && (
        <table aria-label="Runs"><thead><tr><th>When</th><th>Workflow</th><th>State</th><th>Trigger</th><th>Rev</th><th>Evidence</th><th /></tr></thead>
          <tbody>{q.data.items.map((r) => (
            <tr key={r.id}><td>{fmt(r.queued_at)}</td><td>{r.workflow_name}{r.dry_run && <span className="badge avail-partial" style={{ marginLeft: 6 }}>SIMULATED</span>}</td>
              <td><Badge v={tone(r.state)} /> {r.state.replace(/_/g, " ")}{r.error_code ? ` · ${r.error_code}` : ""}</td><td>{r.trigger_type}</td><td>{r.revision ?? "—"}</td><td>{r.evidence_count}</td>
              <td><button onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>Details</button> <button onClick={() => setCmp(cmp === r.id ? null : r.id)} aria-pressed={cmp === r.id}>Compare…</button></td></tr>))}</tbody></table>)}
      {open && <RunDetailView id={open} compareWith={cmp && cmp !== open ? cmp : null} />}
    </div>
  );
}

export function RunDetailView({ id, compareWith }: { id: string; compareWith: string | null }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["auto-run", id], queryFn: () => api<RunDetail>(`/automations/runs/${id}`), refetchInterval: (x) => (["queued", "running", "retrying"].includes(x.state.data?.state ?? "") ? 1500 : false) });
  const diag = useMutation({ mutationFn: () => api<DiagnoseResult>("/automations/ai/diagnose", { method: "POST", json: { run_id: id } }) });
  const act = useMutation({ mutationFn: (p: { path: string; json?: unknown }) => api(`/automations/runs/${id}/${p.path}`, { method: "POST", json: p.json }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["auto-run", id] }); qc.invalidateQueries({ queryKey: ["auto-runs"] }); } });
  const cmp = useQuery({ queryKey: ["auto-cmp", id, compareWith], enabled: !!compareWith, queryFn: () => api<{ nodes: { node: string; a: { state: string } | null; b: { state: string } | null; same_input: boolean; differs: boolean }[] }>(`/automations/runs/${id}/compare/${compareWith}`) });
  if (q.isLoading) return <Loading what="run" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const r = q.data;
  const waiting = r.nodes.filter((n) => n.state === "waiting");
  return (
    <section className="card" aria-label={`Run ${r.id.slice(0, 8)}`} style={{ marginTop: 10 }}>
      <div className="row"><b>Run {r.id.slice(0, 8)}</b><Badge v={tone(r.state)} /> <span>{r.state.replace(/_/g, " ")}</span>{r.label && <span className="badge avail-partial">{r.label}</span>}<span className="grow" />
        {["queued", "running", "paused", "waiting_for_approval", "retrying"].includes(r.state) && <button onClick={() => act.mutate({ path: "cancel" })}>Stop</button>}
        {["failed", "cancelled", "completed_with_warnings", "paused"].includes(r.state) && <button onClick={() => act.mutate({ path: "retry" })}>Retry safe failures</button>}
        {r.state !== "completed" && <button onClick={() => diag.mutate()}>Diagnose</button>}</div>
      <p className="muted" style={{ fontSize: 12 }}>{r.version ? `version ${r.version.revision} (${r.version.hash.slice(0, 12)})` : "draft (dry run)"} · {r.environment?.platform} · app {r.environment?.app} · trigger {r.trigger_type} · evidence {r.evidence_count}</p>
      {waiting.map((n) => <div key={n.node} className="banner">Waiting for your decision on <b>{n.node}</b>: {String(n.diagnostics.prompt ?? "")} <button className="primary" onClick={() => act.mutate({ path: "review", json: { node: n.node, approve: true } })}>Approve</button> <button onClick={() => act.mutate({ path: "review", json: { node: n.node, approve: false } })}>Reject</button></div>)}
      {act.isError && <ErrorBox error={act.error instanceof ApiError ? act.error : new Error("action failed")} />}
      <table aria-label="Step timeline"><thead><tr><th>Step</th><th>Attempt</th><th>State</th><th>Time</th><th>Result</th></tr></thead>
        <tbody>{r.nodes.map((n, i) => (
          <tr key={i}><td>{n.node}</td><td>{n.attempt}</td><td><Badge v={n.state === "succeeded" ? "succeeded" : n.state === "failed" ? "failed" : "skipped"} /> {n.state}{n.error_code ? ` · ${n.error_code}` : ""}</td>
            <td>{n.duration_ms != null ? `${Math.round(n.duration_ms)} ms` : "—"}</td><td><code>{n.output ? JSON.stringify(n.output).slice(0, 160) : String(n.diagnostics.message ?? n.diagnostics.why ?? "—").slice(0, 160)}</code></td></tr>))}</tbody></table>
      {r.source_urls.length > 0 && <details><summary>{r.source_urls.length} source URL(s) contacted</summary><ul>{r.source_urls.map((u) => <li key={u}><code>{u}</code></li>)}</ul></details>}
      {(r.summary.warnings?.length ?? 0) > 0 && <details open><summary>{r.summary.warnings?.length} warning(s)</summary><ul>{r.summary.warnings?.map((w) => <li key={w}>{w}</li>)}</ul></details>}
      {diag.data && (
        <div role="region" aria-label="Diagnosis">
          <h4>Diagnosis</h4>
          {diag.data.problems.length === 0 && <p>No failed steps in this run.</p>}
          {diag.data.problems.map((p, i) => <div key={i} className="banner warn"><b>{p.code}</b> at <b>{p.node}</b>: {p.message ?? ""} <div>{p.fix}</div></div>)}
          {diag.data.proposals.length > 0 && <><p>Repairs I can propose (applied to the draft only, after you click):</p>
            <ul>{diag.data.proposals.map((p, i) => <li key={i}>{p.why} <button onClick={async () => { await api(`/automations/workflows/${r.workflow_id}/repair`, { method: "POST", json: { ops: [p] } }); window.location.hash = `/automations/${r.workflow_id}`; }}>Apply to draft</button></li>)}</ul></>}
          <p className="muted">{diag.data.note}</p>
        </div>)}
      {compareWith && cmp.data && (
        <div role="region" aria-label="Comparison"><h4>Compared with run {compareWith.slice(0, 8)}</h4>
          <table><thead><tr><th>Step</th><th>This run</th><th>Other run</th><th>Same input?</th><th>Output differs?</th></tr></thead>
            <tbody>{cmp.data.nodes.map((n) => <tr key={n.node}><td>{n.node}</td><td>{n.a?.state ?? "—"}</td><td>{n.b?.state ?? "—"}</td><td>{n.same_input ? "yes" : "no"}</td><td>{n.differs ? "yes" : "no"}</td></tr>)}</tbody></table></div>)}
    </section>
  );
}

export default function Runs() {
  return <RunList />;
}
