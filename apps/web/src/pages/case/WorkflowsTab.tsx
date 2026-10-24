import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, fmt } from "../../components/ui";
import { api } from "../../lib/api";

interface Tpl { id: string; name: string; valid: boolean; nodes: { id: string; adapter?: string; task?: string }[] }
interface Wf { id: string; name: string; nodes: number }
interface Sched { id: string; workflow_id: string; target: string; interval: string; enabled: boolean; next_run_at: string; last_status: string | null }
interface AlertT { id: string; type: string; severity: string; message: string; created_at: string; acknowledged_at: string | null; details: { added?: string[]; no_longer_observed?: string[] } }

export default function WorkflowsTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const inv = () => ["wfs", "scheds", "alerts"].forEach((k) => qc.invalidateQueries({ queryKey: [k, id] }));
  const tpls = useQuery({ queryKey: ["tpls"], queryFn: () => api<{ items: Tpl[] }>("/workflow-templates") });
  const wfs = useQuery({ queryKey: ["wfs", id], queryFn: () => api<{ items: Wf[] }>(`/workflows?case_id=${id}`) });
  const scheds = useQuery({ queryKey: ["scheds", id], queryFn: () => api<{ items: Sched[] }>(`/schedules?case_id=${id}`) });
  const alerts = useQuery({ queryKey: ["alerts", id], queryFn: () => api<{ items: AlertT[] }>(`/cases/${id}/alerts`) });
  const [target, setTarget] = useState("");
  const [interval, setInterval_] = useState("1d");
  const [preview, setPreview] = useState<{ wid: string; data: { waves: string[][]; estimated_requests: number; warnings: string[] } } | null>(null);
  const create = useMutation({ mutationFn: (t: Tpl) => api("/workflows", { method: "POST", json: { case_id: id, definition: t } }), onSuccess: inv });
  const prev = useMutation({ mutationFn: (wid: string) => api<{ waves: string[][]; estimated_requests: number; warnings: string[] }>(`/workflows/${wid}/preview`, { method: "POST", json: { case_id: id, target } }),
    onSuccess: (data, wid) => setPreview({ wid, data }) });
  const run = useMutation({ mutationFn: (wid: string) => api<{ status: string }>(`/workflows/${wid}/run`, { method: "POST", json: { case_id: id, target } }), onSuccess: () => { setPreview(null); inv(); qc.invalidateQueries({ queryKey: ["findings", id] }); } });
  const mkSched = useMutation({ mutationFn: (wid: string) => api("/schedules", { method: "POST", json: { workflow_id: wid, case_id: id, target, interval, reason: "recurring check of a target I am authorized to monitor" } }), onSuccess: inv });
  const enable = useMutation({ mutationFn: (sid: string) => api(`/schedules/${sid}/enable`, { method: "POST", json: { confirm: true } }), onSuccess: inv });
  const disable = useMutation({ mutationFn: (sid: string) => api(`/schedules/${sid}/disable`, { method: "POST" }), onSuccess: inv });
  const ack = useMutation({ mutationFn: (aid: string) => api(`/alerts/${aid}/acknowledge`, { method: "POST" }), onSuccess: inv });
  const err = create.error ?? prev.error ?? run.error ?? mkSched.error ?? enable.error;
  return (
    <>
      <div className="banner">Workflows are data-only DAGs of registered sources. Monitoring is <b>off</b> until you enable a schedule, and policy is re-checked on every run.</div>
      <h3>Templates</h3>
      {tpls.data?.items.map((t) => (
        <div key={t.id} className="row" style={{ marginBottom: 4 }}>
          <b>{t.name}</b> <span className="muted">{t.nodes.length} nodes</span> {!t.valid && <Badge v="failed" />}
          <button disabled={!t.valid || (wfs.data?.items ?? []).some((w) => w.name === t.name)} onClick={() => create.mutate(t)}>Add to this case</button></div>))}
      {err && <ErrorBox error={err} />}
      <h3>This case</h3>
      <input aria-label="Workflow target" placeholder="target (e.g. example.com)" value={target} onChange={(e) => setTarget(e.target.value)} style={{ maxWidth: 360 }} />
      {wfs.data?.items.length === 0 && <Empty title="No workflows in this case" />}
      {wfs.data?.items.map((w) => (
        <div key={w.id} className="card" style={{ marginTop: 6 }}>
          <b>{w.name}</b>
          <div className="row">
            <button disabled={!target || prev.isPending} onClick={() => prev.mutate(w.id)}>Preview</button>
            <button className="primary" disabled={!target || preview?.wid !== w.id || run.isPending} onClick={() => run.mutate(w.id)}>Run now</button>
            <select aria-label="Interval" value={interval} onChange={(e) => setInterval_(e.target.value)} style={{ width: 90 }}>{["15m", "1h", "6h", "1d"].map((x) => <option key={x}>{x}</option>)}</select>
            <button disabled={!target} onClick={() => mkSched.mutate(w.id)}>Create schedule (disabled)</button></div>
          {preview?.wid === w.id && <div className="muted">Waves: {preview.data.waves.map((x) => x.join("+")).join(" → ")} · ≈{preview.data.estimated_requests} requests · nothing sent yet {preview.data.warnings.map((x) => <div key={x}>{x}</div>)}</div>}
        </div>))}
      <h3>Schedules</h3>
      {scheds.data?.items.length === 0 && <Empty title="No schedules" hint="Recurring monitoring is off unless you create and enable one." />}
      {scheds.data?.items.map((s) => (
        <div key={s.id} className="row"><b>{s.target}</b> every {s.interval} <Badge v={s.enabled ? "healthy" : "disabled"} /> <span className="muted">next {fmt(s.next_run_at)} · {s.last_status ?? "never run"}</span>
          {s.enabled ? <button onClick={() => disable.mutate(s.id)}>Disable</button> : <button className="primary" onClick={() => enable.mutate(s.id)}>Enable (I confirm)</button>}</div>))}
      <h3>Alerts</h3>
      {alerts.data?.items.length === 0 && <Empty title="No alerts" />}
      {alerts.data?.items.map((a) => (
        <div key={a.id} className="card" style={{ marginTop: 6 }}><Badge v={a.severity === "info" ? "unknown" : "medium"} /> {a.message}
          {a.details.added?.slice(0, 5).map((x) => <div key={x} className="muted">+ {x}</div>)}{a.details.no_longer_observed?.slice(0, 5).map((x) => <div key={x} className="muted">− {x}</div>)}
          <div className="muted">{fmt(a.created_at)} {a.acknowledged_at ? "· acknowledged" : <button onClick={() => ack.mutate(a.id)}>Acknowledge</button>}</div></div>))}
    </>
  );
}
