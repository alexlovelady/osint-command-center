import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ProfileT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

interface Task { id: string; issue: string; priority: string; guidance: string; owner: string | null; state: string; due_at: string | null; recheck_due: boolean; indicator_id: string | null; resolution_evidence_id: string | null }

export default function Remediation({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const q = useQuery({ queryKey: ["remediations", sid], enabled: p.role !== "viewer", queryFn: () => api<{ items: Task[] }>(`/subjects/${sid}/remediations`) });
  const evq = useQuery({ queryKey: ["evidence", p.case.id], queryFn: () => api<{ items: { id: string; title: string }[] }>(`/cases/${p.case.id}/evidence`) });
  const inv = () => { qc.invalidateQueries({ queryKey: ["remediations", sid] }); qc.invalidateQueries({ queryKey: ["exposure", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const [f, setF] = useState({ issue: "", priority: "medium", indicator_id: "", due_in_days: 14 });
  const create = useMutation({ mutationFn: () => api(`/subjects/${sid}/remediations`, { method: "POST", json: { issue: f.issue, priority: f.priority, due_in_days: f.due_in_days, indicator_id: f.indicator_id || null } }), onSuccess: () => { setF({ ...f, issue: "" }); inv(); } });
  const [ev, setEv] = useState<Record<string, string>>({});
  const upd = useMutation({ mutationFn: (v: { id: string; state: string }) => api(`/subjects/${sid}/remediations/${v.id}`, { method: "PATCH", json: { state: v.state, resolution_evidence_id: ev[v.id] || null } }), onSuccess: inv });
  if (p.role === "viewer") return <div className="banner">Remediation tasks are hidden for your role.</div>;
  const exposures = p.exposure.filter((x) => x.status === "confirmed_exposure");
  return (
    <>
      <div className="banner">A task is resolved only with evidence of the fix or of a retest. Guidance comes from the exposure class; follow it on the real accounts and services yourself.</div>
      <form className="card row" aria-label="Create remediation task" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <input aria-label="Issue" placeholder="What needs fixing" value={f.issue} onChange={(e) => setF({ ...f, issue: e.target.value })} style={{ flex: 1, minWidth: 240 }} />
        <select aria-label="From exposure" value={f.indicator_id} onChange={(e) => setF({ ...f, indicator_id: e.target.value })} style={{ width: 260 }}>
          <option value="">not tied to an exposure record</option>{exposures.map((x) => <option key={x.id} value={x.id}>{x.class.replace(/_/g, " ")} · {x.descriptor.slice(0, 40)}</option>)}</select>
        <select aria-label="Priority" value={f.priority} onChange={(e) => setF({ ...f, priority: e.target.value })} style={{ width: 100 }}>{["low", "medium", "high"].map((x) => <option key={x}>{x}</option>)}</select>
        <label>due in <input aria-label="Due in days" type="number" min={1} max={730} value={f.due_in_days} onChange={(e) => setF({ ...f, due_in_days: Number(e.target.value) })} style={{ width: 70 }} /> days</label>
        <button className="primary" disabled={!f.issue.trim() || create.isPending}>Create</button>
        {create.isError && <ErrorBox error={create.error} />}
      </form>
      {q.data?.items.length === 0 && <Empty title="No remediation tasks" hint="Create one from a confirmed exposure to get the standard checklist." />}
      {(q.data?.items ?? []).map((t) => (
        <article key={t.id} className="card" aria-label={`Task ${t.issue.slice(0, 30)}`} style={{ marginTop: 8 }}>
          <div className="row"><b>{t.issue}</b> <StateBadge state={t.state === "resolved" ? "completed" : t.state === "wont_fix" ? "cancelled" : "approved"} label={t.state.replace(/_/g, " ")} />
            <span className="muted">priority {t.priority}{t.due_at ? ` · due ${fmt(t.due_at)}` : ""}</span>{t.recheck_due && <span className="badge failed">recheck due</span>}</div>
          {t.guidance && <div className="muted" style={{ whiteSpace: "pre-wrap" }}>{t.guidance}</div>}
          {t.state !== "resolved" && (
            <div className="row" style={{ marginTop: 6 }}>
              <button onClick={() => upd.mutate({ id: t.id, state: "in_progress" })} disabled={t.state === "in_progress"}>Start</button>
              <select aria-label={`Evidence for ${t.id.slice(0, 6)}`} value={ev[t.id] ?? ""} onChange={(e) => setEv({ ...ev, [t.id]: e.target.value })} style={{ width: 240 }}>
                <option value="">resolution evidence…</option>{(evq.data?.items ?? []).map((x) => <option key={x.id} value={x.id}>{(x.title || x.id).slice(0, 40)}</option>)}</select>
              <button className="primary" disabled={!ev[t.id]} onClick={() => upd.mutate({ id: t.id, state: "resolved" })}>Mark resolved</button>
              <button onClick={() => upd.mutate({ id: t.id, state: "wont_fix" })}>Accept the risk</button>
            </div>)}
        </article>))}
      {upd.isError && <ErrorBox error={upd.error} />}
    </>
  );
}
