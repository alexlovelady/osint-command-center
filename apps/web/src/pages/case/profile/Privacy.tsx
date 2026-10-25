import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ProfileT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

interface Correction { id: string; target_type: string; request: string; justification: string; requested_by: string; status: string; resolution: string; event_time: string }
interface PurgePreview { will_delete: Record<string, number>; kept: string[]; confirm_with: string; note: string; evidence_objects_redacted: number }

/** Subject corrections and data retention: dispute a record, see exactly what a purge would remove, then purge with a typed confirmation. */
export default function Privacy({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const owner = p.role === "owner";
  const corr = useQuery({ queryKey: ["corrections", sid], enabled: p.role !== "viewer", queryFn: () => api<{ items: Correction[] }>(`/subjects/${sid}/corrections`) });
  const [f, setF] = useState({ target_type: "other", request: "", justification: "", requested_by: "subject" });
  const [res, setRes] = useState<Record<string, string>>({});
  const inv = () => { qc.invalidateQueries({ queryKey: ["corrections", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const add = useMutation({ mutationFn: () => api(`/subjects/${sid}/corrections`, { method: "POST", json: f }), onSuccess: () => { setF({ ...f, request: "", justification: "" }); inv(); } });
  const resolve = useMutation({ mutationFn: (v: { id: string; decision: string }) => api(`/subjects/${sid}/corrections/${v.id}/resolve`, { method: "POST", json: { decision: v.decision, resolution: res[v.id] ?? "" } }), onSuccess: inv });
  const prev = useMutation({ mutationFn: () => api<PurgePreview>(`/subjects/${sid}/retention/preview`) });
  const [typed, setTyped] = useState("");
  const purge = useMutation({ mutationFn: () => api(`/subjects/${sid}/retention/purge`, { method: "POST", json: { confirm: typed } }), onSuccess: () => { prev.reset(); setTyped(""); qc.invalidateQueries(); } });
  if (p.role === "viewer") return <div className="banner">Corrections and retention controls are hidden for your role.</div>;
  return (
    <>
      <div className="banner">The subject can ask for any record to be corrected or removed. Requests are logged with the time and the audit entry; a decision always records why.
        Reports separate what is verified from what is only a lead, and never include speculative sensitive associations.</div>
      <form className="card row" aria-label="Record a correction request" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
        <select aria-label="Applies to" value={f.target_type} onChange={(e) => setF({ ...f, target_type: e.target.value })} style={{ width: 140 }}>
          {["other", "claim", "candidate", "exposure", "image_match", "identifier"].map((t) => <option key={t}>{t}</option>)}</select>
        <input aria-label="Correction request" placeholder="What should be corrected or removed" value={f.request} onChange={(e) => setF({ ...f, request: e.target.value })} style={{ flex: 1, minWidth: 240 }} />
        <input aria-label="Requested by" value={f.requested_by} onChange={(e) => setF({ ...f, requested_by: e.target.value })} style={{ maxWidth: 160 }} />
        <button className="primary" disabled={!f.request.trim() || add.isPending}>Record request</button>
        {add.isError && <ErrorBox error={add.error} />}
      </form>
      {corr.data?.items.length === 0 && <Empty title="No correction requests" />}
      {(corr.data?.items ?? []).map((c) => (
        <div key={c.id} className="card" style={{ marginTop: 8 }}>
          <div className="row"><b>{c.target_type}</b> <StateBadge state={c.status === "declined" ? "rejected" : c.status === "open" ? "candidate" : "completed"} label={c.status} />
            <span className="muted">by {c.requested_by} · {fmt(c.event_time)}</span></div>
          <div>{c.request}</div>
          {c.resolution && <div className="muted">Decision: {c.resolution}</div>}
          {c.status === "open" && (
            <div className="row">
              <input aria-label={`Decision reason ${c.id.slice(0, 6)}`} placeholder="Reason (required)" value={res[c.id] ?? ""} onChange={(e) => setRes({ ...res, [c.id]: e.target.value })} style={{ flex: 1 }} />
              <button disabled={!(res[c.id] ?? "").trim()} onClick={() => resolve.mutate({ id: c.id, decision: "accepted" })}>Accept</button>
              <button disabled={!(res[c.id] ?? "").trim()} onClick={() => resolve.mutate({ id: c.id, decision: "applied" })}>Accept and apply</button>
              <button disabled={!(res[c.id] ?? "").trim()} onClick={() => resolve.mutate({ id: c.id, decision: "declined" })}>Decline</button>
            </div>)}
        </div>))}
      {resolve.isError && <ErrorBox error={resolve.error} />}
      <section className="card" aria-label="Retention" style={{ marginTop: 14 }}>
        <h3 style={{ margin: "0 0 6px" }}>Retention and deletion</h3>
        {!owner ? <p className="muted">Only a case owner can preview or perform a purge.</p> : (
          <>
            <button onClick={() => prev.mutate()}>Preview what a purge would remove</button>
            {prev.isError && <ErrorBox error={prev.error} />}
            {prev.data && (
              <div className="banner warn" aria-label="Purge preview">
                <b>Irreversible.</b> It would delete: {Object.entries(prev.data.will_delete).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k.replace(/_/g, " ")}`).join(", ") || "nothing"}; {prev.data.evidence_objects_redacted} evidence object(s) would be redacted and removed.
                <ul>{prev.data.kept.map((k) => <li key={k}>Kept: {k}</li>)}</ul>
                <div className="muted">{prev.data.note}</div>
                <label>Type <code>{prev.data.confirm_with}</code> to confirm <input aria-label="Type to confirm" value={typed} onChange={(e) => setTyped(e.target.value)} style={{ maxWidth: 280 }} /></label>
                <div><button className="primary" disabled={typed !== prev.data.confirm_with || purge.isPending} onClick={() => purge.mutate()}>Purge this subject</button></div>
                {purge.isError && <ErrorBox error={purge.error} />}
              </div>)}
          </>)}
      </section>
    </>
  );
}
