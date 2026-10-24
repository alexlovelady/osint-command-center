import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api } from "../../lib/api";
import type { NoteT, SuggestionT } from "../../lib/automationsApi";
import { goWf } from "./Library";

export default function Inbox() {
  const qc = useQueryClient();
  const notes = useQuery({ queryKey: ["auto-notes"], queryFn: () => api<{ total: number; unacknowledged: number; items: NoteT[] }>("/automations/notifications?limit=100"), refetchInterval: 10_000 });
  const sugg = useQuery({ queryKey: ["auto-sugg"], queryFn: () => api<{ enabled: boolean; items: SuggestionT[]; note: string }>("/automations/suggestions") });
  const ack = useMutation({ mutationFn: (id: string) => api(`/automations/notifications/${id}`, { method: "PATCH", json: { acknowledge: true } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["auto-notes"] }) });
  const dismiss = useMutation({ mutationFn: (id: string) => api(`/automations/suggestions/${id}/dismiss`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["auto-sugg"] }) });
  const snooze = useMutation({ mutationFn: (id: string) => api(`/automations/suggestions/${id}/snooze`, { method: "POST", json: { days: 7 } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["auto-sugg"] }) });
  const use = useMutation({ mutationFn: (s: SuggestionT) => api<{ id: string }>("/automations/from-template", { method: "POST", json: { slug: s.template, case_id: s.case_id } }), onSuccess: (w) => goWf(w.id) });
  // desktop notification for NEW unacknowledged items while the app is open (only after the user allowed it in the browser/OS)
  const seen = useRef<Set<string>>(new Set());
  useEffect(() => {
    for (const n of notes.data?.items ?? []) {
      if (n.acknowledged_at || seen.current.has(n.id)) continue;
      seen.current.add(n.id);
      try { if (typeof Notification !== "undefined" && Notification.permission === "granted" && seen.current.size > 1) new Notification(n.title, { body: n.body.slice(0, 120) }); } catch { /* notifications are optional */ }
    }
  }, [notes.data]);
  return (
    <>
      <h3>Notifications {notes.data?.unacknowledged ? <span className="badge failed">{notes.data.unacknowledged} new</span> : null}</h3>
      {notes.isLoading && <Loading what="notifications" />}
      {notes.isError && <ErrorBox error={notes.error} />}
      {notes.data?.items.length === 0 && <Empty title="Nothing to report" hint="Notifications appear here when an automation finds a meaningful change or fails. Repeats are merged into one." />}
      {notes.data?.items.map((n) => (
        <article key={n.id} className={`card ${n.severity === "critical" || n.severity === "warning" ? "tone-alert" : "tone-tech"}`} style={{ margin: "8px 0" }} aria-label={n.title}>
          <div className="row"><b>{n.title}</b><span className={`badge ${n.severity === "info" ? "unknown" : "failed"}`}>{n.severity}</span>{n.count > 1 && <span className="badge">×{n.count} merged</span>}
            {n.status !== "delivered" && <span className="badge">{n.status.replace(/_/g, " ")}</span>}<span className="grow" /><span className="muted">{fmt(n.created_at)}</span>
            {!n.acknowledged_at && <button onClick={() => ack.mutate(n.id)}>Acknowledge</button>}</div>
          <p style={{ margin: "6px 0 0", whiteSpace: "pre-wrap" }}>{n.body}</p>
          {n.workflow_id && <button className="linklike" onClick={() => goWf(n.workflow_id as string)}>Open workflow</button>}
        </article>))}
      <h3>Suggested automations</h3>
      {sugg.data && !sugg.data.enabled && <div className="banner" role="note">{sugg.data.note} Nothing is observed unless you turn it on.</div>}
      {sugg.data?.enabled && sugg.data.items.length === 0 && <p className="muted">No suggestions. They appear only after you repeat the same manual action several times in this app.</p>}
      {sugg.data?.items.map((s) => (
        <article key={s.id} className="card" style={{ margin: "8px 0" }}>
          <p style={{ margin: 0 }}>{s.rationale}</p>
          <p className="muted" style={{ fontSize: 12 }}>Why you are seeing this: {JSON.stringify(s.basis)}. Template: {s.template}. Accepting only creates a disabled draft.</p>
          <div className="row"><button className="primary" onClick={() => use.mutate(s)}>Create draft from template</button><button onClick={() => snooze.mutate(s.id)}>Snooze 7 days</button><button onClick={() => dismiss.mutate(s.id)}>Dismiss</button></div>
        </article>))}
      <ApprovalsWaiting />
    </>
  );
}

function ApprovalsWaiting() {
  const q = useQuery({ queryKey: ["auto-approvals-all"], queryFn: () => api<{ items: { id: string; workflow_id: string; kind: string; status: string }[] }>("/automations/approvals?status=pending") });
  if (!q.data?.items.length) return null;
  return (
    <>
      <h3>Waiting for your decision</h3>
      <ul>{q.data.items.map((a) => <li key={a.id}>{a.kind} approval <button className="linklike" onClick={() => goWf(a.workflow_id)}>open workflow</button></li>)}</ul>
    </>
  );
}
