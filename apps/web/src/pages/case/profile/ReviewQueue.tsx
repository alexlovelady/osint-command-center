import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { CandidateT, HistoryT, ProfileT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

/** Multi-select ownership triage. Nothing is merged automatically; every decision is attributable and reversible. */
export default function ReviewQueue({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const canEdit = p.role !== "viewer";
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const [basis, setBasis] = useState("");
  const [subj, setSubj] = useState(false);
  const [ev, setEv] = useState<string[]>([]);
  const q = useQuery({ queryKey: ["candidates", sid, filter], queryFn: () => api<{ items: CandidateT[] }>(`/subjects/${sid}/candidates${filter ? `?state=${filter}` : ""}`) });
  const hist = useQuery({ queryKey: ["history", sid], queryFn: () => api<{ items: HistoryT[] }>(`/subjects/${sid}/review-history`) });
  const evq = useQuery({ queryKey: ["evidence", p.case.id], queryFn: () => api<{ items: { id: string; title: string }[] }>(`/cases/${p.case.id}/evidence`) });
  const done = () => { setSel([]); setBasis(""); setEv([]); qc.invalidateQueries({ queryKey: ["candidates", sid] }); qc.invalidateQueries({ queryKey: ["history", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const review = useMutation({
    mutationFn: (state: string) => api(`/subjects/${sid}/candidates/bulk-review`, { method: "POST", json: { candidate_ids: sel, state, basis, attestation: subj ? "subject" : "none", evidence_ids: ev } }),
    onSuccess: done,
  });
  const undo = useMutation({ mutationFn: (b: { event_id?: string; bulk_id?: string }) => api(`/subjects/${sid}/candidates/reverse`, { method: "POST", json: b }), onSuccess: done });
  const items = q.data?.items ?? [];
  const decisions = (hist.data?.items ?? []).filter((h) => h.target_type === "candidate" && !h.reverts && !(hist.data?.items ?? []).some((r) => r.reverts === h.id));
  const bulks = new Map<string, HistoryT>();
  decisions.forEach((d) => bulks.set(d.bulk_id ?? d.id, d));
  return (
    <>
      <div className="banner">
        A username match is a <b>lead</b>. Sherlock and Maigret agreeing is still one signal. Mark an account <b>Mine</b> only with the subject&apos;s own
        attestation or independent evidence; absence of a result never proves an account does not exist.
      </div>
      <div className="row">
        <select aria-label="Filter by state" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 160 }}>
          <option value="">all states</option>{["candidate", "confirmed", "rejected", "unsure"].map((s) => <option key={s}>{s}</option>)}</select>
        <span className="muted">{items.length} account(s) · {sel.length} selected</span>
        {canEdit && <button onClick={() => setSel(items.map((i) => i.id))}>Select all shown</button>}
        {canEdit && <button onClick={() => setSel([])}>Clear</button>}
      </div>
      {q.isError && <ErrorBox error={q.error} />}
      {items.length === 0 && <Empty title="No candidate accounts" hint="Add a username as an input and run an approved username check; results land here." />}
      {items.length > 0 && (
        <table aria-label="Candidate accounts">
          <thead><tr><th /><th>Account</th><th>Seen by</th><th>State</th><th>Evidence</th></tr></thead>
          <tbody>{items.map((c) => (
            <tr key={c.id}>
              <td><input type="checkbox" aria-label={`Select ${c.canonical_url}`} style={{ width: "auto" }} disabled={!canEdit} checked={sel.includes(c.id)}
                onChange={(e) => setSel(e.target.checked ? [...sel, c.id] : sel.filter((x) => x !== c.id))} /></td>
              <td><code>{c.canonical_url}</code><div className="muted">{c.site} · first {fmt(c.first_seen_at)} · last {fmt(c.last_seen_at)}</div>
                {c.note && <div className="muted">{c.note}</div>}</td>
              <td>{c.adapters.join(", ")}<div className="muted">{c.observation_count} observation(s) · {c.independent_signals} independent signal(s)</div></td>
              <td><StateBadge state={c.state} />{c.reviewed_by && <div className="muted">by {c.reviewed_by}</div>}{c.review_basis && <div className="muted">{c.review_basis}</div>}</td>
              <td>{c.evidence.map((e) => <code key={e.id} title={e.title}> {e.id.slice(0, 8)}</code>)}</td>
            </tr>))}</tbody>
        </table>)}
      {canEdit && items.length > 0 && (
        <form className="card" aria-label="Review selected" onSubmit={(e) => e.preventDefault()} style={{ marginTop: 10 }}>
          <div className="row">
            <input aria-label="Reason or method" placeholder="Reason or method (required)" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: 1, minWidth: 240 }} />
            <label><input type="checkbox" style={{ width: "auto" }} checked={subj} onChange={(e) => setSubj(e.target.checked)} /> the subject attests to this decision</label>
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <label>Independent evidence{" "}
              <select aria-label="Corroborating evidence" multiple value={ev} onChange={(e) => setEv([...e.target.selectedOptions].map((o) => o.value))} style={{ minWidth: 220 }}>
                {(evq.data?.items ?? []).map((x) => <option key={x.id} value={x.id}>{(x.title || x.id).slice(0, 50)}</option>)}</select></label>
            <button className="primary" disabled={!sel.length || !basis.trim() || review.isPending} onClick={() => review.mutate("confirmed")}>Mine / Confirmed</button>
            <button disabled={!sel.length || !basis.trim() || review.isPending} onClick={() => review.mutate("rejected")}>Not mine / Rejected</button>
            <button disabled={!sel.length || !basis.trim() || review.isPending} onClick={() => review.mutate("unsure")}>Unsure</button>
          </div>
          {review.isError && <ErrorBox error={review.error} />}
        </form>)}
      {bulks.size > 0 && (
        <section className="card" aria-label="Recent decisions" style={{ marginTop: 10 }}>
          <h3 style={{ margin: "0 0 6px" }}>Recent decisions</h3>
          {[...bulks.entries()].slice(-6).reverse().map(([key, d]) => (
            <div key={key} className="row">
              <code>{fmt(d.at)}</code> {d.from} → {d.to} by {d.reviewer}{d.bulk_id ? " (bulk)" : ""} <span className="muted">{d.basis}</span>
              {canEdit && <button onClick={() => undo.mutate(d.bulk_id ? { bulk_id: d.bulk_id } : { event_id: d.id })}>Undo</button>}
            </div>))}
          {undo.isError && <ErrorBox error={undo.error} />}
        </section>)}
    </>
  );
}
