import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import type { DecideOut, InboxItem } from "../../lib/investigationApi";

const ACTIONS: [string, string, string][] = [
  ["mine", "Mine / confirmed", "Recorded as your own statement (self-attested). It is not independent corroboration."],
  ["not_mine", "Not mine", "Rejected: never used as a starting point, kept on record."],
  ["unsure", "Unsure", "Stays a candidate, marked unsure."],
  ["need_evidence", "Need evidence", "Stays a candidate, marked as waiting for evidence."],
];

interface Ev { id: string; title: string; kind: string; original_url?: string | null }

/** Decide on the selected items: shows the impact first, never attaches evidence unless you pick it, can be undone. */
export function DecisionBar({ sid, caseId, ids, clear, onDone }: { sid: string; caseId: string; ids: string[]; clear: () => void; onDone: () => void }) {
  const qc = useQueryClient();
  const [basis, setBasis] = useState("");
  const [evidence, setEvidence] = useState("");
  const [preview, setPreview] = useState<{ action: string; out: DecideOut } | null>(null);
  const [last, setLast] = useState<DecideOut | null>(null);
  const evs = useQuery({ queryKey: ["evidence-list", caseId], queryFn: () => api<{ items: Ev[] }>(`/cases/${caseId}/evidence?limit=200`) });
  const usable = (evs.data?.items ?? []).filter((e) => !e.kind.includes(".raw") && e.kind !== "adapter_result");
  const call = (action: string, pv: boolean) => api<DecideOut>(`/subjects/${sid}/review-inbox/decide`, { method: "POST", json: { ids, action, basis, evidence_ids: evidence ? [evidence] : [], preview: pv } });
  const prev = useMutation({ mutationFn: (action: string) => call(action, true).then((out) => ({ action, out })), onSuccess: setPreview });
  const apply = useMutation({
    mutationFn: (action: string) => call(action, false),
    onSuccess: (out) => { setLast(out); setPreview(null); setBasis(""); clear(); onDone(); qc.invalidateQueries({ queryKey: ["global-review"] }); },
  });
  const undo = useMutation({ mutationFn: (bulk: string) => api(`/subjects/${sid}/review-inbox/undo`, { method: "POST", json: { bulk_id: bulk } }), onSuccess: () => { setLast(null); onDone(); } });
  return (
    <div className="card" aria-label="Decide on selected items" style={{ position: "sticky", bottom: 8 }}>
      <div className="row">
        <b>{ids.length} selected</b>
        <button onClick={clear} disabled={!ids.length}>Clear selection</button>
        <input aria-label="Reason or method" placeholder="Reason or method (recorded)" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
        <label>Independent evidence
          <select aria-label="Independent evidence" value={evidence} onChange={(e) => setEvidence(e.target.value)} style={{ width: 240 }}>
            <option value="">None (self-attested only)</option>
            {usable.map((e) => <option key={e.id} value={e.id}>{e.title}</option>)}</select></label>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        {ACTIONS.map(([k, label, hint]) => <button key={k} title={hint} disabled={!ids.length || !basis.trim() || prev.isPending} onClick={() => prev.mutate(k)}>{label}</button>)}
      </div>
      {preview && (
        <div className="banner" role="status" aria-label="Impact preview">
          <b>{ACTIONS.find((a) => a[0] === preview.action)?.[1]}: {preview.out.total} item(s)</b>
          {preview.out.sites.length > 0 && <> on {preview.out.sites.join(", ")}</>}. {preview.out.effect}
          {preview.out.exceptions.length > 0 && (<ul>{preview.out.exceptions.map((x) => <li key={x.id}>{x.reason}</li>)}</ul>)}
          <div className="row"><button className="primary" onClick={() => apply.mutate(preview.action)} disabled={apply.isPending}>Apply to {preview.out.total}</button><button onClick={() => setPreview(null)}>Cancel</button></div>
        </div>)}
      {last && last.bulk_id && (
        <div className="banner" role="status">{last.applied} item(s) updated. <button onClick={() => undo.mutate(last.bulk_id as string)} disabled={undo.isPending}>Undo this batch</button>
          <span className="muted"> Undo covers accounts; other items can be reopened one by one.</span></div>)}
      {(prev.isError || apply.isError || undo.isError) && <ErrorBox error={prev.error ?? apply.error ?? undo.error} />}
    </div>
  );
}

function UseAsInput({ sid, id, onDone }: { sid: string; id: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [basis, setBasis] = useState("");
  const use = useMutation({ mutationFn: () => api<{ note: string }>(`/subjects/${sid}/review-inbox/use-as-input`, { method: "POST", json: { id, basis } }), onSuccess: () => { setOpen(false); onDone(); } });
  if (!open) return <button onClick={() => setOpen(true)} title="Make this a starting point for research. Only your decision does this.">Use as input</button>;
  return (
    <span className="row" aria-label="Use as input">
      <input aria-label="Why this belongs to the subject" placeholder="Why it belongs to the subject (recorded)" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ width: 260 }} />
      <button className="primary" disabled={!basis.trim() || use.isPending} onClick={() => use.mutate()}>Use</button><button onClick={() => setOpen(false)}>Cancel</button>
      {use.isError && <ErrorBox error={use.error} />}
    </span>
  );
}

const INPUT_TYPES = ["Username or handle", "Email address", "Full name", "Alias or alternate name", "Organization affiliation", "Social, developer, forum or gaming profile", "Website"];

export function InboxList({ items, sel, setSel, sid, onDone }: { items: InboxItem[]; sel: string[]; setSel: (s: string[]) => void; sid?: string; onDone?: () => void }) {
  const toggle = (id: string) => setSel(sel.includes(id) ? sel.filter((x) => x !== id) : [...sel, id]);
  return (
    <ul style={{ listStyle: "none", padding: 0 }} aria-label="Items to decide">
      {items.map((i) => (
        <li key={i.id} className="card" style={{ marginBottom: 6 }}>
          <label className="row">
            <input type="checkbox" style={{ width: "auto" }} checked={sel.includes(i.id)} onChange={() => toggle(i.id)} aria-label={`Select ${i.title}`} />
            <b>{i.title}</b><span className="badge st-mute">{i.kind === "account" ? "account" : i.kind === "email" ? "email" : i.kind === "seed" ? "confirmed" : "lead"}</span>
          </label>
          {sid && (i.kind === "seed" || (i.kind === "item" && INPUT_TYPES.includes(i.detail))) && <UseAsInput sid={sid} id={i.id} onDone={onDone ?? (() => undefined)} />}
          <div className="muted">{i.detail} · Question: <i>{i.claim}?</i> · {i.signals} independent signal(s) · {i.evidence} evidence item(s){i.tools.length > 0 && <> · seen by {i.tools.join(", ")}</>}</div>
          {i.note && <div className="muted">{i.note}</div>}
        </li>))}
    </ul>
  );
}

/** Review: everything waiting for a human decision, across investigations, in one place. */
export default function Review({ go }: { go: (to: string) => void }) {
  const q = useQuery({ queryKey: ["global-review"], queryFn: () => api<{ subjects: { subject_id: string; case_id: string; name: string; role: string; items: InboxItem[]; total: number }[]; total: number }>("/investigations/review") });
  const qc = useQueryClient();
  const [sel, setSel] = useState<Record<string, string[]>>({});
  if (q.isLoading) return <Loading what="the review inbox" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const subs = q.data.subjects.filter((s) => s.total > 0);
  return (
    <section aria-label="Review">
      <h2>Review</h2>
      <p className="muted">A handle that exists is not the person, and two tools agreeing on it is still one signal. Nothing here is a confirmed fact until you decide, and nothing is researched further from a lead until you confirm it.</p>
      {subs.length === 0 && <Empty title="Nothing waiting for you" hint="When an investigation finds accounts, addresses or facts it cannot place, they appear here."><button onClick={() => go("new")}>New investigation</button></Empty>}
      {subs.map((s) => {
        const mine = sel[s.subject_id] ?? [];
        return (
          <div key={s.subject_id} aria-label={`Review for ${s.name}`}>
            <h3>{s.name} <span className="muted">({s.total})</span></h3>
            <InboxList items={s.items} sel={mine} setSel={(v) => setSel({ ...sel, [s.subject_id]: v })} sid={s.role !== "viewer" ? s.subject_id : undefined} onDone={() => qc.invalidateQueries({ queryKey: ["global-review"] })} />
            {s.role !== "viewer" && <DecisionBar sid={s.subject_id} caseId={s.case_id} ids={mine} clear={() => setSel({ ...sel, [s.subject_id]: [] })} onDone={() => qc.invalidateQueries({ queryKey: ["global-review"] })} />}
          </div>);
      })}
    </section>
  );
}
