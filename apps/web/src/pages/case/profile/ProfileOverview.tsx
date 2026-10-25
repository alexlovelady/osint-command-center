import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { STATE_CLASS, type ClaimT, type ProfileT } from "../../../lib/profileApi";

const FIELDS = ["name", "alias", "professional_contact", "employer", "role", "education", "business_association", "owned_domain", "document", "publication", "location_public", "other"];

export const StateBadge = ({ state, label }: { state: string; label?: string }) =>
  <span className={`badge ${STATE_CLASS[state] ?? "st-mute"}`}>{label ?? state.replace(/_/g, " ")}</span>;

function EvidenceLinks({ c }: { c: ClaimT }) {
  if (!c.evidence?.length) return <span className="muted">no evidence attached</span>;
  return <>{c.evidence.map((e) => <code key={e.id} title={`${e.title || e.kind} · sha256 ${e.sha256.slice(0, 12)}`}> {e.id.slice(0, 8)}</code>)}</>;
}

function ClaimRow({ c, subjectId, canEdit, evidence }: { c: ClaimT; subjectId: string; canEdit: boolean; evidence: { id: string; title: string }[] }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [state, setState] = useState("verified");
  const [basis, setBasis] = useState("");
  const [ev, setEv] = useState<string[]>([]);
  const [subj, setSubj] = useState(false);
  const verify = useMutation({
    mutationFn: () => api(`/subjects/${subjectId}/claims/${c.id}/verify`, { method: "POST", json: { state, basis, evidence_ids: ev, attestation: subj ? "subject" : "none" } }),
    onSuccess: () => { setOpen(false); setBasis(""); qc.invalidateQueries({ queryKey: ["profile", subjectId] }); },
  });
  const val = c.value as Record<string, unknown>;
  return (
    <li>
      <StateBadge state={c.state} label={c.state_label} /> <b>{c.field.replace(/_/g, " ")}</b>: {String(val.text ?? val.url ?? JSON.stringify(val))} · <EvidenceLinks c={c} />
      {c.reviewer && <span className="muted"> · decided by {c.reviewer}{c.reason ? ` (${c.reason})` : ""}</span>}
      {canEdit && c.from !== "candidate_queue" && <> <button onClick={() => setOpen(!open)} aria-expanded={open}>Review</button></>}
      {open && (
        <form className="card row" aria-label={`Review ${c.field}`} onSubmit={(e) => { e.preventDefault(); verify.mutate(); }}>
          <select aria-label="Decision" value={state} onChange={(e) => setState(e.target.value)} style={{ width: 170 }}>
            {["verified", "subject_confirmed", "conflicting", "rejected", "not_assessed"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
          </select>
          <input aria-label="Basis" placeholder="Method or reason (required)" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
          <select aria-label="Supporting evidence" multiple value={ev} onChange={(e) => setEv([...e.target.selectedOptions].map((o) => o.value))} style={{ minWidth: 200 }}>
            {evidence.map((x) => <option key={x.id} value={x.id}>{(x.title || x.id).slice(0, 40)}</option>)}
          </select>
          <label><input type="checkbox" style={{ width: "auto" }} checked={subj} onChange={(e) => setSubj(e.target.checked)} /> subject attests</label>
          <button className="primary" disabled={!basis.trim() || verify.isPending}>Record decision</button>
          {verify.isError && <ErrorBox error={verify.error} />}
        </form>)}
    </li>
  );
}

const ACTIONS: [string, string][] = [["Request verification", "Review queue"], ["Approve next collection", "Research"], ["Create remediation", "Remediation"],
  ["Generate report", "Reports"], ["Refresh approved checks", "Research"]];

export default function ProfileOverview({ p, onGo, tabs }: { p: ProfileT; onGo: (tab: string) => void; tabs: string[] }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const canEdit = p.role !== "viewer";
  const evq = useQuery({ queryKey: ["evidence", p.case.id], queryFn: () => api<{ items: { id: string; title: string }[] }>(`/cases/${p.case.id}/evidence`) });
  const [idForm, setIdForm] = useState({ kind: "username", value: "" });
  const [claim, setClaim] = useState({ field: "employer", value: "" });
  const addId = useMutation({ mutationFn: () => api(`/subjects/${sid}/identifiers`, { method: "POST", json: idForm }), onSuccess: () => { setIdForm({ ...idForm, value: "" }); qc.invalidateQueries({ queryKey: ["profile", sid] }); } });
  const addClaim = useMutation({ mutationFn: () => api(`/subjects/${sid}/claims`, { method: "POST", json: claim }), onSuccess: () => { setClaim({ ...claim, value: "" }); qc.invalidateQueries({ queryKey: ["profile", sid] }); } });
  const tl = useQuery({ queryKey: ["timeline", sid], queryFn: () => api<{ items: { at: string; kind: string; text: string; basis: string }[] }>(`/subjects/${sid}/timeline`) });
  return (
    <>
      <p className="muted">{p.notice}</p>
      {canEdit && (
        <div className="row" role="group" aria-label="Profile actions">
          {ACTIONS.filter(([, tab]) => tabs.includes(tab)).map(([label, tab]) => <button key={label} onClick={() => onGo(tab)}>{label}</button>)}
        </div>)}
      {p.sections.map((s) => (
        <section key={s.key} className="card" aria-label={s.title} style={{ marginTop: 10 }}>
          <h3 style={{ margin: "0 0 6px" }}>{s.title}</h3>
          {s.state_note && <div className="muted"><StateBadge state="not_assessed" label="not assessed" /> {s.state_note}</div>}
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {s.identifiers.map((i) => <li key={i.id}><StateBadge state="candidate" label="recorded input" /> {i.kind}: <code>{i.value}</code> {i.masked && <span className="muted">(masked for your role)</span>}</li>)}
            {s.claims.map((c) => <ClaimRow key={c.id} c={c} subjectId={sid} canEdit={canEdit} evidence={evq.data?.items ?? []} />)}
          </ul>
        </section>))}
      <section className="card" aria-label="Unresolved leads" style={{ marginTop: 10 }}>
        <h3 style={{ margin: "0 0 6px" }}>Unresolved leads ({p.unresolved_leads.length})</h3>
        {p.unresolved_leads.length === 0 ? <span className="muted">None. Leads from username tools appear here until you decide on them.</span> :
          <button onClick={() => onGo("Review queue")}>Open the review queue</button>}
      </section>
      <section className="card" aria-label="Timeline" style={{ marginTop: 10 }}>
        <h3 style={{ margin: "0 0 6px" }}>Timeline</h3>
        <ul style={{ margin: 0, paddingLeft: 18 }}>{(tl.data?.items ?? []).slice(-15).map((e, i) => <li key={i}><code>{fmt(e.at)}</code> {e.text} <span className="muted">({e.basis})</span></li>)}</ul>
      </section>
      {canEdit && (
        <div className="row" style={{ marginTop: 10, alignItems: "flex-start" }}>
          <form className="card row" aria-label="Add an input" onSubmit={(e) => { e.preventDefault(); addId.mutate(); }}>
            <select aria-label="Input kind" value={idForm.kind} onChange={(e) => setIdForm({ ...idForm, kind: e.target.value })} style={{ width: 120 }}>
              {["username", "email", "domain", "url", "name", "alias", "organization"].map((k) => <option key={k}>{k}</option>)}</select>
            <input aria-label="Input value" placeholder="Identifier you are authorised to research" value={idForm.value} onChange={(e) => setIdForm({ ...idForm, value: e.target.value })} />
            <button className="primary" disabled={!idForm.value.trim() || addId.isPending}>Add input</button>
            {addId.isError && <ErrorBox error={addId.error} />}
          </form>
          <form className="card row" aria-label="Add a claim" onSubmit={(e) => { e.preventDefault(); addClaim.mutate(); }}>
            <select aria-label="Claim field" value={claim.field} onChange={(e) => setClaim({ ...claim, field: e.target.value })} style={{ width: 170 }}>{FIELDS.map((f) => <option key={f} value={f}>{f.replace(/_/g, " ")}</option>)}</select>
            <input aria-label="Claim value" placeholder="What is claimed (stays a candidate until reviewed)" value={claim.value} onChange={(e) => setClaim({ ...claim, value: e.target.value })} />
            <button className="primary" disabled={!claim.value.trim() || addClaim.isPending}>Add claim</button>
            {addClaim.isError && <ErrorBox error={addClaim.error} />}
          </form>
        </div>)}
    </>
  );
}
