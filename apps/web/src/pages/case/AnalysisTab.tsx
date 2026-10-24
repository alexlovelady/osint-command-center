import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, val } from "../../components/ui";
import { api } from "../../lib/api";

interface Claim { id: string; subject: string; predicate: string; value: unknown; object: string | null; confidence_label: string;
  verification_status: string; independent_source_groups: number; sources: { evidence_id: string; group: string }[] }
interface Contradiction { subject: string; predicate: string; positions: Claim[]; note: string }
interface Gaps { summary: string; unanswered_requirements: { id: string; question: string; priority: string }[]; stale_findings: number;
  disputed_claims: number; unverified_claims: number; contradictions: number }
interface Req { id: string; question: string; priority: string; status: string; answer_status: string; supporting: { evidence_id: string }[] }
interface Hyp { id: string; statement: string; status: string; tally: { support: number; contradict: number; neutral: number }; note: string }

/** Fusion workspace: claims with independence-based labels, side-by-side contradictions, gaps, requirements, hypotheses. */
export default function AnalysisTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const refresh = () => ["claims", "contradictions", "gaps", "reqs", "hyps"].forEach((k) => qc.invalidateQueries({ queryKey: [k, id] }));
  const claims = useQuery({ queryKey: ["claims", id], queryFn: () => api<{ items: Claim[]; total: number }>(`/claims?case_id=${id}`) });
  const contra = useQuery({ queryKey: ["contradictions", id], queryFn: () => api<{ items: Contradiction[] }>(`/cases/${id}/contradictions`) });
  const gaps = useQuery({ queryKey: ["gaps", id], queryFn: () => api<Gaps>(`/cases/${id}/gaps`) });
  const reqs = useQuery({ queryKey: ["reqs", id], queryFn: () => api<{ items: Req[] }>(`/requirements?case_id=${id}`) });
  const hyps = useQuery({ queryKey: ["hyps", id], queryFn: () => api<{ items: Hyp[] }>(`/hypotheses?case_id=${id}`) });
  const verify = useMutation({ mutationFn: (v: { cid: string; status: string }) => api(`/claims/${v.cid}/verification`, { method: "POST", json: { status: v.status } }), onSuccess: refresh });
  const [q, setQ] = useState(""); const [h, setH] = useState("");
  const addReq = useMutation({ mutationFn: () => api("/requirements", { method: "POST", json: { case_id: id, question: q } }), onSuccess: () => { setQ(""); refresh(); } });
  const addHyp = useMutation({ mutationFn: () => api("/hypotheses", { method: "POST", json: { case_id: id, statement: h } }), onSuccess: () => { setH(""); refresh(); } });
  const [fid, setFid] = useState("");
  const promote = useMutation({ mutationFn: () => api("/claims/from-finding", { method: "POST", json: { finding_id: fid } }), onSuccess: () => { setFid(""); refresh(); } });
  const [prov, setProv] = useState<string | null>(null);
  const provenance = useQuery({ queryKey: ["prov", prov], enabled: !!prov, queryFn: () => api<{ provenance: { method: string; group: string; evidence: { sha256: string; kind: string }; source: { adapter: string; url: string | null } | null }[] }>(`/claims/${prov}/provenance`) });
  return (
    <>
      <div className="banner">Labels are heuristics from the number of <b>independent</b> source groups, not probabilities. Only you can mark a claim verified.</div>
      {gaps.data && <div className="card" data-tour="analysis-coverage"><b>Coverage &amp; gaps</b> — {gaps.data.summary}
        {gaps.data.unanswered_requirements.map((r) => <div key={r.id} className="muted">open: {r.question} ({r.priority})</div>)}</div>}
      <h3>Contradictions</h3>
      {contra.isLoading && <Loading what="contradictions" />}
      {contra.data?.items.length === 0 && <Empty title="No conflicting claims" hint="Sources that disagree appear here side by side; nothing is overwritten." />}
      {contra.data?.items.map((c) => (
        <div key={c.subject + c.predicate} className="card" style={{ marginBottom: 8 }}>
          <b>{c.subject}</b> · {c.predicate}
          <div className="row" style={{ alignItems: "stretch" }}>
            {c.positions.map((p) => (
              <div key={p.id} className="card" style={{ flex: 1, minWidth: 220 }}>
                <code>{val(p.value ?? p.object)}</code> <Badge v={p.confidence_label} /> <Badge v={p.verification_status} />
                <div className="muted">{p.independent_source_groups} independent source group(s)</div>
              </div>))}
          </div>
        </div>))}
      <h3 data-tour="analysis-claims">Claims</h3>
      <div className="row"><input aria-label="Finding id to promote" placeholder="finding id (from the Findings tab API) → claim" value={fid} onChange={(e) => setFid(e.target.value)} style={{ maxWidth: 380 }} />
        <button disabled={!fid} onClick={() => promote.mutate()}>Promote finding to claim</button></div>
      {promote.isError && <ErrorBox error={promote.error} />}
      {claims.data?.items.length === 0 && <Empty title="No claims yet" hint="A claim is a statement you stand behind, with cited evidence." />}
      {!!claims.data?.items.length && (
        <table><thead><tr><th>Statement</th><th>Confidence</th><th>Verification</th><th /></tr></thead>
          <tbody>{claims.data.items.map((c) => (
            <tr key={c.id}><td>{c.subject} · {c.predicate} = <code>{val(c.value ?? c.object)}</code></td>
              <td><Badge v={c.confidence_label} /><div className="muted">{c.independent_source_groups} group(s)</div></td>
              <td><Badge v={c.verification_status} /></td>
              <td className="row">
                <button onClick={() => verify.mutate({ cid: c.id, status: "analyst_verified" })}>Verify</button>
                <button onClick={() => verify.mutate({ cid: c.id, status: "disputed" })}>Dispute</button>
                <button onClick={() => verify.mutate({ cid: c.id, status: "rejected" })}>Reject</button>
                <button onClick={() => setProv(c.id)}>Provenance</button></td></tr>))}</tbody></table>)}
      {prov && provenance.data && (
        <div className="card"><b>Provenance</b> <button onClick={() => setProv(null)}>close</button>
          {provenance.data.provenance.map((p, i) => <div key={i} className="muted">{p.group || p.method} → {p.source?.adapter ?? "manual"} {p.source?.url ?? ""} · {p.evidence.kind} · <code>{p.evidence.sha256.slice(0, 16)}…</code></div>)}</div>)}
      <h3>Intelligence requirements</h3>
      <form className="row" onSubmit={(e) => { e.preventDefault(); addReq.mutate(); }}>
        <input aria-label="New requirement" placeholder="Question this case must answer" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 520 }} />
        <button className="primary" disabled={!q.trim()}>Add</button></form>
      {reqs.data?.items.map((r) => <div key={r.id} className="muted">{r.question} — <Badge v={r.answer_status} /> {r.supporting.length} supporting item(s)</div>)}
      <h3>Hypotheses</h3>
      <form className="row" onSubmit={(e) => { e.preventDefault(); addHyp.mutate(); }}>
        <input aria-label="New hypothesis" placeholder="A statement you are testing" value={h} onChange={(e) => setH(e.target.value)} style={{ maxWidth: 520 }} />
        <button className="primary" disabled={h.trim().length < 3}>Add</button></form>
      {hyps.data?.items.map((x) => <div key={x.id} className="card" style={{ marginTop: 6 }}>{x.statement} <Badge v={x.status} />
        <div className="muted">supports {x.tally.support} · contradicts {x.tally.contradict} · neutral {x.tally.neutral} — a tally, not a probability</div></div>)}
    </>
  );
}
