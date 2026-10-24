import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, ErrorBox } from "../../components/ui";
import { api } from "../../lib/api";

interface Profile { id: string; name: string; model_id: string; kind: "local" | "cloud"; provider_type: string }
interface Answer { status: "answered" | "approval_required"; verified_evidence: { statement: string; evidence_ids: string[] }[]; inferences: string[]; contradictions: string[];
  unknowns: string[]; next_steps: string[]; proposed_actions: { type: string; target: string; adapters: string[] | null }[]; rejected_citations: { statement: string; reason: string }[];
  structured: boolean; warning?: string; sensitive_items_withheld: number; local: boolean; model: string; transfer_token?: string;
  preview?: { provider: string; model: string; chunks: number; approx_tokens: number; estimated_cost: string; retention_warning: string; sensitive_items_withheld: number } }

export default function AiTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const profiles = useQuery({ queryKey: ["aiprof"], queryFn: () => api<{ ai_enabled: boolean; items: Profile[] }>("/ai/profiles") });
  const policy = useQuery({ queryKey: ["aipol", id], queryFn: () => api<{ allow_cloud: boolean; require_preview: boolean; deny_sensitive_cloud: boolean }>(`/cases/${id}/ai-policy`) });
  const setPolicy = useMutation({ mutationFn: (p: object) => api(`/cases/${id}/ai-policy`, { method: "PUT", json: p }), onSuccess: () => qc.invalidateQueries({ queryKey: ["aipol", id] }) });
  const [pid, setPid] = useState(""); const [q, setQ] = useState(""); const [restricted, setRestricted] = useState(false);
  const [ans, setAns] = useState<Answer | null>(null);
  const prof = profiles.data?.items.find((p) => p.id === (pid || profiles.data.items[0]?.id));
  const ask = useMutation({ mutationFn: (token?: string) => api<Answer>("/ai/ask", { method: "POST", json: { case_id: id, profile_id: prof!.id, question: q, include_restricted: restricted, transfer_token: token } }), onSuccess: setAns });
  const [prevAct, setPrevAct] = useState<string>("");
  const act = useMutation({ mutationFn: (t: string) => api<{ steps: { name: string; runnable: boolean; reason: string }[] }>("/ai/action/preview", { method: "POST", json: { case_id: id, target: t } }),
    onSuccess: (d) => setPrevAct(d.steps.map((s) => `${s.name}: ${s.runnable ? "allowed" : s.reason}`).join(" · ")) });
  if (profiles.isLoading) return null;
  if (!profiles.data?.ai_enabled) return <div className="banner">AI is <b>off</b>. Every other feature works without it. Turn it on in Settings → AI, add a local model profile (Ollama / llama.cpp), then return here.</div>;
  if (!profiles.data.items.length) return <div className="banner">No model profile yet. Add one under Settings → AI.</div>;
  return (
    <>
      <div className="banner">The assistant only sees this case. Its answer is checked against stored evidence: statements without a valid citation are shown as <b>rejected</b>, and it can only <i>propose</i> actions — it cannot run, authorise or widen anything.</div>
      <div className="row">
        <select aria-label="Model profile" value={prof?.id ?? ""} onChange={(e) => setPid(e.target.value)} style={{ maxWidth: 320 }}>
          {profiles.data.items.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.model_id} · {p.kind}</option>)}</select>
        {prof?.kind === "cloud" && <Badge v="medium" />}
        <label><input type="checkbox" style={{ width: "auto" }} checked={restricted} onChange={(e) => setRestricted(e.target.checked)} /> include restricted material (local models only)</label></div>
      {prof?.kind === "cloud" && policy.data && (
        <div className="card">Cloud use for this case: <b>{policy.data.allow_cloud ? "allowed" : "not allowed"}</b>
          <button onClick={() => setPolicy.mutate({ ...policy.data, allow_cloud: !policy.data!.allow_cloud })}>{policy.data.allow_cloud ? "Revoke" : "Allow for this case"}</button>
          <div className="muted">Content leaves this machine only after you approve the exact payload; restricted material is blocked when "deny sensitive" is on.</div></div>)}
      <form className="row" style={{ marginTop: 8 }} onSubmit={(e) => { e.preventDefault(); setAns(null); ask.mutate(undefined); }}>
        <input aria-label="Question" placeholder="Ask about this case's evidence" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1 }} maxLength={1000} />
        <button className="primary" disabled={!q.trim() || ask.isPending}>Ask</button></form>
      {ask.isError && <ErrorBox error={ask.error} />}
      {ans?.status === "approval_required" && ans.preview && (
        <div className="card" role="alertdialog" aria-label="Approve cloud transfer"><b>Approval needed before anything is sent</b>
          <div>To <code>{ans.preview.provider}</code> · model {ans.preview.model} · {ans.preview.chunks} record(s) · ≈{ans.preview.approx_tokens} tokens · cost: {ans.preview.estimated_cost}</div>
          <div className="muted">{ans.preview.retention_warning} {ans.preview.sensitive_items_withheld > 0 && `${ans.preview.sensitive_items_withheld} sensitive item(s) withheld.`}</div>
          <div className="row"><button className="primary" onClick={() => ask.mutate(ans.transfer_token)}>Approve and send exactly this</button><button onClick={() => setAns(null)}>Cancel</button></div></div>)}
      {ans?.status === "answered" && (
        <div className="card" style={{ marginTop: 8 }} aria-live="polite">
          <div className="muted">{ans.model} · {ans.local ? "local" : "cloud"}{ans.sensitive_items_withheld ? ` · ${ans.sensitive_items_withheld} sensitive item(s) withheld` : ""}</div>
          {!ans.structured && <div className="banner err">{ans.warning}</div>}
          <h4>Verified against stored evidence</h4>
          {ans.verified_evidence.length === 0 ? <div className="muted">Nothing could be verified.</div> : ans.verified_evidence.map((v) => <div key={v.statement}>{v.statement} {v.evidence_ids.map((e) => <code key={e}> [{e.slice(0, 8)}]</code>)}</div>)}
          {ans.rejected_citations.length > 0 && <><h4>Rejected (bad or missing citation)</h4>{ans.rejected_citations.map((r) => <div key={r.statement} className="muted">✗ {r.statement} — {r.reason}</div>)}</>}
          {([["Inferences (the model's own)", ans.inferences], ["Contradictions", ans.contradictions], ["Unknowns", ans.unknowns], ["Suggested next steps", ans.next_steps]] as const).map(([t, xs]) => xs.length > 0 && <div key={t}><h4>{t}</h4>{xs.map((x) => <div key={x} className="muted">{x}</div>)}</div>)}
          {ans.proposed_actions.length > 0 && <><h4>Proposed actions (not executed)</h4>{ans.proposed_actions.map((a) => (
            <div key={a.target} className="row"><code>{a.type} {a.target}</code><button onClick={() => act.mutate(a.target)}>Preview what it would do</button></div>))}
            {prevAct && <div className="muted">{prevAct}</div>}{act.isError && <ErrorBox error={act.error} />}</>}
        </div>)}
    </>
  );
}
