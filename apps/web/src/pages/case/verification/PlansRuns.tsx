import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { SEV_CLASS, type AivObs, type AivPlanT, type AivRunT, type AssetAuth, type PlanPreview } from "../../../lib/aivApi";

type StepKind = "http_metadata" | "tls_handshake" | "tcp_connect" | "service_detect" | "signature_check";

function buildStep(kind: StepKind, host: string, port: string, ports: string, path: string, tool: string, templates: string): Record<string, unknown> {
  const list = ports.split(/[\s,]+/).filter(Boolean).map(Number);
  if (kind === "http_metadata") return { kind, url: `${+port === 443 ? "https" : "http"}://${host}${+port === 443 || +port === 80 ? "" : ":" + port}${path || "/"}`, method: "HEAD", follow_redirects: false };
  if (kind === "tls_handshake") return { kind, host, port: +port };
  if (kind === "tcp_connect") return { kind, host, ports: list };
  if (kind === "service_detect") return { kind, host, ports: list, tool };
  return { kind, url: `${+port === 443 ? "https" : "http"}://${host}${+port === 443 || +port === 80 ? "" : ":" + port}${path || "/"}`, template_ids: templates.split(/[\s,]+/).filter(Boolean) };
}

function PlanBuilder({ caseId, auths, onCreated }: { caseId: string; auths: AssetAuth[]; onCreated: () => void }) {
  const live = auths.filter((a) => a.state === "live");
  const [authId, setAuthId] = useState("");
  const a = live.find((x) => x.id === authId) ?? live[0];
  const [kind, setKind] = useState<StepKind>("http_metadata");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [ports, setPorts] = useState("80,443");
  const [path, setPath] = useState("/");
  const [tool, setTool] = useState("nmap");
  const [templates, setTemplates] = useState("");
  const step = buildStep(kind, host || a?.scope[0] || "", port, ports, path, tool, templates);
  const body = { authorization_id: a?.id, steps: [step] };
  const preview = useMutation({ mutationFn: () => api<PlanPreview>(`/cases/${caseId}/aiv/plans/preview`, { method: "POST", json: body }) });
  const create = useMutation({ mutationFn: () => api(`/cases/${caseId}/aiv/plans`, { method: "POST", json: body }), onSuccess: () => { preview.reset(); onCreated(); } });
  if (!live.length) return <div className="banner">Record a live asset authorization first; a plan can only use one that is in force.</div>;
  const pv = preview.data;
  return (
    <form className="card" aria-label="Build a verification plan" onSubmit={(e) => { e.preventDefault(); preview.mutate(); }}>
      <b>Build a plan</b>
      <div className="row">
        <select aria-label="Authorization" value={a?.id} onChange={(e) => { setAuthId(e.target.value); preview.reset(); }}>{live.map((x) => <option key={x.id} value={x.id}>{x.scope.join(", ")}</option>)}</select>
        <select aria-label="Check" value={kind} onChange={(e) => { setKind(e.target.value as StepKind); preview.reset(); }} style={{ width: 230 }}>
          {a?.allowed_classes.filter((c) => c !== "lab_network").map((c) => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}</select>
        <input aria-label="Host" placeholder={a?.scope[0] ?? "host"} value={host} onChange={(e) => { setHost(e.target.value); preview.reset(); }} />
        {(kind === "http_metadata" || kind === "tls_handshake" || kind === "signature_check") && <input aria-label="Port" value={port} onChange={(e) => { setPort(e.target.value); preview.reset(); }} style={{ width: 90 }} />}
        {(kind === "tcp_connect" || kind === "service_detect") && <input aria-label="Ports" value={ports} onChange={(e) => { setPorts(e.target.value); preview.reset(); }} style={{ width: 170 }} />}
        {(kind === "http_metadata" || kind === "signature_check") && <input aria-label="Path" value={path} onChange={(e) => { setPath(e.target.value); preview.reset(); }} style={{ width: 130 }} />}
        {kind === "service_detect" && <select aria-label="Tool" value={tool} onChange={(e) => setTool(e.target.value)} style={{ width: 110 }}><option>nmap</option><option>naabu</option></select>}
        {kind === "signature_check" && <input aria-label="Template ids" placeholder="approved template ids" value={templates} onChange={(e) => setTemplates(e.target.value)} />}
        <button className="primary" disabled={preview.isPending || !a}>Preview (sends nothing)</button>
      </div>
      {preview.isError && <ErrorBox error={preview.error} />}
      {pv && (
        <div aria-label="Plan preview">
          <table><thead><tr><th>Step</th><th>Policy</th><th>Impact</th></tr></thead><tbody>
            {pv.steps.map((s) => (<tr key={s.index}><td>{s.kind.replace(/_/g, " ")} → <code>{s.target}</code><div className="muted">{JSON.stringify(s.detail)}</div></td>
              <td><Badge v={s.allowed ? "healthy" : "failed"} /> {s.allowed ? "allowed" : "blocked"}<div className="muted">{s.reason}</div></td><td>{s.impact} · ~{s.estimated_requests} request(s)</td></tr>))}
          </tbody></table>
          {pv.problems.map((p) => <div key={p} className="banner warn">{p}</div>)}
          <div className="muted">{pv.disclosure.what_is_sent} Retention: {pv.disclosure.data_retention}. Hash <code>{pv.plan_hash.slice(0, 12)}</code></div>
          <div className="row" style={{ marginTop: 8 }}><button className="primary" type="button" disabled={!pv.ok || create.isPending} onClick={() => create.mutate()}>Save as draft plan</button>
            {!pv.ok && <span className="muted">A blocked plan cannot be saved.</span>}</div>
        </div>)}
      {create.isError && <ErrorBox error={create.error} />}
    </form>
  );
}

function PlanCard({ plan, onChanged }: { plan: AivPlanT; onChanged: () => void }) {
  const [confirm, setConfirm] = useState(false);
  const [minutes, setMinutes] = useState(60);
  const approve = useMutation({ mutationFn: () => api<{ approval_id: string }>(`/aiv/plans/${plan.id}/approve`, { method: "POST", json: { confirm: true, expires_in_minutes: minutes } }) });
  const run = useMutation({ mutationFn: (approval_id: string) => api<AivRunT>(`/aiv/plans/${plan.id}/run`, { method: "POST", json: { approval_id } }), onSuccess: onChanged });
  return (
    <div className="card" aria-label={`Plan ${plan.id.slice(0, 8)}`}>
      <div className="row"><b>Plan {plan.id.slice(0, 8)}</b> <span className="badge">v{plan.version}</span> <Badge v={plan.status === "approved" ? "medium" : "unknown"} /> {plan.status}
        <span className="grow" /><code>{plan.plan_hash.slice(0, 12)}</code></div>
      <ol>{plan.steps.map((s, i) => <li key={i}><code>{JSON.stringify(s)}</code></li>)}</ol>
      {plan.status === "draft" && !approve.data && (
        <div className="row">
          <label><input type="checkbox" style={{ width: "auto" }} checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I read this exact plan and approve it</label>
          <input aria-label="Approval minutes" type="number" min={1} max={240} value={minutes} onChange={(e) => setMinutes(+e.target.value)} style={{ width: 90 }} /> <span className="muted">minutes, single use</span>
          <button className="primary" disabled={!confirm || approve.isPending} onClick={() => approve.mutate()}>Approve this plan</button>
        </div>)}
      {approve.data && <div className="row"><span className="muted">Approved for one run.</span><button className="primary" disabled={run.isPending} onClick={() => run.mutate(approve.data!.approval_id)}>Run now</button></div>}
      {approve.isError && <ErrorBox error={approve.error} />}
      {run.isError && <ErrorBox error={run.error} />}
    </div>
  );
}

export function Plans({ caseId, auths }: { caseId: string; auths: AssetAuth[] }) {
  const qc = useQueryClient();
  const plans = useQuery({ queryKey: ["aiv-plans", caseId], queryFn: () => api<{ items: AivPlanT[] }>(`/cases/${caseId}/aiv/plans`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["aiv-plans", caseId] }); qc.invalidateQueries({ queryKey: ["aiv-obs", caseId] }); qc.invalidateQueries({ queryKey: ["aiv-runs", caseId] }); };
  return (
    <>
      <div className="banner">A plan lists every request before anything is sent. Approving one is a separate, deliberate act: the approval covers exactly this plan, once, and expires.</div>
      <PlanBuilder caseId={caseId} auths={auths} onCreated={refresh} />
      {plans.isLoading && <Loading what="plans" />}
      {plans.data && !plans.data.items.length && <Empty title="No plans yet" />}
      {plans.data?.items.map((p) => <PlanCard key={p.id} plan={p} onChanged={refresh} />)}
    </>
  );
}

export function Observations({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["aiv-obs", caseId], queryFn: () => api<{ items: AivObs[] }>(`/cases/${caseId}/aiv/observations`) });
  const review = useMutation({ mutationFn: (v: { id: string; status: string; note: string }) => api(`/cases/${caseId}/aiv/observations/${v.id}/review`, { method: "POST", json: { status: v.status, note: v.note } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["aiv-obs", caseId] }) });
  const [note, setNote] = useState("");
  if (q.isLoading) return <Loading what="observations" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  if (!q.data?.items.length) return <Empty title="No observations yet" hint="Run an approved plan to create some." />;
  return (
    <>
      <div className="banner">An observation is what a check saw at one moment. It is not proof of compromise. Review each one and say why.</div>
      <input aria-label="Review reason" placeholder="Reason for the review decision (recorded)" value={note} onChange={(e) => setNote(e.target.value)} />
      {q.data.items.map((o) => (
        <div className="card" key={o.id}>
          <div className="row"><Badge v={SEV_CLASS[o.severity] ?? "unknown"} /> <b>{String((o.observed as { title?: string }).title ?? o.finding_key)}</b><span className="grow" />
            <span className="badge">{o.review_status.replace(/_/g, " ")}</span></div>
          <div className="muted"><code>{o.target_asset}</code> · {o.check_type} · confidence {o.confidence} · {o.basis} · {fmt(o.observed_at)}</div>
          {o.remediation && <div>Suggested remedy: {o.remediation}</div>}
          <div className="row">{(["confirmed", "false_positive", "accepted_risk"] as const).map((s) => (
            <button key={s} disabled={review.isPending || note.trim().length < 3} onClick={() => review.mutate({ id: o.id, status: s, note })}>{s.replace(/_/g, " ")}</button>))}</div>
        </div>))}
      {review.isError && <ErrorBox error={review.error} />}
    </>
  );
}
