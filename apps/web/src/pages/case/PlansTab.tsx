import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox } from "../../components/ui";
import { api, type PlanStep } from "../../lib/api";

interface PlanOut { policy_status: string; steps: PlanStep[]; warnings: string[]; offline: boolean; reason: string; data_sensitivity: string;
  cache_policy: string; recursion: string; budget: { paid_requests: number; estimated_requests: number; currency: string };
  target: { type: string; canonical: string } }
interface Created { id: string; policy_status: string; plan: PlanOut }
interface PlanState { id: string; status: string; policy_status: string; steps: { adapter_id: string; status: string; error_code: string | null }[] }

/** Collection plans: see exactly what would be contacted, why, and at what cost, before anything runs. */
export default function PlansTab({ id }: { id: string }) {
  const [target, setTarget] = useState("");
  const [type, setType] = useState("");
  const [mode, setMode] = useState("passive");
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState<Created | null>(null);
  const [confirmed, setConfirmed] = useState<string[]>([]);
  const body = { case_id: id, target, target_type: type || null, mode, reason };
  const preview = useMutation({ mutationFn: () => api<PlanOut>("/collection-plans/preview", { method: "POST", json: body }) });
  const create = useMutation({ mutationFn: () => api<Created>("/collection-plans", { method: "POST", json: body }), onSuccess: (p) => { setPlan(p); setConfirmed([]); } });
  const approve = useMutation({ mutationFn: () => api(`/collection-plans/${plan!.id}/approve`, { method: "POST", json: { confirmed_adapters: confirmed } }) });
  const cancel = useMutation({ mutationFn: () => api(`/collection-plans/${plan!.id}/cancel`, { method: "POST" }) });
  const state = useQuery({ queryKey: ["plan", plan?.id, approve.isSuccess, cancel.isSuccess], enabled: !!plan,
    refetchInterval: (q) => (q.state.data && ["approved", "queued"].includes(q.state.data.status) ? 2000 : false),
    queryFn: () => api<PlanState>(`/collection-plans/${plan!.id}`) });
  const shown = plan?.plan ?? preview.data;
  const needsConfirm = shown?.steps.filter((s) => s.runnable && s.requires_confirmation) ?? [];
  return (
    <>
      <div className="banner">A plan is a preview of what would be contacted. Nothing runs until you approve it, and policy is checked again at approval.</div>
      <form className="card row" onSubmit={(e) => { e.preventDefault(); setPlan(null); preview.mutate(); }}>
        <input aria-label="Plan target" placeholder="Target (domain, IP, URL, email or username)" value={target} onChange={(e) => setTarget(e.target.value)} style={{ maxWidth: 280 }} />
        <select aria-label="Target type" value={type} onChange={(e) => setType(e.target.value)} style={{ width: 130 }}>
          <option value="">auto-detect</option>{["domain", "ip", "url", "email", "username"].map((t) => <option key={t}>{t}</option>)}</select>
        <select aria-label="Mode" value={mode} onChange={(e) => setMode(e.target.value)} style={{ width: 170 }}>
          {["passive", "public_site_query", "active"].map((m) => <option key={m}>{m}</option>)}</select>
        <input aria-label="Reason" placeholder="Why are you collecting this? (recorded)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
        <button className="primary" disabled={!target.trim() || reason.trim().length < 3 || preview.isPending}>Preview plan</button>
      </form>
      {preview.isError && <ErrorBox error={preview.error} />}
      {!shown && <Empty title="No plan yet" hint="Preview shows each source, what it contacts and whether policy allows it." />}
      {shown && (
        <div className="card">
          <b>Plan for {shown.target.canonical}</b> <Badge v={plan ? plan.policy_status : "unknown"} /> {plan ? plan.policy_status : "preview (not saved)"}
          {shown.offline && <div className="banner warn">Offline mode is on: nothing network-bound can run.</div>}
          <table>
            <thead><tr><th>Source</th><th>Contacts</th><th>Policy</th><th>Cost</th></tr></thead>
            <tbody>{shown.steps.map((s) => (
              <tr key={s.adapter_id}><td>{s.name}<div className="muted">{s.operation_class}</div></td>
                <td className="muted">{(s.endpoints ?? []).join(", ") || "local only"}</td>
                <td>{s.runnable ? <Badge v="medium" /> : <Badge v="low" />} {s.runnable ? (s.requires_confirmation ? "needs your confirmation" : "allowed") : "blocked"}<div className="muted">{s.reason}</div>
                  {plan && s.runnable && s.requires_confirmation && (
                    <label><input type="checkbox" style={{ width: "auto" }} checked={confirmed.includes(s.adapter_id)}
                      onChange={(e) => setConfirmed(e.target.checked ? [...confirmed, s.adapter_id] : confirmed.filter((x) => x !== s.adapter_id))} /> I confirm this source</label>)}</td>
                <td>{s.cost ?? "free"}</td></tr>))}</tbody>
          </table>
          <div className="muted">Estimated requests {shown.budget.estimated_requests} · paid {shown.budget.paid_requests} ({shown.budget.currency}) · {shown.cache_policy} · {shown.recursion}</div>
          {shown.warnings.map((w) => <div key={w} className="muted">⚠ {w}</div>)}
          <div className="row" style={{ marginTop: 8 }}>
            {!plan && <button className="primary" onClick={() => create.mutate()} disabled={create.isPending}>Save plan</button>}
            {plan && !state.data?.status.match(/approved|cancelled/) && (
              <button className="primary" disabled={approve.isPending || plan.policy_status === "denied" || confirmed.length < needsConfirm.length} onClick={() => approve.mutate()}>Approve and run</button>)}
            {plan && state.data?.status === "draft" && <button onClick={() => cancel.mutate()}>Cancel plan</button>}
          </div>
          {create.isError && <ErrorBox error={create.error} />}
          {approve.isError && <ErrorBox error={approve.error} />}
          {state.data && <div className="muted">Plan status: <b>{state.data.status}</b>{state.data.steps.map((s) => <div key={s.adapter_id}>{s.adapter_id}: {s.status}{s.error_code ? ` (${s.error_code})` : ""}</div>)}</div>}
        </div>
      )}
    </>
  );
}
