import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Plan, type RunT } from "../lib/api";
import { Badge, ErrorBox } from "./ui";

const TYPES = ["auto-detect", "domain", "ip", "url", "email", "username"] as const;

/** Preview -> explicit confirm -> run viewer. Nothing is sent until the analyst confirms the previewed plan. */
export default function SearchComposer({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const [target, setTarget] = useState("");
  const [type, setType] = useState<(typeof TYPES)[number]>("auto-detect");
  const [selected, setSelected] = useState<string[] | null>(null);
  const [confirmed, setConfirmed] = useState<string[]>([]);
  const [runId, setRunId] = useState<string | null>(null);

  const body = () => ({
    target, target_type: type === "auto-detect" ? null : type,
    adapters: selected, mode: confirmed.length ? "public_site_query" : "passive", confirmed_adapters: confirmed,
  });
  const preview = useMutation({
    mutationFn: () => api<Plan>(`/cases/${caseId}/searches/preview`, { method: "POST", json: body() }),
    onSuccess: (p) => setSelected(selected ?? p.steps.filter((s) => s.runnable && !s.requires_confirmation && (s.health ?? "healthy") === "healthy").map((s) => s.adapter_id)),
  });
  const launch = useMutation({
    mutationFn: () => api<RunT>(`/cases/${caseId}/searches`, { method: "POST", json: { ...body(), adapters: selected } }),
    onSuccess: (r) => setRunId(r.id),
  });
  const run = useQuery({
    queryKey: ["run", runId], enabled: !!runId,
    queryFn: () => api<RunT>(`/search-runs/${runId}`),
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 800 : false),
  });
  const cancel = useMutation({ mutationFn: () => api(`/search-runs/${runId}/cancel`, { method: "POST" }) });
  if (run.data && !["queued", "running"].includes(run.data.status)) {
    qc.invalidateQueries({ queryKey: ["findings", caseId] });
    qc.invalidateQueries({ queryKey: ["graph", caseId] });
  }
  const plan = preview.data;
  return (
    <section aria-label="Search composer">
      <form className="row" onSubmit={(e) => { e.preventDefault(); setSelected(null); setConfirmed([]); setRunId(null); preview.mutate(); }}>
        <input aria-label="Target" placeholder="domain, IP, URL, email — or pick 'username' explicitly" value={target}
          onChange={(e) => setTarget(e.target.value)} style={{ flex: 1, minWidth: 260 }} maxLength={2048} />
        <select aria-label="Target type" value={type} onChange={(e) => setType(e.target.value as typeof type)} style={{ width: 150 }}>
          {TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <button className="primary" disabled={!target.trim() || preview.isPending}>Preview</button>
      </form>
      <p className="muted">Typing sends nothing. Preview shows what would be contacted; you then confirm.</p>
      {preview.isError && <ErrorBox error={preview.error} />}
      {plan && (
        <div className="card">
          <div className="row">
            <b>Detected: {plan.target.type}</b> <code>{plan.target.canonical}</code>
            {plan.target.ambiguous_with.length > 0 && <span className="badge medium">could also be a {plan.target.ambiguous_with.join(", ")}</span>}
            {plan.offline && <span className="badge failed">offline mode</span>}
          </div>
          <table aria-label="Planned sources">
            <thead><tr><th /><th>Source</th><th>Class</th><th>Will contact</th><th>Notes</th></tr></thead>
            <tbody>
              {plan.steps.map((s) => (
                <tr key={s.adapter_id}>
                  <td>
                    <input type="checkbox" aria-label={`Run ${s.name}`} style={{ width: "auto" }} disabled={!s.runnable}
                      checked={!!selected?.includes(s.adapter_id)}
                      onChange={(e) => setSelected((cur) => (e.target.checked ? [...(cur ?? []), s.adapter_id] : (cur ?? []).filter((x) => x !== s.adapter_id)))} />
                  </td>
                  <td>{s.name} {s.health && s.health !== "healthy" && <Badge v={s.health} />}</td>
                  <td><Badge v={s.operation_class ?? "n/a"} /></td>
                  <td>{(s.endpoints ?? []).map((e) => <div key={e}><code>{e}</code></div>)}</td>
                  <td>
                    {!s.runnable && <span className="muted">{s.reason}</span>}
                    {s.requires_confirmation && (
                      <label><input type="checkbox" style={{ width: "auto" }} checked={confirmed.includes(s.adapter_id)}
                        onChange={(e) => setConfirmed((c) => (e.target.checked ? [...c, s.adapter_id] : c.filter((x) => x !== s.adapter_id)))} /> I confirm this contacts third-party public sites</label>
                    )}
                    {(s.warnings ?? []).map((w) => <div key={w} className="muted">{w}</div>)}
                    <div className="muted">cost: free · {s.rate_limit_per_minute ? `${s.rate_limit_per_minute}/min` : "no declared limit"}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {plan.steps.length === 0 && <div className="banner warn">No sources can run for this target right now.</div>}
          <div className="row" style={{ marginTop: 8 }}>
            <button className="primary" disabled={launch.isPending || !selected?.length || !!runId} onClick={() => launch.mutate()}>
              Confirm and run {selected?.length ?? 0} source(s)
            </button>
            <span className="muted">{plan.note}</span>
          </div>
        </div>
      )}
      {launch.isError && <ErrorBox error={launch.error} />}
      {run.data && (
        <div className="card" style={{ marginTop: 12 }} aria-live="polite">
          <div className="row"><b>Run</b> <Badge v={run.data.status} />
            {["queued", "running"].includes(run.data.status) && <button onClick={() => cancel.mutate()}>Cancel</button>}</div>
          <table>
            <thead><tr><th>Source</th><th>Status</th><th>Attempts</th><th>Details</th></tr></thead>
            <tbody>
              {run.data.jobs.map((j) => (
                <tr key={j.id}><td>{j.adapter_id}</td><td><Badge v={j.status} /></td><td>{j.attempts}</td>
                  <td className="muted">{j.error_code ? `${j.error_code} — ` : ""}{j.warnings.join(" ")}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
