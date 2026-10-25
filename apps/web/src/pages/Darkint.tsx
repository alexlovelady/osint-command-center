import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../components/ui";
import { api } from "../lib/api";
import { COV_CLASS, COV_LABEL, type CovState, type DarkDashRow, type DarkSource } from "../lib/darkintApi";

/** Cross-case DARKINT view: counts and labels only. Identifiers, titles and references stay inside their own case. */
export default function Darkint({ openCase }: { openCase: (id: string) => void }) {
  const q = useQuery({ queryKey: ["darkint-dashboard"], queryFn: () => api<{ items: DarkDashRow[]; totals: Record<CovState, number>; notice: string }>("/darkint/dashboard") });
  const src = useQuery({ queryKey: ["darkint-sources"], queryFn: () => api<{ items: DarkSource[]; mock_mode: boolean }>("/darkint/sources") });
  const qc = useQueryClient();
  const mock = useMutation({ mutationFn: (enabled: boolean) => api("/darkint/mock-mode", { method: "PUT", json: { enabled } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["darkint-sources"] }) });
  const set = useMutation({ mutationFn: (v: { id: string; enabled: boolean; ack: boolean }) => api(`/darkint/sources/${v.id}`, { method: "PUT", json: { enabled: v.enabled, acknowledge_terms: v.ack } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["darkint-sources"] }) });
  return (
    <>
      <h2>DARKINT: exposure intelligence</h2>
      <div className="banner">Defensive exposure assessment only: provider-reported breaches, mentions and ransomware listings for yourself, verified clients and authorized organizations. A report is a lead, not proof. “Not checked” and “Unknown” never mean “no exposure”.</div>
      {q.isLoading && <Loading what="exposure overview" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data && (
        <>
          <div className="row" aria-label="Totals">
            {(Object.keys(COV_LABEL) as CovState[]).map((s) => <span key={s} className="card"><Badge v={COV_CLASS[s]} /> <b>{q.data.totals[s]}</b> {COV_LABEL[s]}</span>)}
          </div>
          {!q.data.items.length && <Empty title="No targets with checkable inputs" hint="Open a person or organization case, add an email, domain or organization input, and an authorization that covers exposure checks." />}
          <table><thead><tr><th>Case</th><th>Target</th><th>Coverage</th><th>To review</th><th>Tasks</th><th>Monitors</th><th>Last checked</th></tr></thead><tbody>
            {q.data.items.map((r) => (
              <tr key={r.subject_id}><td><a href={`#/case/${r.case_id}`} onClick={(e) => { e.preventDefault(); openCase(r.case_id); }}>{r.case}</a></td><td>{r.subject}<div className="muted">{r.mode}</div></td>
                <td>{(Object.keys(COV_LABEL) as CovState[]).filter((s) => r.states[s]).map((s) => <div key={s}><Badge v={COV_CLASS[s]} /> {r.states[s]} {COV_LABEL[s].toLowerCase()}</div>)}</td>
                <td>{r.unreviewed_events}</td><td>{r.open_remediation}</td>
                <td>{r.monitors_active} on{r.monitors_stopped ? `, ${r.monitors_stopped} stopped` : ""}</td><td>{r.last_checked ? fmt(r.last_checked) : "never"}</td></tr>))}
          </tbody></table>
          <div className="muted">{q.data.notice}</div>
        </>)}
      {src.data && (
        <div className="card" aria-label="Provider administration">
          <b>Providers (administrators)</b>
          <div className="muted">Enable a provider only after reading its terms. Keys are stored in the credential vault under the provider’s name (Setup → API keys), never here.</div>
          {src.data.items.filter((s) => s.automated).map((s) => (
            <div className="row" key={s.provider_id}><b>{s.name}</b> <Badge v={s.state === "live" ? "healthy" : s.state === "disabled" ? "failed" : "medium"} /> {s.state}
              <span className="muted">{s.reason}</span><span className="grow" />
              <button onClick={() => set.mutate({ id: s.provider_id, enabled: !s.enabled, ack: !s.enabled })} disabled={set.isPending}>{s.enabled ? "Disable" : "Enable and accept its terms"}</button></div>))}
          <label><input type="checkbox" style={{ width: "auto" }} checked={src.data.mock_mode} onChange={(e) => mock.mutate(e.target.checked)} /> Fixture mode: synthetic answers, nothing leaves this machine (for demonstrations and tests)</label>
          {(set.isError || mock.isError) && <ErrorBox error={set.error ?? mock.error} />}
        </div>)}
    </>
  );
}
