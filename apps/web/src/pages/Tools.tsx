import { useQuery } from "@tanstack/react-query";
import { Badge, ErrorBox, Loading } from "../components/ui";
import { api, type ToolT } from "../lib/api";

export default function Tools() {
  const q = useQuery({ queryKey: ["tools"], queryFn: () => api<{ items: ToolT[] }>("/tools") });
  const doc = useQuery({ queryKey: ["doctor"], queryFn: () => api<{ tools: Record<string, { found: boolean; version?: string; level: string; install_hint: string }>; audit_chain: { ok: boolean; events: number }; db_integrity: string; disk_free_gb: number }>("/system/doctor") });
  return (
    <>
      <h2>Tool Manager</h2>
      <p className="muted">Status reflects actual detection and smoke tests, never an assumption.</p>
      {q.isLoading && <Loading what="tools" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data && (
        <table>
          <thead><tr><th>Source</th><th>Health</th><th>Class</th><th>Targets</th><th>License / notes</th></tr></thead>
          <tbody>
            {q.data.items.map((t) => (
              <tr key={t.id}>
                <td><b>{t.name}</b><div className="muted">{t.description}</div></td>
                <td><Badge v={t.health.status} /><div className="muted">{t.health.version ?? t.health.detail ?? ""}</div>
                  {t.health.status === "not_installed" && t.install_hint && <div className="muted">{t.install_hint}</div>}</td>
                <td><Badge v={t.operation_class} /></td><td>{t.supported_target_types.join(", ")}</td><td>{t.license}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>System diagnostics</h3>
      {doc.isLoading && <Loading what="diagnostics" />}
      {doc.data && (
        <>
          <p>Database integrity: <Badge v={doc.data.db_integrity === "ok" ? "healthy" : "failed"} /> · audit chain: <Badge v={doc.data.audit_chain.ok ? "healthy" : "failed"} /> ({doc.data.audit_chain.events} events) · disk free {doc.data.disk_free_gb} GB</p>
          <table>
            <thead><tr><th>Dependency</th><th>State</th><th>Needed for</th></tr></thead>
            <tbody>
              {Object.entries(doc.data.tools).map(([k, t]) => (
                <tr key={k}><td>{k}</td><td>{t.found ? <><Badge v="healthy" /> <span className="muted">{t.version}</span></> : <><Badge v="not_installed" /> <span className="muted">{t.install_hint}</span></>}</td><td>{t.level}</td></tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}
