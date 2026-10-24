import { useQuery } from "@tanstack/react-query";
import { Badge, Empty, ErrorBox, Loading } from "../components/ui";
import { api } from "../lib/api";

interface Ov { open_cases: number; pending_jobs: number; findings: number; offline: boolean; adapters: Record<string, string>; storage_bytes: number }

interface Egress { enabled: boolean; state: string; verdict: string | null; note: string; samples: number; window_s: number;
  offenders: { process: string; remote: string }[]; engine_connections: { process: string; remote: string }[] }

function EgressCard() {
  const q = useQuery({ queryKey: ["egress"], queryFn: () => api<Egress>("/system/egress-check"),
    refetchInterval: (x) => (x.state.data?.state === "running" || x.state.data?.state === "pending" ? 3000 : false) });
  const e = q.data;
  if (!e || !e.enabled) return null;
  const running = e.state === "running" || e.state === "pending";
  const cls = running ? "banner" : e.verdict === "clean" ? "banner" : e.verdict === "offending" ? "banner err" : "banner warn";
  return (
    <div className={cls} role="status" aria-label="Start-up network self-check">
      <b>Start-up network self-check:</b>{" "}
      {running ? `watching this app's processes for outside connections (${e.samples} samples, ${e.window_s} s window)…`
        : e.verdict === "clean" ? "no outside connections from this app." : e.verdict === "engine_only" ? "the app made none; its browser engine did."
        : e.verdict === "offending" ? "OUTSIDE CONNECTIONS DETECTED while idle." : "could not be run on this system."}
      {!running && <div className="muted">{e.note}</div>}
      {[...(e.offenders ?? []), ...(e.engine_connections ?? [])].slice(0, 6).map((c, i) => <div key={i} className="muted"><code>{c.process}</code> → <code>{c.remote}</code></div>)}
    </div>
  );
}

export default function Overview({ go }: { go: (r: string) => void }) {
  const q = useQuery({ queryKey: ["overview"], queryFn: () => api<Ov>("/overview"), refetchInterval: 5000 });
  if (q.isLoading) return <Loading what="overview" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const o = q.data!;
  const online = Object.values(o.adapters).filter((s) => s === "healthy").length;
  return (
    <>
      <h2>Overview</h2>
      <EgressCard />
      {o.offline && <div className="banner warn">Offline mode is on: saved cases are readable, network sources are paused.</div>}
      <div className="cards">
        <div className="card"><div className="n">{o.open_cases}</div>open cases</div>
        <div className="card"><div className="n">{o.pending_jobs}</div>pending jobs</div>
        <div className="card"><div className="n">{o.findings}</div>stored findings</div>
        <div className="card"><div className="n">{online}/{Object.keys(o.adapters).length}</div>sources available</div>
        <div className="card"><div className="n">{(o.storage_bytes / 1024).toFixed(1)} KB</div>evidence vault</div>
      </div>
      <h3>Source health</h3>
      <table>
        <tbody>{Object.entries(o.adapters).map(([k, s]) => <tr key={k}><td>{k}</td><td><Badge v={s} /></td></tr>)}</tbody>
      </table>
      {o.open_cases === 0 && <Empty title="No cases yet" hint="Create a case to start a scoped, cited investigation."><button className="primary" onClick={() => go("cases")}>Go to Cases</button></Empty>}
    </>
  );
}
