import { useQuery } from "@tanstack/react-query";
import { Badge, Empty, ErrorBox, Loading } from "../components/ui";
import { api } from "../lib/api";

interface Ov { open_cases: number; pending_jobs: number; findings: number; offline: boolean; adapters: Record<string, string>; storage_bytes: number }

export default function Overview({ go }: { go: (r: string) => void }) {
  const q = useQuery({ queryKey: ["overview"], queryFn: () => api<Ov>("/overview"), refetchInterval: 5000 });
  if (q.isLoading) return <Loading what="overview" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const o = q.data!;
  const online = Object.values(o.adapters).filter((s) => s === "healthy").length;
  return (
    <>
      <h2>Overview</h2>
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
