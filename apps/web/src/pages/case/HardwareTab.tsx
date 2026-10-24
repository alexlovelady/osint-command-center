import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, fmt } from "../../components/ui";
import { api } from "../../lib/api";

interface Dev { id: string; name: string; kind: string; present: boolean; simulated: boolean; label: string }
interface Cap { id: string; device_id: string; status: string; started_at: string; artifact_id: string | null; detail: string }
interface Diag { drivers: { driver_id: string; status: string; detail?: string; remediation?: string[]; verified_on_physical_device: boolean }[] }

export default function HardwareTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const inv = () => { qc.invalidateQueries({ queryKey: ["caps", id] }); qc.invalidateQueries({ queryKey: ["obs", id] }); qc.invalidateQueries({ queryKey: ["evidence", id] }); };
  const devs = useQuery({ queryKey: ["devs"], queryFn: () => api<{ items: Dev[] }>("/devices") });
  const diag = useQuery({ queryKey: ["hwdiag"], queryFn: () => api<Diag>("/hardware/diagnostics") });
  const caps = useQuery({ queryKey: ["caps", id], queryFn: () => api<{ items: Cap[] }>(`/captures?case_id=${id}`), refetchInterval: 1500 });
  const [dev, setDev] = useState(""); const [secs, setSecs] = useState(2); const [purpose, setPurpose] = useState("bench test");
  const [own, setOwn] = useState("simulation"); const [region, setRegion] = useState(""); const [laws, setLaws] = useState(false);
  const selected = devs.data?.items.find((d) => d.id === (dev || devs.data.items.find((x) => x.present)?.id));
  const start = useMutation({ mutationFn: () => api("/captures", { method: "POST", json: { device_id: selected!.id, case_id: id, confirm: true, duration_s: secs,
    scope: { purpose, ownership: selected!.simulated ? "simulation" : own, region, acknowledged_laws: laws } } }), onSuccess: inv });
  const stop = useMutation({ mutationFn: (sid: string) => api(`/captures/${sid}/stop`, { method: "POST" }), onSuccess: inv });
  const recording = caps.data?.items.filter((c) => c.status === "recording") ?? [];
  return (
    <>
      {recording.length > 0 && <div className="banner err" role="status">● RECORDING ({recording.length}) — receive only {recording.map((c) => <button key={c.id} onClick={() => stop.mutate(c.id)} style={{ marginLeft: 8 }}>Stop {c.id.slice(0, 6)}</button>)}</div>}
      <div className="banner">Receive-only. No device is required for anything in this app; simulated devices are always labelled. Real receivers need an ownership/authorization assessment and your acknowledgement of local radio and recording laws.</div>
      <h3>Devices</h3>
      {devs.data?.items.length === 0 && <Empty title="No devices" />}
      <table><tbody>{devs.data?.items.map((d) => (
        <tr key={d.id}><td><input type="radio" name="dev" aria-label={`Select ${d.name}`} style={{ width: "auto" }} disabled={!d.present} checked={selected?.id === d.id} onChange={() => setDev(d.id)} /></td>
          <td>{d.name}</td><td><Badge v={d.simulated ? "unknown" : "healthy"} /> {d.label}</td><td>{d.kind}</td><td>{d.present ? "present" : "not connected"}</td></tr>))}</tbody></table>
      {selected && (
        <form className="card row" onSubmit={(e) => { e.preventDefault(); start.mutate(); }} aria-label="Start capture">
          <input aria-label="Purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
          <label>seconds <input type="number" min={0.2} max={300} step={0.2} value={secs} onChange={(e) => setSecs(Number(e.target.value))} style={{ width: 90 }} aria-label="Duration" /></label>
          {!selected.simulated && <>
            <select aria-label="Ownership" value={own} onChange={(e) => setOwn(e.target.value)} style={{ width: 170 }}>{["owned_signal", "authorized_lab", "public_broadcast"].map((o) => <option key={o}>{o}</option>)}</select>
            <input aria-label="Region" placeholder="Region (e.g. US)" value={region} onChange={(e) => setRegion(e.target.value)} style={{ width: 120 }} />
            <label><input type="checkbox" style={{ width: "auto" }} checked={laws} onChange={(e) => setLaws(e.target.checked)} /> I have checked local laws</label></>}
          <button className="primary" disabled={start.isPending || purpose.length < 3}>Start capture</button></form>)}
      {start.isError && <ErrorBox error={start.error} />}
      <h3>Captures in this case</h3>
      {caps.data?.items.length === 0 && <Empty title="No captures" />}
      {caps.data?.items.map((c) => <div key={c.id} className="muted"><Badge v={c.status === "completed" || c.status === "stopped" ? "healthy" : c.status === "recording" ? "medium" : "failed"} /> {fmt(c.started_at)} · {c.detail} {c.artifact_id && <code>evidence {c.artifact_id.slice(0, 8)}</code>}</div>)}
      <h3>Driver diagnostics</h3>
      {diag.data?.drivers.map((d) => <div key={d.driver_id} className="muted"><Badge v={d.status} /> {d.driver_id} — {d.detail} {!d.verified_on_physical_device && <i>(not verified on physical hardware)</i>}{d.remediation?.map((r) => <div key={r}>• {r}</div>)}</div>)}
    </>
  );
}
