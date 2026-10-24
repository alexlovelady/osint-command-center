import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api } from "../../lib/api";

const WINDOWS = [5, 30, 60, 300, 900, 3600, 86400];
const label = (s: number) => (s < 60 ? `${s} s` : s < 3600 ? `${s / 60} min` : `${s / 3600} h`);

interface Side { id: string; discipline: string; kind: string; observed_at: string | null; evidence_id: string; access_class: string; quality_hint: string }
interface Link { key: string; type: "temporal" | "spatial" | "both"; a: Side; b: Side; delta_s: number | null; distance_m: number | null;
  warnings: string[]; status: string; correlation_id: string | null }
interface Row { source: string; id: string; time: string | null; time_basis: string; discipline: string; label: string; evidence_id: string | null; located: boolean }

/** Cross-discipline coincidences and the unified timeline. A suggestion is never a relationship until you accept it. */
export default function CrossLinksTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const [wi, setWi] = useState(3);
  const [radius, setRadius] = useState(1000);
  const [restricted, setRestricted] = useState(false);
  const [disc, setDisc] = useState("");
  const win = WINDOWS[wi];
  const links = useQuery({ queryKey: ["xlinks", id, win, radius, restricted], placeholderData: keepPreviousData,
    queryFn: () => api<{ items: Link[]; total: number; caveat: string; truncated: boolean }>(`/cases/${id}/cross-links?window_s=${win}&radius_m=${radius}&include_restricted=${restricted}`) });
  const tl = useQuery({ queryKey: ["utl", id, disc, restricted],
    queryFn: () => api<{ items: Row[]; note: string }>(`/cases/${id}/timeline/unified?include_restricted=${restricted}${disc ? `&discipline=${disc}` : ""}`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["xlinks", id] });
  const decide = useMutation({ mutationFn: (v: { l: Link; decision: "accept" | "reject" }) =>
    api(`/cases/${id}/cross-links/decision`, { method: "POST", json: { obs_a: v.l.a.id, obs_b: v.l.b.id, kind: v.l.type, decision: v.decision } }), onSuccess: refresh });
  const revoke = useMutation({ mutationFn: (cid: string) => api(`/correlations/${cid}/revoke`, { method: "POST" }), onSuccess: refresh });
  return (
    <>
      <div className="banner">{links.data?.caveat ?? "Coincidence in time or place is not a relationship."} Nothing here is linked until you accept it, and you can revoke it later.</div>
      <div className="card row">
        <label>Time window: <b>{label(win)}</b>
          <input type="range" aria-label="Time window" min={0} max={WINDOWS.length - 1} step={1} value={wi} onChange={(e) => setWi(Number(e.target.value))} style={{ width: 200 }} /></label>
        <label>Distance: <b>{radius >= 1000 ? `${radius / 1000} km` : `${radius} m`}</b>
          <input type="range" aria-label="Distance" min={100} max={50000} step={100} value={radius} onChange={(e) => setRadius(Number(e.target.value))} style={{ width: 200 }} /></label>
        <label><input type="checkbox" style={{ width: "auto" }} checked={restricted} onChange={(e) => setRestricted(e.target.checked)} /> include RESTRICTED observations (positions, private captures)</label>
      </div>
      {links.isLoading && <Loading what="cross-links" />}
      {links.isError && <ErrorBox error={links.error} />}
      {decide.isError && <ErrorBox error={decide.error} />}
      {links.data?.items.length === 0 && <Empty title="No coincidences in this window" hint="Only observations from different disciplines are compared. Restricted items are excluded unless you include them." />}
      {links.data?.truncated && <div className="banner warn">Large case: only part of it was compared. Narrow the window or discipline.</div>}
      {!!links.data?.items.length && (
        <table>
          <thead><tr><th>Observation A</th><th>Observation B</th><th>Coincidence</th><th>Status</th><th /></tr></thead>
          <tbody>{links.data.items.map((l) => (
            <tr key={l.key}>
              {[l.a, l.b].map((s) => <td key={s.id}><Badge v={s.discipline} /> {s.kind}<div className="muted">{fmt(s.observed_at)} · {s.access_class}</div><div className="muted">quality: {s.quality_hint}</div></td>)}
              <td>{l.type}{l.delta_s !== null && <div className="muted">Δt {Math.round(l.delta_s)} s</div>}{l.distance_m !== null && <div className="muted">≈ {Math.round(l.distance_m)} m apart</div>}
                {l.warnings.map((w) => <div key={w} className="muted">⚠ {w}</div>)}</td>
              <td><Badge v={l.status === "suggested" ? "unknown" : l.status === "accepted" ? "medium" : "low"} /> {l.status}</td>
              <td className="row">
                {l.status === "suggested" && <><button onClick={() => decide.mutate({ l, decision: "accept" })}>Accept</button>
                  <button onClick={() => decide.mutate({ l, decision: "reject" })}>Reject</button></>}
                {l.status === "accepted" && l.correlation_id && <button onClick={() => revoke.mutate(l.correlation_id!)}>Revoke</button>}
              </td>
            </tr>))}</tbody>
        </table>
      )}
      <h3>Unified timeline</h3>
      <div className="row">
        <select aria-label="Discipline" value={disc} onChange={(e) => setDisc(e.target.value)} style={{ width: 160 }}>
          <option value="">all disciplines</option>{["OSINT", "COMINT", "SIGINT", "ELINT", "FISINT", "HUMINT", "GEOINT", "MASINT", "CYBINT", "FININT", "TECHINT"].map((d) => <option key={d}>{d}</option>)}
        </select>
        <span className="muted">{tl.data?.note}</span>
      </div>
      {tl.isLoading && <Loading what="timeline" />}
      {tl.data?.items.length === 0 && <Empty title="Nothing on the timeline" />}
      {!!tl.data?.items.length && (
        <table>
          <thead><tr><th>Time (UTC)</th><th>Which time</th><th>Discipline</th><th>Item</th></tr></thead>
          <tbody>{tl.data.items.map((r) => (
            <tr key={r.source + r.id}><td>{fmt(r.time)}</td><td className="muted">{r.time_basis}</td><td><Badge v={r.discipline} /></td>
              <td>{r.label} <span className="muted">({r.source}{r.located ? ", located" : ""})</span></td></tr>))}</tbody>
        </table>
      )}
    </>
  );
}
