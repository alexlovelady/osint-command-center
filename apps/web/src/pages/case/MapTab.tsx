import { useQuery } from "@tanstack/react-query";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { useEffect, useRef, useState } from "react";
import { Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api } from "../../lib/api";

interface Pt { observation_id: string; evidence_id: string; lat: number; lon: number; accuracy_m: number | null; accuracy_note: string; observed_at: string | null; source: string; sensitivity: string }

/** Basemap tiles are an opt-in (they contact tile.openstreetmap.org); points show without any network. */
export default function MapTab({ id }: { id: string }) {
  const pts = useQuery({ queryKey: ["geo", id], queryFn: () => api<{ items: Pt[]; attribution: string; warning: string }>(`/cases/${id}/geo/points`) });
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api<{ offline: boolean }>("/settings") });
  const [tiles, setTiles] = useState(false);
  const [sel, setSel] = useState<Pt | null>(null);
  const el = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!el.current || !pts.data || pts.data.items.length === 0) return;
    const map = L.map(el.current, { zoomControl: true, attributionControl: true }).setView([pts.data.items[0].lat, pts.data.items[0].lon], 5);
    if (tiles && !settings.data?.offline) L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "© OpenStreetMap contributors" }).addTo(map);
    const group = L.featureGroup();
    for (const p of pts.data.items) {
      // Dashed ring = accuracy radius when the file states one; no ring means the accuracy is UNKNOWN, never "exact".
      if (p.accuracy_m) L.circle([p.lat, p.lon], { radius: p.accuracy_m, dashArray: "4", color: "#f0b429", weight: 1, fillOpacity: 0.05 }).addTo(group);
      L.circleMarker([p.lat, p.lon], { radius: 7, color: "#2ec4b6", fillColor: "#2ec4b6", fillOpacity: 0.8 }).on("click", () => setSel(p)).addTo(group);
    }
    group.addTo(map);
    map.fitBounds(group.getBounds().pad(0.4), { maxZoom: 12 });
    return () => { map.remove(); };
  }, [pts.data, tiles, settings.data?.offline]);
  if (pts.isLoading) return <Loading what="map points" />;
  if (pts.isError) return <ErrorBox error={pts.error} />;
  if (!pts.data?.items.length) return <Empty title="No geotagged evidence" hint="Import a photo with GPS EXIF (Imports tab). IP-based locations are never plotted as street-level." />;
  return (
    <>
      <div className="banner warn">{pts.data.warning}</div>
      <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={tiles} disabled={settings.data?.offline} onChange={(e) => setTiles(e.target.checked)} />
        Load the OpenStreetMap basemap (contacts tile.openstreetmap.org; off in offline mode)</label>
      <div ref={el} className="graph" role="application" aria-label="Map of geotagged evidence" />
      <div className="muted">{tiles ? "Basemap © OpenStreetMap contributors (ODbL)" : "No basemap loaded: points only"}</div>
      {sel && <div className="card" style={{ marginTop: 8 }}><b>{sel.lat.toFixed(5)}, {sel.lon.toFixed(5)}</b> · {sel.source}
        <div>Accuracy: {sel.accuracy_m ? `±${sel.accuracy_m} m (stated by the file)` : <b>unknown</b>} — {sel.accuracy_note}</div>
        <div className="muted">time {fmt(sel.observed_at)} · sensitivity {sel.sensitivity} · evidence <code>{sel.evidence_id.slice(0, 8)}</code></div></div>}
    </>
  );
}
