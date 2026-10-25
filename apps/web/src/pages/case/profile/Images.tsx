import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ErrorBox, Empty, fmt } from "../../../components/ui";
import { api, apiUrl, authHeader } from "../../../lib/api";
import type { ProfileT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

interface Asset { id: string; created_at: string; evidence_id: string; sha256: string; format: string; width: number; height: number; ownership: string; source_url: string | null; has_gps: boolean;
  gps: { lat: number; lon: number; precision: string } | null; exif: Record<string, string>; notes: string[]; unreviewed_matches?: number; limits: string; metadata_caveat: string }
interface Match { id: string; type: string; provider: string | null; matched_url: string | null; score: number | null; distance: number | null; state: string; reviewer: string | null; note: string;
  observed_at: string; confidence_note: string; other_asset_id: string | null }
interface Guide { public_url_known: boolean; authorization: { allowed: boolean; reason: string }; steps: string[]; limits: string;
  providers: { id: string; name: string; home: string; link: string | null; how: string; automation: string }[] }

/** Thumbnails are server re-encoded, pixel-only PNGs fetched with the session token (an <img src> cannot send the Authorization header). */
function Thumb({ sid, id }: { sid: string; id: string }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let url: string | null = null;
    let live = true;
    fetch(apiUrl(`/subjects/${sid}/images/${id}/thumbnail`), { headers: authHeader() }).then((r) => (r.ok ? r.blob() : null)).then((b) => {
      if (b && live) { url = URL.createObjectURL(b); setSrc(url); }
    }).catch(() => undefined);
    return () => { live = false; if (url) URL.revokeObjectURL(url); };
  }, [sid, id]);
  return src ? <img src={src} alt="Sanitized preview of the imported image" style={{ maxWidth: 220, maxHeight: 160, border: "1px solid var(--c-border)" }} /> : <span className="muted">no preview</span>;
}

function Matches({ sid, a, canEdit }: { sid: string; a: Asset; canEdit: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["img-matches", sid, a.id], queryFn: () => api<{ items: Match[]; limits: string }>(`/subjects/${sid}/images/${a.id}/matches`) });
  const [note, setNote] = useState<Record<string, string>>({});
  const inv = () => { qc.invalidateQueries({ queryKey: ["img-matches", sid, a.id] }); qc.invalidateQueries({ queryKey: ["images", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const review = useMutation({ mutationFn: (v: { id: string; state: string }) => api(`/subjects/${sid}/images/${a.id}/review`, { method: "POST", json: { match_id: v.id, state: v.state, note: note[v.id] ?? "" } }), onSuccess: inv });
  const [th, setTh] = useState({ phash_max: 6, dhash_max: 10, crop_max: 8 });
  const rematch = useMutation({ mutationFn: () => api<{ new_matches: number }>(`/subjects/${sid}/images/${a.id}/rematch`, { method: "POST", json: th }), onSuccess: inv });
  return (
    <div>
      <p className="muted">{q.data?.limits}</p>
      {q.data?.items.length === 0 && <span className="muted">No matches among the images held in this case. That does not mean the image appears nowhere else.</span>}
      {(q.data?.items ?? []).map((m) => (
        <div key={m.id} className="row" style={{ marginTop: 4 }}>
          <StateBadge state={m.state === "confirmed_same_image" ? "confirmed" : m.state} label={m.state.replace(/_/g, " ")} /> <b>{m.type.replace(/_/g, " ")}</b>
          {m.matched_url && <a href={m.matched_url} target="_blank" rel="noopener noreferrer">{m.matched_url}</a>}
          {m.score != null && <span className="muted">similarity {Math.round(m.score * 100)}% (distance {m.distance})</span>}
          <span className="muted">{m.confidence_note}</span>
          {canEdit && (
            <>
              <input aria-label={`Reason for ${m.id.slice(0, 6)}`} placeholder="Reason (required)" value={note[m.id] ?? ""} onChange={(e) => setNote({ ...note, [m.id]: e.target.value })} style={{ maxWidth: 220 }} />
              <button disabled={!(note[m.id] ?? "").trim()} onClick={() => review.mutate({ id: m.id, state: "confirmed_same_image" })}>Same image</button>
              <button disabled={!(note[m.id] ?? "").trim()} onClick={() => review.mutate({ id: m.id, state: "rejected" })}>False positive</button>
              <button disabled={!(note[m.id] ?? "").trim()} onClick={() => review.mutate({ id: m.id, state: "unsure" })}>Unsure</button>
            </>)}
        </div>))}
      {review.isError && <ErrorBox error={review.error} />}
      {canEdit && (
        <div className="row" style={{ marginTop: 6 }}>
          <label>pHash ≤ <input aria-label="pHash threshold" type="number" min={0} max={20} value={th.phash_max} onChange={(e) => setTh({ ...th, phash_max: Number(e.target.value) })} style={{ width: 70 }} /></label>
          <label>dHash ≤ <input aria-label="dHash threshold" type="number" min={0} max={24} value={th.dhash_max} onChange={(e) => setTh({ ...th, dhash_max: Number(e.target.value) })} style={{ width: 70 }} /></label>
          <label>crop ≤ <input aria-label="Crop threshold" type="number" min={0} max={16} value={th.crop_max} onChange={(e) => setTh({ ...th, crop_max: Number(e.target.value) })} style={{ width: 70 }} /></label>
          <button onClick={() => rematch.mutate()}>Re-run local matching</button>
          {rematch.isSuccess && <span className="muted">{rematch.data.new_matches} new candidate(s)</span>}
        </div>)}
    </div>
  );
}

function ReverseSearch({ sid, a }: { sid: string; a: Asset }) {
  const qc = useQueryClient();
  const g = useQuery({ queryKey: ["img-reverse", sid, a.id], queryFn: () => api<Guide>(`/subjects/${sid}/images/${a.id}/reverse-search`) });
  const [f, setF] = useState({ provider: "tineye", matched_url: "", note: "" });
  const add = useMutation({
    mutationFn: () => api(`/subjects/${sid}/images/${a.id}/matches`, { method: "POST", json: f }),
    onSuccess: () => { setF({ ...f, matched_url: "", note: "" }); qc.invalidateQueries({ queryKey: ["img-matches", sid, a.id] }); },
  });
  if (!g.data) return null;
  return (
    <details>
      <summary>Manual reverse-image search (never automated)</summary>
      <AuthLine g={g.data} />
      <ol>{g.data.steps.map((s) => <li key={s}>{s}</li>)}</ol>
      <ul>{g.data.providers.map((p) => (
        <li key={p.id}><b>{p.name}</b>: {p.link ? <a href={p.link} target="_blank" rel="noopener noreferrer">open search for the public image address</a> : <a href={p.home} target="_blank" rel="noopener noreferrer">open {p.name}</a>}
          <div className="muted">{p.how} {p.automation}.</div></li>))}</ul>
      <p className="muted">{g.data.limits}</p>
      {g.data.authorization.allowed && (
        <form className="row" aria-label="Record a result you found" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
          <select aria-label="Provider" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })} style={{ width: 170 }}>
            <option value="google_lens">Google Lens</option><option value="bing_visual">Bing Visual Search</option><option value="tineye">TinEye</option><option value="other">Other</option></select>
          <input aria-label="Result page address" placeholder="https:// address of a page that shows the image" value={f.matched_url} onChange={(e) => setF({ ...f, matched_url: e.target.value })} style={{ flex: 1, minWidth: 260 }} />
          <input aria-label="Note" placeholder="Note (date searched, what you saw)" value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} />
          <button className="primary" disabled={!f.matched_url.trim() || add.isPending}>Record result</button>
          {add.isError && <ErrorBox error={add.error} />}
        </form>)}
    </details>
  );
}
const AuthLine = ({ g }: { g: Guide }) => (g.authorization.allowed ? null : <div className="banner warn">Reverse-image search needs a current authorization with email confirmation, provider verification, a signed document or in-person verification: {g.authorization.reason}.</div>);

export default function Images({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const canEdit = p.role !== "viewer";
  const list = useQuery({ queryKey: ["images", sid], queryFn: () => api<{ items: Asset[]; limits: string }>(`/subjects/${sid}/images`) });
  const [file, setFile] = useState<File | null>(null);
  const [own, setOwn] = useState("user_owned");
  const [url, setUrl] = useState("");
  const [rights, setRights] = useState(false);
  const up = useMutation({
    mutationFn: () => api(`/subjects/${sid}/images?filename=${encodeURIComponent(file!.name)}&ownership=${own}&confirm_rights=true${url ? `&source_url=${encodeURIComponent(url)}` : ""}`, { method: "POST", body: file }),
    onSuccess: () => { setFile(null); setRights(false); qc.invalidateQueries({ queryKey: ["images", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); },
  });
  return (
    <>
      <div className="banner">Images are decoded locally and stored unchanged as evidence; previews are re-encoded pixel-only copies. Matching runs only against images already in this case.
        This workbench does not recognise or identify people, and reverse-image providers are used by hand, never automatically.</div>
      {canEdit && (
        <form className="card row" aria-label="Import an image" onSubmit={(e) => { e.preventDefault(); up.mutate(); }}>
          <input aria-label="Image file" type="file" accept="image/jpeg,image/png,image/gif,image/webp,image/bmp,image/tiff" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <select aria-label="Image ownership" value={own} onChange={(e) => setOwn(e.target.value)} style={{ width: 200 }}>
            <option value="user_owned">I own it</option><option value="public">Public image</option><option value="authorized">Provided with documented authorization</option></select>
          <input aria-label="Public address of the image" placeholder="Public address (optional; used only for reverse-search links)" value={url} onChange={(e) => setUrl(e.target.value)} style={{ flex: 1, minWidth: 240 }} />
          <label><input type="checkbox" style={{ width: "auto" }} checked={rights} onChange={(e) => setRights(e.target.checked)} /> I have the right to analyse this image</label>
          <button className="primary" disabled={!file || !rights || up.isPending}>Import</button>
          {up.isError && <ErrorBox error={up.error} />}
        </form>)}
      {list.data?.items.length === 0 && <Empty title="No images yet" hint="Import an image you own or are authorised to use." />}
      {(list.data?.items ?? []).map((a) => (
        <article key={a.id} className="card" aria-label={`Image ${a.sha256.slice(0, 8)}`} style={{ marginTop: 8 }}>
          <div className="row" style={{ alignItems: "flex-start" }}>
            <Thumb sid={sid} id={a.id} />
            <div>
              <div><b>{a.format}</b> {a.width}×{a.height} · sha256 <code>{a.sha256.slice(0, 16)}…</code> · {a.ownership.replace(/_/g, " ")}</div>
              {Object.entries(a.exif).map(([k, v]) => <div key={k} className="muted">{k}: {v}</div>)}
              {a.gps && <div><StateBadge state={a.gps.precision.startsWith("exact") ? "unavailable" : "partial"} label={`GPS ${a.gps.precision}`} /> {a.gps.lat}, {a.gps.lon} <span className="muted">(reports and exports always use the coarse form)</span></div>}
              {a.notes.map((n) => <div key={n} className="muted">⚠ {n}</div>)}
              <div className="muted">{a.metadata_caveat}</div>
            </div>
          </div>
          <Matches sid={sid} a={a} canEdit={canEdit} />
          {canEdit && <ReverseSearch sid={sid} a={a} />}
          <div className="muted">Imported {fmt(a.created_at)}</div>
        </article>))}
    </>
  );
}
