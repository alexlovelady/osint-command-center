import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, ErrorBox } from "../components/ui";
import { api } from "../lib/api";

interface Check { configured: boolean; current: string; latest?: string; update_available?: boolean; signature?: string; released?: string; notes?: string;
  artifact?: { name: string; size: number | null; sha256: string } | null; no_build_for_this_platform?: boolean; note: string }
interface Dl { version: string; file: string; sha256: string; bytes: number; next: string }

/** Updates are never automatic: you point the app at your update server, check, download (hash-verified), and run the file yourself. */
export default function UpdatesCard() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api<{ update_manifest_url: string }>("/settings") });
  const [url, setUrl] = useState<string | null>(null);
  const shown = url ?? settings.data?.update_manifest_url ?? "";
  const save = useMutation({ mutationFn: () => api("/settings", { method: "PUT", json: { values: { update_manifest_url: shown.trim() } } }),
    onSuccess: () => { setUrl(null); qc.invalidateQueries({ queryKey: ["settings"] }); } });
  const check = useMutation({ mutationFn: () => api<Check>("/updates/check", { method: "POST" }) });
  const [confirm, setConfirm] = useState(false);
  const dl = useMutation({ mutationFn: () => api<Dl>("/updates/download", { method: "POST", json: { confirm: true } }) });
  const c = check.data;
  return (
    <>
      <h3>Updates</h3>
      <div className="card">
        <p className="muted">The app never updates itself. Set the address of your update server (a folder published with <code>scripts/update_tool.py</code>), check,
          and download. The manifest signature and the file&rsquo;s SHA-256 are verified; then you run the file yourself.</p>
        <div className="row">
          <input aria-label="Update server manifest URL" placeholder="http://192.168.1.10:8800/manifest.json" value={shown} onChange={(e) => setUrl(e.target.value)} style={{ flex: 1, minWidth: 280 }} />
          <button onClick={() => save.mutate()} disabled={url === null || save.isPending}>Save address</button>
          <button className="primary" onClick={() => check.mutate()} disabled={check.isPending}>Check for updates</button>
        </div>
        {(save.isError || check.isError || dl.isError) && <ErrorBox error={save.error ?? check.error ?? dl.error} />}
        {c && !c.configured && <div className="banner">{c.note}</div>}
        {c?.configured && (
          <div className="banner" role="status">
            Installed <b>{c.current}</b> · latest <b>{c.latest}</b> {c.signature === "verified" && <Badge v="healthy" />} signature verified
            {c.update_available ? <> · <b>an update is available</b>{c.released ? ` (${c.released})` : ""}</> : " · you are up to date"}
            {c.notes && <div className="muted">{c.notes}</div>}
            {c.update_available && c.artifact && (
              <div className="row" style={{ marginTop: 6 }}>
                <span className="muted">{c.artifact.name}{c.artifact.size ? ` · ${(c.artifact.size / 1e6).toFixed(1)} MB` : ""} · sha256 <code>{c.artifact.sha256.slice(0, 16)}…</code></span>
                <label><input type="checkbox" style={{ width: "auto" }} checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> download this file</label>
                <button disabled={!confirm || dl.isPending} onClick={() => dl.mutate()}>Download and verify</button>
              </div>)}
            {c.update_available && c.no_build_for_this_platform && <div className="muted">The signed manifest has no build for this platform.</div>}
          </div>)}
        {dl.data && <div className="banner" role="status">Verified and saved to <code>{dl.data.file}</code> ({(dl.data.bytes / 1e6).toFixed(1)} MB). {dl.data.next}</div>}
      </div>
    </>
  );
}
