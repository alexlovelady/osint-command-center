import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import type { BrandingT } from "../lib/aivApi";
import { ErrorBox } from "./ui";

/** The product name shown inside the app. Display text only: nothing that identifies the installation changes. */
export function useBranding() {
  return useQuery({ queryKey: ["branding"], queryFn: () => api<BrandingT>("/branding"), retry: false, staleTime: 60_000 });
}

export default function BrandingCard() {
  const qc = useQueryClient();
  const q = useBranding();
  const [choice, setChoice] = useState("");
  const [approve, setApprove] = useState(false);
  const preview = useMutation({ mutationFn: (preset: string) => api<{ preview: { productName: string; shortName: string; tagline: string } }>("/branding", { method: "PUT", json: { preset, preview_only: true } }) });
  const apply = useMutation({ mutationFn: (preset: string) => api("/branding", { method: "PUT", json: { preset, approve_display_change: true } }), onSuccess: () => { setApprove(false); qc.invalidateQueries({ queryKey: ["branding"] }); } });
  if (!q.data) return null;
  const b = q.data;
  const sel = choice || b.preset;
  return (
    <>
      <h3>Product name</h3>
      <div className="card" aria-label="Product name">
        <div>Shown now: <b>{b.active.productName}</b> <span className="muted">({b.active.edition})</span></div>
        <div className="row" style={{ marginTop: 6 }}>
          <select aria-label="Name" value={sel} onChange={(e) => { setChoice(e.target.value); setApprove(false); preview.reset(); }} style={{ maxWidth: 420 }}>
            {Object.entries(b.presets).map(([k, p]) => <option key={k} value={k}>{p.label}</option>)}</select>
          <button onClick={() => preview.mutate(sel)} disabled={preview.isPending}>Preview</button>
        </div>
        <div className="muted">{b.presets[sel]?.status}</div>
        {preview.data && <div className="banner" aria-label="Name preview"><b>{preview.data.preview.productName}</b><div className="muted">{preview.data.preview.tagline}</div></div>}
        <label><input type="checkbox" style={{ width: "auto" }} checked={approve} onChange={(e) => setApprove(e.target.checked)} /> I approve changing the name shown in the app</label>{" "}
        <button className="primary" disabled={!approve || sel === b.preset || apply.isPending} onClick={() => apply.mutate(sel)}>Apply</button>
        <p className="muted">{b.notice}</p>
        <details><summary className="muted">What does not change</summary><ul>{b.unchanged.map((u) => <li key={u}>{u}</li>)}</ul></details>
        {apply.isError && <ErrorBox error={apply.error} />}
      </div>
    </>
  );
}
