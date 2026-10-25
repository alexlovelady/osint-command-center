import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, fmt } from "../../../components/ui";
import { api, apiUrl, authHeader } from "../../../lib/api";
import type { ProfileT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

interface Check { ok: boolean; problems: string[]; warnings: string[]; statements_checked: number; evidence_checked: number }
interface Preview { markdown: string; citation_check: Check; exported: boolean; report: { header: { status: string }; manifest_sha256: string } }
interface Row { id: string; audience: string; file: string; sha256: string; generated_at: string; status: string }

/** Draft, check, then export. The citation check re-reads every cited evidence object and compares it with its stored hash. */
export default function Reports({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const [audience, setAudience] = useState<"subject" | "analyst">("subject");
  const [format, setFormat] = useState<"markdown" | "html" | "json">("markdown");
  const list = useQuery({ queryKey: ["subject-reports", sid], enabled: p.role !== "viewer", queryFn: () => api<{ items: Row[] }>(`/subjects/${sid}/reports`) });
  const preview = useMutation({ mutationFn: () => api<Preview>(`/subjects/${sid}/report/preview`, { method: "POST", json: { audience } }) });
  const create = useMutation({
    mutationFn: () => api<{ id: string; file: string; sha256: string }>(`/subjects/${sid}/report/create`, { method: "POST", json: { audience, format } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["subject-reports", sid] }); },
  });
  async function download(r: Row) {
    const res = await fetch(apiUrl(`/reports/${r.id}/download`), { headers: authHeader() });
    if (!res.ok) return;
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url; a.download = r.file.replace(/\.enc$/, ""); a.click();
    URL.revokeObjectURL(url);
  }
  if (p.role === "viewer") return <div className="banner">Reports are prepared by editors and owners. Ask for the exported subject report if you need to see one.</div>;
  const chk = preview.data?.citation_check;
  return (
    <>
      <div className="banner">The <b>subject report</b> is redacted: verified information only, no leads, no exposure details, no identifiers or coordinates. The <b>analyst package</b> is private and includes leads, conflicts and decision history.
        Nothing is exported until you create it, and it cannot be created while a verified statement fails the citation check.</div>
      <div className="row">
        <select aria-label="Audience" value={audience} onChange={(e) => { setAudience(e.target.value as typeof audience); preview.reset(); }} style={{ width: 200 }}>
          <option value="subject">Subject report (redacted)</option><option value="analyst">Analyst evidence package</option></select>
        <select aria-label="Format" value={format} onChange={(e) => setFormat(e.target.value as typeof format)} style={{ width: 120 }}><option>markdown</option><option>html</option><option>json</option></select>
        <button className="primary" onClick={() => preview.mutate()} disabled={preview.isPending}>Preview draft</button>
        <button onClick={() => create.mutate()} disabled={!preview.data || !chk?.ok || create.isPending}>Create and seal the report</button>
      </div>
      {preview.isError && <ErrorBox error={preview.error} />}
      {preview.data && (
        <section className="card" aria-label="Report preview" style={{ marginTop: 10 }}>
          <div className="row"><b>Draft</b> <StateBadge state={chk?.ok ? "completed" : "failed"} label={chk?.ok ? "citation check passed" : "citation check failed"} />
            <span className="muted">{chk?.statements_checked} verified statement(s), {chk?.evidence_checked} evidence item(s) re-checked against their hashes</span></div>
          {chk?.problems.map((x) => <div key={x} className="banner err">{x}</div>)}
          {chk?.warnings.map((x) => <div key={x} className="banner warn">{x}</div>)}
          <pre style={{ whiteSpace: "pre-wrap", maxHeight: 420, overflow: "auto" }}>{preview.data.markdown}</pre>
        </section>)}
      {create.isError && <ErrorBox error={create.error} />}
      {create.data && <div role="status" className="banner">Report created and sealed. sha256 <code>{create.data.sha256.slice(0, 16)}…</code></div>}
      <h3>Exported reports</h3>
      <table aria-label="Exported reports"><thead><tr><th>When</th><th>Audience</th><th>File</th><th /></tr></thead>
        <tbody>{(list.data?.items ?? []).map((r) => <tr key={r.id}><td>{fmt(r.generated_at)}</td><td>{r.audience}</td><td><code>{r.file}</code></td><td><button onClick={() => void download(r)}>Download</button></td></tr>)}</tbody></table>
    </>
  );
}
