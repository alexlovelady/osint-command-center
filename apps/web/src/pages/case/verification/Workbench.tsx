import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api, apiUrl, authHeader } from "../../../lib/api";
import type { AivCaps, AssetAuth, TemplateApproval } from "../../../lib/aivApi";
import Authorizations from "./Authorizations";
import { Observations, Plans } from "./PlansRuns";

const SUB = ["Status", "Authorizations", "Plans", "Observations", "Templates", "Reports"] as const;

function Status({ caps, refresh }: { caps: AivCaps; refresh: () => void }) {
  const toggle = useMutation({ mutationFn: (enabled: boolean) => api("/aiv/settings", { method: "PUT", json: { enabled } }), onSuccess: refresh });
  return (
    <>
      <div className={`banner${caps.enabled ? "" : " warn"}`} role="status">
        {caps.enabled ? "Active verification is ON. Every check still needs a live asset authorization and a plan you approve."
          : "Active verification is OFF. Nothing active can run. An administrator can switch it on here."}
        {" "}<button onClick={() => toggle.mutate(!caps.enabled)} disabled={toggle.isPending}>{caps.enabled ? "Switch off" : "Switch on"}</button>
        {caps.offline && <div>Offline mode is on: remote checks are blocked either way.</div>}
      </div>
      {toggle.isError && <ErrorBox error={toggle.error} />}
      <div className="card"><b>What this module is for</b><p className="muted">{caps.boundary}</p>
        <b>Never done, and no control exists for it</b><ul>{caps.forbidden.map((f) => <li key={f}>{f}</li>)}</ul></div>
      <div className="card" aria-label="Tool status"><b>Tools</b>
        <table><thead><tr><th>Tool</th><th>Status</th><th>Role</th></tr></thead><tbody>
          {caps.tools.map((t) => (<tr key={t.id}><td>{t.name}<div className="muted">{t.version ?? ""}</div></td>
            <td><Badge v={t.status === "healthy" ? "healthy" : t.status === "not_installed" ? "not_installed" : "degraded"} /> {t.status.replace(/_/g, " ")}<div className="muted">{t.detail}</div></td>
            <td className="muted">{t.role}</td></tr>))}
        </tbody></table>
        <div className="muted">Nmap, Naabu, Nuclei and dnstwist are optional and run only when installed and version-verified. Every check was exercised against local lab servers, not third-party systems.</div></div>
    </>
  );
}

function Templates({ caps }: { caps: AivCaps }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["aiv-templates"], queryFn: () => api<{ items: TemplateApproval[] }>("/aiv/templates") });
  const [content, setContent] = useState("");
  const [confirm, setConfirm] = useState(false);
  const review = useMutation({ mutationFn: () => api<{ ok: boolean; errors: string[]; semantics: TemplateApproval["semantics"]; sha256: string }>("/aiv/templates/review", { method: "POST", json: { content } }) });
  const approve = useMutation({ mutationFn: () => api("/aiv/templates", { method: "POST", json: { content, confirm_reviewed: true } }), onSuccess: () => { setContent(""); setConfirm(false); review.reset(); qc.invalidateQueries({ queryKey: ["aiv-templates"] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/aiv/templates/${id}/revoke`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["aiv-templates"] }) });
  const r = review.data;
  const nuclei = caps.tools.find((t) => t.id === "nuclei");
  return (
    <>
      <div className="banner">Signature checks run only templates you reviewed here, pinned by id and content hash. Templates may only make read-only GET or HEAD requests with word, regex, status or size matchers. {nuclei?.status !== "healthy" && "Nuclei is not usable on this machine, so approved templates cannot run yet."}</div>
      {q.data?.items.map((t) => (<div className="card" key={t.id}><div className="row"><b>{t.template_id}</b> <code>{t.sha256.slice(0, 12)}</code> {t.revoked_at ? <Badge v="failed" /> : <Badge v="healthy" />} {t.revoked_at ? "revoked" : "approved"}
        <span className="grow" />{!t.revoked_at && <button onClick={() => revoke.mutate(t.id)}>Revoke</button>}</div>
        <div className="muted">{t.semantics.name} · {t.semantics.methods?.join(", ")} · {t.semantics.request_count} request(s) · reviewed by {t.reviewed_by} {fmt(t.reviewed_at)}</div></div>))}
      {q.data && !q.data.items.length && <Empty title="No approved templates" hint="None are bundled. Paste a template to review it." />}
      <div className="card">
        <textarea aria-label="Template" rows={8} placeholder="Paste a Nuclei template (YAML)" value={content} onChange={(e) => { setContent(e.target.value); review.reset(); setConfirm(false); }} style={{ width: "100%", fontFamily: "monospace" }} />
        <div className="row"><button onClick={() => review.mutate()} disabled={content.trim().length < 10 || review.isPending}>Review (stores nothing)</button></div>
        {r && !r.ok && <div className="banner err" role="alert"><b>Rejected</b><ul>{r.errors.map((e) => <li key={e}>{e}</li>)}</ul></div>}
        {r?.ok && (<div><div className="banner">It will send {r.semantics.request_count} {r.semantics.methods?.join("/")} request(s) to: <code>{r.semantics.paths?.join(", ")}</code>. Hash <code>{r.sha256.slice(0, 16)}</code></div>
          <label><input type="checkbox" style={{ width: "auto" }} checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I read the requests above and approve this exact template</label>{" "}
          <button className="primary" disabled={!confirm || approve.isPending} onClick={() => approve.mutate()}>Approve template</button></div>)}
        {review.isError && <ErrorBox error={review.error} />}{approve.isError && <ErrorBox error={approve.error} />}
      </div>
    </>
  );
}

async function download(id: string, file: string) {
  const res = await fetch(apiUrl(`/reports/${id}/download`), { headers: authHeader() });
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url; a.download = file.replace(/\.enc$/, ""); a.click(); URL.revokeObjectURL(url);
}

function Reports({ caseId }: { caseId: string }) {
  const [fmtSel, setFmt] = useState("html");
  const [confirm, setConfirm] = useState(false);
  const report = useMutation({ mutationFn: () => api<{ id: string; file: string; sha256: string }>(`/cases/${caseId}/aiv/report`, { method: "POST", json: { format: fmtSel } }) });
  const hand = useMutation({ mutationFn: () => api<{ id: string; file: string; preview: { observations: number } }>(`/cases/${caseId}/aiv/handoff`, { method: "POST", json: { confirm_handoff: confirm, min_severity: "medium" } }) });
  return (
    <>
      <div className="card"><b>Verification report</b>
        <p className="muted">What was authorized, what you approved, what ran, what was observed, what the checks cannot show, and an audit appendix. Sealed like every other report.</p>
        <div className="row"><select aria-label="Report format" value={fmtSel} onChange={(e) => setFmt(e.target.value)} style={{ width: 140 }}>{["html", "markdown", "json"].map((f) => <option key={f}>{f}</option>)}</select>
          <button className="primary" onClick={() => report.mutate()} disabled={report.isPending}>Create report</button></div>
        {report.data && <div className="banner">Created <code>{report.data.file}</code> (sha256 {report.data.sha256.slice(0, 16)}…) <button onClick={() => void download(report.data!.id, report.data!.file)}>Download</button></div>}
        {report.isError && <ErrorBox error={report.error} />}</div>
      <div className="card"><b>Export for PHANTOM</b>
        <p className="muted">A data file with <b>confirmed</b> observations at medium severity or above, and the limits they were found under. It carries no raw responses or secrets and it launches nothing. The receiving tool needs its own written authorization.</p>
        <label><input type="checkbox" style={{ width: "auto" }} checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I approve exporting these confirmed observations (case owner only)</label>{" "}
        <button disabled={!confirm || hand.isPending} onClick={() => hand.mutate()}>Export handoff file</button>
        {hand.data && <div className="banner">Exported <code>{hand.data.file}</code> with {hand.data.preview.observations} observation(s). Nothing was launched. <button onClick={() => void download(hand.data!.id, hand.data!.file)}>Download</button></div>}
        {hand.isError && <ErrorBox error={hand.error} />}</div>
    </>
  );
}

/** The AIV workbench: authorize assets, build and approve exact plans, run, review, report. */
export default function Workbench({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const [sub, setSub] = useState<(typeof SUB)[number]>("Status");
  const caps = useQuery({ queryKey: ["aiv-caps"], queryFn: () => api<AivCaps>("/aiv/capabilities") });
  const auths = useQuery({ queryKey: ["aiv-auths", caseId], queryFn: () => api<{ items: AssetAuth[] }>(`/cases/${caseId}/asset-authorizations`) });
  if (caps.isLoading) return <Loading what="verification" />;
  if (caps.isError || !caps.data) return <ErrorBox error={caps.error} />;
  const c = caps.data;
  const off = !c.enabled && sub !== "Status";
  return (
    <section aria-label="Verification workbench">
      <div className="banner">Verification checks only assets someone has authorized, with bounded, disclosed requests. Exploitation, password testing and intrusive testing are out of scope here.</div>
      <div className="tabs" role="tablist" aria-label="Verification sections">
        {SUB.map((t) => <button key={t} role="tab" aria-selected={sub === t} onClick={() => setSub(t)}>{t}</button>)}
      </div>
      {sub === "Status" && <Status caps={c} refresh={() => qc.invalidateQueries({ queryKey: ["aiv-caps"] })} />}
      {off && <Empty title="Verification is switched off" hint="Switch it on under Status to create authorizations and plans. Existing records stay readable." />}
      {!off && sub === "Authorizations" && <Authorizations caseId={caseId} caps={c} />}
      {!off && sub === "Plans" && <Plans caseId={caseId} auths={auths.data?.items ?? []} />}
      {!off && sub === "Observations" && <Observations caseId={caseId} />}
      {!off && sub === "Templates" && <Templates caps={c} />}
      {!off && sub === "Reports" && <Reports caseId={caseId} />}
    </section>
  );
}
