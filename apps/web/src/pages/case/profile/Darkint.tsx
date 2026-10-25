import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { COV_CLASS, COV_LABEL, type CheckResult, type DarkExposures, type DarkMonitor, type DarkSource, type PreviewRow } from "../../../lib/darkintApi";
import type { ProfileT } from "../../../lib/profileApi";

const STATE_CLASS: Record<string, string> = { live: "healthy", mocked: "medium", manual_only: "unknown", disabled: "failed" };

function Providers({ sources }: { sources: DarkSource[] }) {
  return (
    <div className="card" aria-label="Exposure providers">
      <b>Providers</b>
      <table><thead><tr><th>Provider</th><th>State</th><th>Terms and limits</th></tr></thead><tbody>
        {sources.map((s) => (
          <tr key={s.provider_id}><td>{s.name}<div className="muted">{s.source_type.replace(/_/g, " ")} · {s.cost_tier}</div></td>
            <td><Badge v={STATE_CLASS[s.state]} /> {s.state.replace(/_/g, " ")}<div className="muted">{s.reason}</div><div className="muted">verification: {s.verification.replace(/_/g, " ")}; last live check: {s.last_verified ?? "never"}</div></td>
            <td className="muted">{s.coverage_limitations}{s.terms_note && <div>{s.terms_note}</div>}{s.terms_url && <div><code>{s.terms_url}</code></div>}</td></tr>))}
      </tbody></table>
    </div>
  );
}

function Coverage({ d }: { d: DarkExposures }) {
  if (!d.coverage.items.length) return <Empty title="No checkable inputs" hint="Add an email, domain or organization input to this target to see what has and has not been checked." />;
  return (
    <div className="card" aria-label="Exposure coverage">
      <b>What has been checked</b>
      {d.coverage.items.map((c) => (
        <div key={c.identifier_id} style={{ marginTop: 8 }}>
          <div className="row"><code>{c.identifier}</code> <span className="muted">{c.kind}</span> <Badge v={COV_CLASS[c.state]} /> <b>{c.label}</b></div>
          <div className="muted">{c.meaning}</div>
          <ul>{c.providers.map((p) => <li key={p.provider_id}>{p.provider}: {COV_LABEL[p.state]}{p.checked_at ? ` (${fmt(p.checked_at)})` : ""}{p.last_outcome && p.state === "unknown" ? ` · last attempt: ${p.last_outcome.replace(/_/g, " ")}` : ""}</li>)}</ul>
        </div>))}
      <div className="muted">{d.coverage.notice}</div>
    </div>
  );
}

function RunCheck({ p, sources, onDone }: { p: ProfileT; sources: DarkSource[]; onDone: () => void }) {
  const idents = useQuery({ queryKey: ["darkint-idents", p.subject.id], queryFn: () => api<{ items: { id: string; kind: string; value: string }[] }>(`/subjects/${p.subject.id}/identifiers`) });
  const [ident, setIdent] = useState("");
  const [provs, setProvs] = useState<string[]>([]);
  const [attest, setAttest] = useState(false);
  const body = { subject_id: p.subject.id, identifier_ids: [ident], provider_ids: provs, domain_control_attested: attest };
  const preview = useMutation({ mutationFn: () => api<{ items: PreviewRow[]; runnable: number; note: string }>(`/cases/${p.case.id}/darkint/preview`, { method: "POST", json: body }) });
  const run = useMutation({ mutationFn: () => api<{ results: CheckResult[]; partial: boolean; all_failed: boolean; note: string }>(`/cases/${p.case.id}/darkint/check`, { method: "POST", json: { ...body, confirm: true } }), onSuccess: onDone });
  const usable = sources.filter((s) => s.automated);
  const items = idents.data?.items.filter((i) => ["email", "domain", "organization"].includes(i.kind)) ?? [];
  const reset = () => { preview.reset(); run.reset(); };
  return (
    <form className="card" aria-label="Run an exposure check" onSubmit={(e) => { e.preventDefault(); preview.mutate(); }}>
      <b>Check an input</b>
      <div className="banner">Nothing is sent until you review the preview and confirm. A failed or refused check is shown as such and is never counted as “no exposure”.</div>
      <div className="row">
        <select aria-label="Input to check" value={ident} onChange={(e) => { setIdent(e.target.value); reset(); }}><option value="">choose an input</option>
          {items.map((i) => <option key={i.id} value={i.id}>{i.kind}: {i.value.length > 3 ? i.value.slice(0, 2) + "…" + i.value.slice(-8) : i.value}</option>)}</select>
        {usable.map((s) => (
          <label key={s.provider_id}><input type="checkbox" style={{ width: "auto" }} checked={provs.includes(s.provider_id)}
            onChange={(e) => { setProvs(e.target.checked ? [...provs, s.provider_id] : provs.filter((x) => x !== s.provider_id)); reset(); }} /> {s.name} <Badge v={STATE_CLASS[s.state]} /></label>))}
        <label><input type="checkbox" style={{ width: "auto" }} checked={attest} onChange={(e) => { setAttest(e.target.checked); reset(); }} /> I verified this domain with the provider (domain-wide lookups only)</label>
        <button className="primary" disabled={!ident || !provs.length || preview.isPending}>Preview</button>
      </div>
      {preview.isError && <ErrorBox error={preview.error} />}
      {preview.data && (
        <div aria-label="Check preview">
          <table><thead><tr><th>Provider</th><th>Will be sent</th><th>Status</th></tr></thead><tbody>
            {preview.data.items.map((r) => (
              <tr key={r.provider_id}><td>{r.provider}<div className="muted">{r.cost} · {r.quota}</div></td>
                <td className="muted">{r.will_send.data} to {r.will_send.to}; credentials: {r.will_send.credentials}<div>{r.will_store}</div>{r.terms_note && <div>{r.terms_note}</div>}</td>
                <td><Badge v={r.allowed ? "healthy" : "failed"} /> {r.allowed ? "allowed" : "refused"}<div className="muted">{r.reason}</div>{r.mocked && <div className="muted">fixture mode: synthetic answers</div>}</td></tr>))}
          </tbody></table>
          <button className="primary" disabled={!preview.data.runnable || run.isPending} onClick={() => run.mutate()}>Confirm and check</button>
        </div>)}
      {run.isError && <ErrorBox error={run.error} />}
      {run.data && (
        <div className={`banner${run.data.all_failed ? " warn" : ""}`} role="status">
          {run.data.results.map((r) => <div key={r.provider_id}><b>{r.provider_id}</b>: {r.outcome.replace(/_/g, " ")} ({r.events} reported). {r.detail}</div>)}
          <div className="muted">{run.data.note}</div>
        </div>)}
    </form>
  );
}

function Incidents({ p, d, refresh }: { p: ProfileT; d: DarkExposures; refresh: () => void }) {
  const [reason, setReason] = useState("");
  const review = useMutation({ mutationFn: (v: { id: string; status: string }) => api(`/cases/${p.case.id}/darkint/exposures/${v.id}/review`, { method: "PATCH", json: { status: v.status, rationale: reason } }), onSuccess: refresh });
  const task = useMutation({ mutationFn: (v: { id: string; action_type: string }) => api(`/cases/${p.case.id}/darkint/exposures/${v.id}/remediation`, { method: "POST", json: { action_type: v.action_type } }), onSuccess: refresh });
  if (!d.groups.length) return <Empty title="No reported incidents" hint="Nothing was reported by the sources that were checked. That is not proof nothing exists." />;
  return (
    <div aria-label="Reported incidents">
      <input aria-label="Review reason" placeholder="Reason for a review decision (recorded)" value={reason} onChange={(e) => setReason(e.target.value)} />
      {d.groups.map((g) => (
        <div className="card" key={g.group + g.events[0].id}>
          <div className="row"><b>{g.categories.join(", ") || "category not stated"}</b> <span className="badge">{g.review_status}</span>{g.corroborated && <span className="badge medium">reported by {g.sources.length} sources</span>}</div>
          <div className="muted">{g.note}</div>
          {g.events.map((e) => (
            <div key={e.id} style={{ marginTop: 6 }}>
              <div>{e.title} <span className="muted">· {e.provider} · {e.claim_label} · confidence {e.confidence}</span></div>
              <div className="muted">{e.caveat}{e.provider_ref && <> Source: <code>{e.provider_ref}</code></>}{e.evidence_id && <> · evidence <code>{e.evidence_id.slice(0, 8)}</code></>}</div>
              <div className="row">
                {(["acknowledged", "relevant", "not_relevant", "corroborated", "resolved", "accepted_risk"] as const).map((s) => (
                  <button key={s} disabled={review.isPending || reason.trim().length < 3} onClick={() => review.mutate({ id: e.id, status: s })}>{s.replace(/_/g, " ")}</button>))}
              </div>
              <div className="row"><span className="muted">Create a task (nothing is sent):</span>
                {(d.suggested[e.id] ?? []).map((a) => <button key={a} onClick={() => task.mutate({ id: e.id, action_type: a })}>{a.replace(/_/g, " ")}</button>)}</div>
            </div>))}
        </div>))}
      {review.isError && <ErrorBox error={review.error} />}{task.isError && <ErrorBox error={task.error} />}
    </div>
  );
}

function Manual({ p, onDone }: { p: ProfileT; onDone: () => void }) {
  const [f, setF] = useState({ title: "", event_type: "manual_report", source_url: "", reported_at: "", categories: "" });
  const [csv, setCsv] = useState("");
  const add = useMutation({ mutationFn: () => api(`/cases/${p.case.id}/darkint/manual`, { method: "POST", json: { subject_id: p.subject.id, title: f.title, event_type: f.event_type, source_url: f.source_url,
    reported_at: f.reported_at || null, categories: f.categories.split(/[;,]/).map((x) => x.trim()).filter(Boolean) } }), onSuccess: () => { setF({ ...f, title: "" }); onDone(); } });
  const imp = useMutation({ mutationFn: (kind: "csv" | "json" | "misp") => api<{ created: number; redacted: number; note: string }>(`/cases/${p.case.id}/darkint/import`, { method: "POST", json: { subject_id: p.subject.id, kind, content: csv } }), onSuccess: onDone });
  return (
    <div className="card" aria-label="Manual intake">
      <b>Record a report by hand, or import a file</b>
      <div className="muted">For public reports, provider notices, customer incident notices and exports. Passwords, hashes, numbers and addresses are redacted before anything is stored; the uploaded file is not kept. Nothing is crawled.</div>
      <div className="row">
        <input aria-label="Report title" placeholder="Short title of the report" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} style={{ flex: 2, minWidth: 220 }} />
        <select aria-label="Report type" value={f.event_type} onChange={(e) => setF({ ...f, event_type: e.target.value })} style={{ width: 170 }}>
          {["manual_report", "breach", "paste", "darkweb_mention", "ransomware_listing", "advisory"].map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}</select>
        <input aria-label="Source link" placeholder="Source link" value={f.source_url} onChange={(e) => setF({ ...f, source_url: e.target.value })} />
        <input aria-label="Reported date" placeholder="YYYY-MM-DD" value={f.reported_at} onChange={(e) => setF({ ...f, reported_at: e.target.value })} style={{ width: 130 }} />
        <input aria-label="Data categories" placeholder="categories, e.g. email addresses; credential indicator" value={f.categories} onChange={(e) => setF({ ...f, categories: e.target.value })} />
        <button className="primary" disabled={f.title.trim().length < 3 || add.isPending} onClick={() => add.mutate()}>Record</button>
      </div>
      <textarea aria-label="Import content" rows={4} placeholder="Paste CSV (title,date,categories,reference), a JSON list, or a MISP event export" value={csv} onChange={(e) => setCsv(e.target.value)} style={{ width: "100%", fontFamily: "monospace" }} />
      <div className="row">{(["csv", "json", "misp"] as const).map((k) => <button key={k} disabled={!csv.trim() || imp.isPending} onClick={() => imp.mutate(k)}>Import {k.toUpperCase()}</button>)}</div>
      {imp.data && <div className="banner">{imp.data.created} imported, {imp.data.redacted} redacted. {imp.data.note}</div>}
      {add.isError && <ErrorBox error={add.error} />}{imp.isError && <ErrorBox error={imp.error} />}
    </div>
  );
}

function Monitors({ p, d }: { p: ProfileT; d: DarkExposures }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["darkint-monitors", p.case.id], queryFn: () => api<{ items: DarkMonitor[] }>(`/cases/${p.case.id}/darkint/monitors`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["darkint-monitors", p.case.id] });
  const [ident, setIdent] = useState("");
  const [prov, setProv] = useState("hibp");
  const create = useMutation({ mutationFn: () => api(`/cases/${p.case.id}/darkint/monitors`, { method: "POST", json: { subject_id: p.subject.id, name: "Exposure monitor", identifier_ids: [ident], provider_ids: [prov],
    cadence_hours: 168, expires_at: new Date(Date.now() + 90 * 86400000).toISOString() } }), onSuccess: refresh });
  const toggle = useMutation({ mutationFn: (v: { id: string; enabled: boolean }) => api(`/cases/${p.case.id}/darkint/monitors/${v.id}`, { method: "PATCH", json: { enabled: v.enabled } }), onSuccess: refresh });
  return (
    <div className="card" aria-label="Exposure monitors">
      <b>Monitors</b>
      <div className="muted">A monitor is the bounded scope a scheduled automation may use: named inputs, named providers, a cadence and an expiry that never outlives the authorization. Revoking the authorization switches it off.</div>
      {q.data?.items.map((m) => (
        <div className="row" key={m.id}><b>{m.name}</b> <span className="muted">{m.providers.join(", ")} · every {m.cadence_hours} h · until {fmt(m.expires_at)}</span> <code>{m.id}</code>
          <Badge v={m.enabled ? "healthy" : "unknown"} /> {m.enabled ? "on" : `off${m.disabled_reason ? ` (${m.disabled_reason})` : ""}`}
          <button onClick={() => toggle.mutate({ id: m.id, enabled: !m.enabled })}>{m.enabled ? "Turn off" : "Turn on"}</button></div>))}
      <div className="row">
        <select aria-label="Monitor input" value={ident} onChange={(e) => setIdent(e.target.value)}><option value="">choose an input</option>{d.coverage.items.map((c) => <option key={c.identifier_id} value={c.identifier_id}>{c.kind}: {c.identifier}</option>)}</select>
        <select aria-label="Monitor provider" value={prov} onChange={(e) => setProv(e.target.value)}><option value="hibp">Have I Been Pwned</option><option value="ransomware_live">Ransomware.live</option></select>
        <button disabled={!ident || create.isPending} onClick={() => create.mutate()}>Create monitor (off)</button>
      </div>
      {(create.isError || toggle.isError) && <ErrorBox error={create.error ?? toggle.error} />}
    </div>
  );
}

function Report({ p }: { p: ProfileT }) {
  const prev = useMutation({ mutationFn: () => api<{ markdown: string }>(`/cases/${p.case.id}/darkint/reports/preview`, { method: "POST", json: { subject_id: p.subject.id } }) });
  return (
    <div className="card" aria-label="Exposure report">
      <div className="row"><b>Exposure assessment</b><button onClick={() => prev.mutate()} disabled={prev.isPending}>Preview report (exports nothing)</button></div>
      {prev.isError && <ErrorBox error={prev.error} />}
      {prev.data && <pre style={{ whiteSpace: "pre-wrap" }}>{prev.data.markdown}</pre>}
    </div>
  );
}

/** DARKINT / Exposure: which providers exist and in what state, what has and has not been checked, what was reported, and what to do about it. */
export default function Darkint({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const src = useQuery({ queryKey: ["darkint-sources"], queryFn: () => api<{ items: DarkSource[]; notice: string }>("/darkint/sources") });
  const ex = useQuery({ queryKey: ["darkint-exposures", p.subject.id], enabled: p.role !== "viewer", queryFn: () => api<DarkExposures>(`/cases/${p.case.id}/darkint/exposures?subject_id=${p.subject.id}`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["darkint-exposures", p.subject.id] }); qc.invalidateQueries({ queryKey: ["profile", p.subject.id] }); };
  if (p.role === "viewer") return <div className="banner">Exposure details are hidden for your role.</div>;
  if (src.isLoading || ex.isLoading) return <Loading what="exposure data" />;
  if (src.isError || ex.isError || !src.data || !ex.data) return <ErrorBox error={src.error ?? ex.error} />;
  return (
    <>
      <div className="banner">{src.data.notice}</div>
      <Coverage d={ex.data} />
      <RunCheck p={p} sources={src.data.items} onDone={refresh} />
      <Incidents p={p} d={ex.data} refresh={refresh} />
      <Manual p={p} onDone={refresh} />
      <Monitors p={p} d={ex.data} />
      <Providers sources={src.data.items} />
      <Report p={p} />
    </>
  );
}
