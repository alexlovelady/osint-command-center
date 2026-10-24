import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { useEffect, useRef, useState } from "react";
import SearchComposer from "../components/SearchComposer";
import AiTab from "./case/AiTab";
import AnalysisTab from "./case/AnalysisTab";
import CrossLinksTab from "./case/CrossLinksTab";
import PlansTab from "./case/PlansTab";
import HardwareTab from "./case/HardwareTab";
import HumintTab from "./case/HumintTab";
import MapTab from "./case/MapTab";
import WorkflowsTab from "./case/WorkflowsTab";
import { Badge, Empty, ErrorBox, Loading, fmt, val } from "../components/ui";
import { api, apiUrl, authHeader, type CaseT, type FindingT, type GraphT } from "../lib/api";
import { setAppCtx } from "../lib/appContext";

const TABS = ["Search", "Plans", "Findings", "Graph", "Timeline", "Map", "Evidence", "Imports", "Analysis", "Cross-links", "Workflows", "Humint", "AI", "Hardware", "Notes", "Reports"] as const;
type Tab = (typeof TABS)[number];

export default function CaseView({ id }: { id: string }) {
  const [tab, setTab] = useState<Tab>("Search");
  useEffect(() => { setAppCtx({ route: "case", case_id: id, tab }); }, [id, tab]);
  useEffect(() => {  // the Copilot / tutorials switch tabs with an event; unknown names are ignored
    const on = (e: Event) => { const t = (e as CustomEvent<string>).detail; if ((TABS as readonly string[]).includes(t)) setTab(t as Tab); };
    window.addEventListener("osintcc:tab", on);
    return () => window.removeEventListener("osintcc:tab", on);
  }, []);
  const c = useQuery({ queryKey: ["case", id], queryFn: () => api<CaseT>(`/cases/${id}`) });
  if (c.isLoading) return <Loading what="case" />;
  if (c.isError) return <ErrorBox error={c.error} />;
  const cs = c.data!;
  return (
    <>
      <div className="muted"><a href="#/cases">Cases</a> / {cs.title}</div>
      <h2 style={{ margin: "4px 0" }}>{cs.title} <Badge v={cs.status} /></h2>
      <div className="banner">
        <b>Scope &amp; purpose:</b> {cs.purpose || <span className="muted">not stated — add one before sharing results</span>} · category <b>{cs.category}</b> ·
        passive sources only unless a scope authorization exists.
      </div>
      <div className="tabs" role="tablist">
        {TABS.map((t) => <button key={t} role="tab" data-tour={`tab-${t}`} aria-selected={tab === t} onClick={() => setTab(t)}>{t}</button>)}
      </div>
      {tab === "Search" && <SearchComposer caseId={id} />}
      {tab === "Plans" && <PlansTab id={id} />}
      {tab === "Cross-links" && <CrossLinksTab id={id} />}
      {tab === "Findings" && <Findings id={id} />}
      {tab === "Graph" && <Graph id={id} />}
      {tab === "Timeline" && <Timeline id={id} />}
      {tab === "Evidence" && <EvidenceTab id={id} />}
      {tab === "Imports" && <Imports id={id} />}
      {tab === "Map" && <MapTab id={id} />}
      {tab === "Analysis" && <AnalysisTab id={id} />}
      {tab === "Workflows" && <WorkflowsTab id={id} />}
      {tab === "Humint" && <HumintTab id={id} />}
      {tab === "AI" && <AiTab id={id} />}
      {tab === "Hardware" && <HardwareTab id={id} />}
      {tab === "Notes" && <Notes id={id} />}
      {tab === "Reports" && <Reports id={id} />}
    </>
  );
}

function Findings({ id }: { id: string }) {
  const [filter, setFilter] = useState("");
  const [conf, setConf] = useState("");
  const qc = useQueryClient();
  const promote = useMutation({ mutationFn: (fid: string) => api("/claims/from-finding", { method: "POST", json: { finding_id: fid } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["claims", id] }) });
  const q = useQuery({ queryKey: ["findings", id, filter, conf], queryFn: () => api<{ total: number; items: FindingT[] }>(
    `/cases/${id}/findings?limit=500${filter ? `&q=${encodeURIComponent(filter)}` : ""}${conf ? `&confidence=${conf}` : ""}`) });
  return (
    <>
      <div className="row">
        <input aria-label="Filter findings" placeholder="Filter by subject, predicate or value" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 360 }} />
        <select aria-label="Confidence" value={conf} onChange={(e) => setConf(e.target.value)} style={{ width: 140 }}>
          <option value="">any confidence</option>{["high", "medium", "low", "unknown"].map((x) => <option key={x}>{x}</option>)}
        </select>
        <span className="muted">{q.data?.total ?? 0} findings</span>
      </div>
      {promote.isSuccess && <div className="banner">Promoted. Review it in the Analysis tab, where only you can mark it verified.</div>}
      {promote.isError && <ErrorBox error={promote.error} />}
      {q.isLoading && <Loading what="findings" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data?.items.length === 0 && <Empty title="No findings" hint="Run a search from the Search tab. Absence of findings is not evidence of absence." />}
      {!!q.data?.items.length && (
        <table>
          <thead><tr><th>Subject</th><th>Predicate</th><th>Value</th><th>Confidence</th><th>Observed (UTC)</th><th>Source</th><th /></tr></thead>
          <tbody>
            {q.data.items.map((f) => (
              <tr key={f.id}>
                <td>{f.subject}</td><td>{f.predicate}</td><td><code>{val(f.value)}</code></td>
                <td><Badge v={f.confidence} /><div className="muted">{f.confidence_reason}</div></td>
                <td>{fmt(f.observed_at)}</td>
                <td>{f.source_url?.startsWith("http") ? <a href={f.source_url} target="_blank" rel="noreferrer noopener">{f.adapter}</a> : f.adapter}
                  <div className="muted">evidence <code>{f.evidence_id.slice(0, 8)}</code></div></td>
                <td><button title="Make this a claim you can verify, dispute or cite" disabled={promote.isPending} onClick={() => promote.mutate(f.id)}>Promote to claim</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function Graph({ id }: { id: string }) {
  const qc = useQueryClient();
  const [merged, setMerged] = useState(false);
  const q = useQuery({ queryKey: ["graph", id, merged], queryFn: () => api<GraphT>(`/cases/${id}/graph?apply_merges=${merged}`) });
  const ents = useQuery({ queryKey: ["ents", id], queryFn: () => api<{ items: { id: string; type: string; display: string }[] }>(`/cases/${id}/entities?limit=1000`) });
  const links = useQuery({ queryKey: ["links", id], queryFn: () => api<{ items: { id: string; entity_id: string; canonical_entity_id: string; status: string; reason: string }[] }>(`/cases/${id}/entity-links`) });
  const [a, setA] = useState(""); const [b, setB] = useState(""); const [why, setWhy] = useState("");
  const refresh = () => { qc.invalidateQueries({ queryKey: ["graph", id] }); qc.invalidateQueries({ queryKey: ["links", id] }); };
  const link = useMutation({ mutationFn: () => api(`/cases/${id}/entity-links`, { method: "POST", json: { entity_id: a, canonical_entity_id: b, reason: why } }), onSuccess: () => { setWhy(""); refresh(); } });
  const revert = useMutation({ mutationFn: (lid: string) => api(`/entity-links/${lid}/revert`, { method: "POST" }), onSuccess: refresh });
  const el = useRef<HTMLDivElement>(null);
  const [sel, setSel] = useState<GraphT["edges"][number] | null>(null);
  useEffect(() => {
    if (!q.data || !el.current || q.data.nodes.length === 0) return;
    const cy = cytoscape({
      container: el.current,
      elements: [
        ...q.data.nodes.map((n) => ({ data: { id: n.id, label: n.label, type: n.type } })),
        ...q.data.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, label: e.type, status: e.status } })),
      ],
      layout: { name: "cose", animate: false },
      style: [
        { selector: "node", style: { label: "data(label)", "font-size": 6, color: "#8fa6bb", "text-valign": "bottom", "text-margin-y": 3, "min-zoomed-font-size": 4, "background-color": "#2ec4b6", width: 14, height: 14 } },
        { selector: 'node[type = "ip"]', style: { "background-color": "#f0b429", shape: "diamond" } },
        { selector: "edge", style: { width: 1.2, "line-color": "#4a6a85", "target-arrow-shape": "triangle", "target-arrow-color": "#4a6a85", "curve-style": "bezier", label: "data(label)", "font-size": 5, color: "#6d8499", "text-opacity": 0 } },
        { selector: "edge:selected, edge:active", style: { "text-opacity": 1, "line-color": "#2ec4b6", width: 2 } },
        { selector: 'edge[status = "unverified"]', style: { "line-style": "dashed" } },
      ],
    });
    cy.on("tap", "edge", (ev) => setSel(q.data!.edges.find((e) => e.id === ev.target.id()) ?? null));
    return () => cy.destroy();
  }, [q.data]);
  if (q.isLoading) return <Loading what="graph" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const name = (i: string) => ents.data?.items.find((e) => e.id === i)?.display ?? i.slice(0, 8);
  return (
    <>
      {q.data && q.data.nodes.length === 0 ? <Empty title="No relationships yet" hint="Relationships appear once a source reports them, each linked to evidence." /> : q.data && (
        <>
          <div className="banner">{q.data.note} Dashed = unverified. {q.data.truncated && `Showing the ${q.data.nodes.length} best-connected of ${q.data.total_nodes} nodes.`}</div>
          <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={merged} onChange={(e) => setMerged(e.target.checked)} /> Show analyst merge decisions (reversible; underlying entities are never changed)</label>
          <div ref={el} className="graph" role="img" aria-label={`Entity graph with ${q.data.nodes.length} nodes`} />
          {sel && <div className="card" style={{ marginTop: 8 }}><b>{sel.type}</b> <Badge v={sel.status} /> <Badge v={sel.confidence} /><div className="muted">{sel.confidence_reason}</div>
            <div>Evidence: {sel.evidence_ids.map((e) => <code key={e}> {e.slice(0, 8)}</code>)}</div></div>}
        </>)}
      <h3>Merge decisions</h3>
      <p className="muted">Two entities that look like the same thing stay separate until you decide. A merge is a recorded, reversible view: it never rewrites evidence, and entities are never merged automatically (names and handles can collide).</p>
      <form className="row" onSubmit={(e) => { e.preventDefault(); link.mutate(); }}>
        <select aria-label="Entity to merge" value={a} onChange={(e) => setA(e.target.value)} style={{ maxWidth: 260 }}><option value="">entity…</option>{ents.data?.items.map((e) => <option key={e.id} value={e.id}>{e.type}: {e.display}</option>)}</select>
        <span>into</span>
        <select aria-label="Canonical entity" value={b} onChange={(e) => setB(e.target.value)} style={{ maxWidth: 260 }}><option value="">entity…</option>{ents.data?.items.map((e) => <option key={e.id} value={e.id}>{e.type}: {e.display}</option>)}</select>
        <input aria-label="Reason" placeholder="Why do you think they are the same? (recorded)" value={why} onChange={(e) => setWhy(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
        <button className="primary" disabled={!a || !b || why.trim().length < 3 || link.isPending}>Record merge</button></form>
      {link.isError && <ErrorBox error={link.error} />}
      {links.data?.items.map((l) => <div key={l.id} className="row muted"><Badge v={l.status === "active" ? "medium" : "unknown"} /> {name(l.entity_id)} → {name(l.canonical_entity_id)} · {l.reason}{l.status === "active" && <button onClick={() => revert.mutate(l.id)}>Split (revert)</button>}</div>)}
    </>
  );
}

function Timeline({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["timeline", id], queryFn: () => api<{ items: { finding_id: string; subject: string; predicate: string; value: unknown; observed_at: string; source_published_at: string | null; captured_at: string; time_unknown: boolean }[] }>(`/cases/${id}/timeline`) });
  if (q.isLoading) return <Loading what="timeline" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  if (!q.data?.items.length) return <Empty title="Nothing on the timeline" />;
  return (
    <table>
      <thead><tr><th>Subject / predicate</th><th>Value</th><th>Source published</th><th>Observed</th><th>Captured</th></tr></thead>
      <tbody>{q.data.items.map((i) => (
        <tr key={i.finding_id}><td>{i.subject}<div className="muted">{i.predicate}</div></td><td><code>{val(i.value)}</code></td>
          <td>{i.time_unknown ? <span className="badge unknown">time unknown</span> : fmt(i.source_published_at)}</td><td>{fmt(i.observed_at)}</td><td>{fmt(i.captured_at)}</td></tr>
      ))}</tbody>
    </table>
  );
}

interface Ev { id: string; title: string; kind: string; sha256: string; byte_size: number; mime_type: string | null; original_url: string | null; retrieved_at: string; sensitivity: string }

function EvidenceTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["evidence", id], queryFn: () => api<{ items: Ev[] }>(`/cases/${id}/evidence`) });
  const [consent, setConsent] = useState(false);
  const up = useMutation({
    mutationFn: async (f: File) => api(`/cases/${id}/evidence/import?filename=${encodeURIComponent(f.name)}&consent_confirmed=true`, { method: "POST", body: f }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["evidence", id] }),
  });
  return (
    <>
      <div className="card row">
        <label><input type="checkbox" style={{ width: "auto" }} checked={consent} onChange={(e) => setConsent(e.target.checked)} /> I own or am authorized to import this file</label>
        <input type="file" aria-label="Import file" disabled={!consent} style={{ maxWidth: 300 }} onChange={(e) => e.target.files?.[0] && up.mutate(e.target.files[0])} />
        <span className="muted">Files are hashed, stored inert and never executed or rendered.</span>
      </div>
      {up.isError && <ErrorBox error={up.error} />}
      {q.isLoading && <Loading what="evidence" />}
      {q.data && q.data.items.length === 0 && <Empty title="No evidence yet" />}
      {!!q.data?.items.length && (
        <table>
          <thead><tr><th>Item</th><th>SHA-256</th><th>Size</th><th>Retrieved</th><th /></tr></thead>
          <tbody>{q.data.items.map((e) => (
            <tr key={e.id}><td>{e.title}<div className="muted">{e.kind} · {e.mime_type}</div></td><td><code>{e.sha256}</code></td><td>{e.byte_size} B</td><td>{fmt(e.retrieved_at)}</td>
              <td><button onClick={async () => {
                const r = await fetch(apiUrl(`/evidence/${e.id}/download`), { headers: authHeader() });
                if (!r.ok) { alert("Integrity check failed or file unavailable"); return; }
                const url = URL.createObjectURL(await r.blob()); const a = document.createElement("a"); a.href = url; a.download = e.title; a.click(); URL.revokeObjectURL(url);
              }}>Download (hash-verified)</button></td></tr>
          ))}</tbody>
        </table>
      )}
    </>
  );
}

function Notes({ id }: { id: string }) {
  const qc = useQueryClient();
  const [body, setBody] = useState("");
  const q = useQuery({ queryKey: ["notes", id], queryFn: () => api<{ items: { id: string; html: string; created_at: string }[] }>(`/cases/${id}/notes`) });
  const add = useMutation({ mutationFn: () => api(`/cases/${id}/notes`, { method: "POST", json: { body_markdown: body } }),
    onSuccess: () => { setBody(""); qc.invalidateQueries({ queryKey: ["notes", id] }); } });
  return (
    <>
      <textarea aria-label="New note" rows={4} placeholder="Analyst note (Markdown; HTML is stripped)" value={body} onChange={(e) => setBody(e.target.value)} />
      <button className="primary" disabled={!body.trim()} onClick={() => add.mutate()} style={{ margin: "6px 0" }}>Add note</button>
      {add.isError && <ErrorBox error={add.error} />}
      {q.data?.items.length === 0 && <Empty title="No notes" />}
      {/* Server-sanitized HTML (nh3 allow-list; no scripts, handlers or javascript: URLs). */}
      {q.data?.items.map((n) => (
        <div key={n.id} className="card" style={{ marginTop: 8 }}>
          <div className="muted">{fmt(n.created_at)}</div>
          {/* eslint-disable-next-line no-restricted-syntax -- html is produced by the server's nh3 allow-list sanitizer */}
          <div dangerouslySetInnerHTML={{ __html: n.html }} />
        </div>
      ))}
    </>
  );
}

interface Preview { will_include: Record<string, number>; will_withhold: Record<string, number>; coordinates: string; destination: string;
  encryption: { note: string; report_file_encrypted: boolean }; sensitive_included: boolean }

function Reports({ id }: { id: string }) {
  const [fmtSel, setFmt] = useState("html");
  const [profile, setProfile] = useState("technical");
  const [sensitive, setSensitive] = useState(false);
  const preview = useMutation({ mutationFn: () => api<Preview>(`/cases/${id}/reports/preview`, { method: "POST", json: { profile, include_sensitive: sensitive } }) });
  const mk = useMutation({ mutationFn: () => api<{ id: string; file: string; sha256: string }>(`/cases/${id}/reports`, { method: "POST", json: { format: fmtSel, profile, include_sensitive: sensitive } }) });
  const dl = async () => {
    if (!mk.data) return;
    const r = await fetch(apiUrl(`/reports/${mk.data.id}/download`), { headers: authHeader() });
    const url = URL.createObjectURL(await r.blob()); const a = document.createElement("a"); a.href = url; a.download = mk.data.file; a.click(); URL.revokeObjectURL(url);
  };
  return (
    <div className="card">
      <div className="row">
        <select data-tour="report-profile" aria-label="Profile" value={profile} onChange={(e) => setProfile(e.target.value)} style={{ width: 160 }}>{["executive", "technical", "evidence_pack", "multi_int"].map((p) => <option key={p}>{p}</option>)}</select>
        <select aria-label="Format" value={fmtSel} onChange={(e) => setFmt(e.target.value)} style={{ width: 120 }}>{["html", "markdown", "json", "pdf"].map((p) => <option key={p}>{p}</option>)}</select>
        <label><input type="checkbox" style={{ width: "auto" }} checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} /> include RESTRICTED material and exact coordinates</label>
        <button data-tour="report-preview" onClick={() => preview.mutate()} disabled={preview.isPending}>Preview what will be included</button>
        <button data-tour="report-generate" className="primary" onClick={() => mk.mutate()} disabled={mk.isPending}>Generate</button>
      </div>
      <p className="muted">Restricted-sensitivity evidence is excluded by default. Every report carries limitations and an evidence hash manifest. The multi_int profile adds claims, contradictions, gaps, discipline annexes and methodology.</p>
      {preview.isError && <ErrorBox error={preview.error} />}
      {preview.data && (
        <div className="banner" aria-label="Report preview">
          <b>Included:</b> {Object.entries(preview.data.will_include).map(([k, v]) => `${v} ${k}`).join(", ")}.<br />
          <b>Withheld:</b> {Object.entries(preview.data.will_withhold).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ")}.<br />
          <b>Coordinates:</b> {preview.data.coordinates}. <b>Written to:</b> <code>{preview.data.destination}</code><br />
          <span className="muted">{preview.data.encryption.note}</span>
        </div>)}
      {mk.isError && <ErrorBox error={mk.error} />}
      {mk.data && <div className="banner">Generated <code>{mk.data.file}</code> · sha256 <code>{mk.data.sha256}</code> <button onClick={dl}>Download</button></div>}
    </div>
  );
}

interface Obs { id: string; discipline: string; kind: string; access_class: string; observed_at: string | null; ingested_at: string;
  data: Record<string, unknown>; raw_evidence_id: string; confidence: string; sensitivity: string }

function Imports({ id }: { id: string }) {
  const qc = useQueryClient();
  const [consent, setConsent] = useState(false);
  const [kind, setKind] = useState("auto");
  const [term, setTerm] = useState("");
  const obs = useQuery({ queryKey: ["obs", id], queryFn: () => api<{ items: Obs[] }>(`/cases/${id}/observations`) });
  const hits = useQuery({ queryKey: ["fts", id, term], enabled: term.trim().length > 1,
    queryFn: () => api<{ items: { kind: string; id: string; snippet: string }[] }>(`/cases/${id}/search?q=${encodeURIComponent(term)}`) });
  const up = useMutation({
    mutationFn: (f: File) => api<{ warnings: string[]; observations_added: number }>(
      `/cases/${id}/ingest?filename=${encodeURIComponent(f.name)}&kind=${kind}&consent_confirmed=true`, { method: "POST", body: f }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["obs", id] }); qc.invalidateQueries({ queryKey: ["evidence", id] }); qc.invalidateQueries({ queryKey: ["graph", id] }); },
  });
  return (
    <>
      <div className="card">
        <b>Import user-supplied material</b>
        <p className="muted">Import-only and offline: .eml (COMINT), .sigmf archive (SIGINT), sensor .csv (MASINT). Nothing is intercepted, collected live or sent anywhere. Malformed files are rejected before storage.</p>
        <div className="row">
          <select aria-label="Import type" value={kind} onChange={(e) => setKind(e.target.value)} style={{ width: 170 }}>
            {["auto", "eml", "sigmf", "sensor_csv"].map((k) => <option key={k}>{k}</option>)}
          </select>
          <label data-tour="import-consent"><input type="checkbox" style={{ width: "auto" }} checked={consent} onChange={(e) => setConsent(e.target.checked)} /> I own or am authorized to analyse this material</label>
          <input data-tour="import-file" type="file" aria-label="Import analysis file" disabled={!consent} style={{ maxWidth: 280 }} onChange={(e) => e.target.files?.[0] && up.mutate(e.target.files[0])} />
        </div>
        {up.isError && <ErrorBox error={up.error} />}
        {up.data?.warnings.map((w) => <div key={w} className="banner warn">{w}</div>)}
      </div>
      <h3>Case search</h3>
      <input aria-label="Search this case" placeholder="Full-text search across findings, notes, evidence and observations" value={term} onChange={(e) => setTerm(e.target.value)} />
      {hits.data?.items.length === 0 && <p className="muted">No matches.</p>}
      {hits.data?.items.map((h) => <div key={h.kind + h.id} className="muted"><Badge v={h.kind} /> {h.snippet}</div>)}
      <h3 data-tour="import-results">Observations</h3>
      {obs.isLoading && <Loading what="observations" />}
      {obs.isError && <ErrorBox error={obs.error} />}
      {obs.data?.items.length === 0 && <Empty title="No imported observations" hint="Observations are facts a parser extracted from a file, not conclusions." />}
      {!!obs.data?.items.length && (
        <table>
          <thead><tr><th>Discipline</th><th>Kind</th><th>Observed</th><th>Sensitivity</th><th>Data</th></tr></thead>
          <tbody>{obs.data.items.map((o) => (
            <tr key={o.id}><td><Badge v={o.discipline} /><div className="muted">{o.access_class}</div></td><td>{o.kind}</td><td>{fmt(o.observed_at)}</td><td>{o.sensitivity}</td>
              <td><details><summary>view</summary><pre style={{ whiteSpace: "pre-wrap", maxWidth: 520 }}>{JSON.stringify(o.data, null, 2)}</pre></details>
                <div className="muted">evidence <code>{o.raw_evidence_id.slice(0, 8)}</code></div></td></tr>
          ))}</tbody>
        </table>
      )}
    </>
  );
}
