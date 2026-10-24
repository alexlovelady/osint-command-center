import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import WorkflowCanvas from "../../components/WorkflowCanvas";
import { Badge, ErrorBox, Loading } from "../../components/ui";
import { api, ApiError, type CaseT } from "../../lib/api";
import type { ApprovalT, Explanation, NodeTypeT, ProposeResult, RunDetail, Validation, WorkflowT } from "../../lib/automationsApi";
import { removeNode, uniqueId, type WfDef, type WfNode } from "../../lib/workflowGraph";
import { goWf } from "./Library";
import { RunList } from "./Runs";

interface Caps { adapters: { id: string; name: string; class: string; status: string }[] }

export default function Builder({ id }: { id: string }) {
  const qc = useQueryClient();
  const wf = useQuery({ queryKey: ["auto-wf", id], queryFn: () => api<WorkflowT>(`/automations/workflows/${id}`) });
  const types = useQuery({ queryKey: ["auto-node-types"], queryFn: () => api<{ items: NodeTypeT[] }>("/automations/node-types"), staleTime: 600_000 });
  const caps = useQuery({ queryKey: ["auto-caps"], queryFn: () => api<Caps>("/automations/capabilities"), staleTime: 30_000 });
  const cases = useQuery({ queryKey: ["cases-all"], queryFn: () => api<{ items: CaseT[] }>("/cases?limit=200") });
  const [def, setDef] = useState<WfDef | null>(null);
  const [rev, setRev] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [tab, setTab] = useState<"check" | "explain" | "dry" | "approvals" | "runs" | "versions">("check");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [dry, setDry] = useState<{ run: RunDetail; nodes: RunDetail["nodes"]; label: string } | null>(null);
  const [runCase, setRunCase] = useState("");

  useEffect(() => { if (wf.data?.definition && !dirty) { setDef(wf.data.definition); setRev(wf.data.rev); } }, [wf.data, dirty]);
  const meta = wf.data;
  const typeMap = useMemo(() => Object.fromEntries((types.data?.items ?? []).map((t) => [t.type, t])), [types.data]);
  const titles = useMemo(() => Object.fromEntries((types.data?.items ?? []).map((t) => [t.type, t.title])), [types.data]);
  const netTypes = useMemo(() => new Set((types.data?.items ?? []).filter((t) => t.network).map((t) => t.type)), [types.data]);

  const validation = useQuery({ queryKey: ["auto-validate", id, rev, dirty ? JSON.stringify(def?.nodes) : "saved"], enabled: !!meta,
    queryFn: async () => {
      if (dirty && def) {                         // unsaved edits are validated without saving: explain endpoint validates and describes the definition
        const e = await api<Explanation>("/automations/ai/explain", { method: "POST", json: { definition: def } });
        return { valid: e.validation.valid, errors: e.validation.errors, warnings: e.validation.warnings, permissions: e.permissions, nodes: {}, estimated_requests: {}, explanation: e } as Validation;
      }
      return api<Validation>(`/automations/workflows/${id}/validate`, { method: "POST" });
    } });
  const v = validation.data;

  const update = (f: (d: WfDef) => WfDef) => { setDef((d) => (d ? f(structuredClone(d)) : d)); setDirty(true); setMsg(null); };
  const patchNode = (nid: string, f: (n: WfNode) => void) => update((d) => { const n = d.nodes.find((x) => x.id === nid); if (n) f(n); return d; });
  const fail = (e: unknown) => { setErr(e); setMsg(null); };
  const ok = (m: string) => { setErr(null); setMsg(m); };
  const refresh = () => { qc.invalidateQueries({ queryKey: ["auto-wf", id] }); qc.invalidateQueries({ queryKey: ["auto-approvals", id] }); qc.invalidateQueries({ queryKey: ["auto-runs"] }); };

  const save = useMutation({
    mutationFn: () => api<WorkflowT>(`/automations/workflows/${id}`, { method: "PATCH", json: { definition: def, rev } }),
    onSuccess: (w) => { setDirty(false); setRev(w.rev); setDef(w.definition ?? def); ok("Saved the draft."); refresh(); }, onError: fail });
  const publish = useMutation({ mutationFn: async () => { if (dirty) await save.mutateAsync(); return api<{ revision: number; note: string }>(`/automations/workflows/${id}/publish`, { method: "POST" }); },
    onSuccess: (r) => { ok(`Published revision ${r.revision}. ${r.note}`); refresh(); }, onError: fail });
  const dryRun = useMutation({ mutationFn: async () => { if (dirty) await save.mutateAsync(); return api<{ run: RunDetail; nodes: RunDetail["nodes"]; label: string }>(`/automations/workflows/${id}/dry-run`, { method: "POST", json: {} }); },
    onSuccess: (r) => { setDry(r); setTab("dry"); ok("Dry run finished (simulated data, nothing was contacted or saved)."); }, onError: fail });
  const run = useMutation({ mutationFn: (confirmed: string[]) => api<{ id: string; state: string }>(`/automations/workflows/${id}/run`, { method: "POST", json: { case_id: runCase || meta?.case_id, confirmed_adapters: confirmed, wait: false } }),
    onSuccess: (r) => { ok(`Run started (${r.state}). Open the Runs tab to follow it.`); setTab("runs"); refresh(); }, onError: fail });
  const requestApproval = useMutation({ mutationFn: () => api<{ items: ApprovalT[] }>(`/automations/workflows/${id}/request-approval`, { method: "POST", json: {} }),
    onSuccess: () => { setTab("approvals"); ok("Approval requested. Nothing runs until you decide."); refresh(); }, onError: fail });
  const activate = useMutation({ mutationFn: () => api<{ note: string }>(`/automations/workflows/${id}/activate`, { method: "POST", json: {} }), onSuccess: (r) => { ok(`Activated. ${r.note}`); refresh(); }, onError: fail });
  const deactivate = useMutation({ mutationFn: () => api(`/automations/workflows/${id}/deactivate`, { method: "POST" }), onSuccess: () => { ok("Deactivated."); refresh(); }, onError: fail });
  const del = useMutation({ mutationFn: () => api(`/automations/workflows/${id}`, { method: "DELETE" }), onSuccess: () => { window.location.hash = "/automations"; }, onError: fail });

  const addNode = (type: string) => update((d) => {
    const spec = typeMap[type];
    const nid = uniqueId(d.nodes, type.split("_")[0]);
    d.nodes.push({ id: nid, type, depends_on: sel ? [sel] : [], config: Object.fromEntries((spec?.fields ?? []).filter((f) => f.kind === "enum").map((f) => [f.name, f.options?.[0]])) });
    setSel(nid);
    return d;
  });

  if (wf.isLoading) return <Loading what="workflow" />;
  if (wf.isError || !meta) return <ErrorBox error={wf.error} />;
  if (!def) return <Loading what="definition" />;
  const node = def.nodes.find((n) => n.id === sel) ?? null;
  const states = dry ? Object.fromEntries(dry.nodes.map((n) => [n.node, n.state])) : undefined;
  const canRun = meta.published && !!(runCase || meta.case_id);

  return (
    <>
      <div className="muted"><a href="#/automations">Automations</a> / {meta.name}</div>
      <div className="row" style={{ margin: "4px 0 8px" }}>
        <h2 style={{ margin: 0 }}>{def.name}</h2><Badge v={meta.state} />
        <span className="muted">draft revision {rev}{meta.latest_revision ? ` · published ${meta.latest_revision}` : " · unpublished"}{meta.unpublished_changes && !dirty ? " · unpublished changes" : ""}{dirty ? " · unsaved edits" : ""}</span>
      </div>
      <div className="row" role="toolbar" aria-label="Workflow actions" data-tour="auto-actions">
        <button onClick={() => save.mutate()} disabled={!dirty || save.isPending}>Save draft</button>
        <button onClick={() => { setTab("check"); validation.refetch(); }}>Validate</button>
        <button onClick={() => setTab("explain")}>Explain</button>
        <button onClick={() => dryRun.mutate()} disabled={dryRun.isPending}>Dry run</button>
        <button onClick={() => publish.mutate()} disabled={publish.isPending || (v ? !v.valid : true)}>Publish version</button>
        <button onClick={() => requestApproval.mutate()} disabled={!meta.published}>Request approval</button>
        {meta.state === "active" ? <button onClick={() => deactivate.mutate()}>Deactivate</button> : <button className="primary" onClick={() => activate.mutate()} disabled={!meta.published || def.trigger.type === "manual" || def.trigger.type === "file"} title="Needs an approved, unexpired approval for the published version">Activate</button>}
        <span className="grow" />
        <button onClick={async () => { const d = await api<unknown>(`/automations/workflows/${id}/export`); const b = new Blob([JSON.stringify(d, null, 1)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = `${def.workflow_key}.automation.json`; a.click(); }}>Export</button>
        <button onClick={() => { if (window.confirm("Delete this workflow and stop its schedule?")) del.mutate(); }}>Delete</button>
      </div>
      {msg && <div className="banner" role="status">{msg}</div>}
      {err != null && <ErrorBox error={err instanceof ApiError ? err : new Error(String(err))} />}
      {def.trigger.type !== "manual" && <div className="banner warn">Trigger: <b>{def.trigger.type}</b>{def.trigger.schedule ? ` (${def.trigger.schedule}, ${def.trigger.timezone})` : ""}. It stays OFF until you approve and activate it; it only runs while this application is open.</div>}

      <div className="builder">
        <AiPanel caseId={meta.case_id} onUse={async (d) => { setDef(d); setDirty(true); setSel(null); setMsg("Draft loaded into the editor. Review it, then Save."); }} />
        <div>
          <WorkflowCanvas nodes={def.nodes} selected={sel} onSelect={setSel} onDelete={(nid) => update((d) => { d.nodes = removeNode(d.nodes, nid); setSel(null); return d; })}
            issues={v?.errors ?? []} warnings={v?.warnings ?? []} states={states} titles={titles} networkTypes={netTypes} />
          <div className="row" style={{ marginTop: 8 }}>
            <select aria-label="Add a step" value="" onChange={(e) => e.target.value && addNode(e.target.value)} style={{ maxWidth: 260 }}>
              <option value="">Add a step…</option>
              {(types.data?.items ?? []).map((t) => <option key={t.type} value={t.type}>{t.title}{t.network ? " (network)" : ""}</option>)}
            </select>
            <span className="muted">New steps depend on the selected step. Each network step needs a scope check upstream.</span>
          </div>
        </div>
        <Inspector def={def} node={node} spec={node ? typeMap[node.type] : undefined} adapters={caps.data?.adapters ?? []} update={update} patchNode={patchNode}
          onDelete={(nid) => update((d) => { d.nodes = removeNode(d.nodes, nid); setSel(null); return d; })} />
      </div>

      <div className="tabs" role="tablist" aria-label="Workflow details" style={{ marginTop: 14 }}>
        {([["check", "Checks"], ["explain", "Explanation"], ["dry", "Dry run"], ["approvals", "Approvals & run"], ["runs", "Runs"], ["versions", "Versions"]] as const).map(([k, l]) =>
          <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
      </div>
      {tab === "check" && <Checks v={v} loading={validation.isLoading} />}
      {tab === "explain" && (v?.explanation ? <ExplainView e={v.explanation} /> : <ExplainFetch id={id} def={def} dirty={dirty} />)}
      {tab === "dry" && (dry ? <DryView d={dry} /> : <p className="muted">Press <b>Dry run</b> to run the draft against the template's fixture. No network, nothing saved; every result is labelled simulated.</p>)}
      {tab === "approvals" && <Approvals id={id} meta={meta} def={def} cases={cases.data?.items ?? []} runCase={runCase} setRunCase={setRunCase} canRun={canRun} onRun={(c) => run.mutate(c)} onChange={refresh} fail={fail} />}
      {tab === "runs" && <RunList workflowId={id} />}
      {tab === "versions" && (
        <table><thead><tr><th>Revision</th><th>Hash</th><th>Published</th><th /></tr></thead>
          <tbody>{(meta.versions ?? []).map((x) => <tr key={x.id}><td>{x.revision}{x.id === meta.active_version_id ? " (active)" : ""}</td><td><code>{x.hash.slice(0, 16)}</code></td><td>{x.published_at}</td>
            <td><button onClick={async () => { await api(`/automations/workflows/${id}/versions/${x.revision}/clone`, { method: "POST" }); setDirty(false); refresh(); ok(`Draft reset to revision ${x.revision}.`); }}>Clone to draft</button></td></tr>)}</tbody></table>)}
    </>
  );
}

// -------------------------------------------------------------------------------------------------------------------------------- AI builder
function AiPanel({ caseId, onUse }: { caseId: string | null; onUse: (d: WfDef) => void }) {
  const [goal, setGoal] = useState("");
  const m = useMutation({ mutationFn: () => api<ProposeResult>("/automations/ai/propose", { method: "POST", json: { goal, case_id: caseId } }) });
  const r = m.data;
  return (
    <aside className="card ai-panel" aria-label="AI Automation Builder" data-tour="auto-ai">
      <b>Describe what you want</b>
      <textarea aria-label="Describe the automation" rows={4} value={goal} onChange={(e) => setGoal(e.target.value)} placeholder="Monitor my approved domains for new public-facing assets and alert me only on meaningful changes" />
      <button className="primary" onClick={() => m.mutate()} disabled={goal.trim().length < 8 || m.isPending}>{m.isPending ? "Thinking…" : "Generate a draft"}</button>
      <p className="muted" style={{ fontSize: 12 }}>The assistant returns a typed draft that a strict validator checks. It cannot approve, schedule or run anything.</p>
      {m.isError && <ErrorBox error={m.error} />}
      {r && (
        <div role="region" aria-label="Proposed draft">
          {r.draft ? (
            <>
              <div className="chips"><span className="chip">{r.source === "model" ? `model: ${r.model.profile ?? "local"}` : r.source === "template_match" ? "closest template" : r.source}</span><span className={`badge ${r.valid ? "healthy" : "failed"}`}>{r.valid ? "valid" : "needs fixes"}</span></div>
              <p><b>{r.draft.name}</b>: {r.draft.nodes.length} steps, trigger {r.draft.trigger.type}{r.draft.trigger.schedule ? ` (${r.draft.trigger.schedule})` : ""}.</p>
              {r.assumptions.map((a) => <p key={a} className="muted" style={{ fontSize: 12 }}>• {a}</p>)}
              {r.questions.length > 0 && <div className="banner"><b>I need:</b> {r.questions.join(" ")}</div>}
              {r.validation?.errors.map((e, i) => <div key={i} className="banner err" style={{ fontSize: 12 }}>[{e.code}] {e.message}</div>)}
              {r.attempts.length > 0 && <details><summary>{r.attempts.length} correction attempt(s)</summary>{r.attempts.map((a) => <p key={a.attempt} className="muted" style={{ fontSize: 12 }}>#{a.attempt}: {a.problem}</p>)}</details>}
              <button onClick={() => onUse(r.draft as WfDef)}>Load into the editor</button>
            </>
          ) : <div className="banner warn">{r.message}</div>}
          {!r.model.used && r.model.reason && <p className="muted" style={{ fontSize: 12 }}>No model was used: {r.model.reason}</p>}
        </div>)}
    </aside>
  );
}

// -------------------------------------------------------------------------------------------------------------------------------- inspector
function Inspector({ def, node, spec, adapters, update, patchNode, onDelete }: { def: WfDef; node: WfNode | null; spec?: NodeTypeT; adapters: Caps["adapters"];
  update: (f: (d: WfDef) => WfDef) => void; patchNode: (id: string, f: (n: WfNode) => void) => void; onDelete: (id: string) => void }) {
  const refs = (n: WfNode) => [...Object.keys(def.inputs).map((k) => `$inputs.${k}`), ...def.nodes.filter((x) => x.id !== n.id).map((x) => `$nodes.${x.id}.output`)];
  return (
    <aside className="card inspector" aria-label="Inspector" data-tour="auto-inspector">
      {!node ? (
        <>
          <b>Workflow settings</b>
          <label>Name<input value={def.name} onChange={(e) => update((d) => { d.name = e.target.value; return d; })} /></label>
          <label>Trigger<select value={def.trigger.type} onChange={(e) => update((d) => { d.trigger.type = e.target.value; return d; })}>{["manual", "schedule", "event", "file"].map((t) => <option key={t}>{t}</option>)}</select></label>
          {def.trigger.type === "schedule" && <>
            <label>Cron (5 fields)<input value={def.trigger.schedule ?? ""} onChange={(e) => update((d) => { d.trigger.schedule = e.target.value; return d; })} /></label>
            <label>Time zone (IANA)<input value={def.trigger.timezone ?? "UTC"} onChange={(e) => update((d) => { d.trigger.timezone = e.target.value; return d; })} /></label>
            <label>If runs were missed<select value={def.trigger.missed_run_policy ?? "coalesce"} onChange={(e) => update((d) => { d.trigger.missed_run_policy = e.target.value; return d; })}>
              <option value="coalesce">run once when I'm back (default)</option><option value="skip">skip them</option><option value="catch_up">catch up (max 10)</option></select></label></>}
          <label>Network mode<select value={String(def.policy.network_mode)} onChange={(e) => update((d) => { d.policy.network_mode = e.target.value; return d; })}>
            <option value="passive_only">passive only</option><option value="active_with_approval">active (needs a separate approval)</option></select></label>
          <b style={{ marginTop: 8 }}>Inputs</b>
          {Object.entries(def.inputs).map(([k, val]) => <label key={k}>{k}<input value={val == null ? "" : String(val)} onChange={(e) => update((d) => { d.inputs[k] = e.target.value === "" ? null : e.target.value; return d; })} /></label>)}
          <p className="muted" style={{ fontSize: 12 }}>Select a step on the canvas to edit it.</p>
        </>
      ) : (
        <>
          <b>{node.id}</b> <span className="muted">{spec?.title ?? node.type}</span>
          <p className="muted" style={{ fontSize: 12 }}>{spec?.description}</p>
          <p className="muted" style={{ fontSize: 12 }}>Produces: {spec?.produces} · side effects: {spec?.side_effects} · risk: {spec?.risk}</p>
          <label>Label<input value={node.label ?? ""} onChange={(e) => patchNode(node.id, (n) => { n.label = e.target.value || null; })} /></label>
          {(spec?.fields ?? []).map((f) => {
            const cur = node.config[f.name];
            const set = (v: unknown) => patchNode(node.id, (n) => { n.config[f.name] = v; });
            if (f.kind === "enum") return <label key={f.name}>{f.name}<select value={String(cur ?? "")} onChange={(e) => set(e.target.value || null)}><option value="" />{f.options?.map((o) => <option key={o}>{o}</option>)}</select></label>;
            if (f.kind === "bool") return <label key={f.name} className="row"><input type="checkbox" style={{ width: "auto" }} checked={!!cur} onChange={(e) => set(e.target.checked)} />{f.name}</label>;
            if (f.kind === "int") return <label key={f.name}>{f.name}<input type="number" min={f.min} max={f.max} value={cur == null ? "" : Number(cur)} onChange={(e) => set(e.target.value === "" ? null : Number(e.target.value))} /></label>;
            if (f.kind === "adapter") return <label key={f.name}>{f.name}<select value={String(cur ?? "")} onChange={(e) => set(e.target.value)}><option value="" />{adapters.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.status.replace(/_/g, " ")})</option>)}</select></label>;
            if (f.kind === "list") return <label key={f.name}>{f.name} (comma separated)<input value={Array.isArray(cur) ? cur.join(", ") : ""} onChange={(e) => set(e.target.value.split(",").map((s) => s.trim()).filter(Boolean))} /></label>;
            if (f.kind === "ref") return <label key={f.name}>{f.name}<input list={`refs-${node.id}`} value={String(cur ?? "")} onChange={(e) => set(e.target.value || null)} /><datalist id={`refs-${node.id}`}>{refs(node).map((r) => <option key={r} value={r} />)}</datalist></label>;
            return <label key={f.name}>{f.name}<input value={cur == null ? "" : String(cur)} onChange={(e) => set(e.target.value || null)} /></label>;
          })}
          <fieldset><legend>Runs after</legend>
            {def.nodes.filter((x) => x.id !== node.id).map((x) => <label key={x.id} className="row"><input type="checkbox" style={{ width: "auto" }} checked={node.depends_on.includes(x.id)}
              onChange={(e) => patchNode(node.id, (n) => { n.depends_on = e.target.checked ? [...n.depends_on, x.id] : n.depends_on.filter((d) => d !== x.id); })} />{x.id}</label>)}</fieldset>
          <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={!!node.optional} onChange={(e) => patchNode(node.id, (n) => { n.optional = e.target.checked; })} />Optional (a failure becomes a warning)</label>
          <label>Run when<select value={node.run_on ?? "success"} onChange={(e) => patchNode(node.id, (n) => { n.run_on = e.target.value; })}><option value="success">upstream succeeded</option><option value="failure">something failed (error handler)</option><option value="always">always</option></select></label>
          <button onClick={() => onDelete(node.id)}>Delete this step</button>
        </>)}
    </aside>
  );
}

// -------------------------------------------------------------------------------------------------------------------------------- panels
function Checks({ v, loading }: { v?: Validation; loading: boolean }) {
  if (loading || !v) return <Loading what="checks" />;
  return (
    <div role="region" aria-label="Validation">
      <div className={`banner ${v.valid ? "" : "err"}`}>{v.valid ? "Valid: the graph, references, scope checks and limits pass the validator." : `${v.errors.length} problem(s) to fix before this can be published.`}</div>
      {v.errors.map((e, i) => <div key={i} className="banner err"><b>{e.code}</b>{e.node ? ` · ${e.node}` : ""}: {e.message}</div>)}
      {v.warnings.map((e, i) => <div key={i} className="banner warn"><b>{e.code}</b>{e.node ? ` · ${e.node}` : ""}: {e.message}</div>)}
      <h4>Permissions this workflow needs</h4>
      <ul>
        <li>Network: <b>{v.permissions.network ? "yes" : "no"}</b> ({v.permissions.network_mode.replace(/_/g, " ")}){v.permissions.adapters.length ? `: ${v.permissions.adapters.join(", ")}` : ""}</li>
        <li>Writes to the case: {v.permissions.writes_local ? "yes" : "no"} · Notifies outside the app: {v.permissions.external ? "yes (in-app/desktop/approved webhook)" : "no"} · Active probing: {v.permissions.active ? "YES (separate approval)" : "no"}</li>
      </ul>
    </div>
  );
}

function ExplainFetch({ id, def, dirty }: { id: string; def: WfDef; dirty: boolean }) {
  const q = useQuery({ queryKey: ["auto-explain", id, dirty ? JSON.stringify(def) : "saved"], queryFn: () => api<Explanation>("/automations/ai/explain", { method: "POST", json: dirty ? { definition: def } : { workflow_id: id } }) });
  if (q.isLoading) return <Loading what="explanation" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  return <ExplainView e={q.data} />;
}

function ExplainView({ e }: { e: Explanation }) {
  return (
    <div role="region" aria-label="Explanation">
      <p><b>{e.name}</b> runs <b>{e.runs}</b>. It starts disabled. Limits: {e.limits.requests_per_provider} requests per provider, {e.limits.seconds}s, {e.limits.parallel_steps} parallel steps.</p>
      <ol>{e.steps.map((s) => (
        <li key={s.id}><b>{s.title}</b> <span className="muted">({s.id}{s.after.length ? `, after ${s.after.join(", ")}` : ""})</span> — {s.what}
          <div className="muted" style={{ fontSize: 12 }}>risk {s.risk} · {s.side_effects.replace(/_/g, " ")}{s.contacts.length ? ` · contacts ${s.contacts.join(", ")}` : ""}{s.optional ? " · optional" : ""}</div></li>))}</ol>
      <p className="muted">{e.note}</p>
    </div>
  );
}

function DryView({ d }: { d: { run: RunDetail; nodes: RunDetail["nodes"]; label: string } }) {
  return (
    <div role="region" aria-label="Dry run result">
      <div className="banner warn"><b>{d.label}</b>. State: {d.run.state.replace(/_/g, " ")}.</div>
      <table><thead><tr><th>Step</th><th>State</th><th>Result (simulated)</th></tr></thead>
        <tbody>{d.nodes.map((n, i) => <tr key={i}><td>{n.node}</td><td><Badge v={n.state === "succeeded" ? "succeeded" : n.state === "failed" ? "failed" : "skipped"} /> {n.error_code ?? ""}</td>
          <td><code>{n.output ? JSON.stringify(n.output).slice(0, 220) : "—"}</code></td></tr>)}</tbody></table>
    </div>
  );
}

function Approvals({ id, meta, def, cases, runCase, setRunCase, canRun, onRun, onChange, fail }: { id: string; meta: WorkflowT; def: WfDef; cases: CaseT[]; runCase: string; setRunCase: (v: string) => void;
  canRun: boolean; onRun: (confirmed: string[]) => void; onChange: () => void; fail: (e: unknown) => void }) {
  const list = useQuery({ queryKey: ["auto-approvals", id], queryFn: () => api<{ items: ApprovalT[] }>(`/automations/approvals?workflow_id=${id}`) });
  const [days, setDays] = useState(30);
  const [conf, setConf] = useState<string[]>([]);
  const [auth, setAuth] = useState("");
  const auths = useQuery({ queryKey: ["auto-auths", meta.case_id], enabled: !!meta.case_id, queryFn: () => api<{ items: { id: string; scope: string; current: boolean }[] }>(`/automations/scope-authorizations?case_id=${meta.case_id}`) });
  const decide = useMutation({ mutationFn: (v: { id: string; approve: boolean }) => api(`/automations/approvals/${v.id}/decide`, { method: "POST", json: { approve: v.approve, expires_in_days: days, confirmed_adapters: conf, authorization_id: auth || null } }),
    onSuccess: onChange, onError: fail });
  const revoke = useMutation({ mutationFn: (aid: string) => api(`/automations/approvals/${aid}/revoke`, { method: "POST" }), onSuccess: onChange, onError: fail });
  const needsConfirm = Array.from(new Set(list.data?.items.filter((a) => a.status === "pending").flatMap((a) => a.scope.needs_confirmation) ?? []));
  const active = def.policy.network_mode === "active_with_approval";
  return (
    <div role="region" aria-label="Approvals and running">
      <h4>Run now</h4>
      <div className="row">
        {!meta.case_id && <select aria-label="Case for the run" value={runCase} onChange={(e) => setRunCase(e.target.value)} style={{ maxWidth: 260 }}><option value="">Choose a case…</option>{cases.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}</select>}
        <button className="primary" onClick={() => onRun(conf)} disabled={!canRun}>Run now</button>
        <span className="muted">{meta.published ? "Runs the latest published version. A manual run needs no schedule approval; sources that contact many sites need the confirmation below." : "Publish a version first."}</span>
      </div>
      {needsConfirm.length > 0 && <div className="banner">Sources that need your explicit confirmation: {needsConfirm.map((a) => <label key={a} className="row"><input type="checkbox" style={{ width: "auto" }} checked={conf.includes(a)} onChange={(e) => setConf(e.target.checked ? [...conf, a] : conf.filter((x) => x !== a))} />I confirm {a} may contact many third-party sites</label>)}</div>}
      <h4>Approvals</h4>
      {list.data?.items.length === 0 && <p className="muted">None yet. Press <b>Request approval</b> after publishing. An approval is bound to one exact version, has an expiry, and is the only way a schedule can start.</p>}
      <table><thead><tr><th>Kind</th><th>Status</th><th>Covers</th><th>Expires</th><th /></tr></thead>
        <tbody>{list.data?.items.map((a) => (
          <tr key={a.id}><td>{a.kind}</td><td><Badge v={a.status === "approved" ? "healthy" : a.status === "pending" ? "queued" : "failed"} /> {a.status}</td>
            <td>{a.scope.adapters.join(", ") || "local only"} · {a.scope.network_mode.replace(/_/g, " ")} · risk {a.scope.risk}</td><td>{a.expires_at ?? "—"}</td>
            <td>{a.status === "pending" && <><button className="primary" onClick={() => decide.mutate({ id: a.id, approve: true })}>Approve</button> <button onClick={() => decide.mutate({ id: a.id, approve: false })}>Reject</button></>}
              {a.status === "approved" && <button onClick={() => revoke.mutate(a.id)}>Revoke</button>}</td></tr>))}</tbody></table>
      <div className="row" style={{ marginTop: 6 }}>
        <label>Approval expires in (days)<input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 90 }} /></label>
        {active && <label>Scope authorization<select value={auth} onChange={(e) => setAuth(e.target.value)}><option value="">choose…</option>{auths.data?.items.filter((x) => x.current).map((x) => <option key={x.id} value={x.id}>{x.scope}</option>)}</select></label>}
      </div>
    </div>
  );
}

export { goWf };
