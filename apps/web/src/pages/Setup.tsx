import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, ErrorBox, Loading } from "../components/ui";
import { api } from "../lib/api";

interface Tool { id: string; name: string; version: string; license: string; homepage: string; installed: boolean; managed: boolean; path: string | null;
  installable: boolean; reason: string | null; download_mb: number | null }
interface Model { id: string; label: string; download_gb: number; min_ram_gb: number }
interface Status { platform: string | null; ram_gb: number | null; tools: Tool[]; recommended_model: Model; models: Model[]; ollama_found: boolean;
  tools_dir: string; completed: boolean; ai_profiles: string[] }
interface Ev { phase: string; id?: string; bytes?: number; total?: number; status?: string; completed?: number; message?: string }
interface Task { id: string; kind: string; status: string; events: Ev[]; results: { id: string; error?: string; reported_version?: string }[]; error: string | null }
interface PlanItem { id: string; name: string; version: string; urls: string[]; size_mb: number | null }

const mb = (n?: number) => ((n ?? 0) / 1e6).toFixed(0);

interface SecretItem { provider: string; label: string; format: string; get: string; set: boolean; used_by: string[] }

function Keys() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["secrets"], queryFn: () => api<{ items: SecretItem[]; note: string }>("/secrets"), retry: false });
  const [vals, setVals] = useState<Record<string, string>>({});
  const [contact, setContact] = useState("");
  const save = useMutation({ mutationFn: (p: string) => api(`/secrets/${p}`, { method: "POST", json: { value: vals[p] } }),
    onSuccess: (_d, p) => { setVals((v) => ({ ...v, [p]: "" })); qc.invalidateQueries({ queryKey: ["secrets"] }); } });
  const del = useMutation({ mutationFn: (p: string) => api(`/secrets/${p}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["secrets"] }) });
  const edgar = useMutation({ mutationFn: () => api("/settings", { method: "PUT", json: { values: { edgar_contact: contact } } }), onSuccess: () => setContact("") });
  if (q.isError || !q.data) return null;
  return (
    <>
      <h3>API keys and contacts (optional)</h3>
      <div className="card">
        <p className="muted">{q.data.note} Leave anything you do not have blank: that source simply stays unavailable and makes no request.</p>
        {q.data.items.map((k) => (
          <div key={k.provider} className="row" style={{ marginBottom: 6 }}>
            <label style={{ minWidth: 300 }} htmlFor={`key-${k.provider}`}>{k.label} {k.set ? <Badge v="healthy" /> : <span className="muted">not set</span>}
              <div className="muted">{k.format}{k.used_by.length ? ` · used by ${k.used_by.join(", ")}` : ""} · get one at {k.get}</div></label>
            <input id={`key-${k.provider}`} type="password" autoComplete="off" placeholder={k.set ? "stored (enter a new value to replace)" : "paste key"} value={vals[k.provider] ?? ""}
              onChange={(e) => setVals({ ...vals, [k.provider]: e.target.value })} style={{ maxWidth: 360 }} />
            <button disabled={!(vals[k.provider] ?? "").trim() || save.isPending} onClick={() => save.mutate(k.provider)}>Save</button>
            {k.set && <button onClick={() => del.mutate(k.provider)}>Remove</button>}
          </div>))}
        <div className="row"><label style={{ minWidth: 300 }} htmlFor="edgar-contact">SEC EDGAR contact (required by the SEC for any EDGAR request)
          <div className="muted">Your name and email, sent as the User-Agent.</div></label>
          <input id="edgar-contact" placeholder="Your Name you@example.org" value={contact} onChange={(e) => setContact(e.target.value)} style={{ maxWidth: 360 }} />
          <button disabled={!contact.includes("@") || edgar.isPending} onClick={() => edgar.mutate()}>Save</button></div>
        {(save.isError || del.isError || edgar.isError) && <ErrorBox error={save.error ?? del.error ?? edgar.error} />}
      </div>
    </>
  );
}

/** First-run setup: install the optional tools and a local model. Nothing is downloaded until the exact sources are shown and confirmed. */
export default function Setup() {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["setup"], queryFn: () => api<Status>("/setup/status") });
  const [pick, setPick] = useState<Record<string, boolean>>({});
  const [model, setModel] = useState<string>("");
  const [wantModel, setWantModel] = useState(true);
  const [enableAi, setEnableAi] = useState(true);
  const [confirm, setConfirm] = useState(false);
  const [taskIds, setTaskIds] = useState<string[]>([]);
  const tools = st.data?.tools.filter((t) => t.installable && !t.installed && t.id !== "ollama") ?? [];
  const chosen = tools.filter((t) => pick[t.id] ?? true).map((t) => t.id);
  const chosenModel = model || st.data?.recommended_model.id || "";
  const plan = useQuery({ queryKey: ["setup-plan", chosen], enabled: chosen.length > 0, queryFn: () => api<{ items: PlanItem[] }>("/setup/plan", { method: "POST", json: { ids: chosen } }) });
  const tasks = useQuery({
    queryKey: ["setup-tasks", taskIds], enabled: taskIds.length > 0,
    refetchInterval: (q) => (q.state.data?.some((t) => t.status === "running") ? 1000 : false),
    queryFn: () => Promise.all(taskIds.map((id) => api<Task>(`/setup/tasks/${id}`))),
  });
  const start = useMutation({
    mutationFn: async () => {
      const ids: string[] = [];
      if (chosen.length) ids.push((await api<{ task_id: string }>("/setup/install", { method: "POST", json: { ids: chosen, confirm: true } })).task_id);
      if (wantModel) ids.push((await api<{ task_id: string }>("/setup/model", { method: "POST", json: { model_id: chosenModel, enable_ai: enableAi, confirm: true } })).task_id);
      return ids;
    },
    onSuccess: (ids) => setTaskIds(ids),
  });
  const done = useMutation({ mutationFn: () => api("/setup/complete", { method: "POST" }), onSuccess: () => qc.invalidateQueries() });
  const running = tasks.data?.some((t) => t.status === "running") ?? false;
  const nothing = chosen.length === 0 && !wantModel;
  if (st.isLoading) return <Loading what="setup status" />;
  if (st.isError) return <ErrorBox error={st.error} />;
  const s = st.data!;
  return (
    <>
      <h2>Setup</h2>
      <div className="banner">
        Optional tools and a local AI model make the app more capable. They download from their publishers, are checked against pinned SHA-256 values,
        install only under <code>{s.tools_dir}</code>, and need no administrator rights. Nothing starts until you confirm below.
      </div>
      <div className="card">
        <b>This machine</b>: {s.platform ?? "unsupported platform"}, {s.ram_gb ?? "unknown"} GB RAM.
      </div>
      <h3>Tools</h3>
      <table>
        <thead><tr><th /><th>Tool</th><th>Version</th><th>Licence</th><th>Status</th></tr></thead>
        <tbody>{s.tools.filter((t) => t.id !== "ollama").map((t) => {
          const can = t.installable && !t.installed;
          return (
            <tr key={t.id}>
              <td>{can && <input type="checkbox" aria-label={`Install ${t.name}`} style={{ width: "auto" }} checked={pick[t.id] ?? true} onChange={(e) => setPick({ ...pick, [t.id]: e.target.checked })} />}</td>
              <td>{t.name}</td><td>{t.version}</td><td className="muted">{t.license}</td>
              <td>{t.installed ? <><Badge v="healthy" /> {t.managed ? "installed by setup" : "found on PATH"}</> : can ? <>not installed{t.download_mb ? ` · ${t.download_mb} MB` : " · hash-locked packages"}</> : <span className="muted">{t.reason}</span>}</td>
            </tr>);
        })}</tbody>
      </table>
      {plan.data && plan.data.items.length > 0 && (
        <details className="card"><summary>Exact sources that will be contacted</summary>
          {plan.data.items.map((p) => <div key={p.id}><b>{p.name} {p.version}</b>{p.urls.map((u) => <div key={u} className="muted"><code>{u}</code></div>)}</div>)}</details>)}
      <h3>Local AI model</h3>
      <div className="card">
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={wantModel} onChange={(e) => setWantModel(e.target.checked)} /> Download a local model and create an AI profile</label>
        <div className="row">
          <select aria-label="Model" value={chosenModel} onChange={(e) => setModel(e.target.value)} style={{ maxWidth: 640 }}>
            {s.models.map((m) => <option key={m.id} value={m.id}>{m.label} — {m.download_gb} GB{m.id === s.recommended_model.id ? " (recommended for this machine)" : ""}</option>)}
          </select>
        </div>
        <p className="muted">
          Runs entirely on this computer, on the CPU (no GPU needed; expect a few words per second on a laptop). These are community
          &ldquo;abliterated&rdquo; builds with the vendor's refusal training removed, so the model itself will not refuse requests. The app&rsquo;s own
          controls (policy checks, cited evidence, approval for every action) still apply, and model output is never treated as evidence.
          {!s.ollama_found && (s.platform === "win32-x86_64"
            ? " Ollama is not installed; setup will download its installer from github.com (about 1.6 GB) and run it silently for the current user."
            : " Ollama is not installed and cannot be installed without administrator rights: install it from ollama.com, then press Install selected again.")}
        </p>
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={enableAi} onChange={(e) => setEnableAi(e.target.checked)} disabled={!wantModel} /> Turn AI features on afterwards (otherwise AI stays off until you enable it in Settings)</label>
      </div>
      <Keys />
      <div className="card">
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I have reviewed the sources above and want to download and install the selected items</label>
        <div className="row" style={{ marginTop: 8 }}>
          <button className="primary" disabled={!confirm || nothing || start.isPending || running} onClick={() => start.mutate()}>Install selected</button>
          <button onClick={() => done.mutate()} disabled={running}>{s.completed ? "Setup marked complete" : "Finish setup"}</button>
        </div>
        {start.isError && <ErrorBox error={start.error} />}
      </div>
      {tasks.data?.map((t) => {
        const last = t.events[t.events.length - 1];
        const frac = last?.total ? Math.min(100, Math.round(((last.bytes ?? last.completed ?? 0) / last.total) * 100)) : null;
        return (
          <div key={t.id} className="card" role="status" aria-live="polite" style={{ marginTop: 8 }}>
            <b>{t.kind === "model" ? "Model" : "Tools"}</b> <Badge v={t.status === "done" ? "succeeded" : t.status === "running" ? "queued" : "failed"} /> {t.status}
            {last && <div className="muted">{last.phase} {last.id ?? last.status ?? ""}{frac !== null ? ` · ${frac}%` : ""}{last.bytes ? ` (${mb(last.bytes)} / ${mb(last.total)} MB)` : ""}</div>}
            {t.results.map((r) => <div key={r.id} className="muted">{r.id}: {r.error ? `FAILED — ${r.error}` : `installed${r.reported_version ? ` (${r.reported_version})` : ""}`}</div>)}
            {t.error && <div className="banner err">{t.error}</div>}
          </div>);
      })}
    </>
  );
}
