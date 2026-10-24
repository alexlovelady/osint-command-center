import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox } from "../components/ui";
import { api } from "../lib/api";

interface Prof { id: string; name: string; model_id: string; provider_type: string; kind: string }
interface Plug { plugin_id: string; version: string; name: string; enabled: boolean; active: boolean; health: string; tree_sha256: string; maintainer: string; license: string;
  permissions: { network_domains: string[]; max_requests: number }; compatibility: Record<string, boolean>; network_isolation: string }
interface Appr { id: string; tool: string; client: string; arguments: Record<string, unknown>; case_id: string | null }
interface Vault { mode: string; key_available: boolean; objects: number; encrypted_objects: number; plaintext_objects: number; database_encrypted: boolean; note: string }

export default function AdminPanel() {
  const qc = useQueryClient();
  const all = () => qc.invalidateQueries();
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api<{ ai_enabled: boolean; edgar_contact: string | null }>("/settings") });
  const profs = useQuery({ queryKey: ["aiprof"], queryFn: () => api<{ items: Prof[] }>("/ai/profiles") });
  const plugs = useQuery({ queryKey: ["plugins"], queryFn: () => api<{ items: Plug[] }>("/plugins") });
  const appr = useQuery({ queryKey: ["mcp"], queryFn: () => api<{ items: Appr[] }>("/mcp/approvals"), refetchInterval: 4000 });
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => api<Vault>("/system/vault") });
  const put = useMutation({ mutationFn: (v: Record<string, unknown>) => api("/settings", { method: "PUT", json: { values: v } }), onSuccess: all });
  const [np, setNp] = useState({ name: "", provider_type: "ollama", model_id: "", base_url: "" });
  const addProf = useMutation({ mutationFn: () => api("/ai/profiles", { method: "POST", json: { ...np, base_url: np.base_url || undefined } }), onSuccess: () => { setNp({ ...np, name: "", model_id: "" }); all(); } });
  const delProf = useMutation({ mutationFn: (id: string) => api(`/ai/profiles/${id}`, { method: "DELETE" }), onSuccess: all });
  const [path, setPath] = useState("");
  const install = useMutation({ mutationFn: () => api("/plugins/install", { method: "POST", json: { path } }), onSuccess: () => { setPath(""); all(); } });
  const enable = useMutation({ mutationFn: (p: Plug) => api(`/plugins/${p.plugin_id}/${p.version}/enable`, { method: "POST", json: { accept_hash: p.tree_sha256 } }), onSuccess: all });
  const disable = useMutation({ mutationFn: (p: Plug) => api(`/plugins/${p.plugin_id}/disable`, { method: "POST" }), onSuccess: all });
  const decide = useMutation({ mutationFn: (v: { id: string; ok: boolean }) => api(`/mcp/approvals/${v.id}/${v.ok ? "approve" : "deny"}`, { method: "POST" }), onSuccess: all });
  const encrypt = useMutation({ mutationFn: () => api("/system/vault/encrypt-existing", { method: "POST" }), onSuccess: all });
  const [pass, setPass] = useState("");
  const backup = useMutation({ mutationFn: () => api<{ file: string; encrypted: boolean; verification: { ok: boolean; files: number } }>("/backups", { method: "POST", json: { passphrase: pass || undefined, allow_plaintext: !pass } }) });
  const [contact, setContact] = useState("");
  const err = put.error ?? addProf.error ?? install.error ?? enable.error ?? decide.error ?? encrypt.error ?? backup.error;
  return (
    <>
      {err && <ErrorBox error={err} />}
      <h3>AI</h3>
      <div className="card">
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={!!settings.data?.ai_enabled} onChange={(e) => put.mutate({ ai_enabled: e.target.checked })} /> Enable AI features (off by default; nothing else depends on it)</label>
        <p className="muted">Local models: Ollama or any llama.cpp-compatible server on this machine, any model name you like. Cloud models are optional and need a per-case allowance plus approval of each payload.</p>
        <form className="row" onSubmit={(e) => { e.preventDefault(); addProf.mutate(); }}>
          <input aria-label="Profile name" placeholder="name" value={np.name} onChange={(e) => setNp({ ...np, name: e.target.value })} style={{ width: 150 }} />
          <select aria-label="Provider" value={np.provider_type} onChange={(e) => setNp({ ...np, provider_type: e.target.value })} style={{ width: 130 }}>{["ollama", "llamacpp", "fixture"].map((x) => <option key={x}>{x}</option>)}</select>
          <input aria-label="Model" placeholder="model (e.g. llama3:8b)" value={np.model_id} onChange={(e) => setNp({ ...np, model_id: e.target.value })} style={{ width: 200 }} />
          <input aria-label="Base URL" placeholder="loopback URL (optional)" value={np.base_url} onChange={(e) => setNp({ ...np, base_url: e.target.value })} style={{ width: 220 }} />
          <button className="primary" disabled={!np.name || !np.model_id}>Add profile</button></form>
        {profs.data?.items.map((p) => <div key={p.id} className="row"><Badge v={p.kind === "local" ? "healthy" : "medium"} /> {p.name} · {p.provider_type} · {p.model_id} <button onClick={() => delProf.mutate(p.id)}>Remove</button></div>)}
      </div>
      <h3>Plugins</h3>
      <div className="card">
        <p className="muted">Plugins are off until you review and enable them. Enabling records the exact hash you saw; any later file change disables the plugin. Network access is mediated by the host and limited to the domains declared below. Filesystem isolation is not enforced by the OS.</p>
        <div className="row"><input aria-label="Plugin folder" placeholder="Path to a plugin folder containing plugin.json" value={path} onChange={(e) => setPath(e.target.value)} style={{ flex: 1 }} /><button disabled={!path} onClick={() => install.mutate()}>Install</button></div>
        {plugs.data?.items.length === 0 && <Empty title="No plugins installed" />}
        {plugs.data?.items.map((p) => (
          <div key={p.plugin_id + p.version} className="card" style={{ marginTop: 6 }}>
            <b>{p.name}</b> {p.version} <Badge v={p.health === "enabled" ? "healthy" : p.health === "quarantined" || p.health === "tampered" ? "failed" : "unknown"} /> {p.health}{p.active && " · active"}
            <div className="muted">{p.maintainer} · {p.license} · network: {p.permissions.network_domains.join(", ") || "none"} (≤{p.permissions.max_requests} requests) · compat {Object.entries(p.compatibility).filter(([, v]) => !v).map(([k]) => k).join(", ") || "ok"}</div>
            <div className="muted">tree sha256 <code>{p.tree_sha256}</code></div>
            <div className="row">{p.enabled ? <button onClick={() => disable.mutate(p)}>Disable</button> : <button className="primary" onClick={() => enable.mutate(p)}>I reviewed it — enable this exact version</button>}</div>
          </div>))}
      </div>
      <h3>MCP approvals</h3>
      <div className="card">
        <p className="muted">An MCP client asked to change something. Nothing happens until you approve it here; approval is bound to the exact arguments and works once.</p>
        {appr.data?.items.length === 0 && <Empty title="Nothing waiting" />}
        {appr.data?.items.map((a) => (
          <div key={a.id} className="row"><b>{a.tool}</b> from <code>{a.client}</code> <code>{JSON.stringify(a.arguments).slice(0, 160)}</code>
            <button className="primary" onClick={() => decide.mutate({ id: a.id, ok: true })}>Approve</button><button onClick={() => decide.mutate({ id: a.id, ok: false })}>Deny</button></div>))}
      </div>
      <h3>Encryption &amp; backup</h3>
      <div className="card">
        {vault.data && <p>Evidence vault: <Badge v={vault.data.key_available ? "healthy" : "failed"} /> {vault.data.encrypted_objects}/{vault.data.objects} objects encrypted{vault.data.plaintext_objects > 0 && <> · <button onClick={() => encrypt.mutate()}>Encrypt the {vault.data.plaintext_objects} older object(s)</button></>}
          <br /><span className="muted">{vault.data.note} Key: OS credential store. Losing it makes encrypted evidence unreadable; keep an encrypted backup.</span></p>}
        <div className="row"><input type="password" aria-label="Backup passphrase" placeholder="Backup passphrase (8+ characters)" value={pass} onChange={(e) => setPass(e.target.value)} style={{ maxWidth: 320 }} />
          <button onClick={() => backup.mutate()}>{pass ? "Create encrypted backup" : "Create UNENCRYPTED backup"}</button></div>
        {backup.data && <p>Created <code>{backup.data.file}</code> — {backup.data.encrypted ? "AES-256-GCM encrypted" : "not encrypted"}, {backup.data.verification.ok ? "verified" : "VERIFICATION FAILED"} ({backup.data.verification.files} files).</p>}
      </div>
      <h3>SEC EDGAR contact</h3>
      <div className="card row"><input aria-label="EDGAR contact" placeholder={settings.data?.edgar_contact ?? "Your Name you@example.org (sent as the SEC-required User-Agent)"} value={contact} onChange={(e) => setContact(e.target.value)} style={{ flex: 1 }} />
        <button disabled={!contact.includes("@")} onClick={() => { put.mutate({ edgar_contact: contact }); setContact(""); }}>Save</button></div>
    </>
  );
}
