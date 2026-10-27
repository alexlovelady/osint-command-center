import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import EdgarContact from "../../components/EdgarContact";
import { useAdvanced } from "../../lib/mode";
import ProviderUsage from "./ProviderUsage";

interface SecretRow { provider: string; label: string; set: boolean; used_by: string[]; get: string; format?: string; state?: { code: string; label: string; hint: string } }
const STATE_BADGE: Record<string, string> = { verified: "st-ok", stored: "st-warn", rejected: "st-bad", wrong_format: "st-bad", plan_restricted: "st-bad", quota_exhausted: "st-warn", not_configured: "st-mute", disabled: "st-mute", disabled_paid: "st-mute" };
interface SourceRow { id: string; label: string; maturity: string; health?: string | null; needs_key: string | null; registered: boolean; operation_class: string }

const MATURITY: Record<string, string> = { live_tested: "Live-tested", mocked_only: "Fixture-tested only", partially_verified: "Partly verified", manual: "Manual" };

function KeyRow({ s }: { s: SecretRow }) {
  const qc = useQueryClient();
  const [v, setV] = useState("");
  const save = useMutation({ mutationFn: () => api(`/secrets/${s.provider}`, { method: "POST", json: { value: v } }), onSuccess: () => { setV(""); qc.invalidateQueries({ queryKey: ["secrets"] }); qc.invalidateQueries({ queryKey: ["summary"] }); } });
  return (
    <li className="row" style={{ padding: "3px 0" }}>
      <b>{s.label}</b><span className={`badge ${STATE_BADGE[s.state?.code ?? ""] ?? (s.set ? "st-warn" : "st-mute")}`} title={s.state?.hint}>{s.state?.label ?? (s.set ? "Stored (not yet tested)" : "Not configured")}</span>
      <span className="muted">used by {s.used_by.join(", ") || "optional sources"}{s.format ? ` · ${s.format}` : ""}</span>
      <input type="password" aria-label={`${s.label}`} placeholder={s.set ? "replace key" : "paste key"} value={v} onChange={(e) => setV(e.target.value)} style={{ width: 220 }} autoComplete="off" />
      <button disabled={!v.trim() || save.isPending} onClick={() => save.mutate()}>Save</button>
      {s.get && <a href={s.get} target="_blank" rel="noreferrer noopener">Get a key</a>}
      {save.isError && <ErrorBox error={save.error} />}
    </li>
  );
}

/** Settings for people who do not want to learn the workbench: mode, provider status and keys, limits, privacy. The full settings follow below. */
export default function SimpleSettings() {
  const [adv, setAdv] = useAdvanced();
  const keys = useQuery({ queryKey: ["secrets"], queryFn: () => api<{ items: SecretRow[]; note: string }>("/secrets"), retry: false });
  const src = useQuery({ queryKey: ["profile-sources"], queryFn: () => api<{ items: SourceRow[] }>("/profile/sources"), retry: false });
  const live = (src.data?.items ?? []).filter((s) => s.registered && s.operation_class !== "manual");
  return (
    <section aria-label="Simple settings">
      <h2>Settings</h2>
      <div className="card" aria-label="Interface">
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={adv} onChange={(e) => setAdv(e.target.checked)} />
          <b>Advanced mode</b><span className="muted">Shows the full workbench: every tab, tool, graph, import, export and expert control. Turning it on or off never changes stored data or any investigation.</span></label>
      </div>
      <div className="card" aria-label="Providers and keys">
        <h3 style={{ marginTop: 0 }}>Providers and keys</h3>
        {keys.isLoading && <Loading what="providers" />}
        {keys.isError && <div className="muted">Key management is available to administrators.</div>}
        {keys.data && <ul style={{ listStyle: "none", padding: 0 }}>{keys.data.items.map((s) => <KeyRow key={s.provider} s={s} />)}</ul>}
        <div className="muted">{keys.data?.note ?? "Keys are stored in the operating system’s credential store."}</div>
        {src.data && (
          <details><summary>Sources and how well each has been tested ({live.length})</summary>
            <table aria-label="Source status"><thead><tr><th>Source</th><th>Testing</th><th>State</th><th>Needs</th></tr></thead>
              <tbody>{live.map((s) => <tr key={s.id}><td>{s.label}</td><td>{MATURITY[s.maturity] ?? s.maturity}</td><td>{(s.health ?? "unknown").replace(/_/g, " ")}</td><td>{s.needs_key ? `key: ${s.needs_key}` : "nothing"}</td></tr>)}</tbody></table>
            <div className="muted">“Fixture-tested” means checked against recorded responses. It has not been proven against the live service.</div></details>)}
      </div>
      <EdgarContact />
      <ProviderUsage />
      <div className="card" aria-label="Limits and privacy">
        <h3 style={{ marginTop: 0 }}>Limits and privacy</h3>
        <ul>
          <li>Each investigation follows leads at most 2 steps out, uses at most 100 source runs and stops after 30 minutes. You can lower these when you start one.</li>
          <li>Only your own inputs and leads you confirm are used as starting points. A handle or address found on the web is a lead until you decide.</li>
          <li>Sources that send an input to a third party run only after you approve the named providers.</li>
          <li>Sensitive values (phone, date of birth, identity references) are masked, never sent to a cloud model, and not written to logs.</li>
          <li>Local AI and backup: open <a href="#/setup">Setup</a> for the local model and tools, and see the operator runbook for encrypted backups.</li>
        </ul>
      </div>
    </section>
  );
}
