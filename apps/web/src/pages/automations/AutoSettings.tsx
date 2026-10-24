import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import type { AutoSettings } from "../../lib/automationsApi";

interface Profiles { items: { id: string; name: string; model_id: string; kind: string }[] }

export default function AutoSettingsPage() {
  const qc = useQueryClient();
  const s = useQuery({ queryKey: ["auto-settings"], queryFn: () => api<AutoSettings>("/automations/settings") });
  const profiles = useQuery({ queryKey: ["ai-profiles"], queryFn: () => api<Profiles>("/ai/profiles") });
  const [hook, setHook] = useState({ name: "", url: "" });
  const save = useMutation({ mutationFn: (values: Record<string, unknown>) => api<AutoSettings>("/automations/settings", { method: "PATCH", json: { values } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["auto-settings"] }) });
  if (s.isLoading) return <Loading what="settings" />;
  if (s.isError || !s.data) return <ErrorBox error={s.error} />;
  const d = s.data;
  const n = d.notifications;
  return (
    <div data-tour="auto-settings">
      {save.isError && <ErrorBox error={save.error} />}
      <h3>Scheduling</h3>
      <div className="row">
        <label>Default time zone (IANA)<input value={d.timezone} onChange={() => {}} onBlur={(e) => e.target.value !== d.timezone && save.mutate({ timezone: e.target.value })} defaultValue={d.timezone} style={{ width: 220 }} /></label>
        <label>Runs at the same time (1-4)<input type="number" min={1} max={4} defaultValue={d.max_concurrent_runs} onBlur={(e) => save.mutate({ max_concurrent_runs: Number(e.target.value) })} style={{ width: 90 }} /></label>
      </div>
      <p className="muted">Schedules run only while this application is open. If it was closed, each schedule's own missed-run policy decides what happens next (default: one catch-up run).</p>
      <h3>Notifications</h3>
      <div className="row">
        <label>Merge repeats within (hours)<input type="number" min={1} max={168} defaultValue={n.dedupe_window_hours} onBlur={(e) => save.mutate({ notifications: { dedupe_window_hours: Number(e.target.value) } })} style={{ width: 90 }} /></label>
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={n.quiet_hours.enabled} onChange={(e) => save.mutate({ notifications: { quiet_hours: { enabled: e.target.checked } } })} />Quiet hours {n.quiet_hours.start}–{n.quiet_hours.end} ({n.quiet_hours.timezone}); critical alerts still arrive</label>
        <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={n.digest.enabled} onChange={(e) => save.mutate({ notifications: { digest: { enabled: e.target.checked } } })} />Daily digest at {n.digest.time} for info-level notices</label>
      </div>
      <p className="muted">Email: {d.email.note}.</p>
      <h4>Webhook destinations</h4>
      <p className="muted">A workflow can only post to a destination listed here, by name. The address is stored here, never in a workflow or an export.</p>
      <ul>{Object.entries(n.webhooks).map(([k, u]) => <li key={k}><b>{k}</b> <code>{u.replace(/(https?:\/\/[^/]+).*/, "$1/…")}</code> <button onClick={() => { const w = { ...n.webhooks }; delete w[k]; save.mutate({ notifications: { webhooks: w } }); }}>Remove</button></li>)}</ul>
      <div className="row"><input aria-label="Webhook name" placeholder="name (e.g. ops)" value={hook.name} onChange={(e) => setHook({ ...hook, name: e.target.value })} style={{ maxWidth: 160 }} />
        <input aria-label="Webhook URL" placeholder="https://…" value={hook.url} onChange={(e) => setHook({ ...hook, url: e.target.value })} style={{ maxWidth: 360 }} />
        <button onClick={() => { save.mutate({ notifications: { webhooks: { ...n.webhooks, [hook.name]: hook.url } } }); setHook({ name: "", url: "" }); }} disabled={!hook.name || !hook.url}>Approve destination</button></div>
      <h3>Suggestions</h3>
      <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={d.suggestions.enabled} onChange={(e) => save.mutate({ suggestions: { enabled: e.target.checked } })} />Suggest repetitive task automations (uses only searches and reports you run in this app; never turns anything on)</label>
      <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={d.suggestions.include_sensitive} onChange={(e) => save.mutate({ suggestions: { include_sensitive: e.target.checked } })} />Include personal (people) investigations</label>
      <h3>Cloud AI for automations</h3>
      <p className="muted">By default no cloud model receives anything from automations. Allow a specific profile to receive goals and run diagnostics (never evidence content in drafts).</p>
      {(profiles.data?.items ?? []).filter((p) => p.kind === "cloud").length === 0 && <p className="muted">No cloud profile is configured.</p>}
      {(profiles.data?.items ?? []).filter((p) => p.kind === "cloud").map((p) => (
        <label key={p.id} className="row"><input type="checkbox" style={{ width: "auto" }} checked={d.cloud_ai_opt_in.includes(p.id)}
          onChange={(e) => save.mutate({ cloud_ai_opt_in: e.target.checked ? [...d.cloud_ai_opt_in, p.id] : d.cloud_ai_opt_in.filter((x) => x !== p.id) })} />{p.name} ({p.model_id})</label>))}
    </div>
  );
}
