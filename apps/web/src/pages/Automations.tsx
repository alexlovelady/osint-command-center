import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { setAppCtx } from "../lib/appContext";
import AutoSettingsPage from "./automations/AutoSettings";
import Builder from "./automations/Builder";
import Inbox from "./automations/Inbox";
import Library, { goWf } from "./automations/Library";
import Runs from "./automations/Runs";
import { Badge, Empty, Loading } from "../components/ui";
import type { WorkflowT } from "../lib/automationsApi";

const TABS = ["Library", "My automations", "Runs", "Inbox", "Settings"] as const;
type Tab = (typeof TABS)[number];

export default function Automations({ workflowId }: { workflowId?: string }) {
  const [tab, setTab] = useState<Tab>("Library");
  useEffect(() => { setAppCtx({ route: "automations", tab: workflowId ? "Builder" : tab, case_id: null, tool_id: null }); }, [tab, workflowId]);
  const notes = useQuery({ queryKey: ["auto-notes-badge"], queryFn: () => api<{ unacknowledged: number }>("/automations/notifications?limit=1"), refetchInterval: 15_000 });
  if (workflowId) return <Builder id={workflowId} />;
  return (
    <>
      <h2>Automations</h2>
      <p className="muted" style={{ marginTop: 0 }}>Reusable, reviewable workflows. Everything is created disabled; nothing collects data on a schedule until you approve and activate it.</p>
      <div className="tabs" role="tablist" aria-label="Automations" data-tour="auto-tabs">
        {TABS.map((t) => <button key={t} role="tab" data-tour={`auto-tab-${t.split(" ")[0].toLowerCase()}`} aria-selected={tab === t} onClick={() => setTab(t)}>{t}{t === "Inbox" && notes.data?.unacknowledged ? ` (${notes.data.unacknowledged})` : ""}</button>)}
      </div>
      {tab === "Library" && <Library />}
      {tab === "My automations" && <Mine />}
      {tab === "Runs" && <Runs />}
      {tab === "Inbox" && <Inbox />}
      {tab === "Settings" && <AutoSettingsPage />}
    </>
  );
}

function Mine() {
  const q = useQuery({ queryKey: ["auto-mine"], queryFn: () => api<{ total: number; items: WorkflowT[] }>("/automations/workflows?limit=200") });
  if (q.isLoading) return <Loading what="automations" />;
  if (!q.data?.items.length) return <Empty title="No automations yet" hint="Create one from a template in the Library, or describe what you want to the AI builder inside any automation."><span className="muted">Open the Library tab.</span></Empty>;
  return (
    <table aria-label="My automations"><thead><tr><th>Name</th><th>State</th><th>Trigger</th><th>Version</th><th /></tr></thead>
      <tbody>{q.data.items.map((w) => (
        <tr key={w.id}><td>{w.name}</td><td><Badge v={w.state === "active" ? "healthy" : w.state === "draft" ? "unknown" : "queued"} /> {w.state}{w.unpublished_changes && w.published ? " · unpublished changes" : ""}</td>
          <td>{w.trigger.type}{w.trigger.schedule ? ` (${w.trigger.schedule} ${w.trigger.timezone})` : ""}</td><td>{w.latest_revision ?? "draft"}</td><td><button onClick={() => goWf(w.id)}>Open</button></td></tr>))}</tbody></table>
  );
}
