import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/ui";
import { api } from "../../lib/api";
import { INPUT_KINDS, kindLabel, type ManifestRow, type PrepareOut, type RunRow } from "../../lib/investigationApi";

interface Chip { kind: string; value: string }
interface Detected { value: string; kind: string | null; alternatives: string[] }

const GROUPS: [string[], string, string][] = [
  [["ready"], "Will run now", "These run as soon as you press Investigate."],
  [["needs_approval"], "Will run if you approve (sends the input to a third party)", "Pressing Investigate approves exactly the providers ticked here. Untick any you do not want."],
  [["needs_key"], "Needs an API key", "Not run. Add the key in Settings to enable it; nothing is sent."],
  [["needs_authorization", "not_installed", "blocked"], "Not available here", "Not run, with the reason."],
  [["unsupported_input"], "No supported source for this input", "Stored with the investigation; nothing is searched with it."],
  [["separate_approval"], "Needs its own approval later", "Active checks and exposure checks always ask separately."],
];

function PlanGroup({ rows, title, hint, excluded, toggle }: { rows: ManifestRow[]; title: string; hint: string; excluded: string[]; toggle: (id: string) => void }) {
  if (!rows.length) return null;
  const optional = rows.some((r) => r.status === "needs_approval" || r.status === "ready");
  return (
    <div className="card" aria-label={title}>
      <b>{title}</b> <span className="muted">({rows.length})</span>
      <div className="muted">{hint}</div>
      <ul style={{ listStyle: "none", padding: 0, margin: "6px 0 0" }}>
        {rows.map((r) => (
          <li key={r.key} className="row" style={{ padding: "2px 0" }}>
            {optional && r.source_id ? <label><input type="checkbox" style={{ width: "auto" }} checked={!excluded.includes(r.source_id)} onChange={() => toggle(r.source_id)} aria-label={`Include ${r.source} for ${r.identifier}`} /> {r.source}</label> : <span>{r.source}</span>}
            <span className="muted">on {kindLabel(r.identifier_kind).toLowerCase()} <code>{r.identifier}</code></span>
            {r.recipients.length > 0 && <span className="muted">→ {r.recipients.join(", ")}</span>}
            {r.maturity && r.maturity !== "live_tested" && r.maturity !== "manual" && <span className="badge st-mute" title="Tested against recorded responses, not yet against the live service">fixture-tested</span>}
            {r.status !== "ready" && r.status !== "needs_approval" && <span className="muted">— {r.reason}</span>}
          </li>))}
      </ul>
    </div>
  );
}

/** New investigation: pick Person or Business, add one or more identifiers, see exactly who would be contacted, then one click. */
export default function NewInvestigation({ go }: { go: (to: string) => void }) {
  const [kind, setKind] = useState<"person" | "business">("person");
  const [chips, setChips] = useState<Chip[]>([]);
  const [draft, setDraft] = useState("");
  const [draftKind, setDraftKind] = useState("");
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [mode, setMode] = useState<"self" | "organization">("self");
  const [authorized, setAuthorized] = useState(false);
  const [who, setWho] = useState("");
  const [plan, setPlan] = useState<PrepareOut | null>(null);
  const [existing, setExisting] = useState("");
  const runs = useQuery({ queryKey: ["investigations"], queryFn: () => api<{ items: RunRow[] }>("/investigations") });
  const targets = [...new Map((runs.data?.items ?? []).map((r) => [r.subject_id, r])).values()];
  const [excluded, setExcluded] = useState<string[]>([]);

  const detect = useMutation({ mutationFn: (text: string) => api<{ inputs: Detected[] }>("/investigations/detect", { method: "POST", json: { text, investigation: kind } }) });
  const add = async () => {
    const text = draft.trim();
    if (!text) return;
    const res = await detect.mutateAsync(text).catch(() => null);
    const found = (res?.inputs ?? []).filter((d) => d.kind);
    const next = draftKind && found.length === 1 ? [{ kind: draftKind, value: found[0].value }] : found.map((d) => ({ kind: d.kind as string, value: d.value }));
    setChips((c) => [...c, ...next.filter((n) => !c.some((x) => x.kind === n.kind && x.value.toLowerCase() === n.value.toLowerCase()))]);
    setDraft("");
    setDraftKind("");
    setPlan(null);
  };
  const body = (start: boolean) => ({ kind, display_name: name, purpose, mode: kind === "person" ? mode : "organization", inputs: chips, subject_id: plan?.subject_id ?? (existing || undefined), start,
    authorization: authorized ? { verification_method: "self_attestation", verifier: who || "me", expires_days: 30 } : undefined });
  const prepare = useMutation({ mutationFn: () => api<PrepareOut>("/investigations", { method: "POST", json: body(false) }), onSuccess: (p) => { setPlan(p); setExcluded([]); } });
  const run = useMutation({
    mutationFn: async () => {
      if (!plan) throw new Error("Review the plan first");
      const approved = plan.manifest.approvable.filter((s) => !excluded.includes(s));
      return api<{ id: string }>(`/subjects/${plan.subject_id}/investigations`, { method: "POST", json: { approved_sources: approved, excluded_sources: excluded, kind } });
    },
    onSuccess: (r) => go(`investigation/${r.id}`),
  });
  const rows = plan?.manifest.rows ?? [];
  const canPlan = chips.length > 0 && (authorized || plan !== null || existing !== "");
  return (
    <section aria-label="New investigation">
      <h2>New investigation</h2>
      <div className="tabs" role="tablist" aria-label="What are you investigating?">
        {(["person", "business"] as const).map((k) => <button key={k} role="tab" aria-selected={kind === k} onClick={() => { setKind(k); setPlan(null); }}>{k === "person" ? "A person" : "A business"}</button>)}
      </div>
      <div className="card">
        <label htmlFor="inv-input"><b>What do you know?</b> <span className="muted">One is enough. More inputs improve precision and coverage. You can paste several at once.</span></label>
        <div className="row" style={{ marginTop: 6 }}>
          <input id="inv-input" aria-label="Add an identifier" placeholder="Email, @username, website, phone, name, or business name" value={draft} onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void add(); } }} style={{ flex: 1, minWidth: 260 }} />
          <select aria-label="Type of the value being added" value={draftKind} onChange={(e) => setDraftKind(e.target.value)} style={{ width: 200 }}>
            <option value="">Detect automatically</option>{INPUT_KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <button onClick={() => void add()} disabled={!draft.trim() || detect.isPending}>Add</button>
        </div>
        <ul className="chips" aria-label="Identifiers to investigate" style={{ listStyle: "none", padding: 0 }}>
          {chips.map((c, i) => (
            <li key={`${c.kind}:${c.value}`} className="chip badge">
              <select aria-label={`Type of ${c.value}`} value={c.kind} onChange={(e) => { setChips(chips.map((x, j) => (j === i ? { ...x, kind: e.target.value } : x))); setPlan(null); }} style={{ width: "auto", padding: 0, border: "none", background: "none" }}>
                {INPUT_KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
              {" "}<code>{c.kind === "phone" ? c.value.replace(/\d(?=\d{2})/g, "•") : c.value}</code>{" "}
              <button aria-label={`Remove ${c.value}`} onClick={() => { setChips(chips.filter((_, j) => j !== i)); setPlan(null); }} style={{ padding: "0 6px" }}>×</button>
            </li>))}
        </ul>
        {chips.some((c) => c.kind === "phone") && <div className="muted">A phone number is stored privately and masked. No approved phone-lookup source is configured, so nothing will be searched with it.</div>}
      </div>
      {targets.length > 0 && (
        <div className="card">
          <label>Start fresh, or add these to something you already have
            <select aria-label="Existing target" value={existing} onChange={(e) => { setExisting(e.target.value); setPlan(null); }}>
              <option value="">A new investigation</option>{targets.map((r) => <option key={r.subject_id} value={r.subject_id}>Add to: {r.name}</option>)}</select></label>
        </div>)}
      <div className="card">
        <div className="row">
          <label className="grow">Name for this investigation (optional)<input aria-label="Name for this investigation" value={name} onChange={(e) => setName(e.target.value)} placeholder="Defaults to the first thing you entered" /></label>
          {kind === "person" && (
            <label>Whose information is this?
              <select aria-label="Whose information is this" value={mode} onChange={(e) => setMode(e.target.value as "self" | "organization")}>
                <option value="self">My own (a self-audit)</option><option value="organization">An organization’s public information</option></select></label>)}
        </div>
        <label>Why are you doing this? <span className="muted">Recorded with the investigation.</span>
          <input aria-label="Purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder={mode === "self" ? "self audit of my own public footprint" : "purpose"} /></label>
        <div className="row" style={{ marginTop: 6 }}>
          <label><input type="checkbox" style={{ width: "auto" }} checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
            {" "}I confirm this is my own information, or I have the right to research it, for the purpose above (recorded as a 30-day authorization).</label>
        </div>
        {authorized && <label>Your name (recorded as the person who confirmed)<input aria-label="Your name" value={who} onChange={(e) => setWho(e.target.value)} /></label>}
        <div className="muted">Researching someone else on a client’s behalf needs written consent: use the Advanced workbench’s Authorization tab.</div>
      </div>
      <div className="row">
        <button className="primary" disabled={!canPlan || prepare.isPending} onClick={() => prepare.mutate()}>{plan ? "Update plan" : "Review plan"}</button>
        {!authorized && chips.length > 0 && !plan && <span className="muted">Confirm the authorization above to continue.</span>}
      </div>
      {prepare.isError && <ErrorBox error={prepare.error} />}
      {plan && (
        <div aria-label="Plan">
          <h3>What will happen</h3>
          <div className="banner" role="status">
            {plan.manifest.third_parties.length
              ? <>Inputs would be sent to: <b>{plan.manifest.third_parties.join(", ")}</b>.</>
              : <>No third party would be contacted.</>}
            {" "}Limits: leads are followed at most 2 steps out, with at most 100 source runs and 30 minutes. Found handles and addresses are leads: they are not researched until you confirm them.
          </div>
          {plan.skipped.length > 0 && <div className="banner warn">{plan.skipped.map((s) => `${kindLabel(s.kind)}: ${s.message}`).join(" · ")}</div>}
          {GROUPS.map(([codes, title, hint]) => <PlanGroup key={title} rows={rows.filter((r) => codes.includes(r.status))} title={title} hint={hint} excluded={excluded} toggle={(id) => setExcluded(excluded.includes(id) ? excluded.filter((x) => x !== id) : [...excluded, id])} />)}
          <div className="row">
            <button className="primary" style={{ fontSize: 15, padding: "8px 22px" }} onClick={() => run.mutate()} disabled={run.isPending}>Investigate</button>
            <span className="muted">You can pause or stop at any time. Results already collected are kept.</span>
          </div>
          {run.isError && <ErrorBox error={run.error} />}
        </div>)}
    </section>
  );
}
