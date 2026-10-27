import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api } from "../../lib/api";
import { ACTIVE_STATUSES, WAITING_STATUSES, INPUT_KINDS, STATUS_BADGE, STATUS_TEXT, STOP_TEXT, kindLabel, type Candidate, type Inbox, type RunEvent, type Summary } from "../../lib/investigationApi";
import type { MasterDoc, MasterItem } from "../../lib/masterApi";
import { DecisionBar, InboxList } from "./Review";

const VIEWS = ["Overview", "Profile", "Findings", "Activity & Coverage"] as const;
type View = (typeof VIEWS)[number];
const STATE_BADGE: Record<string, string> = { corroborated: "st-ok", self_attested: "st-warn", candidate: "st-warn", conflicting: "st-bad", rejected: "st-bad", unassessed: "st-mute", not_available: "st-mute" };
const STATE_NAME: Record<string, string> = { corroborated: "Independently corroborated", self_attested: "Self-attested", candidate: "Unverified candidate", conflicting: "Conflicting", rejected: "Rejected", unassessed: "Your input (not checked)", not_available: "Not available" };

const GROUP_OF: Record<string, string> = { identity: "Identity & contact", contact: "Identity & contact", online_footprint: "Accounts & online presence", employment: "Organizations & work", education: "Organizations & work",
  business: "Organizations & work", locations: "Locations", images_documents: "Media & documents", relationships: "Relationships", security_exposure: "Security & exposure", devices: "Security & exposure",
  timeline: "Timeline", custom: "Other" };
const GROUP_ORDER = ["Identity & contact", "Accounts & online presence", "Organizations & work", "Locations", "Media & documents", "Relationships", "Security & exposure", "Timeline", "Other"];

function StateBadge({ s, own }: { s: string; own?: boolean }) {
  return <span className={`badge ${own && s === "candidate" ? "st-mute" : STATE_BADGE[s] ?? "st-mute"}`}>{own && s === "candidate" ? "Your entry (not checked)" : STATE_NAME[s] ?? s}</span>;
}

function AddInput({ run, onDone }: { run: Summary; onDone: () => void }) {
  const [kind, setKind] = useState("email");
  const [value, setValue] = useState("");
  const [owned, setOwned] = useState(false);
  const [rel, setRel] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      await api(`/investigations`, { method: "POST", json: { kind: run.run.kind, subject_id: run.subject.id, inputs: [{ kind, value, ...(kind === "organization" && rel ? { relationship: rel } : {}) }] } });
      if (!ACTIVE_STATUSES.includes(run.run.status) && run.run.status !== "cancelled") await api(`/investigations/${run.run.id}/resume`, { method: "POST" });
    },
    onSuccess: () => { setValue(""); setOwned(false); setRel(""); onDone(); },
  });
  const needsOwnership = kind === "domain" || kind === "organization";
  return (
    <form className="row" aria-label="Add another input" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
      <select aria-label="Type of the new input" value={kind} onChange={(e) => setKind(e.target.value)} style={{ width: 200 }}>{INPUT_KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      <input aria-label="New input value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Another email, username, website, business or owned domain" style={{ flex: 1, minWidth: 240 }} />
      {kind === "organization" && (
        <select aria-label="Your connection to the organization" value={rel} onChange={(e) => setRel(e.target.value)} style={{ width: 200 }}>
          <option value="">Connection (optional)</option><option value="founder">Founder</option><option value="owner">Owner</option><option value="employee">Employee</option><option value="contractor">Contractor</option><option value="other">Other</option></select>)}
      {needsOwnership && (
        <label style={{ flexBasis: "100%" }}><input type="checkbox" style={{ width: "auto" }} checked={owned} onChange={(e) => setOwned(e.target.checked)} />
          {" "}{kind === "domain" ? "I own this domain, or am authorized to research it. Domain lookups run only for domains you list here; an email address never implies one." : "This is a business I own or represent, or its public records are in scope."}</label>)}
      <button disabled={!value.trim() || add.isPending || (needsOwnership && !owned)}>Add and continue</button>
      {add.isError && <ErrorBox error={add.error} />}
    </form>
  );
}

function ReportCard({ s }: { s: Summary }) {
  const sid = s.subject.id;
  const [audience, setAudience] = useState<"subject" | "analyst">("subject");
  const [text, setText] = useState("");
  const prev = useMutation({ mutationFn: () => api<{ markdown: string }>(`/subjects/${sid}/report/preview`, { method: "POST", json: { audience } }), onSuccess: (r) => setText(r.markdown) });
  const save = useMutation({ mutationFn: () => api<{ file: string; sha256: string }>(`/subjects/${sid}/report/create`, { method: "POST", json: { audience, format: audience === "analyst" ? "json" : "markdown" } }) });
  return (
    <div className="card" aria-label="Report">
      <b>Report</b> <span className="muted">A brief is readable and redacted. The expert export carries the full provenance. Each statement cites its evidence; restricted values are never included.</span>
      <div className="row">
        <select aria-label="Report type" value={audience} onChange={(e) => { setAudience(e.target.value as "subject" | "analyst"); setText(""); }} style={{ width: 220 }}><option value="subject">Simple brief</option><option value="analyst">Expert (analyst) export</option></select>
        <button onClick={() => prev.mutate()} disabled={prev.isPending}>Preview</button>
        <button onClick={() => save.mutate()} disabled={save.isPending}>Save sealed copy</button>
      </div>
      {save.data && <div className="banner" role="status">Saved {save.data.file} (SHA-256 {save.data.sha256.slice(0, 16)}…).</div>}
      {text && <pre aria-label="Report preview" style={{ whiteSpace: "pre-wrap", maxHeight: 320, overflow: "auto" }}>{text}</pre>}
      {(prev.isError || save.isError) && <ErrorBox error={prev.error ?? save.error} />}
    </div>
  );
}

function Overview({ s, refresh, setView, go }: { s: Summary; refresh: () => void; setView: (v: View) => void; go: (to: string) => void }) {
  const run = s.run;
  const act = useMutation({ mutationFn: (a: string) => api(`/investigations/${run.id}/${a}`, { method: "POST" }), onSuccess: refresh });
  const pending = s.manifest.rows.filter((r) => r.status === "needs_approval" && !run.approved_sources.includes(r.source_id));
  const approve = useMutation({ mutationFn: () => api(`/investigations/${run.id}/approve`, { method: "POST", json: { sources: [...new Set(pending.map((r) => r.source_id))] } }), onSuccess: refresh });
  const active = ACTIVE_STATUSES.includes(run.status);
  const parked = WAITING_STATUSES.includes(run.status);
  const u = s.progress.units;
  return (
    <>
      <div className="card" aria-label="Progress">
        <div className="row">
          <span className={`badge ${STATUS_BADGE[run.status]}`}>{STATUS_TEXT[run.status]}</span>
          <span>{STOP_TEXT[run.stop_reason] ?? (active ? "Working. This page updates by itself." : "")}</span>
          <span className="grow" />
          {(active || parked) && <button onClick={() => act.mutate("pause")}>Pause</button>}
          {["paused", "awaiting_review", "complete_with_limits", "failed"].includes(run.status) && <button className="primary" onClick={() => act.mutate("resume")} title="Looks for new work only: nothing already checked is repeated.">{run.status === "paused" ? "Resume" : "Check for more"}</button>}
          {["awaiting_review", "complete_with_limits", "completed", "failed"].includes(run.status) && <button onClick={() => act.mutate("refresh")} title="Runs the permitted checks again, inside the same limits and approvals. Earlier results are kept.">Refresh results</button>}
          {run.status !== "cancelled" && run.status !== "completed" && <button onClick={() => act.mutate("cancel")}>Stop</button>}
        </div>
        <div className="row" style={{ marginTop: 6 }}>
          <span><b>{u.done}</b> completed</span><span><b>{u.no_match ?? 0}</b> no match</span><span><b>{u.running}</b> running</span><span><b>{u.queued ?? 0}</b> queued</span>
          <span><b>{u.waiting_limits ?? 0}</b> waiting for limits</span><span><b>{u.blocked ?? 0}</b> blocked by key or plan</span><span><b>{u.failed}</b> failed</span><span><b>{u.unavailable ?? 0}</b> not available here</span><span><b>{u.remaining ?? 0}</b> remaining</span>
          <span><b>{u.waiting_approval}</b> waiting for approval</span><span><b>{u.not_run}</b> not run, with reasons</span>
        </div>
        {(u.waiting_limits ?? 0) > 0 && (
          <div className="banner" role="status" aria-label="Waiting for provider limits">
            <b>{u.waiting_limits} check(s) are waiting for a provider’s limit to reset.</b> Nothing needs you; they continue by themselves
            {s.progress.next_eligible_at ? <> (earliest around {s.progress.next_eligible_at.slice(0, 16).replace("T", " ")} UTC; an estimate, not a promise)</> : null}.
            <div className="row"><button onClick={() => go("settings")}>See provider usage</button></div>
          </div>)}
        <div className="muted">{s.progress.label}</div>
        {s.progress.last_error && <div className="banner err">{s.progress.last_error}</div>}
        {act.isError && <ErrorBox error={act.error} />}
      </div>
      {pending.length > 0 && (
        <div className="banner warn" role="status" aria-label="Approval needed">
          <b>Needs your approval.</b> These providers would receive an input: {[...new Set(pending.map((r) => `${r.source} (${r.recipients.join(", ") || "third party"})`))].join("; ")}.
          <div className="row"><button className="primary" onClick={() => approve.mutate()} disabled={approve.isPending}>Approve these providers and continue</button></div>
          {approve.isError && <ErrorBox error={approve.error} />}
        </div>)}
      <div className="cards" aria-label="Key facts">
        <div className="card"><div>Independently corroborated</div><div className="n">{s.fact_counts.independently_corroborated}</div></div>
        <div className="card"><div>Self-attested</div><div className="n">{s.fact_counts.self_attested}</div></div>
        <div className="card"><div>Possible, unverified</div><div className="n">{s.possible_associations}</div></div>
        <div className="card"><div>Decisions waiting</div><div className="n">{s.decisions.open}</div></div>
      </div>
      {s.fact_counts.independently_corroborated + s.fact_counts.self_attested + s.fact_counts.self_provided > 0 && (
        <div className="card" aria-label="Confirmed and provided facts">
          <b>What is known</b>
          <ul>
            {[...s.facts.independently_corroborated, ...s.facts.self_attested, ...s.facts.self_provided].slice(0, 10).map((f, i) => (
              <li key={`${f.value}${i}`}>{f.type}: <b>{f.value}</b> <StateBadge s={f.state} /></li>))}
          </ul>
          <div className="muted">Possible associations are kept separate and are not counted here. <button onClick={() => setView("Profile")}>Open the full profile</button></div>
        </div>)}
      {s.limits.length > 0 && (
        <div className="card" aria-label="Limits">
          <b>What could not be done</b>
          <ul>{s.limits.slice(0, 8).map((l, i) => <li key={`${l.code}${i}`}>{l.source ? <b>{l.source}</b> : null}{l.input ? <> on {l.input}</> : null}: {l.text}</li>)}</ul>
          {s.limits.length > 8 && <button onClick={() => setView("Activity & Coverage")}>See all {s.limits.length}</button>}
          <div className="muted">A source that did not run says nothing about the subject. “Nothing found” appears only where a permitted source actually ran.</div>
        </div>)}
      {s.decisions.open > 0 && (
        <div className="card" aria-label="Next decisions">
          <b>Next decisions</b>
          <ul>{s.decisions.top.map((d) => <li key={d.id}>{d.title} <span className="muted">({d.detail})</span></li>)}</ul>
          <button className="primary" onClick={() => go("review")}>Review {s.decisions.open} item(s)</button>
        </div>)}
      <div className="card"><b>Improve coverage</b><div className="muted">{s.invite}</div><AddInput run={s} onDone={refresh} /></div>
      <ReportCard s={s} />
    </>
  );
}

function Reclassify({ it, doc, sid, done }: { it: MasterItem; doc: MasterDoc; sid: string; done: () => void }) {
  const [to, setTo] = useState("");
  const [reason, setReason] = useState("");
  const [pv, setPv] = useState<{ effects: string[]; to_category: string } | null>(null);
  const types = doc.types.filter((t) => !t.restricted && !t.reference_only && t.type !== it.type && t.type !== "custom" && !t.feeds_research);
  const url = `/subjects/${sid}/master/items/${encodeURIComponent(it.id)}`;
  const preview = useMutation({ mutationFn: () => api<{ effects: string[]; to_category: string }>(`${url}/reclassify`, { method: "POST", json: { to_type: to, preview: true } }), onSuccess: setPv });
  const apply = useMutation({ mutationFn: () => api(`${url}/reclassify`, { method: "POST", json: { to_type: to, reason } }), onSuccess: () => { setPv(null); setTo(""); done(); } });
  const undo = useMutation({ mutationFn: () => api(`${url}/reclassify/undo`, { method: "POST" }), onSuccess: done });
  return (
    <div className="row" aria-label="Change type">
      <select aria-label={`New type for ${it.value}`} value={to} onChange={(e) => { setTo(e.target.value); setPv(null); }} style={{ width: 220 }}><option value="">Change type…</option>{types.map((t) => <option key={t.type} value={t.type}>{t.label}</option>)}</select>
      {to && <button onClick={() => preview.mutate()}>Preview</button>}
      <button onClick={() => undo.mutate()} title="Undo the last type change">Undo type change</button>
      {pv && (
        <div className="banner" style={{ flexBasis: "100%" }}>
          <ul>{pv.effects.map((e) => <li key={e}>{e}</li>)}</ul>
          <div className="row"><input aria-label="Why the type is wrong" placeholder="Why (recorded)" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button className="primary" disabled={reason.trim().length < 5 || apply.isPending} onClick={() => apply.mutate()}>Change type</button></div>
        </div>)}
      {(preview.isError || apply.isError) && <ErrorBox error={preview.error ?? apply.error} />}
    </div>
  );
}

function Dossier({ s, go }: { s: Summary; go: (to: string) => void }) {
  const sid = s.subject.id;
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["master", sid, "", ""], queryFn: () => api<MasterDoc>(`/subjects/${sid}/master`) });
  const [open, setOpen] = useState<string | null>(null);
  if (q.isLoading) return <Loading what="the profile" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const doc = q.data;
  const refresh = () => qc.invalidateQueries({ queryKey: ["master", sid] });
  const groups = GROUP_ORDER.map((g) => ({ g, items: doc.sections.filter((x) => GROUP_OF[x.key] === g).flatMap((x) => x.items.map((i) => ({ ...i, section: x.title }))) }));
  const filled = groups.filter((x) => x.items.length), empty = groups.filter((x) => !x.items.length);
  const editor = doc.role === "owner" || doc.role === "editor";
  return (
    <>
      <p className="muted">{doc.notice}</p>
      {filled.map(({ g, items }) => (
        <section key={g} className="card" aria-label={g}>
          <h3 style={{ marginTop: 0 }}>{g} <span className="muted">({items.length})</span></h3>
          {items.slice(0, 60).map((i) => (
            <div key={i.id} style={{ borderTop: "1px solid var(--c-border)", padding: "6px 0" }}>
              <div className="row">
                <b>{i.value}</b><span className="muted">{i.type_label}</span><StateBadge s={i.verification_state} own={i.origin !== "discovered"} />
                <span className="grow" />
                <button aria-expanded={open === i.id} onClick={() => setOpen(open === i.id ? null : i.id)}>Why we think this</button>
              </div>
              {open === i.id && (
                <div className="muted" aria-label={`Evidence for ${i.value}`}>
                  <div>Source: {i.source_id || i.origin.replace(/_/g, " ")}{i.collection_method ? ` (${i.collection_method.replace("adapter:", "")})` : ""} · confidence {i.confidence}{i.observed_at ? ` · observed ${fmt(i.observed_at)}` : ""}</div>
                  {i.note && <div>{i.note}</div>}
                  {i.caveat && <div>{i.caveat}</div>}
                  {i.evidence.length > 0 ? <ul>{i.evidence.map((e) => <li key={e.id}>{e.title ?? e.id}{e.url ? <> — <code>{e.url}</code></> : null}</li>)}</ul> : <div>No evidence item is attached.</div>}
                  {i.open && <button onClick={() => go(`case/${s.subject.case_id}`)}>Open in the workbench</button>}
                  {editor && i.id.startsWith("item:") && !i.readonly && !i.is_input && !i.masked && <Reclassify it={i} doc={doc} sid={sid} done={refresh} />}
                </div>)}
            </div>))}
          {items.length > 60 && <div className="muted">Showing 60 of {items.length}. Use the Findings view to filter.</div>}
        </section>))}
      {empty.length > 0 && <details className="card"><summary>Other sections ({empty.length}): not researched or empty</summary><div className="muted">An empty section means unknown, never evidence that nothing exists: {empty.map((e) => e.g).join(", ")}.</div></details>}
    </>
  );
}

function Findings({ s }: { s: Summary }) {
  const sid = s.subject.id;
  const qc = useQueryClient();
  const cand = useQuery({ queryKey: ["candidates", sid], queryFn: () => api<{ items: Candidate[] }>(`/subjects/${sid}/candidates`) });
  const inbox = useQuery({ queryKey: ["inbox", sid], queryFn: () => api<Inbox>(`/subjects/${sid}/review-inbox`) });
  const [text, setText] = useState("");
  const [state, setState] = useState("all");
  const [sort, setSort] = useState("site");
  const [sel, setSel] = useState<string[]>([]);
  const [tech, setTech] = useState(false);
  const [limit, setLimit] = useState(150);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["candidates", sid] }); qc.invalidateQueries({ queryKey: ["inbox", sid] }); qc.invalidateQueries({ queryKey: ["summary"] }); };
  if (cand.isLoading || inbox.isLoading) return <Loading what="findings" />;
  if (cand.isError || !cand.data) return <ErrorBox error={cand.error} />;
  const label = (c: Candidate) => (c.ownership === "self_attested" ? "self_attested" : c.ownership === "independently_corroborated" ? "corroborated" : c.state === "rejected" ? "rejected" : "candidate");
  let rows = cand.data.items.filter((c) => (state === "all" || label(c) === state) && (!text || (c.canonical_url + c.site).toLowerCase().includes(text.toLowerCase())));
  rows = [...rows].sort((a, b) => (sort === "recent" ? b.last_seen_at.localeCompare(a.last_seen_at) : (a.site || a.canonical_url).localeCompare(b.site || b.canonical_url)));
  const shownRows = rows.slice(0, limit);
  const bySite = new Map<string, Candidate[]>();
  for (const c of shownRows) bySite.set(c.site || new URL(c.canonical_url).hostname, [...(bySite.get(c.site || new URL(c.canonical_url).hostname) ?? []), c]);
  const others = (inbox.data?.items ?? []).filter((i) => i.kind !== "account");
  const toggle = (id: string) => setSel(sel.includes(id) ? sel.filter((x) => x !== id) : [...sel, id]);
  const total = s.accounting.accounts;
  return (
    <>
      <div className="banner">{total.explain}</div>
      <div className="row" aria-label="Filters">
        <input aria-label="Search findings" placeholder="Search sites and links" value={text} onChange={(e) => setText(e.target.value)} />
        <select aria-label="Filter by status" value={state} onChange={(e) => setState(e.target.value)} style={{ width: 200 }}>
          <option value="all">All</option><option value="candidate">Needs review</option><option value="self_attested">Self-attested</option><option value="corroborated">Independently corroborated</option><option value="rejected">Rejected</option></select>
        <select aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value)} style={{ width: 160 }}><option value="site">By site</option><option value="recent">Most recent</option></select>
        <label><input type="checkbox" style={{ width: "auto" }} checked={tech} onChange={(e) => setTech(e.target.checked)} /> Technical details</label>
        <button onClick={() => setSel(rows.filter((c) => c.state !== "rejected").map((c) => `account:${c.id}`))}>Select shown</button>
      </div>
      {rows.length === 0 && <Empty title="No accounts match" hint="Accounts appear here when a username source such as Sherlock or Maigret has run for a username input." />}
      {[...bySite.entries()].map(([site, list]) => (
        <details key={site} className="card" open={bySite.size < 8} aria-label={`Findings on ${site}`}>
          <summary><b>{site}</b> <span className="muted">({list.length})</span></summary>
          {list.map((c) => (
            <div key={c.id} className="row" style={{ borderTop: "1px solid var(--c-border)", padding: "4px 0" }}>
              <input type="checkbox" style={{ width: "auto" }} aria-label={`Select ${c.canonical_url}`} checked={sel.includes(`account:${c.id}`)} onChange={() => toggle(`account:${c.id}`)} />
              <a href={c.canonical_url} target="_blank" rel="noreferrer noopener">{c.canonical_url.replace("https://", "")}</a>
              <StateBadge s={label(c)} />
              <span className="muted">{c.adapters.join(" + ")} · {c.independent_signals} signal(s) · last seen {fmt(c.last_seen_at)}</span>
              {tech && <span className="muted">evidence {c.evidence.map((e) => `${e.id.slice(0, 8)} ${e.sha256.slice(0, 10)}…`).join(", ") || "none"} · {c.observation_count} sighting(s)</span>}
            </div>))}
        </details>))}
      {rows.length > limit && <div className="row"><span className="muted">Showing {limit} of {rows.length}. Use the filters to narrow the list.</span><button onClick={() => setLimit(limit + 150)}>Show more</button></div>}
      {others.length > 0 && (<><h3>Other leads</h3><InboxList items={others} sel={sel} setSel={setSel} sid={sid} onDone={refresh} /></>)}
      {sel.length > 0 && <DecisionBar sid={sid} caseId={s.subject.case_id} ids={sel} clear={() => setSel([])} onDone={refresh} />}
    </>
  );
}

function Activity({ s }: { s: Summary }) {
  const rid = s.run.id;
  const ev = useQuery({ queryKey: ["events", rid], queryFn: () => api<{ events: RunEvent[] }>(`/investigations/${rid}/events`), refetchInterval: ACTIVE_STATUSES.includes(s.run.status) ? 2500 : WAITING_STATUSES.includes(s.run.status) ? 15000 : false });
  const groups: [string[], string][] = [[["ready", "already_done"], "Ran or ready"], [["needs_approval"], "Needs approval"], [["needs_key", "needs_authorization", "not_installed", "blocked"], "Configured but unavailable"],
    [["unsupported_input"], "No supported source"], [["separate_approval"], "Needs its own approval"]];
  const rows = s.manifest.rows;
  return (
    <>
      <h3>Pipeline: from results to profile entries</h3>
      <div className="banner">{s.accounting.accounts.explain}</div>
      {s.accounting.sources.length > 0 ? (
        <table aria-label="Result accounting"><thead><tr><th>Source</th><th>Status</th><th>Returned</th><th>Findings</th><th>Unique accounts</th><th>Profile entries</th></tr></thead>
          <tbody>{s.accounting.sources.map((x) => <tr key={x.source_id}><td>{x.source}<div className="muted">{x.explain}</div></td><td>{x.status.replace(/_/g, " ")}{x.limitations && <div className="muted">{x.limitations}</div>}</td>
            <td>{x.retrieved}</td><td>{x.findings}</td><td>{x.candidate_accounts}</td><td>{x.profile_items}</td></tr>)}</tbody></table>) : <div className="muted">No source has returned results yet.</div>}
      <h3>Coverage</h3>
      {groups.map(([codes, title]) => {
        const list = rows.filter((r) => codes.includes(r.status));
        return list.length ? (
          <div className="card" key={title} aria-label={title}><b>{title}</b> <span className="muted">({list.length})</span>
            <ul>{list.map((r) => <li key={r.key}>{r.source} on {kindLabel(r.identifier_kind).toLowerCase()} <code>{r.identifier}</code>{r.status !== "ready" ? <span className="muted"> — {r.reason}</span> : null}
              {r.maturity && r.maturity !== "live_tested" && r.maturity !== "manual" ? <span className="badge st-mute" style={{ marginLeft: 6 }}>fixture-tested</span> : null}</li>)}</ul></div>) : null;
      })}
      <h3>Activity</h3>
      {ev.isLoading ? <Loading what="activity" /> : (
        <ol aria-label="Activity log" style={{ paddingLeft: 18 }}>{[...(ev.data?.events ?? [])].reverse().map((e) => <li key={e.seq}><span className="muted">{fmt(e.at)}</span> {e.message}</li>)}</ol>)}
    </>
  );
}

/** One investigation: Overview, Profile, Findings, Activity & Coverage in a single shell. */
export default function Investigation({ id, go }: { id: string; go: (to: string) => void }) {
  const [view, setView] = useState<View>("Overview");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["summary", id], queryFn: () => api<Summary>(`/investigations/${id}/summary`),
    refetchInterval: (query) => (query.state.data && ACTIVE_STATUSES.includes(query.state.data.run.status) ? 3000 : query.state.data && WAITING_STATUSES.includes(query.state.data.run.status) ? 15000 : false) });
  if (q.isLoading) return <Loading what="the investigation" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const s = q.data;
  const refresh = () => { qc.invalidateQueries({ queryKey: ["summary", id] }); qc.invalidateQueries({ queryKey: ["investigations"] }); qc.invalidateQueries({ queryKey: ["master", s.subject.id] }); };
  return (
    <section aria-label="Investigation">
      <div className="row">
        <h2 style={{ margin: 0 }}>{s.subject.display_name}</h2>
        <span className={`badge ${STATUS_BADGE[s.run.status]}`}>{STATUS_TEXT[s.run.status]}</span>
        <span className="grow" />
        <button onClick={() => go(`case/${s.subject.case_id}`)}>Open in Advanced workbench</button>
      </div>
      <div className="muted">Purpose: {s.subject.purpose || "not recorded"} · authorization: {s.authorization.status.replace(/_/g, " ")}</div>
      <div className="tabs" role="tablist" aria-label="Investigation views">{VIEWS.map((v) => <button key={v} role="tab" aria-selected={view === v} onClick={() => setView(v)}>{v}{v === "Findings" && s.decisions.open ? ` (${s.decisions.open})` : ""}</button>)}</div>
      {view === "Overview" && <Overview s={s} refresh={refresh} setView={setView} go={go} />}
      {view === "Profile" && <Dossier s={s} go={go} />}
      {view === "Findings" && <Findings s={s} />}
      {view === "Activity & Coverage" && <Activity s={s} />}
    </section>
  );
}
