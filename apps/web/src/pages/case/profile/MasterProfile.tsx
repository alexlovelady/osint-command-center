import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { BatchResult, GapCategory, MasterDoc, MasterItem, MasterSection, MasterState } from "../../../lib/masterApi";
import type { ProfileT } from "../../../lib/profileApi";

const STATE_CLASS: Record<MasterState, string> = { unassessed: "st-mute", candidate: "st-warn", corroborated: "st-ok", conflicting: "st-bad", rejected: "st-bad", not_available: "st-mute" };
const ORIGINS: [string, string][] = [["analyst_supplied", "Analyst supplied"], ["subject_provided", "Subject provided (self-attested)"], ["published_source", "Published source"], ["verified_provider", "Verified provider"]];

type Pending = { id: string; kind: "corroborated" | "rejected" | "candidate" | "reveal" | "promote" } | null;

function Gap({ c }: { c: GapCategory | undefined }) {
  if (!c) return null;
  return (
    <div className="muted" aria-label={`Why ${c.title} is ${c.label.toLowerCase()}`}>
      <span className={`badge ${c.status === "has_data" ? "st-ok" : c.status === "needs_verification" ? "st-warn" : "st-mute"}`}>{c.label}</span> {c.why}
      {c.sources.length > 0 && <ul>{c.sources.map((s) => <li key={s.source}>{s.name}: {s.status.replace(/_/g, " ")}{s.detail ? ` (${s.detail})` : ""}</li>)}</ul>}
    </div>
  );
}

function ItemRow({ it, sid, editor, owner, onChanged, onGo }: { it: MasterItem; sid: string; editor: boolean; owner: boolean; onChanged: () => void; onGo: (tab: string) => void }) {
  const [pending, setPending] = useState<Pending>(null);
  const [basis, setBasis] = useState("");
  const [independent, setIndependent] = useState(false);
  const [evidence, setEvidence] = useState("");
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(it.masked ? "" : it.value);
  const [revealed, setRevealed] = useState<string | null>(null);
  const done = () => { setPending(null); setBasis(""); setEvidence(""); setIndependent(false); setEditing(false); onChanged(); };
  const url = `/subjects/${sid}/master/items/${encodeURIComponent(it.id)}`;
  const state = useMutation({ mutationFn: (to_state: string) => api(`${url}/state`, { method: "POST", json: { to_state, basis, independent, evidence_ids: evidence.split(",").map((x) => x.trim()).filter(Boolean) } }), onSuccess: done });
  const promote = useMutation({ mutationFn: () => api(`${url}/use-as-input`, { method: "POST", json: { basis } }), onSuccess: done });
  const reveal = useMutation({ mutationFn: () => api<{ value: string }>(`${url}/reveal`, { method: "POST", json: { reason: basis } }), onSuccess: (r) => { setRevealed(r.value); setPending(null); setBasis(""); } });
  const edit = useMutation({ mutationFn: () => api(url, { method: "PATCH", json: { value: val } }), onSuccess: done });
  const retire = useMutation({ mutationFn: () => api(url, { method: "DELETE" }), onSuccess: onChanged });
  const err = state.error ?? promote.error ?? reveal.error ?? edit.error ?? retire.error;
  const canAct = editor && !it.readonly;
  return (
    <>
      <tr aria-label={`${it.type_label}: ${it.value}`}>
        <td>
          {editing ? (
            <span className="row"><input aria-label={`Edit ${it.type_label}`} value={val} onChange={(e) => setVal(e.target.value)} />
              <button disabled={!val.trim() || edit.isPending} onClick={() => edit.mutate()}>Save</button><button onClick={() => setEditing(false)}>Cancel</button></span>)
            : <><code>{revealed ?? it.value}</code>{it.masked && !revealed && <span className="muted"> (masked)</span>}</>}
          <div className="muted">{it.type_label}{it.custom_type ? ` · ${it.custom_type}` : ""}{it.is_input ? " · input" : ""}{it.feeds_research ? " · feeds research" : ""}</div>
          {it.caveat && <div className="muted">{it.caveat}</div>}
          {it.note && <div className="muted">{it.note}</div>}
        </td>
        <td><span className={`badge ${STATE_CLASS[it.verification_state] ?? "st-mute"}`}>{it.state_label}</span>{it.self_attested && <div className="muted">self-attested</div>}</td>
        <td className="muted">{it.origin.replace(/_/g, " ")}{it.source_id ? ` · ${it.source_id}` : ""}{it.collection_method ? ` · ${it.collection_method}` : ""}
          <div>{it.evidence.length} evidence item(s){it.recorded_by ? ` · by ${it.recorded_by}` : ""}</div></td>
        <td className="muted">{it.confidence}{it.observed_at ? <div>observed {fmt(it.observed_at)}</div> : null}{it.last_verified_at ? <div>verified {fmt(it.last_verified_at)}</div> : null}
          {it.asset_authorization && <div>{it.asset_authorization.covered ? "authorized asset" : "no asset authorization"}: {it.asset_authorization.reason}</div>}</td>
        <td>
          {it.readonly && it.open && <button onClick={() => onGo(it.open!)}>Open in {it.open}</button>}
          {canAct && (
            <span className="row">
              <button onClick={() => setEditing(true)} disabled={it.masked && !owner}>Edit</button>
              <button onClick={() => setPending({ id: it.id, kind: "corroborated" })}>Corroborate</button>
              <button onClick={() => setPending({ id: it.id, kind: "rejected" })}>Reject</button>
              <button onClick={() => setPending({ id: it.id, kind: "candidate" })}>Needs review</button>
              {!it.is_input && ["email", "username", "profile_url", "website", "owned_domain", "full_name", "alias", "organization"].includes(it.type) && <button onClick={() => setPending({ id: it.id, kind: "promote" })}>Use as input</button>}
              {it.masked && owner && !revealed && <button onClick={() => setPending({ id: it.id, kind: "reveal" })}>Reveal</button>}
              {revealed && <button onClick={() => setRevealed(null)}>Hide</button>}
              <button onClick={() => retire.mutate()} disabled={retire.isPending}>Retire</button>
            </span>)}
        </td>
      </tr>
      {pending && (
        <tr><td colSpan={5}>
          <div className="card row" aria-label="Record a decision">
            <input aria-label={pending.kind === "reveal" ? "Reason for revealing" : "Reason or method"} placeholder={pending.kind === "reveal" ? "Why you need to see it (audited, 10+ characters)" : "Reason or method (recorded)"} value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: 1, minWidth: 240 }} />
            {pending.kind === "corroborated" && (<>
              <input aria-label="Evidence ids" placeholder="Evidence ids (comma separated)" value={evidence} onChange={(e) => setEvidence(e.target.value)} />
              <label><input type="checkbox" style={{ width: "auto" }} checked={independent} onChange={(e) => setIndependent(e.target.checked)} /> independent of the subject</label></>)}
            <button className="primary" disabled={!basis.trim() || state.isPending || promote.isPending || reveal.isPending}
              onClick={() => (pending.kind === "promote" ? promote.mutate() : pending.kind === "reveal" ? reveal.mutate() : state.mutate(pending.kind))}>Confirm</button>
            <button onClick={() => setPending(null)}>Cancel</button>
            {pending.kind === "corroborated" && <div className="muted" style={{ flexBasis: "100%" }}>The subject’s own statement is recorded as self-attestation and is not corroboration.</div>}
          </div>
        </td></tr>)}
      {err != null && <tr><td colSpan={5}><ErrorBox error={err} /></td></tr>}
    </>
  );
}

function AddForm({ sid, section, doc, onChanged }: { sid: string; section: MasterSection; doc: MasterDoc; onChanged: () => void }) {
  const types = doc.types.filter((t) => t.category === section.key);
  const [f, setF] = useState({ type: types[0]?.type ?? "custom", value: "", origin: "analyst_supplied", source: "", note: "", custom_type: "", need_to_know: "" });
  const spec = types.find((t) => t.type === f.type);
  const add = useMutation({ mutationFn: () => api(`/subjects/${sid}/master/items`, { method: "POST", json: { ...f, evidence_ids: [] } }), onSuccess: () => { setF({ ...f, value: "", note: "", need_to_know: "" }); onChanged(); } });
  return (
    <form className="card row" aria-label={`Add to ${section.title}`} onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
      <select aria-label="Item type" value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })} style={{ width: 240 }}>{types.map((t) => <option key={t.type} value={t.type}>{t.label}</option>)}</select>
      <input aria-label="Value" placeholder={spec?.reference_only ? "Number (only a masked form and a token are stored)" : "Value"} value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} style={{ flex: 1, minWidth: 200 }} />
      <select aria-label="Origin" value={f.origin} onChange={(e) => setF({ ...f, origin: e.target.value })} style={{ width: 230 }}>{ORIGINS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      <input aria-label="Source" placeholder="Source (optional)" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })} />
      {f.type === "custom" && <input aria-label="Custom type" placeholder="Attribute name" value={f.custom_type} onChange={(e) => setF({ ...f, custom_type: e.target.value })} />}
      {spec?.restricted && <input aria-label="Need to know" placeholder="Why this is needed (recorded)" value={f.need_to_know} onChange={(e) => setF({ ...f, need_to_know: e.target.value })} style={{ flex: 1, minWidth: 200 }} />}
      <button className="primary" disabled={!f.value.trim() || add.isPending}>Add</button>
      {add.isError && <ErrorBox error={add.error} />}
      {add.data != null && (add.data as { created?: boolean }).created === false && <span className="muted" role="status">Already recorded; nothing duplicated.</span>}
    </form>
  );
}

function Batch({ sid, onChanged }: { sid: string; onChanged: () => void }) {
  const [kind, setKind] = useState<"csv" | "json">("csv");
  const [content, setContent] = useState("");
  const run = useMutation({ mutationFn: () => api<BatchResult>(`/subjects/${sid}/master/items/batch`, { method: "POST", json: { kind, content } }), onSuccess: onChanged });
  const file = async (f: File | undefined) => { if (f) { setContent(await f.text()); setKind(f.name.toLowerCase().endsWith(".json") ? "json" : "csv"); } };
  return (
    <details className="card" aria-label="Batch input and import">
      <summary>Batch input, CSV or JSON import</summary>
      <div className="muted">Columns: type, value, origin, source, evidence_ids, note, need_to_know. Good rows are kept; bad rows are listed with the reason. Restricted types need a stated need.</div>
      <div className="row">
        <select aria-label="Import format" value={kind} onChange={(e) => setKind(e.target.value as "csv" | "json")} style={{ width: 90 }}><option value="csv">CSV</option><option value="json">JSON</option></select>
        <input aria-label="Import file" type="file" accept=".csv,.json,text/csv,application/json" onChange={(e) => void file(e.target.files?.[0])} />
        <button className="primary" disabled={!content.trim() || run.isPending} onClick={() => run.mutate()}>Import</button>
      </div>
      <textarea aria-label="Rows to import" rows={5} value={content} onChange={(e) => setContent(e.target.value)} placeholder={"type,value,origin,source\nusername,janedoe,subject_provided,self"} style={{ width: "100%" }} />
      {run.isError && <ErrorBox error={run.error} />}
      {run.data && (
        <div className="banner" role="status">{run.data.created} added, {run.data.existing} already present, {run.data.errors.length} not imported.
          {run.data.errors.length > 0 && <ul>{run.data.errors.map((e) => <li key={e.row}>Row {e.row}: {e.message} ({e.code.replace(/_/g, " ")})</li>)}</ul>}</div>)}
    </details>
  );
}

/** Master Profile Editor (Master Target Profile addendum): every known fact about the subject in one editable place, backed by the existing stores. */
export default function MasterProfile({ p, onGo }: { p: ProfileT; onGo: (tab: string) => void }) {
  const sid = p.subject.id;
  const qc = useQueryClient();
  const editor = p.role === "owner" || p.role === "editor";
  const owner = p.role === "owner";
  const [cat, setCat] = useState("identity");
  const [stateF, setStateF] = useState("");
  const [search, setSearch] = useState("");
  const q = useQuery({ queryKey: ["master", sid, stateF, search], queryFn: () => api<MasterDoc>(`/subjects/${sid}/master${stateF || search ? `?${new URLSearchParams({ ...(stateF ? { state: stateF } : {}), ...(search ? { q: search } : {}) })}` : ""}`) });
  const changed = () => { qc.invalidateQueries({ queryKey: ["master", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); qc.invalidateQueries({ queryKey: ["assoc-emails", sid] }); qc.invalidateQueries({ queryKey: ["expansion", sid] }); };
  const [lastMerge, setLastMerge] = useState<string[] | null>(null);
  const merge = useMutation({ mutationFn: (g: { ids: string[] }) => api(`/subjects/${sid}/master/merge`, { method: "POST", json: { keep_id: g.ids[0], merge_ids: g.ids.slice(1), reason: "Same fact, confirmed by an analyst" } }).then(() => g.ids), onSuccess: (ids) => { setLastMerge(ids); changed(); } });
  const undo = useMutation({ mutationFn: async () => { for (const id of (lastMerge ?? []).slice(1)) await api(`/subjects/${sid}/master/items/${encodeURIComponent(id)}/unmerge`, { method: "POST" }); }, onSuccess: () => { setLastMerge(null); changed(); } });
  const exp = useMutation({
    mutationFn: async () => {
      const data = await api<unknown>(`/subjects/${sid}/master/export`);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      const a = document.createElement("a"); a.href = url; a.download = `master-profile-${sid.slice(0, 8)}.json`; a.click(); URL.revokeObjectURL(url);
    },
  });
  if (q.isLoading) return <Loading what="the master profile" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const d = q.data;
  const section = d.sections.find((s) => s.key === cat) ?? d.sections[0];
  const gap = d.gaps?.categories.find((c) => c.key === section.key);
  const totals = d.states.map((s) => ({ ...s, n: d.sections.reduce((a, x) => a + (x.counts[s.key] ?? 0), 0) }));
  return (
    <section aria-label="Master profile" className="card">
      <div className="row"><h3 style={{ margin: 0 }}>Master profile</h3>
        {totals.map((t) => <span key={t.key} className={`badge ${STATE_CLASS[t.key]}`}>{t.n} {t.label.toLowerCase()}</span>)}
        {editor && <button onClick={() => exp.mutate()} disabled={exp.isPending}>Export (restricted values omitted)</button>}</div>
      <div className="muted">{d.notice}{d.restricted_hidden > 0 && ` ${d.restricted_hidden} restricted value(s) are hidden for your role.`}</div>
      {exp.isError && <ErrorBox error={exp.error} />}
      {d.gaps?.email_first.has_email && <div className="banner" role="status" aria-label="Email-first discovery">{d.gaps.email_first.message}</div>}
      <div className="row">
        <div className="tabs" role="tablist" aria-label="Profile categories">
          {d.sections.map((s) => <button key={s.key} role="tab" aria-selected={cat === s.key} onClick={() => setCat(s.key)}>{s.title} ({s.items.length})</button>)}
        </div>
      </div>
      <div className="row">
        <input aria-label="Search the profile" placeholder="Search values" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select aria-label="Filter by state" value={stateF} onChange={(e) => setStateF(e.target.value)} style={{ width: 170 }}><option value="">All states</option>{d.states.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}</select>
      </div>
      <Gap c={gap} />
      {!section.items.length ? <Empty title={`No ${section.title.toLowerCase()} recorded`} hint={section.empty_note} /> : (
        <table aria-label={`${section.title} items`}><thead><tr><th>Value</th><th>State</th><th>Source</th><th>Confidence and dates</th><th /></tr></thead>
          <tbody>{section.items.map((it) => <ItemRow key={it.id} it={it} sid={sid} editor={editor} owner={owner} onChanged={changed} onGo={onGo} />)}</tbody></table>)}
      {editor && section.types.length > 0 && <AddForm key={section.key} sid={sid} section={section} doc={d} onChanged={changed} />}
      {editor && <Batch sid={sid} onChanged={changed} />}
      {lastMerge && <div className="banner" role="status">Merged {lastMerge.length} entries; every source and piece of evidence was kept. <button onClick={() => undo.mutate()} disabled={undo.isPending}>Undo merge</button>{undo.isError && <ErrorBox error={undo.error} />}</div>}
      {editor && d.duplicates.length > 0 && (
        <div className="card" aria-label="Possible duplicates"><b>Possible duplicates</b>
          {d.duplicates.map((g) => (<div className="row" key={g.ids.join()}>{g.values.join(" · ")} <span className="muted">{g.reason}</span>
            <button onClick={() => merge.mutate(g)} disabled={merge.isPending}>Merge (reversible)</button></div>))}
          {merge.isError && <ErrorBox error={merge.error} />}</div>)}
      {d.gaps && (
        <div className="card" aria-label="Research gaps and next actions">
          <b>Research gaps and next actions</b>
          <div className="muted">{d.gaps.coverage.label} ({d.gaps.coverage.attempted_categories} of {d.gaps.coverage.of} categories)</div>
          {d.gaps.next_actions.length === 0 ? <div className="muted">No outstanding actions.</div> : (
            <ol>{d.gaps.next_actions.map((a) => <li key={a.text}>{a.text}{a.go && <> <button onClick={() => onGo(a.go!)}>Go to {a.go}</button></>}</li>)}</ol>)}
          <ul>{d.gaps.categories.filter((c) => c.status !== "has_data").map((c) => <li key={c.key}><b>{c.title}</b>: {c.label}. {c.why}</li>)}</ul>
          {d.gaps.email_first.has_email && d.gaps.email_first.sources.length > 0 && (
            <details><summary>Email-first sources</summary>
              <ul>{d.gaps.email_first.sources.map((s) => <li key={s.source_id}>{s.name}: {s.state.replace(/_/g, " ")}{s.needs_key ? ` (key: ${s.needs_key})` : ""}. Sends {s.sends}; {s.cost}.</li>)}</ul></details>)}
        </div>)}
    </section>
  );
}
