import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { CLASS_BADGE, NEEDS_LABEL, type AssociatedEmailT, type EmailClass, type EmailList, type ExpansionPlan } from "../../../lib/emailApi";
import type { ProfileT } from "../../../lib/profileApi";

const FILTERS: (EmailClass | "all")[] = ["all", "confirmed", "likely", "possible", "rejected"];

function Row({ e, selected, toggle, sid, refresh, editor }: { e: AssociatedEmailT; selected: boolean; toggle: () => void; sid: string; refresh: () => void; editor: boolean }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState(e.note);
  const saveNote = useMutation({ mutationFn: () => api(`/subjects/${sid}/associated-emails/${e.id}`, { method: "PATCH", json: { note } }), onSuccess: refresh });
  const promote = useMutation({ mutationFn: () => api(`/subjects/${sid}/associated-emails/${e.id}/promote`, { method: "POST" }), onSuccess: refresh });
  return (
    <>
      <tr>
        <td>{editor && <input type="checkbox" aria-label={`Select ${e.address}`} style={{ width: "auto" }} checked={selected} onChange={toggle} />}</td>
        <td><code>{e.address}</code>{e.origin !== "observed" && <div className="muted">{e.origin_label}</div>}</td>
        <td><Badge v={CLASS_BADGE[e.classification]} /> <b>{e.label}</b>{e.confirmation_kind && <div className="muted">{e.confirmation_kind.replace(/_/g, " ")}</div>}</td>
        <td className="muted">{e.sources.slice(0, 2).map((s) => `${s.kind.replace(/_/g, " ")} (${s.group})`).join(", ")}{e.sources.length > 2 ? ` +${e.sources.length - 2}` : ""}<div>{e.evidence.length} evidence item(s)</div></td>
        <td className="muted">found {fmt(e.discovered_at)}<div>{e.last_verified_at ? `verified ${fmt(e.last_verified_at)}` : "not verified"}</div></td>
        <td className="muted">{e.exposure.label}{e.exposure.credential_indicator && <div className="badge failed">credential indicator</div>}</td>
        <td><button onClick={() => setOpen(!open)} aria-expanded={open}>{open ? "Hide" : "Why"}</button></td>
      </tr>
      {open && (
        <tr><td /><td colSpan={6}>
          <div className="card" aria-label={`Details for ${e.address}`}>
            <b>Why {e.label.toLowerCase()}</b><ul>{e.explanation.map((x) => <li key={x}>{x}</li>)}</ul>
            {e.conflicts.length > 0 && <div className="banner warn"><b>Conflicting evidence</b><ul>{e.conflicts.map((c) => <li key={c.detail}>{c.detail}</li>)}</ul></div>}
            <b>Sources</b>
            <ul>{e.sources.map((s) => (<li key={s.id}>{s.kind.replace(/_/g, " ")} · {s.group} · {s.explicit ? "ties it to the subject" : "does not tie it to the subject"}{s.basis && ` (${s.basis})`}
              {s.context && <div className="muted">“{s.context}”</div>}{s.evidence_id && <div className="muted">evidence <code>{s.evidence_id.slice(0, 8)}</code>{s.url && <> · {s.url}</>}</div>}</li>))}</ul>
            {e.origin_path.length > 0 && <div className="muted">How it was reached: {e.origin_path.join(" → ")}</div>}
            <div className="muted">Associated accounts: {e.associations.usernames.join(", ") || "none"} · domains: {e.associations.domains.join(", ") || "none"} · documents: {e.associations.documents.length}</div>
            <div className="muted">Exposure: {e.exposure.label}. {e.exposure.note}{(e.exposure.recommend ?? []).map((r) => <div key={r}>→ {r}</div>)}</div>
            {e.aliases.length > 0 && <div className="muted">Also written as: {e.aliases.join(", ")}</div>}
            {editor && (
              <div className="row" style={{ marginTop: 6 }}>
                <input aria-label={`Note for ${e.address}`} placeholder="Annotation" value={note} onChange={(ev) => setNote(ev.target.value)} style={{ flex: 1 }} />
                <button onClick={() => saveNote.mutate()} disabled={saveNote.isPending}>Save note</button>
                {e.state === "confirmed" && !e.is_input && <button onClick={() => promote.mutate()} disabled={promote.isPending}>Add as an input</button>}
              </div>)}
            {(saveNote.isError || promote.isError) && <ErrorBox error={saveNote.error ?? promote.error} />}
          </div>
        </td></tr>)}
    </>
  );
}

function Plan({ p, editor, owner, refresh }: { p: ProfileT; editor: boolean; owner: boolean; refresh: () => void }) {
  const sid = p.subject.id;
  const q = useQuery({ queryKey: ["expansion", sid], enabled: editor, queryFn: () => api<ExpansionPlan>(`/subjects/${sid}/expansion`) });
  const [keys, setKeys] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState<string[]>([]);
  const qc = useQueryClient();
  const done = () => { setKeys([]); qc.invalidateQueries({ queryKey: ["expansion", sid] }); refresh(); };
  const run = useMutation({ mutationFn: () => api<{ status: string; stop_reason: string; started_runs: number }>(`/subjects/${sid}/expansion/run`, { method: "POST", json: { keys, confirmed_sources: confirmed, wait: false } }), onSuccess: done });
  const policy = useMutation({ mutationFn: (v: Record<string, number | boolean>) => api(`/subjects/${sid}/expansion/policy`, { method: "PUT", json: v }), onSuccess: done });
  if (!editor) return null;
  if (q.isLoading) return <Loading what="the research plan" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const d = q.data;
  const selectable = d.steps.filter((s) => s.executable_now || s.needs === "confirmation");
  return (
    <div className="card" aria-label="Cross-INT research plan">
      <b>Research plan across disciplines</b>
      <div className="muted">Starting points are your inputs and addresses you confirmed. {d.rules[1]} Budget {d.budget.used}/{d.budget.max_runs} source runs; depth limit {d.policy.max_depth}; at most {d.policy.max_per_pass} per pass.
        {d.stop_reason && <b> Stopped: {d.stop_reason.replace(/_/g, " ")}.</b>}</div>
      <table><thead><tr><th /><th>Step</th><th>On</th><th>Depth</th><th>Status</th></tr></thead><tbody>
        {d.steps.slice(0, 40).map((s) => (
          <tr key={s.key}><td>{selectable.includes(s) && <input type="checkbox" style={{ width: "auto" }} aria-label={`Include ${s.source} on ${s.identifier}`} checked={keys.includes(s.key)}
            onChange={(e) => setKeys(e.target.checked ? [...keys, s.key] : keys.filter((k) => k !== s.key))} />}</td>
            <td>{s.source}<div className="muted">{s.module}</div></td><td><code>{s.identifier}</code></td><td>{s.depth}</td>
            <td><Badge v={s.executable_now ? "healthy" : s.needs === "blocked" || s.needs === "depth_limit" ? "failed" : "medium"} /> {NEEDS_LABEL[s.needs] ?? s.needs}<div className="muted">{s.reason}</div>
              {s.needs === "confirmation" && keys.includes(s.key) && (
                <label><input type="checkbox" style={{ width: "auto" }} checked={confirmed.includes(s.source_id)} onChange={(e) => setConfirmed(e.target.checked ? [...confirmed, s.source_id] : confirmed.filter((x) => x !== s.source_id))} /> I confirm this contacts that public site with this handle</label>)}</td></tr>))}
      </tbody></table>
      {d.seeds.proposals.length > 0 && (<><b>Candidates (nothing is researched from these until you confirm them)</b><ul>{d.seeds.proposals.map((x) => <li key={x.label + x.state}><code>{x.label}</code>: {x.state}. {x.reason}</li>)}</ul></>)}
      {d.seeds.skipped.rejected_emails > 0 && <div className="muted">{d.seeds.skipped.rejected_emails} rejected address(es) are ignored.</div>}
      <div className="row"><button className="primary" disabled={!keys.length || run.isPending} onClick={() => run.mutate()}>Run the {keys.length} selected step(s)</button>
        <span className="muted">Passive steps only. Exposure checks and active verification have their own screens and approvals.</span></div>
      {run.isError && <ErrorBox error={run.error} />}
      {run.data && <div className="banner" role="status">Pass {run.data.status}: {run.data.started_runs} run(s) started{run.data.stop_reason ? `; ${run.data.stop_reason.replace(/_/g, " ")}` : ""}. New addresses appear as candidates.</div>}
      {owner && (
        <div className="row" aria-label="Expansion limits">
          <label>Depth <select aria-label="Maximum depth" value={d.policy.max_depth} onChange={(e) => policy.mutate({ max_depth: Number(e.target.value) })} style={{ width: 70 }}>{[1, 2, 3, 4].map((n) => <option key={n}>{n}</option>)}</select></label>
          <label>Total runs <input aria-label="Maximum runs" type="number" min={1} max={100} defaultValue={d.policy.max_runs} onBlur={(e) => policy.mutate({ max_runs: Number(e.target.value) })} style={{ width: 80 }} /></label>
          <label><input type="checkbox" style={{ width: "auto" }} checked={d.policy.auto_passive} onChange={(e) => policy.mutate({ auto_passive: e.target.checked })} /> run ready passive steps without ticking (still inside the authorization and limits)</label>
        </div>)}
      {policy.isError && <ErrorBox error={policy.error} />}
    </div>
  );
}

/** Associated Emails: candidates with evidence, an explainable classification, analyst decisions, and the cross-INT plan they feed. */
export default function AssociatedEmails({ p }: { p: ProfileT }) {
  const sid = p.subject.id;
  const qc = useQueryClient();
  const editor = p.role === "owner" || p.role === "editor";
  const q = useQuery({ queryKey: ["assoc-emails", sid], queryFn: () => api<EmailList>(`/subjects/${sid}/associated-emails`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["assoc-emails", sid] }); qc.invalidateQueries({ queryKey: ["expansion", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const [filter, setFilter] = useState<EmailClass | "all">("all");
  const [sel, setSel] = useState<string[]>([]);
  const [basis, setBasis] = useState("");
  const [attest, setAttest] = useState(false);
  const [manual, setManual] = useState({ address: "", url: "", note: "" });
  const discover = useMutation({ mutationFn: () => api<{ swept: { created: number }; speculative: { address: string; label: string }[] }>(`/subjects/${sid}/associated-emails/discover`, { method: "POST" }), onSuccess: refresh });
  const review = useMutation({ mutationFn: (to_state: string) => api(`/subjects/${sid}/associated-emails/review`, { method: "POST", json: { ids: sel, to_state, basis, attestation: attest ? "subject" : "none" } }), onSuccess: () => { setSel([]); setBasis(""); refresh(); } });
  const add = useMutation({ mutationFn: () => api(`/subjects/${sid}/associated-emails`, { method: "POST", json: manual }), onSuccess: () => { setManual({ address: "", url: "", note: "" }); refresh(); } });
  const merge = useMutation({ mutationFn: (ids: string[]) => api(`/subjects/${sid}/associated-emails/merge`, { method: "POST", json: { keep_id: ids[0], merge_ids: ids.slice(1) } }), onSuccess: refresh });
  const guess = useMutation({ mutationFn: (address: string) => api(`/subjects/${sid}/associated-emails/speculative`, { method: "POST", json: { address } }), onSuccess: refresh });
  if (q.isLoading) return <Loading what="associated emails" />;
  if (q.isError || !q.data) return <ErrorBox error={q.error} />;
  const d = q.data;
  const shown = d.items.filter((i) => filter === "all" || i.classification === filter);
  return (
    <>
      <div className="banner">{d.notice} Guessed patterns are never shown as discoveries. {p.role === "viewer" && "Addresses are masked for your role."}</div>
      <div className="row" aria-label="Classification counts">
        {FILTERS.map((f) => <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>{f === "all" ? `All (${d.items.length})` : `${f[0].toUpperCase() + f.slice(1)} (${d.counts[f]})`}</button>)}
        {editor && <button className="primary" onClick={() => discover.mutate()} disabled={discover.isPending}>Find in stored evidence</button>}
      </div>
      {discover.data && <div className="banner" role="status">{discover.data.swept.created} new candidate(s) from stored evidence. Nothing was sent.
        {discover.data.speculative.length > 0 && <> Pattern guesses (speculative, not observed): {discover.data.speculative.slice(0, 4).map((g) => (
          <button key={g.address} onClick={() => guess.mutate(g.address)} title={g.label} style={{ marginLeft: 4 }}>track {g.address}</button>))}</>}</div>}
      {(d.inputs ?? []).length > 0 && (
        <div className="card" aria-label="Your email inputs"><b>Your inputs</b>
          <ul>{(d.inputs ?? []).map((i) => <li key={i.id}><code>{i.address}</code> · {i.label}<div className="muted">{i.note} {i.domain_research}</div></li>)}</ul></div>)}
      {!shown.length && <Empty title="No associated addresses yet" hint="Run a discovery step below (GitHub profile, a public contact page) or add an address with the evidence that shows it." />}
      {shown.length > 0 && (
        <table aria-label="Associated emails"><thead><tr><th /><th>Address</th><th>Ownership</th><th>Source</th><th>Dates</th><th>Exposure</th><th /></tr></thead>
          <tbody>{shown.map((e) => <Row key={e.id} e={e} sid={sid} refresh={refresh} editor={editor} selected={sel.includes(e.id)} toggle={() => setSel(sel.includes(e.id) ? sel.filter((x) => x !== e.id) : [...sel, e.id])} />)}</tbody></table>)}
      {editor && sel.length > 0 && (
        <div className="card row" aria-label="Decide on selected addresses">
          <b>{sel.length} selected</b>
          <input aria-label="Reason for the decision" placeholder="Reason or method (recorded)" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
          <label><input type="checkbox" style={{ width: "auto" }} checked={attest} onChange={(e) => setAttest(e.target.checked)} /> the owner attests it is theirs</label>
          <button disabled={!basis.trim() || review.isPending} onClick={() => review.mutate("confirmed")}>Confirm</button>
          <button disabled={!basis.trim() || review.isPending} onClick={() => review.mutate("rejected")}>Reject</button>
          <button disabled={!basis.trim() || review.isPending} onClick={() => review.mutate("candidate")}>Reopen</button>
          <div className="muted" style={{ flexBasis: "100%" }}>Confirming needs the owner’s attestation or independent corroboration from a second source; the record states which.</div>
        </div>)}
      {review.isError && <ErrorBox error={review.error} />}{merge.isError && <ErrorBox error={merge.error} />}{guess.isError && <ErrorBox error={guess.error} />}
      {editor && d.duplicates.length > 0 && (
        <div className="card" aria-label="Possible duplicates"><b>Possible duplicates</b>
          {d.duplicates.map((g) => (<div className="row" key={g.key}>{g.addresses.join(" · ")}<button onClick={() => merge.mutate(g.ids)} disabled={merge.isPending}>Merge (keeps every source)</button></div>))}</div>)}
      {editor && (
        <form className="card row" aria-label="Add an address" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
          <input aria-label="Email address" placeholder="Address you found" value={manual.address} onChange={(e) => setManual({ ...manual, address: e.target.value })} />
          <input aria-label="Where it was found" placeholder="Where it was found (link)" value={manual.url} onChange={(e) => setManual({ ...manual, url: e.target.value })} style={{ flex: 1, minWidth: 200 }} />
          <input aria-label="What the source says" placeholder="What the source says about it" value={manual.note} onChange={(e) => setManual({ ...manual, note: e.target.value })} style={{ flex: 1, minWidth: 200 }} />
          <button disabled={!manual.address.includes("@") || add.isPending}>Add as a candidate</button>
          {add.isError && <ErrorBox error={add.error} />}
        </form>)}
      <Plan p={p} editor={editor} owner={p.role === "owner"} refresh={refresh} />
    </>
  );
}
