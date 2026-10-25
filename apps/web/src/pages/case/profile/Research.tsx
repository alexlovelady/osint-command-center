import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { CoverageT, ProfileT, ResearchPlanT, TaskT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

/** Research coverage grid: completed methods against the approved plan. It is deliberately not a percentage of what exists. */
export function CoverageGrid({ cov }: { cov: CoverageT }) {
  return (
    <section aria-label="Research coverage" className="card">
      <h3 style={{ margin: "0 0 4px" }}>Research coverage</h3>
      <p className="muted" style={{ margin: "0 0 8px" }}>{cov.label} Approved tasks: {cov.approved_tasks}, completed: {cov.completed_tasks}.</p>
      <table aria-label="Coverage grid">
        <thead><tr><th>Method group</th><th>Methods and their state</th></tr></thead>
        <tbody>{cov.categories.map((c) => (
          <tr key={c.key}><th scope="row" style={{ textAlign: "left", whiteSpace: "nowrap" }}>{c.title}</th>
            <td>{c.cells.map((x) => (
              <div key={x.source_id} className="row" style={{ gap: 6 }}>
                <StateBadge state={x.status} label={x.status.replace(/_/g, " ")} /> <b>{x.name}</b>
                <span className="muted">{x.detail}{x.last_success ? ` · last success ${fmt(x.last_success)}` : ""}{x.maturity === "mocked_only" ? " · integration only tested against fixtures" : ""}</span>
              </div>))}</td></tr>))}</tbody>
      </table>
    </section>
  );
}

export default function Research({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const canEdit = p.role !== "viewer";
  const cov = useQuery({ queryKey: ["coverage", sid], queryFn: () => api<CoverageT>(`/subjects/${sid}/coverage`), refetchInterval: (q) => (q.state.data?.categories.some((c) => c.cells.some((x) => ["running", "approved"].includes(x.status))) ? 2500 : false) });
  const tasks = useQuery({ queryKey: ["tasks", sid], queryFn: () => api<{ items: TaskT[] }>(`/subjects/${sid}/research/runs`) });
  const [sel, setSel] = useState<string[]>([]);
  const [conf, setConf] = useState<string[]>([]);
  const preview = useMutation({ mutationFn: () => api<ResearchPlanT>(`/subjects/${sid}/research/preview`, { method: "POST", json: {} }), onSuccess: () => { setSel([]); setConf([]); } });
  const plan = preview.data;
  const approve = useMutation({
    mutationFn: () => api(`/subjects/${sid}/research/approve`, { method: "POST", json: { keys: sel, confirmed_sources: conf } }),
    onSuccess: () => { setSel([]); setConf([]); preview.reset(); ["coverage", "tasks", "profile", "candidates"].forEach((k) => qc.invalidateQueries({ queryKey: [k, sid] })); },
  });
  const chosen = (plan?.entries ?? []).filter((e) => sel.includes(e.key));
  const needConfirm = [...new Set(chosen.filter((e) => e.requires_confirmation).map((e) => e.source_id))];
  const unconfirmed = needConfirm.filter((s) => !conf.includes(s));
  return (
    <>
      {cov.data && <CoverageGrid cov={cov.data} />}
      {cov.data && <p className="muted"><b>Next:</b> {cov.data.next_action}</p>}
      {canEdit && (
        <section aria-label="Research plan" className="card" style={{ marginTop: 10 }}>
          <div className="row">
            <h3 style={{ margin: 0 }}>Plan the next collection</h3>
            <button className="primary" onClick={() => preview.mutate()} disabled={preview.isPending}>Preview what would be contacted</button>
          </div>
          <p className="muted">Preview sends nothing. Each source is checked against this subject&apos;s authorization, scope and your policy before it can be selected.</p>
          {preview.isError && <ErrorBox error={preview.error} />}
          {plan && (
            <>
              {plan.entries.length === 0 && <div className="banner warn">There is nothing to plan: add an input (username, email, domain or organisation) on the Profile tab first.</div>}
              {plan.entries.length > 0 && (
                <table aria-label="Planned sources">
                  <thead><tr><th /><th>Source</th><th>Input</th><th>Contacts</th><th>Class and limits</th><th>Why / notes</th></tr></thead>
                  <tbody>{plan.entries.map((e) => (
                    <tr key={e.key}>
                      <td><input type="checkbox" style={{ width: "auto" }} aria-label={`Run ${e.name} on ${e.identifier}`} disabled={!e.runnable} checked={sel.includes(e.key)}
                        onChange={(ev) => setSel(ev.target.checked ? [...sel, e.key] : sel.filter((x) => x !== e.key))} /></td>
                      <td>{e.name}<div className="muted">{e.maturity.replace(/_/g, " ")}{e.health ? ` · ${e.health === "healthy" ? "installed · healthy" : e.health.replace(/_/g, " ")}` : ""}</div></td>
                      <td style={{ minWidth: 150, wordBreak: "normal", overflowWrap: "anywhere" }}><code>{e.identifier}</code><div className="muted">{e.identifier_kind}</div></td>
                      <td>{e.endpoints.map((x) => <div key={x}><code>{x}</code></div>)}</td>
                      <td>{e.consent_class.replace(/_/g, " ")} · {e.privacy.replace(/_/g, " ")}<div className="muted">cost {e.cost}{e.needs_key ? ` (${e.needs_key})` : ""} · {e.rate_limit_per_minute ? `${e.rate_limit_per_minute}/min` : "no declared limit"}</div></td>
                      <td>{!e.runnable && <div className="muted">Blocked: {e.reason}</div>}
                        {e.warnings.map((w) => <div key={w} className="muted">⚠ {w}</div>)}
                        <div className="muted">{e.legal_note}</div>
                        {e.requires_confirmation && (
                          <label><input type="checkbox" style={{ width: "auto" }} aria-label={`Confirm ${e.name} contacts third-party sites`} disabled={!sel.includes(e.key)}
                            checked={conf.includes(e.source_id)} onChange={(ev) => setConf(ev.target.checked ? [...conf, e.source_id] : conf.filter((x) => x !== e.source_id))} /> I confirm this contacts third-party public sites with this handle</label>)}
                      </td>
                    </tr>))}</tbody>
                </table>)}
              <ul className="muted">{plan.stop_rules.map((r) => <li key={r}>{r}</li>)}</ul>
              <div className="row">
                <button className="primary" disabled={!sel.length || unconfirmed.length > 0 || approve.isPending} onClick={() => approve.mutate()}>Approve and run {sel.length} source(s)</button>
                {unconfirmed.length > 0 && <span className="muted">Confirm {unconfirmed.join(", ")} first.</span>}
                <span className="muted">{plan.note}</span>
              </div>
            </>)}
          {approve.isError && <ErrorBox error={approve.error} />}
        </section>)}
      <section className="card" aria-label="Research tasks" style={{ marginTop: 10 }}>
        <h3 style={{ margin: "0 0 6px" }}>Research tasks</h3>
        <table aria-label="Tasks"><thead><tr><th>Source</th><th>Status</th><th>Results</th><th>Last attempt</th><th>Limitations</th></tr></thead>
          <tbody>{(tasks.data?.items ?? []).map((t) => (
            <tr key={t.id}><td>{t.source_id}</td><td><StateBadge state={t.status} /></td><td>{t.result_count}</td><td>{fmt(t.last_attempt)}</td><td className="muted">{t.limitations}</td></tr>))}</tbody></table>
        {tasks.data?.items.length === 0 && <span className="muted">Nothing has been approved yet.</span>}
      </section>
    </>
  );
}
