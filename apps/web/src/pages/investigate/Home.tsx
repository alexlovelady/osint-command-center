import { useQuery } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, fmt } from "../../components/ui";
import { api } from "../../lib/api";
import { ACTIVE_STATUSES, STATUS_BADGE, STATUS_TEXT, type RunRow } from "../../lib/investigationApi";

export function RunCard({ r, go }: { r: RunRow; go: (to: string) => void }) {
  const active = ACTIVE_STATUSES.includes(r.status);
  return (
    <article className="card" aria-label={`Investigation ${r.name}`}>
      <div className="row">
        <b style={{ fontSize: 16 }}>{r.name || "Untitled"}</b>
        <span className={`badge ${STATUS_BADGE[r.status]}`}>{STATUS_TEXT[r.status]}</span>
        <span className="grow" />
        <button className="primary" onClick={() => go(`investigation/${r.id}`)}>{active ? "Watch" : r.status === "paused" || r.status === "awaiting_review" ? "Continue" : "Open"}</button>
      </div>
      <div className="muted">
        {r.units.done} check(s) done · {r.units.running} running · {r.units.not_run} not run (with reasons)
        {r.pending_decisions > 0 && <> · <b>{r.pending_decisions} decision(s) waiting</b></>} · updated {fmt(r.updated_at)}
      </div>
    </article>
  );
}

/** Home: start something new, resume what is running, see what needs you. */
export default function Home({ go }: { go: (to: string) => void }) {
  const q = useQuery({ queryKey: ["investigations"], queryFn: () => api<{ items: RunRow[] }>("/investigations"),
    refetchInterval: (query) => (query.state.data?.items.some((r) => ACTIVE_STATUSES.includes(r.status)) ? 3000 : false) });
  const rv = useQuery({ queryKey: ["global-review"], queryFn: () => api<{ total: number }>("/investigations/review") });
  const runs = q.data?.items ?? [];
  const live = runs.filter((r) => ACTIVE_STATUSES.includes(r.status) || r.status === "paused");
  const warn = runs.filter((r) => r.status === "draft");
  return (
    <section aria-label="Home">
      <div className="row">
        <h2 style={{ margin: 0 }}>Home</h2>
        <span className="grow" />
        <button className="primary" onClick={() => go("new")} style={{ fontSize: 15, padding: "8px 18px" }}>New investigation</button>
      </div>
      <p className="muted">Start with one or more things you know about the subject: an email, a username, a website, a name or a business. Fusion runs every permitted check, follows what it finds within strict limits, and tells you what it could not do.</p>
      {q.isLoading && <Loading what="investigations" />}
      {q.isError && <ErrorBox error={q.error} />}
      {warn.length > 0 && <div className="banner warn" role="status">{warn.length} investigation(s) are waiting for an authorization before anything can be collected.</div>}
      {(rv.data?.total ?? 0) > 0 && (
        <div className="banner" role="status"><b>{rv.data?.total} decision(s) waiting for you.</b> <button onClick={() => go("review")}>Open Review</button></div>)}
      {live.length > 0 && (<><h3>Running and paused</h3>{live.map((r) => <RunCard key={r.id} r={r} go={go} />)}</>)}
      <h3>Recent investigations</h3>
      {q.data && runs.length === 0 && (
        <Empty title="No investigations yet" hint="Example: start with one email address you own. Fusion will check what is publicly tied to it, list what it found as leads, and show what needs your decision.">
          <button className="primary" onClick={() => go("new")}>Start your first investigation</button>
        </Empty>)}
      {runs.filter((r) => !live.includes(r)).map((r) => <RunCard key={r.id} r={r} go={go} />)}
    </section>
  );
}

/** Investigations: every investigation, newest first. */
export function Investigations({ go }: { go: (to: string) => void }) {
  const q = useQuery({ queryKey: ["investigations"], queryFn: () => api<{ items: RunRow[] }>("/investigations?limit=100") });
  return (
    <section aria-label="Investigations">
      <div className="row"><h2 style={{ margin: 0 }}>Investigations</h2><span className="grow" /><button className="primary" onClick={() => go("new")}>New investigation</button></div>
      {q.isLoading && <Loading what="investigations" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data && q.data.items.length === 0 && <Empty title="No investigations yet" hint="Start one from an email, a username, a website, a name or a business." />}
      {q.data?.items.map((r) => <RunCard key={r.id} r={r} go={go} />)}
    </section>
  );
}
