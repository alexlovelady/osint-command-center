import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ProfileT, SubjectT } from "../../../lib/profileApi";
import AssociatedEmails from "./AssociatedEmails";
import Authorization, { AuthIndicator } from "./Authorization";
import ProfileOverview, { StateBadge } from "./ProfileOverview";
import Darkint from "./Darkint";
import Exposure from "./Exposure";
import Images from "./Images";
import Privacy from "./Privacy";
import Remediation from "./Remediation";
import Reports from "./Reports";
import Research from "./Research";
import ReviewQueue from "./ReviewQueue";
import SubjectWorkflows from "./SubjectWorkflows";
import Verification from "./Verification";

// Sub-tabs are listed here only when the feature behind them exists and is tested.
export const SUBTABS = ["Profile", "Review queue", "Associated emails", "Research", "Images", "Exposure", "DARKINT", "Remediation", "Verification", "Reports", "Workflows", "Authorization", "Privacy & data"] as const;

function NewSubject({ caseId, purpose, onDone }: { caseId: string; purpose: string; onDone: () => void }) {
  const [f, setF] = useState({ display_name: "", mode: "self", purpose });
  const create = useMutation({ mutationFn: () => api(`/cases/${caseId}/subjects`, { method: "POST", json: f }), onSuccess: onDone });
  return (
    <form className="card row" aria-label="Create target" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <input aria-label="Display label" placeholder="Display label (a name or an alias)" value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} />
      <select aria-label="Assessment mode" value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value })} style={{ width: 230 }}>
        <option value="self">Self audit</option><option value="client">Consent-based client audit</option><option value="organization">Organization / public-source diligence</option></select>
      <input aria-label="Purpose" placeholder="Purpose (recorded)" value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })} style={{ flex: 1, minWidth: 220 }} />
      <button className="primary" disabled={!f.display_name.trim() || !f.purpose.trim() || create.isPending}>Create target</button>
      {create.isError && <ErrorBox error={create.error} />}
    </form>
  );
}

export function nextAction(p: ProfileT): string {
  if (p.next_action) return p.next_action;
  if (p.authorization.status === "none") return "Record an authorization before any collection.";
  if (["expired", "revoked"].includes(p.authorization.status)) return "Authorization is no longer valid: renew it to resume collection.";
  if (p.unresolved_leads.length) return `Review ${p.unresolved_leads.length} unresolved lead(s).`;
  if (!p.counts.identifiers) return "Add an input (username, email or domain) to research.";
  return "Choose an approved check to run next.";
}

export default function TargetProfile({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const [sub, setSub] = useState<string>("Profile");
  const subs = useQuery({ queryKey: ["subjects", caseId], queryFn: () => api<{ items: SubjectT[]; total: number }>(`/cases/${caseId}/subjects`) });
  const subject = subs.data?.items[0];
  const prof = useQuery({ queryKey: ["profile", subject?.id], enabled: !!subject, queryFn: () => api<ProfileT>(`/subjects/${subject!.id}/profile`) });
  if (subs.isLoading) return <Loading what="target" />;
  if (subs.isError) return <ErrorBox error={subs.error} />;
  if (!subject) {
    return (
      <>
        <Empty title="No target yet" hint="A target is the person or organisation this case is about. Pick the assessment mode and purpose first; nothing is collected until you approve a plan." />
        <NewSubject caseId={caseId} purpose="" onDone={() => qc.invalidateQueries({ queryKey: ["subjects", caseId] })} />
      </>
    );
  }
  if (prof.isLoading || !prof.data) return prof.isError ? <ErrorBox error={prof.error} /> : <Loading what="profile" />;
  const p = prof.data;
  return (
    <section aria-label="Target profile">
      <div className="card" aria-label="Target header">
        <div className="row">
          <h2 style={{ margin: 0 }}>{p.subject.display_name}</h2>
          <span className="badge">{p.subject.type}</span>
          <span className="badge">{{ self: "self audit", client: "client audit", organization: "organization diligence" }[p.subject.mode]}</span>
          {p.risk_summary.confirmed_exposures > 0
            ? <span className="badge failed">{p.risk_summary.confirmed_exposures} confirmed exposure(s) · highest {p.risk_summary.highest_risk}</span>
            : <StateBadge state="not_assessed" label={p.risk_summary.not_assessed ? "exposure partly assessed" : "exposure not assessed"} />}
        </div>
        <div className="muted">Purpose: {p.subject.purpose} · last collected {p.last_collected ? fmt(p.last_collected) : "never"} · <b>Next:</b> {nextAction(p)}</div>
      </div>
      <AuthIndicator a={p.authorization} />
      <div className="tabs" role="tablist" aria-label="Profile sections">
        {SUBTABS.map((t) => <button key={t} role="tab" aria-selected={sub === t} onClick={() => setSub(t)}>{t}{t === "Review queue" && p.unresolved_leads.length ? ` (${p.unresolved_leads.length})` : ""}</button>)}
      </div>
      {sub === "Profile" && <ProfileOverview p={p} onGo={setSub} tabs={[...SUBTABS]} />}
      {sub === "Review queue" && <ReviewQueue p={p} />}
      {sub === "Associated emails" && <AssociatedEmails p={p} />}
      {sub === "Research" && <Research p={p} />}
      {sub === "Images" && <Images p={p} />}
      {sub === "Exposure" && <Exposure p={p} />}
      {sub === "DARKINT" && <Darkint p={p} />}
      {sub === "Remediation" && <Remediation p={p} />}
      {sub === "Verification" && <Verification p={p} />}
      {sub === "Reports" && <Reports p={p} />}
      {sub === "Privacy & data" && <Privacy p={p} />}
      {sub === "Workflows" && <SubjectWorkflows p={p} />}
      {sub === "Authorization" && <Authorization p={p} />}
    </section>
  );
}
