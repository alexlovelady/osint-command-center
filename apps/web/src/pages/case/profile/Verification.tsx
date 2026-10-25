import { useQuery } from "@tanstack/react-query";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { SEV_CLASS, type ProfileVerification } from "../../../lib/aivApi";
import type { ProfileT } from "../../../lib/profileApi";

/** Verification of assets that belong to this target. Assets appear here only through an explicit link, never because a name looks similar. */
export default function Verification({ p }: { p: ProfileT }) {
  const sid = p.subject.id;
  const q = useQuery({ queryKey: ["profile-verification", sid], enabled: p.role !== "viewer", queryFn: () => api<ProfileVerification>(`/subjects/${sid}/verification`) });
  if (p.role === "viewer") return <div className="banner">Verification details are hidden for your role.</div>;
  if (q.isLoading) return <Loading what="verification" />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const v = q.data!;
  const open = () => window.dispatchEvent(new CustomEvent("osintcc:tab", { detail: "Verification" }));
  return (
    <>
      <div className="banner">{v.notice}</div>
      {!v.enabled && <div className="banner warn">Active verification is switched off in this installation. Nothing active can run.</div>}
      {v.unlinked_case_authorizations > 0 && <div className="muted">{v.unlinked_case_authorizations} other asset authorization(s) in this case are not linked to this profile and are not shown.</div>}
      {!v.authorizations.length && !v.plans.length && <Empty title="No verified assets linked to this profile" hint="Link an asset by recording its authorization from the Verification workspace and choosing this profile as its owner." />}
      {v.authorizations.map((a) => (
        <div className="card" key={a.id}><div className="row"><b>{a.scope.join(", ")}</b> <Badge v={a.state === "live" ? "healthy" : "failed"} /> {a.state}</div>
          <div className="muted">Ports {a.ports.join(", ")} · valid until {fmt(a.expires_at)} · authorized by {a.authorized_by}</div></div>))}
      {v.observations.slice(0, 20).map((o) => (
        <div className="card" key={o.id}><div className="row"><Badge v={SEV_CLASS[o.severity] ?? "unknown"} /> <b>{String((o.observed as { title?: string }).title ?? o.finding_key)}</b>
          <span className="grow" /><span className="badge">{o.review_status.replace(/_/g, " ")}</span></div><div className="muted"><code>{o.target_asset}</code> · {o.check_type}</div></div>))}
      <button onClick={open}>Open the Verification workspace</button>
    </>
  );
}
