import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ProfileT, TemplateT } from "../../../lib/profileApi";
import { StateBadge } from "./ProfileOverview";

const INPUT: Record<string, string> = { "TP-01": "username", "TP-02": "username", "TP-04": "domain", "TP-09": "username" };

/** The twelve Target-profile workflow templates. Installing one creates a DISABLED draft bound to this subject; running it needs approval and live authorization. */
export default function SubjectWorkflows({ p }: { p: ProfileT }) {
  const sid = p.subject.id;
  const t = useQuery({ queryKey: ["tp-templates", sid], queryFn: () => api<{ items: TemplateT[] }>(`/subjects/${sid}/templates`) });
  const [values, setValues] = useState<Record<string, string>>({});
  const [done, setDone] = useState<Record<string, string>>({});
  const install = useMutation({
    mutationFn: (tpl: TemplateT) => {
      const field = INPUT[tpl.key];
      const inputs = field && values[tpl.key] ? { [field]: values[tpl.key] } : {};
      return api<{ id: string }>(`/subjects/${sid}/workflows`, { method: "POST", json: { slug: tpl.slug, inputs } }).then((r) => ({ key: tpl.key, id: r.id }));
    },
    onSuccess: (r) => setDone((d) => ({ ...d, [r.key]: r.id })),
  });
  const canEdit = p.role !== "viewer";
  return (
    <>
      <div className="banner">Templates ship as <b>disabled drafts</b>. Even periodic checks need your approval and activation, and every run re-checks this subject&apos;s authorization.
        Availability below is read from the tools installed on this machine.</div>
      {t.isError && <ErrorBox error={t.error} />}
      {(t.data?.items ?? []).map((tpl) => (
        <article key={tpl.slug} className="card" aria-label={`${tpl.key} ${tpl.name}`} style={{ marginTop: 8 }}>
          <div className="row"><b>{tpl.key} {tpl.name}</b>
            <StateBadge state={tpl.availability?.state === "ready" ? "completed" : tpl.availability?.state === "partial" ? "partial" : "unavailable"} label={(tpl.availability?.state ?? "unknown").replace(/_/g, " ")} />
            <span className="muted">{tpl.trigger} · {tpl.quota_note} · {tpl.maturity.replace(/_/g, " ")}</span></div>
          <div>{tpl.description}</div>
          {tpl.availability?.missing.map((m) => <div key={m.adapter} className="muted">Needs {m.adapter}: {m.setup}</div>)}
          {tpl.capability_gaps.map((g) => <div key={g} className="muted">Gap: {g}</div>)}
          {canEdit && (
            <div className="row" style={{ marginTop: 6 }}>
              {INPUT[tpl.key] && <input aria-label={`${tpl.key} ${INPUT[tpl.key]}`} placeholder={INPUT[tpl.key]} value={values[tpl.key] ?? ""} onChange={(e) => setValues({ ...values, [tpl.key]: e.target.value })} style={{ maxWidth: 240 }} />}
              <button onClick={() => install.mutate(tpl)} disabled={install.isPending || !!done[tpl.key]}>Install as disabled draft</button>
              {done[tpl.key] && <span>Installed. Open <a href="#/automations">Automations</a> to review, dry-run and request approval.</span>}
            </div>)}
        </article>))}
      {install.isError && <ErrorBox error={install.error} />}
    </>
  );
}
