import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading } from "../../components/ui";
import { api, type CaseT } from "../../lib/api";
import { AVAIL_LABEL, MATURITY_LABEL, type TemplateT, type WorkflowT } from "../../lib/automationsApi";

export const goWf = (id: string) => { window.location.hash = `/automations/${id}`; };

export default function Library() {
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["auto-templates", q, cat], queryFn: () => api<{ items: TemplateT[]; categories: string[]; total: number; note: string }>(`/automations/templates?${new URLSearchParams({ ...(q ? { q } : {}), ...(cat ? { category: cat } : {}) })}`) });
  return (
    <>
      <div className="row" role="search" data-tour="auto-library-search">
        <input aria-label="Search templates" placeholder="Search templates (domain, phishing, filings, sensors…)" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 380 }} />
        <select aria-label="Category" value={cat} onChange={(e) => setCat(e.target.value)} style={{ width: 170 }}>
          <option value="">All categories</option>
          {(list.data?.categories ?? []).map((c) => <option key={c}>{c}</option>)}
        </select>
        <span className="muted">{list.data?.total ?? 0} templates</span>
      </div>
      <div className="banner" role="note">{list.data?.note ?? "All templates are installed disabled."}</div>
      {list.isLoading && <Loading what="templates" />}
      {list.isError && <ErrorBox error={list.error} />}
      {list.data?.items.length === 0 && <Empty title="No templates match" hint="Try a different word or clear the category." />}
      <div className="tpl-grid">
        {list.data?.items.map((t) => (
          <article key={t.slug} className={`card tpl ${t.availability.state}`} aria-label={`${t.key} ${t.name}`}>
            <div className="row"><b>{t.key}</b><span className="badge">{t.category}</span><span className="grow" />
              <span className={`badge avail-${t.availability.state}`}>{AVAIL_LABEL[t.availability.state]}</span></div>
            <h4 style={{ margin: "6px 0" }}>{t.name}</h4>
            <p className="muted" style={{ margin: "0 0 8px" }}>{t.description}</p>
            <div className="chips"><span className="chip">trigger: {t.catalog_trigger}</span><span className="chip">{t.quota_note}</span><span className="chip">{MATURITY_LABEL[t.maturity] ?? t.maturity}</span></div>
            <button className="primary" onClick={() => setOpen(open === t.slug ? null : t.slug)} aria-expanded={open === t.slug}>{open === t.slug ? "Close" : "Details"}</button>
            {open === t.slug && <TemplateDetail slug={t.slug} />}
          </article>))}
      </div>
    </>
  );
}

function TemplateDetail({ slug }: { slug: string }) {
  const cases = useQuery({ queryKey: ["cases-all"], queryFn: () => api<{ items: CaseT[] }>("/cases?limit=200") });
  const t = useQuery({ queryKey: ["auto-template", slug], queryFn: () => api<TemplateT>(`/automations/templates/${slug}`) });
  const [caseId, setCaseId] = useState("");
  const [vals, setVals] = useState<Record<string, string>>({});
  const create = useMutation({
    mutationFn: () => api<WorkflowT>("/automations/from-template", { method: "POST", json: { slug, case_id: caseId || null, inputs: Object.fromEntries(Object.entries(vals).filter(([, v]) => v !== "")) } }),
    onSuccess: (w) => goWf(w.id),
  });
  if (t.isLoading) return <Loading what="template" />;
  if (t.isError || !t.data) return <ErrorBox error={t.error} />;
  const d = t.data;
  const av = d.availability;
  return (
    <div className="tpl-detail">
      <h5>Purpose</h5><p>{d.instructions}</p>
      <h5>Sources and tools</h5>
      <p>{d.dependencies.length ? d.dependencies.join(", ") : "none (works on local data)"}{d.optional_dependencies.length ? ` · optional: ${d.optional_dependencies.join(", ")}` : ""}</p>
      {av.missing.length > 0 && <div className="banner warn" role="alert"><b>Setup required.</b><ul style={{ margin: "4px 0 0" }}>{av.missing.map((m) => <li key={m.adapter}><b>{m.adapter}</b> ({m.status.replace(/_/g, " ")}): {m.setup}</li>)}</ul></div>}
      {av.optional_missing.length > 0 && <p className="muted">Optional sources not available (the template still works without them): {av.optional_missing.join(", ")}.</p>}
      {d.capability_gaps.length > 0 && <div className="banner warn"><b>Not implemented yet:</b><ul style={{ margin: "4px 0 0" }}>{d.capability_gaps.map((g) => <li key={g}>{g}</li>)}</ul></div>}
      <h5>Scope and legal notes</h5><p>{d.legal_notes}</p>
      <h5>Estimated quota</h5><p>{d.quota_note}. Scheduled runs are never started until you approve and activate them.</p>
      <h5>Example output</h5><p>{d.example_output}</p>
      <h5>Create from this template</h5>
      <div className="row">
        <select aria-label="Case for this automation" value={caseId} onChange={(e) => setCaseId(e.target.value)} style={{ maxWidth: 260 }}>
          <option value="">No case yet (choose when running)</option>
          {cases.data?.items.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}
        </select>
        {(d.inputs ?? []).filter((i) => i.type !== "evidence").map((i) => (
          <label key={i.name} className="col" style={{ minWidth: 200 }}><span className="muted" style={{ fontSize: 12 }}>{i.label}</span>
            <input aria-label={i.label} placeholder={i.example ?? ""} value={vals[i.name] ?? ""} onChange={(e) => setVals({ ...vals, [i.name]: e.target.value })} /></label>))}
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <button className="primary" onClick={() => create.mutate()} disabled={create.isPending}>Create from template</button>
        <span className="muted">Installs a disabled draft you can dry-run, edit, publish and approve.</span>
      </div>
      {create.isError && <ErrorBox error={create.error} />}
    </div>
  );
}
