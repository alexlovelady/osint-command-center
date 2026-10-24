import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox } from "../../components/ui";
import { api } from "../../lib/api";

interface Src { id: string; alias: string; status: string; reliability_assessment: string | null; reports: number;
  consent: { basis: string; authorizing_party: string; scope: string[]; expires_at: string | null; revoked_at: string | null } }

export default function HumintTab({ id }: { id: string }) {
  const qc = useQueryClient();
  const inv = () => qc.invalidateQueries({ queryKey: ["hsrc", id] });
  const list = useQuery({ queryKey: ["hsrc", id], queryFn: () => api<{ items: Src[] }>(`/cases/${id}/human-sources`) });
  const [f, setF] = useState({ alias: "", basis: "informed_consent", party: "", scope: "interview, internal report" });
  const create = useMutation({ mutationFn: () => api("/cases/" + id + "/human-sources", { method: "POST", json: { alias: f.alias, consent: { basis: f.basis, authorizing_party: f.party, scope: f.scope.split(",").map((x) => x.trim()).filter(Boolean) } } }),
    onSuccess: () => { setF({ ...f, alias: "", party: "" }); inv(); } });
  const [text, setText] = useState(""); const [target, setTarget] = useState("");
  const add = useMutation({ mutationFn: () => api(`/human-sources/${target}/reports`, { method: "POST", json: { text } }), onSuccess: () => { setText(""); inv(); } });
  const assess = useMutation({ mutationFn: (v: { sid: string; r: string }) => api(`/human-sources/${v.sid}/assessment`, { method: "POST", json: { reliability: v.r } }), onSuccess: inv });
  const revoke = useMutation({ mutationFn: (v: { sid: string; del: boolean }) => api(`/human-sources/${v.sid}/revoke`, { method: "POST", json: { delete_content: v.del, confirm: v.del, reason: "withdrawn by the source" } }), onSuccess: inv });
  const corro = useQuery({ queryKey: ["corro", id], queryFn: () => api<{ items: { subject: string; predicate: string; single_source: boolean; groups: string[] }[] }>(`/cases/${id}/humint/corroboration`) });
  return (
    <>
      <div className="banner warn">Sources are known <b>only by alias</b>. Consent is required and can be withdrawn at any time; reports are RESTRICTED, stored encrypted, and left out of exports by default. Reliability grades are your judgement — the system never scores a source.</div>
      <form className="card row" onSubmit={(e) => { e.preventDefault(); create.mutate(); }} aria-label="Add a source">
        <input aria-label="Alias" placeholder="Alias (not a real name)" value={f.alias} onChange={(e) => setF({ ...f, alias: e.target.value })} style={{ maxWidth: 180 }} />
        <select aria-label="Consent basis" value={f.basis} onChange={(e) => setF({ ...f, basis: e.target.value })} style={{ width: 180 }}>{["informed_consent", "contract", "public_interview", "legal_duty"].map((b) => <option key={b}>{b}</option>)}</select>
        <input aria-label="Who gave consent" placeholder="Who gave consent and how (by alias or role)" value={f.party} onChange={(e) => setF({ ...f, party: e.target.value })} style={{ flex: 1, minWidth: 220 }} />
        <input aria-label="Scope of consent" value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} style={{ maxWidth: 240 }} />
        <button className="primary" disabled={f.alias.length < 2 || f.party.length < 2}>Add source</button></form>
      {create.isError && <ErrorBox error={create.error} />}
      {list.data?.items.length === 0 && <Empty title="No human sources" />}
      {list.data?.items.map((s) => (
        <div key={s.id} className="card" style={{ marginTop: 8 }}>
          <b>{s.alias}</b> <Badge v={s.status === "active" ? "healthy" : "failed"} /> {s.status} · {s.reports} report(s) · consent: {s.consent.basis}, scope {s.consent.scope.join(", ")}
          <div className="row">
            Reliability (your judgement):
            <select aria-label={`Reliability for ${s.alias}`} value={s.reliability_assessment ?? ""} onChange={(e) => e.target.value && assess.mutate({ sid: s.id, r: e.target.value })} style={{ width: 90 }}>
              <option value="">unrated</option>{["A", "B", "C", "D", "E", "F"].map((r) => <option key={r}>{r}</option>)}</select>
            <button disabled={s.status !== "active"} onClick={() => setTarget(s.id)}>Add report…</button>
            <button onClick={() => revoke.mutate({ sid: s.id, del: false })} disabled={s.status === "revoked"}>Withdraw consent</button>
            <button onClick={() => window.confirm("Delete all of this source's reports, derived claims and index entries? This cannot be undone.") && revoke.mutate({ sid: s.id, del: true })}>Withdraw and delete content</button></div>
        </div>))}
      {revoke.isError && <ErrorBox error={revoke.error} />}
      {target && (
        <div className="card" style={{ marginTop: 8 }}>
          <textarea aria-label="Report text" rows={4} placeholder="Statement as the source gave it (not verified fact)" value={text} onChange={(e) => setText(e.target.value)} />
          <div className="row"><button className="primary" disabled={!text.trim() || add.isPending} onClick={() => add.mutate()}>Record statement</button><button onClick={() => setTarget("")}>Cancel</button></div>
          {add.isError && <ErrorBox error={add.error} />}</div>)}
      <h3>Corroboration</h3>
      {corro.data?.items.length === 0 && <Empty title="No claims rest on human reports yet" />}
      {corro.data?.items.map((c) => <div key={c.subject + c.predicate + c.groups.join()} className="muted">{c.subject} · {c.predicate} — {c.single_source ? <Badge v="medium" /> : <Badge v="healthy" />} {c.groups.length} independent group(s)</div>)}
    </>
  );
}
