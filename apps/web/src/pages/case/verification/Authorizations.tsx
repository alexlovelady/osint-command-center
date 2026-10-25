import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { CLASS_LABEL, type AivCaps, type AssetAuth } from "../../../lib/aivApi";

const splitList = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function NewAuthorization({ caseId, caps, onDone }: { caseId: string; caps: AivCaps; onDone: () => void }) {
  const inDays = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 16);
  const [f, setF] = useState({ scope: "", ports: "443", classes: ["http_metadata", "tls_handshake"] as string[], authorized_by: "", authority_role: "", source: "", kind: "owner_statement", expires: inDays(7), lab: false });
  const create = useMutation({
    mutationFn: () => api<AssetAuth>(`/cases/${caseId}/asset-authorizations`, { method: "POST", json: {
      asset_type: "fqdn", scope: splitList(f.scope), ports: splitList(f.ports).map(Number), allowed_classes: f.lab ? [...f.classes, caps.lab_class] : f.classes,
      authorized_by: f.authorized_by, authority_role: f.authority_role, source_of_authority: f.source, attestation_kind: f.kind, expires_at: new Date(f.expires).toISOString() } }),
    onSuccess: onDone,
  });
  const toggle = (c: string) => setF({ ...f, classes: f.classes.includes(c) ? f.classes.filter((x) => x !== c) : [...f.classes, c] });
  const ready = splitList(f.scope).length > 0 && splitList(f.ports).every((p) => Number.isInteger(+p) && +p > 0) && f.authorized_by.trim() && f.source.trim().length >= 10 && f.classes.length > 0;
  return (
    <form className="card" aria-label="Record an asset authorization" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <b>Record an asset authorization</b>
      <div className="banner">This is permission from whoever owns or controls the <b>asset</b>. A person’s consent to be researched does <b>not</b> authorize testing a domain or server that carries their name.
        Only the case owner can record one.</div>
      <div className="row">
        <input aria-label="Hosts in scope" placeholder="Exact host names or IPs, e.g. www.example.org" value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} style={{ flex: 2, minWidth: 240 }} />
        <input aria-label="Ports" placeholder="Ports (max 20)" value={f.ports} onChange={(e) => setF({ ...f, ports: e.target.value })} style={{ width: 150 }} />
        <input aria-label="Expires" type="datetime-local" value={f.expires} onChange={(e) => setF({ ...f, expires: e.target.value })} style={{ width: 210 }} />
      </div>
      <fieldset style={{ border: 0, padding: 0, margin: "8px 0" }}>
        <legend className="muted">Checks this authorization permits</legend>
        {caps.classes.map((c) => (
          <label key={c} style={{ display: "block" }}><input type="checkbox" style={{ width: "auto" }} checked={f.classes.includes(c)} onChange={() => toggle(c)} /> {CLASS_LABEL[c] ?? c}</label>))}
        <label style={{ display: "block" }}><input type="checkbox" style={{ width: "auto" }} checked={f.lab} onChange={(e) => setF({ ...f, lab: e.target.checked })} /> {CLASS_LABEL[caps.lab_class]}: only if this target is a private lab you operate</label>
      </fieldset>
      <div className="row">
        <input aria-label="Authorized by" placeholder="Authorized by (name)" value={f.authorized_by} onChange={(e) => setF({ ...f, authorized_by: e.target.value })} />
        <input aria-label="Role" placeholder="Role (owner, IT lead, …)" value={f.authority_role} onChange={(e) => setF({ ...f, authority_role: e.target.value })} />
        <select aria-label="Attestation" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })} style={{ width: 200 }}>
          {caps.attestation_kinds.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}</select>
      </div>
      <textarea aria-label="Source of authority" placeholder="How do you know this person may authorize testing? (for example: I own and operate this server)" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })} rows={2} style={{ width: "100%" }} />
      <div className="row"><button className="primary" disabled={!ready || create.isPending}>Record authorization</button>
        <span className="muted">Default budgets apply: one host per run, at most 10 ports, 2 requests per second, 100 requests, 10 minutes.</span></div>
      {create.isError && <ErrorBox error={create.error} />}
    </form>
  );
}

export default function Authorizations({ caseId, caps }: { caseId: string; caps: AivCaps }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["aiv-auths", caseId], queryFn: () => api<{ items: AssetAuth[] }>(`/cases/${caseId}/asset-authorizations`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["aiv-auths", caseId] });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/cases/${caseId}/asset-authorizations/${id}/revoke`, { method: "POST", json: { reason: "revoked from the Verification workspace" } }), onSuccess: refresh });
  return (
    <>
      {list.isLoading && <Loading what="authorizations" />}
      {list.isError && <ErrorBox error={list.error} />}
      {list.data && !list.data.items.length && <Empty title="No asset authorization yet" hint="Nothing active can run until an authorization names the exact hosts, ports and checks." />}
      {list.data?.items.map((a) => (
        <div className="card" key={a.id} aria-label={`Authorization for ${a.scope.join(", ")}`}>
          <div className="row"><b>{a.scope.join(", ")}</b> <Badge v={a.state === "live" ? "healthy" : "failed"} /> {a.state}
            <span className="grow" />{a.state === "live" && <button onClick={() => revoke.mutate(a.id)} disabled={revoke.isPending}>Revoke now</button>}</div>
          <div className="muted">Ports {a.ports.join(", ")} · {a.allowed_classes.map((c) => CLASS_LABEL[c]?.split(" (")[0] ?? c).join(", ")} · valid until {fmt(a.expires_at)}</div>
          <div className="muted">Authorized by {a.authorized_by}{a.authority_role ? ` (${a.authority_role})` : ""} · {a.attestation_kind.replace(/_/g, " ")} · {a.source_of_authority}</div>
          {a.state_reason && <div className="muted">{a.state_reason}</div>}
        </div>))}
      {revoke.isError && <ErrorBox error={revoke.error} />}
      <NewAuthorization caseId={caseId} caps={caps} onDone={refresh} />
    </>
  );
}
