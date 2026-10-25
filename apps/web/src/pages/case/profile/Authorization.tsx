import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import { SOURCE_CLASSES, type AuthT, type ProfileT } from "../../../lib/profileApi";

interface ConsentOut { current: AuthT; history: { id: string; method: string; verifier: string; classes: string[]; obtained_at: string; expires_at: string | null; revoked_at: string | null; has_proof: boolean }[] }

/** Compact indicator shown on every collection screen. Expired or revoked authorization blocks collection immediately (server-enforced). */
export function AuthIndicator({ a }: { a: AuthT }) {
  const ok = a.status === "active" || a.status.startsWith("not_required");
  return (
    <div className={`banner ${ok ? "" : "warn"}`} role="status" aria-label="Authorization status">
      <b>Authorization:</b> {a.status.replace(/_/g, " ")}{a.expires_at ? ` · expires ${fmt(a.expires_at)}` : ""} · {a.message}
    </div>
  );
}

export default function Authorization({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const owner = p.role === "owner";
  const c = useQuery({ queryKey: ["consent", sid], queryFn: () => api<ConsentOut>(`/subjects/${sid}/consent`) });
  const evq = useQuery({ queryKey: ["evidence", p.case.id], queryFn: () => api<{ items: { id: string; title: string }[] }>(`/cases/${p.case.id}/evidence`) });
  const inDays = (n: number) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
  const [f, setF] = useState({ method: p.subject.mode === "client" ? "signed_document" : "self_attestation", verifier: "", purposes: "privacy self-audit", days: 30, proof: "", classes: ["public_passive", "public_site_query"] as string[], scope: [] as string[], providers: [] as string[] });
  const inv = () => { qc.invalidateQueries({ queryKey: ["consent", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const grant = useMutation({
    mutationFn: () => api(`/subjects/${sid}/consent`, { method: "POST", json: {
      verification_method: f.method, verifier: f.verifier, source_classes: f.classes, permitted_purposes: f.purposes.split(",").map((x) => x.trim()).filter(Boolean),
      expires_at: new Date(inDays(f.days) + "T23:59:59Z").toISOString(), identifier_ids: f.scope, proof_evidence_id: f.proof || null, providers: f.classes.includes("exposure_check") ? f.providers : [] } }),
    onSuccess: inv,
  });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/subjects/${sid}/consent/revoke`, { method: "POST", json: { consent_id: id, reason: "revoked by operator" } }), onSuccess: inv });
  const cur = c.data?.current ?? p.authorization;
  const live = cur.status === "active";
  return (
    <>
      <AuthIndicator a={cur} />
      <div className="banner">
        Mode <b>{p.subject.mode}</b>. {p.subject.mode === "client"
          ? "Client engagements need verifiable consent (signed document, email confirmation or in-person) with proof attached, named identities, purposes and an end date. A checkbox is not enough."
          : p.subject.mode === "self" ? "Self-audits may use a self-attestation for ordinary public checks; sensitive checks (exposure, reverse image) need email confirmation, provider verification or a signed document."
            : "Public organisation sources need no personal consent; checks about a named individual do."}
        {" "}A signed engagement never authorises testing unrelated systems or password-protected resources; infrastructure checks need their own asset scope authorization.
      </div>
      {live && cur.consent_id && owner && <button onClick={() => window.confirm("Revoke now? Pending research and scheduled checks stop immediately.") && revoke.mutate(cur.consent_id!)}>Revoke current authorization</button>}
      {revoke.isError && <ErrorBox error={revoke.error} />}
      {owner ? (
        <form className="card" aria-label="Record authorization" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); grant.mutate(); }}>
          <h3 style={{ margin: "0 0 6px" }}>Record an authorization</h3>
          <div className="row">
            <select aria-label="Verification method" value={f.method} onChange={(e) => setF({ ...f, method: e.target.value })} style={{ width: 200 }}>
              {["self_attestation", "email_confirmation", "provider_verification", "signed_document", "in_person"].map((m) => <option key={m} value={m}>{m.replace(/_/g, " ")}</option>)}</select>
            <input aria-label="Verified by" placeholder="Who verified this (name/role)" value={f.verifier} onChange={(e) => setF({ ...f, verifier: e.target.value })} />
            <label>Valid for (days) <input aria-label="Days" type="number" min={1} max={365} value={f.days} onChange={(e) => setF({ ...f, days: Number(e.target.value) })} style={{ width: 80 }} /></label>
            <select aria-label="Proof evidence" value={f.proof} onChange={(e) => setF({ ...f, proof: e.target.value })} style={{ width: 220 }}>
              <option value="">no proof attached</option>{(evq.data?.items ?? []).map((x) => <option key={x.id} value={x.id}>{(x.title || x.id).slice(0, 40)}</option>)}</select>
          </div>
          <input aria-label="Permitted purposes" placeholder="Permitted purposes, comma separated" value={f.purposes} onChange={(e) => setF({ ...f, purposes: e.target.value })} style={{ marginTop: 6 }} />
          <fieldset style={{ marginTop: 6 }}><legend>Source classes covered</legend>
            {SOURCE_CLASSES.map(([k, label]) => (
              <label key={k} style={{ display: "block" }}><input type="checkbox" style={{ width: "auto" }} checked={f.classes.includes(k)}
                onChange={(e) => setF({ ...f, classes: e.target.checked ? [...f.classes, k] : f.classes.filter((x) => x !== k) })} /> {label}</label>))}
          </fieldset>
          {f.classes.includes("exposure_check") && (
            <fieldset style={{ marginTop: 6 }}><legend>Exposure providers permitted (none ticked = any provider an administrator enabled)</legend>
              {[["hibp", "Have I Been Pwned"], ["ransomware_live", "Ransomware.live"]].map(([k, label]) => (
                <label key={k} style={{ display: "block" }}><input type="checkbox" style={{ width: "auto" }} checked={f.providers.includes(k)}
                  onChange={(e) => setF({ ...f, providers: e.target.checked ? [...f.providers, k] : f.providers.filter((x) => x !== k) })} /> {label}</label>))}
            </fieldset>)}
          <fieldset style={{ marginTop: 6 }}><legend>Identities covered (required for client mode)</legend>
            {p.identifiers.map((i) => (
              <label key={i.id} style={{ display: "block" }}><input type="checkbox" style={{ width: "auto" }} checked={f.scope.includes(i.id)}
                onChange={(e) => setF({ ...f, scope: e.target.checked ? [...f.scope, i.id] : f.scope.filter((x) => x !== i.id) })} /> {i.kind}: {i.value}</label>))}
            {p.identifiers.length === 0 && <span className="muted">Add inputs on the Profile tab first.</span>}
          </fieldset>
          <button className="primary" disabled={!f.verifier.trim() || !f.classes.length || grant.isPending}>Record authorization</button>
          {grant.isError && <ErrorBox error={grant.error} />}
        </form>) : <p className="muted">Only a case owner can record an authorization. Any editor can revoke one.</p>}
      <h3>History</h3>
      <table aria-label="Authorization history"><thead><tr><th>Recorded</th><th>Method</th><th>Verified by</th><th>Classes</th><th>Ends</th><th>State</th></tr></thead>
        <tbody>{(c.data?.history ?? []).map((h) => (
          <tr key={h.id}><td>{fmt(h.obtained_at)}</td><td>{h.method.replace(/_/g, " ")}{h.has_proof ? " + proof" : ""}</td><td>{h.verifier}</td><td>{h.classes.join(", ")}</td><td>{fmt(h.expires_at)}</td>
            <td>{h.revoked_at ? `revoked ${fmt(h.revoked_at)}` : new Date(h.expires_at ?? 0) < new Date() ? "expired" : "current"}</td></tr>))}</tbody></table>
    </>
  );
}
