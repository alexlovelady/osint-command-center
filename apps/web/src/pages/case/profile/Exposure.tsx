import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Empty, ErrorBox, fmt } from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ProfileT } from "../../../lib/profileApi";
import { kAnonymitySplit, sha1Hex } from "../../../lib/sha1";
import { StateBadge } from "./ProfileOverview";

interface Indicator { id: string; class: string; class_label: string; redacted?: boolean; status?: string; status_label?: string; risk?: string; descriptor?: string; provider?: string;
  last_checked?: string; exposure_date?: string | null; remediation_state?: string; caveat?: string; verification_basis?: string }
interface Providers { providers: Record<string, { name: string; cost: string; note: string; maturity: string; terms: string }>; classes: Record<string, { label: string; guidance: string[] }>; never_stored: string[] }
interface Preview { provider_name: string; allowed: boolean; reason: string; cost: string; note: string; maturity: string; requires_key: string | null;
  will_send: { to: string; data: string; also_sent: string }; will_store: string }

const tone = (s?: string) => (s === "confirmed_exposure" ? "failed" : s === "not_found_in_checked_sources" ? "partial" : "not_assessed");

function PasswordCheck({ sid }: { sid: string }) {
  const ref = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  async function run() {
    const pw = ref.current?.value ?? "";
    if (!pw) return;
    setBusy(true); setErr(null); setResult("");
    try {
      const { prefix, suffix } = kAnonymitySplit(sha1Hex(pw));
      if (ref.current) ref.current.value = "";            // the password is gone from the page as soon as it is hashed
      const r = await api<{ suffixes: string[] }>(`/subjects/${sid}/exposure/password-range`, { method: "POST", json: { prefix } });
      const hit = r.suffixes.map((l) => l.split(":")).find(([s]) => s.toUpperCase() === suffix);
      const n = hit ? Number(hit[1]) : 0;
      setResult(n > 0 ? `This password appears ${n.toLocaleString()} time(s) in known breaches. Stop using it everywhere.` : "Not found in the breach list that was checked. That does not prove the password is safe.");
    } catch (e) { setErr(e); } finally { setBusy(false); }
  }
  return (
    <section className="card" aria-label="Password check" style={{ marginTop: 10 }}>
      <h3 style={{ margin: "0 0 4px" }}>Password check (runs in your browser)</h3>
      <p className="muted">Your password is hashed here. Only the first 5 characters of the hash are sent, through this application, to the range service; the rest is compared on this page. Nothing is stored or logged.</p>
      <form className="row" onSubmit={(e) => { e.preventDefault(); void run(); }}>
        <input ref={ref} aria-label="Password to check" type="password" autoComplete="off" spellCheck={false} placeholder="Type a password you use" />
        <button className="primary" disabled={busy}>Check</button>
      </form>
      {result && <div role="status" className="banner">{result}</div>}
      {err != null && <ErrorBox error={err} />}
    </section>
  );
}

export default function Exposure({ p }: { p: ProfileT }) {
  const qc = useQueryClient();
  const sid = p.subject.id;
  const canEdit = p.role !== "viewer";
  const list = useQuery({ queryKey: ["exposure", sid], queryFn: () => api<{ items: Indicator[]; redacted: boolean }>(`/subjects/${sid}/exposure`) });
  const prov = useQuery({ queryKey: ["exposure-providers"], queryFn: () => api<Providers>("/profile/exposure/providers") });
  const inv = () => { qc.invalidateQueries({ queryKey: ["exposure", sid] }); qc.invalidateQueries({ queryKey: ["profile", sid] }); };
  const [f, setF] = useState({ cls: "breach_account", status: "confirmed_exposure", risk: "medium", verification_basis: "owner_confirmed", descriptor: "" });
  const rec = useMutation({ mutationFn: () => api(`/subjects/${sid}/exposure`, { method: "POST", json: { ...f, risk: f.status === "confirmed_exposure" ? f.risk : "unknown" } }), onSuccess: () => { setF({ ...f, descriptor: "" }); inv(); } });
  const emails = p.identifiers.filter((i) => i.kind === "email");
  const [ident, setIdent] = useState("");
  const [ok, setOk] = useState(false);
  const preview = useMutation({ mutationFn: () => api<Preview>(`/subjects/${sid}/exposure/preview`, { method: "POST", json: { identifier_id: ident || emails[0]?.id } }) });
  const run = useMutation({ mutationFn: () => api<{ status: string; message: string }>(`/subjects/${sid}/exposure/approve`, { method: "POST", json: { identifier_id: ident || emails[0]?.id, confirm: true } }), onSuccess: () => { setOk(false); inv(); } });
  return (
    <>
      <div className="banner warn">This screen records <b>status, category, date and remediation</b> only. Passwords, password hashes, tokens, recovery secrets, full government identifiers and breach dumps are never requested or stored.
        <b> Not assessed</b>, <b>not found in checked sources</b> and <b>confirmed exposure</b> are different results; the middle one never proves safety.</div>
      {list.data?.redacted && <div className="banner">Your role shows that exposure records exist, not their contents.</div>}
      {list.data?.items.length === 0 && <Empty title="No exposure records" hint="Nothing has been assessed yet. Absence of records means not assessed." />}
      {(list.data?.items ?? []).length > 0 && (
        <table aria-label="Exposure indicators"><thead><tr><th>Class</th><th>Result</th><th>Risk</th><th>Detail</th><th>Checked</th></tr></thead>
          <tbody>{list.data!.items.map((x) => (
            <tr key={x.id}><td>{x.class_label}</td>
              <td>{x.redacted ? <span className="muted">hidden for your role</span> : <><StateBadge state={tone(x.status)} label={x.status_label} />{x.caveat && <div className="muted">{x.caveat}</div>}</>}</td>
              <td>{x.risk ?? ""}</td><td>{x.descriptor}<div className="muted">{x.provider} · {x.verification_basis?.replace(/_/g, " ")}</div></td><td>{x.last_checked ? fmt(x.last_checked) : ""}</td></tr>))}</tbody></table>)}
      {canEdit && (
        <form className="card" aria-label="Record an exposure result" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); rec.mutate(); }}>
          <h3 style={{ margin: "0 0 6px" }}>Record a result you verified yourself</h3>
          <div className="row">
            <select aria-label="Exposure class" value={f.cls} onChange={(e) => setF({ ...f, cls: e.target.value })} style={{ width: 280 }}>
              {Object.entries(prov.data?.classes ?? {}).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>
            <select aria-label="Result" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })} style={{ width: 240 }}>
              <option value="confirmed_exposure">confirmed exposure</option><option value="not_found_in_checked_sources">not found in checked sources</option><option value="not_assessed">not assessed</option></select>
            {f.status === "confirmed_exposure" && <select aria-label="Risk" value={f.risk} onChange={(e) => setF({ ...f, risk: e.target.value })} style={{ width: 110 }}>{["low", "medium", "high", "critical"].map((r) => <option key={r}>{r}</option>)}</select>}
            <select aria-label="Basis" value={f.verification_basis} onChange={(e) => setF({ ...f, verification_basis: e.target.value })} style={{ width: 190 }}>
              {["owner_confirmed", "provider_notice", "manual_review", "provider_api"].map((b) => <option key={b} value={b}>{b.replace(/_/g, " ")}</option>)}</select>
          </div>
          <input aria-label="Descriptor" maxLength={200} placeholder="Category only, e.g. 'Breach: ExampleService (2023-05); data types: emails, passwords'. Never paste secrets." value={f.descriptor} onChange={(e) => setF({ ...f, descriptor: e.target.value })} style={{ marginTop: 6 }} />
          <button className="primary" style={{ marginTop: 6 }} disabled={rec.isPending}>Record</button>
          {rec.isError && <ErrorBox error={rec.error} />}
        </form>)}
      {canEdit && emails.length > 0 && (
        <section className="card" aria-label="Account breach check" style={{ marginTop: 10 }}>
          <h3 style={{ margin: "0 0 4px" }}>Breach check for one of your email inputs ({prov.data?.providers.hibp?.name})</h3>
          <p className="muted">{prov.data?.providers.hibp?.note} Integration status: <b>{prov.data?.providers.hibp?.maturity.replace(/_/g, " ")}</b> (tested only against recorded responses, not against the live service).</p>
          <div className="row">
            <select aria-label="Email to check" value={ident} onChange={(e) => { setIdent(e.target.value); setOk(false); preview.reset(); }} style={{ width: 280 }}>
              {emails.map((e) => <option key={e.id} value={e.id}>{e.value}</option>)}</select>
            <button onClick={() => preview.mutate()}>Preview what would be sent</button>
          </div>
          {preview.isError && <ErrorBox error={preview.error} />}
          {preview.data && (
            <div className="banner" aria-label="Data preview">
              <div>Sent to <code>{preview.data.will_send.to}</code>: <code>{preview.data.will_send.data}</code> (also {preview.data.will_send.also_sent}).</div>
              <div>Kept: {preview.data.will_store}</div><div className="muted">Cost: {preview.data.cost}. {preview.data.allowed ? "" : `Blocked: ${preview.data.reason}`}</div>
              <label><input type="checkbox" style={{ width: "auto" }} checked={ok} disabled={!preview.data.allowed} onChange={(e) => setOk(e.target.checked)} /> I understand this address will be sent to the provider</label>
              <div><button className="primary" disabled={!ok || run.isPending} onClick={() => run.mutate()}>Run the check</button></div>
            </div>)}
          {run.data && <div role="status" className="banner">{run.data.message}</div>}
          {run.isError && <ErrorBox error={run.error} />}
        </section>)}
      {canEdit && <PasswordCheck sid={sid} />}
    </>
  );
}
