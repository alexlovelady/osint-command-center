import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import { ErrorBox } from "./ui";

interface SettingsOut { edgar_contact?: string | null; edgar_contact_saved_at?: string | null; edgar_contact_verified_readback?: boolean }
interface TestOut { state: string; detail: string }

/** Same rule the server enforces: a human name, then a valid email. The server is the authority; this only saves a round trip. */
export function contactProblem(v: string): string | null {
  const t = v.trim().replace(/\s+/g, " ");
  const m = /^(.*\S)\s+<?([^\s@<>]+@[^\s@<>]+\.[A-Za-z]{2,})>?$/.exec(t);
  if (!m) return "Enter your name and then your email, for example: Jane Analyst jane@example.org";
  if (m[1].replace(/[^A-Za-zÀ-￿]/g, "").length < 2) return "Add your name before the email address.";
  return null;
}

const when = (iso?: string | null) => (iso ? `${iso.slice(0, 16).replace("T", " ")} UTC` : "");

/** The SEC EDGAR contact. It is configuration, not a secret, so it is shown, editable and read back from the database after every save. */
export default function EdgarContact() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<SettingsOut>("/settings"), retry: false });
  const [draft, setDraft] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const saved = q.data?.edgar_contact ?? "";
  const value = draft ?? saved;
  const dirty = draft !== null && draft.trim().replace(/\s+/g, " ") !== saved;
  const problem = value.trim() ? contactProblem(value) : null;
  const save = useMutation({
    mutationFn: () => api<SettingsOut>("/settings", { method: "PUT", json: { values: { edgar_contact: value.trim() } } }),
    onSuccess: (d) => { qc.setQueryData(["settings"], d); setDraft(null); qc.invalidateQueries({ queryKey: ["provider-usage"] }); },
  });
  const test = useMutation({ mutationFn: () => api<TestOut>("/providers/sec_edgar/test", { method: "POST", json: { confirm: true } }), onSuccess: () => { setConfirm(false); qc.invalidateQueries({ queryKey: ["provider-usage"] }); } });
  let status: { text: string; cls: string };
  if (save.isPending) status = { text: "Saving…", cls: "st-warn" };
  else if (save.isError) status = { text: "Failed to save. Nothing was changed.", cls: "st-bad" };
  else if (dirty) status = { text: "Unsaved changes", cls: "st-warn" };
  else if (saved) status = { text: `Saved${q.data?.edgar_contact_saved_at ? ` at ${when(q.data.edgar_contact_saved_at)}` : ""}`, cls: "st-ok" };
  else status = { text: "Not set: SEC requests are blocked until you save a contact", cls: "st-mute" };
  return (
    <div className="card" aria-label="SEC EDGAR contact">
      <div className="row">
        <label htmlFor="edgar-contact" style={{ minWidth: 300 }}><b>SEC EDGAR contact</b>
          <div className="muted">The SEC requires your name and email in every request. This is not a secret and is not masked.</div></label>
        <input id="edgar-contact" placeholder="Your Name you@example.org" value={value} onChange={(e) => { setDraft(e.target.value); save.reset(); }} style={{ maxWidth: 360 }}
          aria-invalid={dirty && !!problem} aria-describedby="edgar-status" autoComplete="off" />
        <button className="primary" disabled={!dirty || !value.trim() || !!problem || save.isPending} onClick={() => save.mutate()}>Save</button>
        {saved && !dirty && !confirm && <button onClick={() => setConfirm(true)} title="Sends one read-only request to data.sec.gov using this contact.">Test</button>}
        {dirty && <button onClick={() => { setDraft(null); save.reset(); }}>Discard changes</button>}
      </div>
      <div id="edgar-status" role="status" aria-live="polite"><span className={`badge ${status.cls}`}>{status.text}</span>
        {save.data?.edgar_contact_verified_readback && !dirty && <span className="muted"> Read back from the database after saving.</span>}</div>
      {dirty && problem && <div className="banner warn">{problem}</div>}
      {confirm && (
        <div className="banner" role="alert">This sends one read-only request to data.sec.gov (a public company record) with your contact as the User-Agent, at the SEC’s fair-access pace. Nothing is submitted.
          <div className="row"><button className="primary" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? "Testing…" : "Send the test"}</button><button onClick={() => setConfirm(false)}>Cancel</button></div></div>)}
      {test.data && <div className={`banner ${test.data.state === "verified" ? "" : "warn"}`} role="status">{test.data.state === "verified" ? "The SEC accepted the request." : test.data.detail}</div>}
      {(save.isError || test.isError) && <ErrorBox error={save.error ?? test.error} />}
      {q.isError && <div className="muted">The saved contact could not be loaded.</div>}
    </div>
  );
}
