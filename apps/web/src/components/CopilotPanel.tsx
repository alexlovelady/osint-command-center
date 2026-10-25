import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import { navigateTo, useAppCtx } from "../lib/appContext";
import {
  streamChat, type Approval, type ChatBody, type ConvResp, type Level, type Mode, type ModelStatus, type Msg, type Proposal, type Source, type Step,
} from "../lib/copilotApi";
import { Markdown } from "../lib/markdown";
import TourOverlay, { type TourStep } from "./TourOverlay";

const LS = {
  get(k: string, d: string): string { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k: string, v: string): void { try { localStorage.setItem(k, v); } catch { /* storage unavailable: the choice lasts until reload */ } },
};
const MODES: [Mode, string, string][] = [
  ["general", "General", "OSINT concepts and how the app works"],
  ["investigation", "Investigation", "Works from the open case's stored evidence"],
  ["tutor", "Tutor", "Guided walkthroughs and troubleshooting"],
];

interface DocHit { id: string; kind: string; title: string; source: string; text: string; where?: { route: string; tab?: string } | null }

export default function CopilotPanel({ open, setOpen }: { open: boolean; setOpen: (v: boolean) => void }) {
  const ctx = useAppCtx();
  const qc = useQueryClient();
  const [view, setView] = useState<"chat" | "docs">("chat");
  const [mode, setMode] = useState<Mode>(() => LS.get("osintcc.copilot.mode", "general") as Mode);
  const [level, setLevel] = useState<Level>(() => LS.get("osintcc.copilot.level", "beginner") as Level);
  const [profileId, setProfileId] = useState<string>(() => LS.get("osintcc.copilot.profile", ""));
  const [restricted, setRestricted] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [props, setProps] = useState<Record<string, Proposal>>({});
  const [convId, setConvId] = useState<string | null>(null);
  const [skipped, setSkipped] = useState(0);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approval, setApproval] = useState<{ body: ChatBody; a: Approval } | null>(null);
  const [tour, setTour] = useState<{ title: string; steps: TourStep[] } | null>(null);
  const [viewing, setViewing] = useState<{ title: string; text: string; where?: DocHit["where"]; evidence?: string[] } | null>(null);
  const abort = useRef<AbortController | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  const inCase = ctx.route === "case" && !!ctx.case_id;

  useEffect(() => { document.body.classList.toggle("copilot-open", open); return () => document.body.classList.remove("copilot-open"); }, [open]);
  useEffect(() => { LS.set("osintcc.copilot.mode", mode); }, [mode]);
  useEffect(() => { LS.set("osintcc.copilot.level", level); }, [level]);
  useEffect(() => { LS.set("osintcc.copilot.profile", profileId); }, [profileId]);
  // being inside a case selects Investigation; leaving a case drops back to General (the user can still pick any mode)
  useEffect(() => {
    if (inCase && mode === "general") setMode("investigation");
    if (!inCase && mode === "investigation") setMode("general");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inCase]);

  const status = useQuery({ queryKey: ["copilot-status", profileId], enabled: open, staleTime: 20_000,
    queryFn: () => api<ModelStatus>(`/copilot/status${profileId ? `?profile_id=${encodeURIComponent(profileId)}` : ""}`) });
  const sugg = useQuery({ queryKey: ["copilot-sugg", mode, ctx.route, ctx.tab, ctx.case_id], enabled: open,
    queryFn: () => api<{ items: { label: string; prompt: string }[] }>(
      `/copilot/suggestions?mode=${mode}&route=${ctx.route}${ctx.tab ? `&tab=${encodeURIComponent(ctx.tab)}` : ""}${ctx.case_id ? `&case_id=${ctx.case_id}` : ""}`) });
  const tutorials = useQuery({ queryKey: ["copilot-tutorials"], enabled: open && mode === "tutor", staleTime: 600_000,
    queryFn: () => api<{ items: { id: string; title: string; steps: number }[] }>("/copilot/tutorials") });

  const loadConversation = useCallback(async () => {
    try {
      const r = await api<ConvResp>(`/copilot/conversation${ctx.case_id && ctx.route === "case" ? `?case_id=${ctx.case_id}` : ""}`);
      setMsgs(r.messages);
      setConvId(r.conversation?.id ?? null);
      setSkipped(r.skipped_corrupt);
      setProps(Object.fromEntries(r.proposals.map((p) => [p.id, p])));
      setError(null);
    } catch (e) {
      setMsgs([]);
      setError(e instanceof ApiError ? e.message : "Could not load the conversation.");
    }
  }, [ctx.case_id, ctx.route]);
  useEffect(() => { if (open) void loadConversation(); }, [open, loadConversation]);
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: "end" }); }, [msgs, props, approval]);

  const chatCtx = useMemo(() => ({ route: ctx.route, tab: ctx.tab, case_id: ctx.route === "case" ? ctx.case_id : null, tool_id: ctx.tool_id }), [ctx]);

  const send = useCallback(async (text: string, extra: Partial<ChatBody> = {}, keepUser = false) => {
    const t = text.trim();
    if (!t || busy) return;
    setBusy(true);
    setError(null);
    setApproval(null);
    const body: ChatBody = { text: t, mode, ctx: chatCtx, conversation_id: convId, profile_id: profileId || null, level, include_restricted: restricted, ...extra };
    if (!keepUser) setMsgs((m) => [...m, { role: "user", mode, content: t }]);
    setMsgs((m) => [...m, { role: "assistant", mode, content: "", pending: true, meta: { tools: [] } }]);
    setInput("");
    const ac = new AbortController();
    abort.current = ac;
    const patch = (f: (m: Msg) => Msg) => setMsgs((all) => all.map((m, i) => (i === all.length - 1 ? f(m) : m)));
    let ended = false;
    try {
      for await (const e of streamChat(body, ac.signal)) {
        if (e.type === "meta") { setConvId(e.conversation_id); patch((m) => ({ ...m, meta: { ...m.meta, model: e.model.ready && e.model.active ? { name: e.model.active.name, model: e.model.active.model, local: e.model.local } : null, degraded: e.model.reason || null } })); }
        else if (e.type === "delta") patch((m) => ({ ...m, content: m.content + e.text }));
        else if (e.type === "tool") patch((m) => ({ ...m, meta: { ...m.meta, tools: [...(m.meta?.tools ?? []), { name: e.name, ok: e.ok, error: e.error }] } }));
        else if (e.type === "proposal") { setProps((p) => ({ ...p, [e.proposal.id]: e.proposal })); patch((m) => ({ ...m, meta: { ...m.meta, proposals: [...(m.meta?.proposals ?? []), e.proposal.id] } })); }
        else if (e.type === "approval_required") {
          setApproval({ body, a: { transfer_token: e.transfer_token, preview: e.preview } });
          setMsgs((all) => all.slice(0, keepUser ? -1 : -2));
          ended = true;
        } else if (e.type === "final") patch((m) => ({ ...m, content: e.text, pending: false, meta: { ...m.meta, sources: e.sources, warnings: e.warnings, steps: e.steps ?? undefined, profile_citations: e.profile_citations ?? undefined } }));
        else if (e.type === "error") { setError(e.message); patch((m) => ({ ...m, pending: false })); ended = true; }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") setError(err instanceof ApiError ? err.message : "The Copilot connection was interrupted.");
      patch((m) => ({ ...m, pending: false, content: m.content || "(stopped)" }));
    } finally {
      abort.current = null;
      setBusy(false);
      if (!ended) void loadConversation();   // reload so what is shown is exactly what was saved
    }
  }, [busy, mode, chatCtx, convId, profileId, level, restricted, loadConversation]);

  const decide = async (p: Proposal, approve: boolean, confirmed: string[]) => {
    try {
      const r = await api<{ proposal: Proposal }>(`/copilot/proposals/${p.id}/${approve ? "approve" : "reject"}`, { method: "POST", json: approve ? { confirm: true, confirmed_adapters: confirmed } : {} });
      setProps((all) => ({ ...all, [p.id]: r.proposal }));
      if (approve) { qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["case"] }); }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not complete that.");
    }
    void loadConversation();
  };

  const startTutorial = async (id: string) => {
    try {
      const t = await api<{ title: string; steps: { n: number; go: { route: string; tab?: string }; target?: string | null; text: string }[] }>(`/copilot/tutorials/${encodeURIComponent(id)}?level=${level}`);
      setTour({ title: t.title, steps: t.steps });
    } catch (e) { setError(e instanceof ApiError ? e.message : "Could not load that tutorial."); }
  };

  const showSource = async (s: Source) => {
    if (s.kind) {
      setViewing({ title: `${s.kind} ${s.ref}`, text: `A stored record from this case. Evidence: ${(s.evidence_ids ?? []).join(", ") || "none"}.`, evidence: s.evidence_ids });
      return;
    }
    try {
      const d = await api<{ title: string; text: string; meta: { where?: DocHit["where"] } }>(`/copilot/docs/${encodeURIComponent(s.id ?? s.source ?? "")}`);
      setViewing({ title: d.title, text: d.text, where: d.meta?.where });
    } catch { setViewing({ title: s.title ?? s.source ?? s.ref, text: "That documentation entry could not be loaded." }); }
  };

  const status_ = status.data;
  const cloudSelected = !!status_?.active && !status_.active.local;
  const placeholder = mode === "tutor" ? "Ask how to do something…" : mode === "investigation" ? (inCase ? "Ask about this case…" : "Open a case to work from its evidence") : "Ask about OSINT or this app…";

  if (!open) {
    return <button className="copilot-fab primary" data-tour="copilot-button" onClick={() => setOpen(true)} aria-label="Open Copilot">Copilot</button>;
  }
  return (
    <aside className="copilot" aria-label="AI Copilot" data-tour="copilot-panel">
      <header className="copilot-head">
        <b>Copilot</b>
        <span className="grow" />
        <button onClick={() => setView(view === "chat" ? "docs" : "chat")} aria-pressed={view === "docs"}>{view === "chat" ? "Search docs" : "Back to chat"}</button>
        <button onClick={() => setOpen(false)} aria-label="Collapse Copilot">–</button>
      </header>
      <div className="copilot-model" aria-live="polite">
        <span className={`dot ${status_?.ready ? "ok" : "off"}`} aria-hidden />
        {status_?.active
          ? <span title={status_.reason || "ready"}><b>{status_.active.model}</b> · {status_.active.local ? "local" : "cloud"}{status_.ready ? "" : " · unavailable"}</span>
          : <span>No AI model: documentation and stored data only</span>}
        {(status_?.profiles.length ?? 0) > 1 && (
          <select aria-label="Model" value={profileId || status_?.active?.id || ""} onChange={(e) => setProfileId(e.target.value)} style={{ maxWidth: 160, marginLeft: "auto" }}>
            {status_!.profiles.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.model} ({p.local ? "local" : "cloud"})</option>)}
          </select>)}
      </div>
      {status_ && !status_.ready && <div className="banner warn" style={{ margin: "4px 10px", fontSize: 12 }}>{status_.reason || "AI is off."} {status_.fallback} <a href="#/settings">Settings</a> · <a href="#/setup">Setup</a></div>}
      {cloudSelected && <div className="banner warn" style={{ margin: "4px 10px", fontSize: 12 }}><b>Cloud model.</b> Your question and the case records it uses leave this computer, and only after you approve each message.</div>}

      {view === "docs" ? <DocsView onTour={startTutorial} /> : (
        <>
          <div className="copilot-modes">
            <div role="tablist" aria-label="Copilot mode" style={{ display: "flex", gap: 4 }}>
              {MODES.map(([k, label, hint]) => <button key={k} role="tab" aria-selected={mode === k} title={hint} onClick={() => setMode(k)} disabled={k === "investigation" && !inCase}>{label}</button>)}
            </div>
            <span className="grow" />
            <select aria-label="Explanation level" value={level} onChange={(e) => setLevel(e.target.value as Level)} style={{ width: 110 }}>
              <option value="beginner">Beginner</option><option value="advanced">Advanced</option>
            </select>
          </div>
          <div className="muted" style={{ fontSize: 12, padding: "0 10px" }}>
            Context: {ctx.route === "case" ? `case · ${ctx.tab ?? "Search"} tab` : ctx.route}{inCase ? "" : ""}
            {mode === "investigation" && inCase && status_?.active?.local && (
              <label style={{ marginLeft: 8 }}><input type="checkbox" checked={restricted} onChange={(e) => setRestricted(e.target.checked)} style={{ width: "auto" }} /> include restricted items (local model only)</label>)}
          </div>
          <div className="copilot-log" role="log" aria-live="polite" aria-label="Conversation">
            {skipped > 0 && <div className="banner warn" style={{ fontSize: 12 }}>{skipped} damaged saved message(s) were skipped. The rest of the history is intact.</div>}
            {msgs.length === 0 && !busy && (
              <div className="muted" style={{ padding: 8 }}>
                <p style={{ marginTop: 0 }}><b>{MODES.find((m) => m[0] === mode)?.[1]}.</b> {MODES.find((m) => m[0] === mode)?.[2]}. I answer from the app's documentation and your stored data, say when something isn't documented, and never run anything without your approval.</p>
              </div>)}
            {msgs.map((m, i) => (
              <div key={m.id ?? i} className={`bubble ${m.role}`}>
                {m.role === "note" ? <div className="muted" style={{ fontSize: 12 }}>{m.content}</div> : m.role === "user"
                  ? <div>{m.content}</div>
                  : (<>
                    {(m.meta?.tools?.length ?? 0) > 0 && <div className="chips">{m.meta!.tools!.map((t, j) => <span key={j} className={`chip ${t.ok ? "" : "bad"}`} title={t.error ?? "read-only check"}>{t.ok ? "checked" : "refused"}: {t.name}</span>)}</div>}
                    {m.content ? <Markdown text={m.content} onCite={(ref) => { const s = m.meta?.sources?.find((x) => x.ref === ref); if (s) void showSource(s); }} /> : (m.pending ? <span className="muted">Thinking…</span> : null)}
                    {m.pending && m.content && <span className="muted">▍</span>}
                    {m.meta?.steps && <StepList steps={m.meta.steps} />}
                    {(m.meta?.proposals ?? []).map((pid) => props[pid] && <ProposalCard key={pid} p={props[pid]} onDecide={decide} />)}
                    {(m.meta?.warnings ?? []).map((w, j) => <div key={j} className="banner warn" style={{ fontSize: 12 }}>{w}</div>)}
                    {!m.pending && m.meta?.profile_citations && m.meta.profile_citations.length > 0 && (
                      <div className="chips" aria-label="Evidence cited">
                        <span className="muted" style={{ fontSize: 12 }}>Evidence cited:</span>
                        {m.meta.profile_citations.map((c) => <code key={c.id} className="chip" title={`${c.title} · sha256 ${c.sha256}`}>{c.id.slice(0, 8)}</code>)}
                      </div>)}
                    {!m.pending && m.meta?.sources && m.meta.sources.length > 0 && (
                      <div className="chips" aria-label="Sources">
                        <span className="muted" style={{ fontSize: 12 }}>Sources:</span>
                        {m.meta.sources.map((s) => <button key={s.ref + (s.source ?? s.id ?? "")} className="chip" onClick={() => void showSource(s)} title={s.source ?? s.id}>{s.title ?? s.source ?? `${s.kind} ${s.ref}`}</button>)}
                        {m.meta.sources.filter((s) => s.source?.startsWith("tutorial:")).map((s) => <button key={"t" + s.source} className="chip primary" onClick={() => void startTutorial(s.source!.slice(9))}>Start walkthrough</button>)}
                      </div>)}
                  </>)}
              </div>))}
            {viewing && (
              <div className="card" style={{ margin: 8 }}>
                <b>{viewing.title}</b>
                <p style={{ whiteSpace: "pre-wrap", margin: "6px 0" }}>{viewing.text}</p>
                <div className="row">
                  {viewing.where && viewing.where.route !== "any" && <button onClick={() => navigateTo({ route: viewing.where!.route, tab: viewing.where!.tab ?? null })}>Go there</button>}
                  {viewing.evidence && <button onClick={() => navigateTo({ route: "case", tab: "Evidence" })}>Open Evidence tab</button>}
                  <button onClick={() => setViewing(null)}>Close</button>
                </div>
              </div>)}
            {approval && <CloudApproval a={approval.a} onSend={() => void send(approval.body.text, { transfer_token: approval.a.transfer_token }, false)} onCancel={() => setApproval(null)} />}
            {error && <div className="banner err" role="alert" style={{ fontSize: 12 }}>{error}</div>}
            <div ref={endRef} />
          </div>
          {mode === "tutor" && (tutorials.data?.items.length ?? 0) > 0 && (
            <div className="chips" style={{ padding: "0 10px" }} aria-label="Guided tutorials">
              {tutorials.data!.items.map((t) => <button key={t.id} className="chip primary" onClick={() => void startTutorial(t.id)}>▶ {t.title}</button>)}
            </div>)}
          <div className="chips" style={{ padding: "4px 10px" }} aria-label="Suggested prompts">
            {inCase && <button className="chip primary" disabled={busy} data-tour="copilot-next-steps"
              onClick={() => { setMode("investigation"); void send("Recommend next steps", { mode: "investigation", intent_hint: "next_steps", quick: true }); }}>Recommend next steps</button>}
            {(sugg.data?.items ?? []).filter((s) => s.label !== "Recommend next steps").slice(0, 5).map((s) => <button key={s.label} className="chip" disabled={busy} onClick={() => void send(s.prompt)}>{s.label}</button>)}
          </div>
          <form className="copilot-input" onSubmit={(e) => { e.preventDefault(); void send(input); }}>
            <textarea aria-label="Ask the Copilot" rows={2} value={input} placeholder={placeholder} maxLength={2000}
              onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(input); } }} />
            {busy ? <button type="button" onClick={() => abort.current?.abort()}>Stop</button> : <button className="primary" type="submit" disabled={!input.trim()}>Send</button>}
          </form>
        </>)}
      {tour && <TourOverlay title={tour.title} steps={tour.steps} onClose={() => setTour(null)} />}
    </aside>
  );
}

function StepList({ steps }: { steps: Step[] }) {
  return (
    <ol className="steps">
      {steps.map((s) => (
        <li key={s.rank}>
          <b>{s.title}</b>
          <div className="muted" style={{ fontSize: 12 }}>{s.why}</div>
          {s.go && <button className="chip" onClick={() => navigateTo({ route: s.go!.route, tab: s.go!.tab ?? null })}>Go to {s.go.route === "case" ? `${s.go.tab ?? "case"} tab` : s.go.route}</button>}
        </li>))}
    </ol>
  );
}

function ProposalCard({ p, onDecide }: { p: Proposal; onDecide: (p: Proposal, approve: boolean, confirmed: string[]) => Promise<void> }) {
  const steps = (p.preview.steps as { adapter_id: string; name: string; runnable: boolean; reason: string; requires_confirmation?: boolean; endpoints?: string[]; operation_class?: string }[] | undefined) ?? [];
  const need = (p.preview.needs_confirmation as string[] | undefined) ?? [];
  const [ticked, setTicked] = useState<string[]>([]);
  const [working, setWorking] = useState(false);
  const ok = need.every((n) => ticked.includes(n));
  return (
    <div className="card proposal" role="group" aria-label={`Proposed action: ${p.tool}`}>
      <div><span className="badge">proposal</span> <b>{p.tool}</b> <span className={`badge ${p.status === "executed" ? "healthy" : p.status === "failed" ? "failed" : ""}`}>{p.status}</span></div>
      <div className="muted" style={{ fontSize: 12 }}>{p.description}{p.sensitive ? ` ${p.sensitive}` : ""}</div>
      {p.tool === "start_search" ? (
        <>
          <div style={{ marginTop: 6 }}>Target: <code>{String((p.args as { target?: string }).target)}</code></div>
          <table style={{ fontSize: 12 }}><thead><tr><th>Source</th><th>Contacts</th><th>Note</th></tr></thead>
            <tbody>{steps.map((s) => <tr key={s.adapter_id}><td>{s.name}</td><td>{s.runnable ? (s.endpoints?.join(", ") || "local only") : "—"}</td><td>{s.runnable ? s.reason : `will not run: ${s.reason}`}</td></tr>)}</tbody></table>
          {p.status === "pending" && need.map((n) => (
            <label key={n} style={{ display: "block", fontSize: 12 }}><input type="checkbox" style={{ width: "auto" }} checked={ticked.includes(n)} onChange={(e) => setTicked(e.target.checked ? [...ticked, n] : ticked.filter((x) => x !== n))} /> I confirm {n} may contact many third-party sites</label>))}
        </>) : <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, margin: "6px 0" }}>{JSON.stringify(p.preview, null, 1).slice(0, 900)}</pre>}
      {p.status === "pending" && (
        <div className="row">
          <button className="primary" disabled={!ok || working} onClick={async () => { setWorking(true); await onDecide(p, true, ticked); setWorking(false); }}>Approve and run</button>
          <button disabled={working} onClick={async () => { setWorking(true); await onDecide(p, false, []); setWorking(false); }}>Reject</button>
        </div>)}
      {p.status === "executed" && <div className="muted" style={{ fontSize: 12 }}>Done. {typeof p.result.run_id === "string" ? `Run ${p.result.run_id.slice(0, 8)} started; watch it in the Search tab or ask me for its status.` : "Saved."}</div>}
      {p.status === "failed" && <div className="banner err" style={{ fontSize: 12 }}>Nothing was done: {String(p.result.error ?? "refused")}</div>}
      {p.status === "rejected" && <div className="muted" style={{ fontSize: 12 }}>Rejected. Nothing was done.</div>}
    </div>
  );
}

function CloudApproval({ a, onSend, onCancel }: { a: Approval; onSend: () => void; onCancel: () => void }) {
  const [show, setShow] = useState(false);
  return (
    <div className="card" role="alertdialog" aria-label="Approve sending to a cloud model" style={{ borderColor: "var(--warn)" }}>
      <b>Approve sending to the cloud?</b>
      <p style={{ margin: "6px 0" }}>{a.preview.warning}</p>
      <div className="muted" style={{ fontSize: 12 }}>Provider: {a.preview.provider ?? "unknown"} · model {a.preview.model} · about {a.preview.approx_tokens} tokens · {a.preview.case_records_included} case record(s) · {a.preview.restricted_items_withheld} restricted item(s) withheld. This approval is valid for exactly this content.</div>
      <button onClick={() => setShow(!show)} style={{ marginTop: 6 }}>{show ? "Hide" : "Show"} exactly what would be sent</button>
      {show && <pre style={{ whiteSpace: "pre-wrap", fontSize: 11, maxHeight: 200, overflow: "auto" }}>{a.preview.messages.map((m) => `[${m.role}]\n${m.content}`).join("\n\n")}</pre>}
      <div className="row" style={{ marginTop: 8 }}><button className="primary" onClick={onSend}>Send this once</button><button onClick={onCancel}>Cancel</button></div>
    </div>
  );
}

function DocsView({ onTour }: { onTour: (id: string) => void }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<DocHit[] | null>(null);
  const [supported, setSupported] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const run = async (text: string) => {
    if (!text.trim()) { setHits(null); return; }
    const r = await api<{ supported: boolean; items: DocHit[] }>(`/copilot/docs/search?q=${encodeURIComponent(text)}&limit=10`);
    setHits(r.items);
    setSupported(r.supported);
  };
  return (
    <div className="copilot-log" style={{ padding: 10 }}>
      <form onSubmit={(e) => { e.preventDefault(); void run(q); }} className="row">
        <input aria-label="Search the documentation" placeholder="Search pages, tools, errors, terms…" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="primary" type="submit">Search</button>
      </form>
      {hits && !supported && <div className="banner warn" style={{ fontSize: 12 }}>Nothing strongly matches; these are the closest entries. If it isn't here, the app's documentation doesn't cover it.</div>}
      {hits?.length === 0 && <div className="muted">No documentation entries match.</div>}
      {hits?.map((h) => (
        <div key={h.id} className="card" style={{ marginTop: 8 }}>
          <button className="linklike" onClick={() => setOpen(open === h.id ? null : h.id)} aria-expanded={open === h.id}><b>{h.title}</b></button> <span className="badge">{h.kind}</span>
          <div className="muted" style={{ fontSize: 12 }}>{open === h.id ? h.text : `${h.text.slice(0, 140)}…`}</div>
          {open === h.id && <div className="row" style={{ marginTop: 6 }}>
            {h.where && h.where.route !== "any" && <button onClick={() => navigateTo({ route: h.where!.route, tab: h.where!.tab ?? null })}>Go there</button>}
            {h.kind === "tutorial" && <button className="primary" onClick={() => onTour(h.id.slice(9))}>Start walkthrough</button>}
          </div>}
        </div>))}
    </div>
  );
}
