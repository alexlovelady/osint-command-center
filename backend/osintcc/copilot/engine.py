"""The Copilot chat engine.

Pipeline for one user message:
  1. access + persistence (the user's message is saved before anything can fail),
  2. model selection and health (missing or failed models degrade to documentation/data-only answers, labelled as such),
  3. deterministic gathering: documentation hits, case facts, evidence, and the read tools the question calls for,
  4. either a deterministic answer (when the answer is a computation: next steps, conflicts, timeline, diagnostics) or a streamed model answer
     that sees the gathered material as DATA,
  5. checks on the model's text: invalid citations are removed, claims of actions that did not happen are flagged, ungrounded answers are marked,
  6. persistence of the reply with its sources, tool calls and proposals.
The model never executes anything: action tools only create proposals that a person approves through a separate endpoint.
"""
from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from ..ai import service as ai
from ..ai.providers import Message, Provider, ProviderError, ProviderUnavailable
from ..db.models import AiCall, AiProfile, Setting
from ..telemetry import audit
from . import context as cx
from . import render, store
from .kb import Hit, KnowledgeBase, tool_chunks
from .prompts import system_prompt
from .tools import TOOLS, Toolbox, ToolRefused, case_access, parse_calls, proposal_dict

DEFAULT_CTX_CHARS = 18000
DETERMINISTIC = {"next_steps", "conflicts", "timeline", "diagnose", "tools"}
MARKER = "```osintcc"
_SENT = re.compile(r"(?<=[.!?])\s+|\n+")
_HEDGE = re.compile(r"propos|approv|pending|waiting|would|will |can |could|let me|if you|once you|should|need|unless|not (yet )?(been|run|started)|nothing", re.IGNORECASE)
_CITE = re.compile(r"\[([cd]\d{1,3})\]")


@dataclass
class ChatRequest:
    text: str
    mode: str = "general"
    ctx: dict[str, Any] = field(default_factory=dict)
    conversation_id: str | None = None
    profile_id: str | None = None
    level: str = "beginner"
    include_restricted: bool = False
    transfer_token: str | None = None
    intent_hint: str | None = None
    quick: bool = False             # deterministic answer only, no model call (used by "Recommend next steps")


class _Hider:
    """Streams text but withholds the machine-readable tool block, tolerating the marker arriving across chunks."""

    def __init__(self) -> None:
        self.buf, self.sent, self.cut = "", 0, False

    def feed(self, piece: str) -> str:
        if self.cut:
            self.buf += piece
            return ""
        self.buf += piece
        i = self.buf.find(MARKER)
        if i >= 0:
            self.cut = True
            out = self.buf[self.sent:i]
            self.sent = i
            return out
        safe = len(self.buf) - (len(MARKER) - 1)
        if safe <= self.sent:
            return ""
        out = self.buf[self.sent:safe]
        self.sent = safe
        return out

    def flush(self) -> str:
        if self.cut:
            return ""
        out = self.buf[self.sent:]
        self.sent = len(self.buf)
        return out


def ev(type_: str, **kw: Any) -> dict[str, Any]:
    return {"type": type_, **kw}


def _short(obj: Any, n: int = 1800) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)[:n]


def sentences_claiming_action(text: str) -> list[str]:
    return [s for s in _SENT.split(text) if s and render.claims_action(s) and not _HEDGE.search(s)]


def suggested_prompts(mode: str, ctx: dict[str, Any], has_case: bool) -> list[dict[str, str]]:
    route, tab = ctx.get("route"), ctx.get("tab")
    P = lambda t, p=None: {"label": t, "prompt": p or t}
    if mode == "tutor":
        base = [P("Walk me through creating a case", "Walk me through creating and managing an investigation"), P("Show me how to run my first search"),
                P("How do I import a file?"), P("How do I make a report?"), P("Help me set up a local AI model", "How do I use and switch the AI model?")]
        return base
    if mode == "investigation" and has_case:
        base = [P("Recommend next steps"), P("Summarise what we know"), P("Do any sources disagree?"), P("Show a timeline"), P("Why is confidence low on these findings?", "Explain the confidence on my findings")]
        if tab == "Search":
            base.insert(1, P("Which sources should I run?", "Which tools are healthy and suit my targets?"))
        return base
    base = [P("What is this page for?"), P("What can the Copilot do?"), P("Which tools are installed and working?"), P("What does 'passive collection' mean?")]
    if route == "setup":
        base.insert(0, P("Walk me through first-run setup"))
    return base


class Engine:
    def __init__(self, st, user_id: str):
        self.st, self.user = st, user_id

    # ------------------------------------------------------------------ model selection
    def select_profile(self, db, profile_id: str | None) -> tuple[AiProfile | None, str]:
        row = db.get(Setting, "ai_enabled")
        if not (row and row.value_json is True):
            return None, "AI is switched off (Settings -> AI)"
        profiles = list(db.scalars(select(AiProfile)))
        if not profiles:
            return None, "no AI profile exists (Setup installs a local model, or add one in Settings -> AI)"
        if profile_id:
            p = db.get(AiProfile, profile_id)
            return (p, "") if p else (None, "the chosen AI profile no longer exists")
        pref = db.get(Setting, "copilot_profile_id")
        if pref and isinstance(pref.value_json, str):
            p = db.get(AiProfile, pref.value_json)
            if p:
                return p, ""
        local = sorted((p for p in profiles if p.local_only), key=lambda p: p.name)
        return (local[0] if local else min(profiles, key=lambda p: p.name)), ""

    async def model_ready(self, p: AiProfile) -> tuple[Provider | None, str]:
        from ..api.v1.ai import build_provider
        try:
            prov = build_provider(self.st, p)
            h = await prov.health()
        except ProviderError as exc:
            return None, str(exc)
        except Exception as exc:
            return None, f"could not start the provider ({type(exc).__name__})"
        if h.get("status") != "healthy":
            return None, h.get("detail") or "the model server is not reachable"
        if h.get("model_present") is False:
            return None, f"model '{p.model_id}' is not installed on that server (Setup can download it, or run: ollama pull {p.model_id})"
        return prov, ""

    async def status(self, profile_id: str | None = None) -> dict[str, Any]:
        with self.st.sm() as db:
            p, why = self.select_profile(db, profile_id)
            profiles = [{"id": x.id, "name": x.name, "model": x.model_id, "type": x.provider_type, "local": x.local_only} for x in db.scalars(select(AiProfile))]
            enabled = bool((db.get(Setting, "ai_enabled") or Setting(key="x", value_json=False)).value_json is True)
        out: dict[str, Any] = {"ai_enabled": enabled, "profiles": profiles, "active": None, "ready": False, "reason": why}
        if p:
            out["active"] = {"id": p.id, "name": p.name, "model": p.model_id, "type": p.provider_type, "local": p.local_only}
            _, why2 = await self.model_ready(p)
            out["ready"], out["reason"] = (not why2), why2
        out["fallback"] = "Without a working model the Copilot still answers from the built-in documentation and your stored data."
        return out

    # ------------------------------------------------------------------ prompt assembly
    def _blocks(self, docs: list[Hit], evidence: list[dict[str, Any]], tool_results: list[tuple[str, Any]], facts: dict[str, Any] | None, ctx: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
        parts, dsrc, csrc = [], [], []
        where = f"The user is on: {ctx['route']}" + (f" / {ctx['tab']} tab" if ctx.get("tab") else "") + "."
        parts.append(where)
        for i, h in enumerate(docs, 1):
            parts.append(f'<doc id="d{i}" source="{h.chunk.source}">{h.chunk.text[:900]}</doc>')
            dsrc.append({"ref": f"d{i}", "id": h.chunk.id, "source": h.chunk.source, "title": h.chunk.title})
        if facts:
            parts.append(f'<data id="case">{_short(facts, 2200)}</data>')
        for i, c in enumerate(evidence, 1):
            parts.append(f'<data id="c{i}" kind="{c["kind"]}" evidence="{",".join(c["evidence_ids"]) or "none"}" confidence="{c["confidence"]}">{c["text"]}</data>')
            csrc.append({"ref": f"c{i}", "kind": c["kind"], "id": c["ref"], "evidence_ids": c["evidence_ids"]})
        for name, res in tool_results:
            parts.append(f'<tool_result name="{name}">{_short(res)}</tool_result>')
        return "\n".join(parts), dsrc, csrc

    def _history(self, msgs: list[dict[str, Any]], budget: int) -> list[Message]:
        out: list[Message] = []
        used = 0
        for m in reversed(msgs):
            if m["role"] == "note":
                text = "[system note] " + m["content"]
                role = "user"
            else:
                text, role = m["content"], m["role"]
            if used + len(text) > budget:
                break
            out.append(Message(role, text[:4000]))
            used += len(text)
        out.reverse()
        while out and out[0].role != "user":    # a conversation must start with the user for most chat templates
            out.pop(0)
        return out

    # ------------------------------------------------------------------ gathering
    async def _gather(self, req: ChatRequest, intent: str | None, box: Toolbox, tools: dict[str, dict[str, Any]], case_id: str | None) -> tuple[list[tuple[str, Any]], list[dict[str, Any]]]:
        results: list[tuple[str, Any]] = []
        events: list[dict[str, Any]] = []

        async def run(name: str, args: dict[str, Any] | None = None) -> Any:
            try:
                r = await box.call_read(name, args or {})
                events.append(ev("tool", name=name, ok=True, args=args or {}))
                results.append((name, r))
                return r
            except ToolRefused as exc:
                events.append(ev("tool", name=name, ok=False, error=str(exc), args=args or {}))
                return None
        txt, ctx = req.text, req.ctx
        if intent == "next_steps" and case_id:
            await run("recommend_next_steps")
        elif intent == "conflicts" and case_id:
            await run("find_conflicts")
        elif intent == "timeline" and case_id:
            await run("timeline")
        elif intent == "summary" and case_id:
            await run("case_summary")
        elif intent in ("diagnose", "tools"):
            named = render.mentioned_tools(txt, tools) or ([ctx["tool_id"]] if ctx.get("tool_id") in tools else [])
            if named:
                for aid in named[:2]:
                    await run("tool_status", {"tool_id": aid})
            elif case_id and intent == "diagnose":
                with self.st.sm() as db:
                    from ..db.models import SearchRun
                    last = db.scalars(select(SearchRun).where(SearchRun.case_id == case_id).order_by(SearchRun.started_at.desc()).limit(3)).all()
                bad = next((r for r in last if r.status in ("failed", "partial")), last[0] if last else None)
                if bad:
                    await run("run_status", {"run_id": bad.id})
                else:
                    await run("list_tools")
            else:
                await run("list_tools")
        if case_id and req.mode == "investigation" and intent not in ("next_steps", "conflicts", "timeline", "diagnose", "tools") or intent == "evidence" and case_id:
            await run("search_evidence", {"query": txt[:400]})
        return results, events

    # ------------------------------------------------------------------ the main entry
    async def chat(self, req: ChatRequest) -> AsyncIterator[dict[str, Any]]:
        st = self.st
        text = " ".join(req.text.split())[:2000]
        if not text:
            yield ev("error", code="empty", message="Type a question first.")
            return
        mode = req.mode if req.mode in store.MODES else "general"
        ctx = cx.clean_ctx(req.ctx)
        req.ctx, req.mode = ctx, mode
        case_id = ctx["case_id"]
        with st.sm() as db:
            try:
                if case_id:
                    case_access(db, self.user, case_id)
            except ToolRefused as exc:
                yield ev("error", code="not_found", message=str(exc))
                return
            conv = store.get_conversation(db, self.user, case_id, req.conversation_id)
            if conv is None:
                yield ev("error", code="not_found", message="conversation not found")
                return
            db.commit()
            conv_id = conv.id
            profile, why_no_profile = self.select_profile(db, req.profile_id)
            policy = None
            if case_id and profile is not None and not profile.local_only:
                from ..api.v1.ai import _policy
                pol = _policy(db, case_id)
                policy = {"allow_cloud": pol.allow_cloud, "require_preview": pol.require_preview}
            prior, skipped = store.load_messages(db, conv_id)
            budget_chars = DEFAULT_CTX_CHARS
            row = db.get(Setting, "copilot_context_chars")
            if row and isinstance(row.value_json, int) and 2000 <= row.value_json <= 200000:
                budget_chars = row.value_json
            prof_snap = {"id": profile.id, "name": profile.name, "model": profile.model_id, "type": profile.provider_type, "local": profile.local_only} if profile else None
        tools = await cx.tool_status(st)
        kb = KnowledgeBase(tool_chunks(st.adapters, tools))
        box = Toolbox(st, self.user, kb, case_id, req.include_restricted and bool(prof_snap and prof_snap["local"]))
        intent = req.intent_hint or render.detect_intent(text)

        # ---- model readiness (cloud needs its own gate before anything is sent)
        provider: Provider | None = None
        degraded = ""
        if profile is None:
            degraded = why_no_profile
        else:
            provider, degraded = await self.model_ready(profile)
        cloud = bool(prof_snap and not prof_snap["local"])
        if cloud and policy is not None and not policy["allow_cloud"]:
            provider, degraded = None, "this case does not allow cloud models (Case -> AI tab); using documentation and stored data only"
        if req.quick:
            provider = None
            degraded = ""
        yield ev("meta", conversation_id=conv_id, mode=mode, intent=intent, skipped_corrupt=skipped,
                 model={"active": prof_snap, "ready": provider is not None, "reason": degraded, "local": (not cloud)})

        # ---- retrieval
        hits = kb.search(text, 6)
        page = kb.module_for(ctx["route"], ctx.get("tab"))
        if page and re.search(r"\b(this|here|current)\b.{0,12}\b(page|tab|screen|view|section)\b|\bwhat can i do here\b", text, re.IGNORECASE) and all(h.chunk.id != page.id for h in hits):
            hits.insert(0, Hit(page, 99.0, 1.0))
        if intent == "tutorial" or mode == "tutor":
            tut = [h for h in kb.search(text, 8, {"tutorial"})][:1]
            hits = tut + [h for h in hits if h.chunk.kind != "tutorial" or not tut]
        supported = kb.supported(hits) or bool(page and hits and hits[0].chunk.id == page.id)
        results, tool_events = await self._gather(req, intent, box, tools, case_id)
        facts = None
        evidence: list[dict[str, Any]] = []
        withheld = 0
        for name, res in results:
            if name == "search_evidence":
                evidence, withheld = res["results"], res["withheld_restricted"]
        if case_id and mode == "investigation":
            with st.sm() as db:
                facts = cx.case_facts(db, case_id)
            if not evidence and "search_evidence" not in [n for n, _ in results]:
                try:
                    r = await box.call_read("search_evidence", {"query": text[:400]})
                    evidence, withheld = r["results"], r["withheld_restricted"]
                except ToolRefused:
                    pass
        docs = hits[:5] if supported or mode != "investigation" else hits[:2]

        # ---- cloud approval gate: nothing is persisted or sent until the user approves exactly this payload
        sys_msg = Message("system", system_prompt(mode, req.level))
        blocks, dsrc, csrc = self._blocks(docs, evidence, [(n, r) for n, r in results if n != "search_evidence"], facts, ctx)
        user_msg = Message("user", f"{blocks}\n\nQuestion: {ai.sanitize(text)}")
        hist_budget = max(1500, budget_chars - len(sys_msg.content) - len(user_msg.content))
        history = self._history(prior, hist_budget)
        messages = [sys_msg, *history, user_msg]
        dropped = max(0, len([m for m in prior if m["role"] != "note"]) - len([m for m in history]))
        use_model = provider is not None and not (intent in DETERMINISTIC and req.quick)
        if use_model and cloud:
            sha = ai.payload_hash(messages)
            token = ai.transfer_token(st.settings.session_token, case_id or "none", profile.id if profile else "", sha)
            if req.transfer_token != token:
                yield ev("approval_required", transfer_token=token, content_sent=False,
                         preview={"provider": (profile.config_json or {}).get("base_url") if profile else None, "model": profile.model_id if profile else None,
                                  "approx_tokens": sum(len(m.content) for m in messages) // 4, "case_records_included": len(evidence), "restricted_items_withheld": withheld,
                                  "warning": "This text and the case records listed will leave this computer for the provider's servers. The provider's retention and training terms apply.",
                                  "messages": [m.__dict__ for m in messages]})
                return

        # ---- persist the user's message now (history survives a failure from here on)
        with st.sm() as db:
            conv = store.get_conversation(db, self.user, case_id, conv_id)
            assert conv is not None
            um = store.add_message(db, conv, "user", text, mode, {"ctx": ctx, "intent": intent})
            um_id = um.id
            if use_model and case_id and profile:
                audit.record(db, "copilot.model_call", actor=self.user, case_id=case_id, metadata={"model": profile.model_id, "local": not cloud, "records": len(evidence)})
                if cloud:
                    audit.record(db, "ai.cloud_transfer", actor=self.user, case_id=case_id,
                                 metadata={"host": urlsplit((profile.config_json or {}).get("base_url", "")).hostname, "model": profile.model_id, "evidence_items": len(evidence),
                                           "payload_sha256": ai.payload_hash(messages)})
            db.commit()
        for e in tool_events:
            yield e
        yield ev("user_saved", message_id=um_id)

        meta: dict[str, Any] = {"ctx": ctx, "intent": intent, "model": prof_snap if use_model else None, "degraded": degraded or None,
                                "tools": [{"name": e["name"], "ok": e["ok"], "error": e.get("error")} for e in tool_events], "context_dropped_turns": dropped}
        shown: list[str] = []
        proposals: list[dict[str, Any]] = []
        warnings: list[str] = []
        det_text, force = self._deterministic(text, intent, results, evidence, hits, kb, mode, supported, case_id)
        sources_all = dsrc + csrc

        # ---- answers that need no model, or when none is available
        if det_text is not None and (not use_model or force):
            lead = ""
            if degraded and not req.quick:
                lead = f"*No AI model answered ({degraded}). This answer comes from the built-in documentation and your stored data.*\n\n"
            body = lead + det_text
            shown.append(body)
            yield ev("delta", text=body)
            if use_model and intent in DETERMINISTIC and not req.quick:
                note = "\n\n**AI analysis** (from the data above):\n"
                yield ev("delta", text=note)
                shown.append(note)
                ask = Message("user", f"{blocks}\n\nQuestion: {ai.sanitize(text)}\n\nIn at most 4 sentences, say what matters most in the tool results above and what to do first. Use only that data; cite [c#]/[d#] if you use them.")
                try:
                    h = _Hider()
                    assert provider is not None
                    async for piece in provider.chat_stream([sys_msg, ask], max_tokens=350):
                        out = h.feed(piece)
                        if out:
                            shown.append(out)
                            yield ev("delta", text=out)
                    tail = h.flush()
                    if tail:
                        shown.append(tail)
                        yield ev("delta", text=tail)
                except (ProviderUnavailable, ProviderError) as exc:
                    warnings.append(f"The AI analysis could not be completed ({exc}); the answer above is complete without it.")
        elif use_model and provider is not None:
            allow_rounds = not cloud
            conv_msgs = list(messages)
            for rnd in range(3):
                h = _Hider()
                raw = ""
                try:
                    async for piece in provider.chat_stream(conv_msgs, max_tokens=900):
                        raw += piece
                        out = h.feed(piece)
                        if out:
                            shown.append(out)
                            yield ev("delta", text=out)
                    tail = h.flush()
                    if tail:
                        shown.append(tail)
                        yield ev("delta", text=tail)
                except (ProviderUnavailable, ProviderError) as exc:
                    degraded = f"the model stopped responding ({exc})"
                    meta["degraded"] = degraded
                    if not "".join(shown).strip():
                        fb = det_text if det_text is not None else render.md_docs(hits, kb)
                        body = f"*The AI model failed to answer ({exc}). Showing the built-in documentation and your stored data instead.*\n\n{fb}"
                        shown.append(body)
                        yield ev("delta", text=body)
                    else:
                        shown.append("\n\n*[The model stopped responding; this reply is incomplete.]*")
                        yield ev("delta", text=shown[-1])
                    break
                calls, _ = parse_calls(raw)
                reads = [c for c in calls if TOOLS[c["tool"]].kind == "read"]
                acts = [c for c in calls if TOOLS[c["tool"]].kind == "action"]
                for c in acts:
                    with st.sm() as db:
                        try:
                            p = box.propose(db, conv_id, c["tool"], c["args"])
                            db.commit()
                            d = proposal_dict(p)
                            proposals.append(d)
                            yield ev("proposal", proposal=d)
                        except ToolRefused as exc:
                            db.rollback()
                            warnings.append(f"I could not propose {c['tool']}: {exc}")
                if reads and allow_rounds and rnd < 2:
                    out_blocks = []
                    for c in reads[:3]:
                        try:
                            r = await box.call_read(c["tool"], c["args"])
                            yield ev("tool", name=c["tool"], ok=True, args=c["args"])
                            meta["tools"].append({"name": c["tool"], "ok": True, "error": None})
                            out_blocks.append(f'<tool_result name="{c["tool"]}">{_short(r)}</tool_result>')
                        except ToolRefused as exc:
                            yield ev("tool", name=c["tool"], ok=False, error=str(exc), args=c["args"])
                            meta["tools"].append({"name": c["tool"], "ok": False, "error": str(exc)})
                            out_blocks.append(f'<tool_result name="{c["tool"]}">refused: {exc}</tool_result>')
                    conv_msgs += [Message("assistant", raw), Message("user", "\n".join(out_blocks) + "\nAnswer the user now using these results.")]
                    shown.append("\n\n")
                    continue
                break
        else:   # nothing deterministic to say and no model: say so plainly
            body = (f"*No AI model is available ({degraded}).* " if degraded else "") + render.md_docs(hits, kb)
            shown.append(body)
            yield ev("delta", text=body)

        # ---- checks on what was said
        final = "".join(shown).replace("[tool_result]", "").strip()
        if use_model and not final:
            if proposals:
                final = "I prepared the proposal below. Nothing happens until you approve it, and you can reject it."
            else:
                final = "The model returned an empty reply. " + (det_text or render.md_docs(hits, kb))
                warnings.append("The model returned an empty reply.")
            yield ev("delta", text=final)
        valid = {s["ref"]: s for s in sources_all}
        bad = [c for c in _CITE.findall(final) if c not in valid]
        if bad:
            final = _CITE.sub(lambda m: m.group(0) if m.group(1) in valid else "", final)
            warnings.append(f"Removed {len(bad)} citation(s) that did not match any record shown to the model.")
        used = [valid[r] for r in dict.fromkeys(_CITE.findall(final)) if r in valid]
        if det_text is not None and final.startswith(det_text[:40]) is False and not used:
            used = []
        if use_model and intent not in DETERMINISTIC:
            if sentences_claiming_action(final):
                final += "\n\n> ⚠ **Nothing was run or changed by this reply.** Actions only happen after you approve a proposal card; any wording above that sounds as if something was done is not a record of an action."
                warnings.append("The reply used wording that suggests an action was taken. No action was taken.")
                meta["action_claim_flagged"] = True
            if (evidence or docs) and not used:
                shown_to_model = (csrc[:5] if mode == "investigation" and evidence else dsrc[:3])
                used = [{**x, "cited": False} for x in shown_to_model]
                warnings.append("The reply has no inline citations. The sources listed are what the model was shown, not proof it used them; treat the reply as unverified.")
                meta["uncited"] = True
        # deterministic sources are always real chunks, list them even when the model cited nothing
        if det_text is not None and not used and (supported or mode == "investigation"):   # an honest "not documented" answer cites nothing
            used = [s for s in dsrc[:3]] if mode != "investigation" else [s for s in csrc[:5]]
        steps = next((r["steps"] for n, r in results if n == "recommend_next_steps"), None)
        meta.update(sources=used, proposals=[p["id"] for p in proposals], warnings=warnings, withheld_restricted=withheld)
        if steps:
            meta["steps"] = steps
        with st.sm() as db:
            conv = store.get_conversation(db, self.user, case_id, conv_id)
            assert conv is not None
            am = store.add_message(db, conv, "assistant", final, mode, meta)
            if use_model and case_id and profile:
                db.add(AiCall(case_id=case_id, actor_id=self.user, provider_type=profile.provider_type, model_id=profile.model_id,
                              evidence_refs_json=sorted({e for c in evidence for e in c["evidence_ids"]}), cloud_transfer_approved=cloud,
                              payload_sha256=ai.payload_hash(messages), outcome="degraded" if meta.get("degraded") else "ok"))
            db.commit()
            am_id = am.id
        yield ev("final", text=final, sources=used, warnings=warnings, message_id=am_id, steps=steps)
        yield ev("done", conversation_id=conv_id, message_id=am_id, proposals=[p["id"] for p in proposals])

    # ------------------------------------------------------------------ deterministic answers
    def _deterministic(self, text: str, intent: str | None, results: list[tuple[str, Any]], evidence: list[dict[str, Any]], hits: list[Hit], kb: KnowledgeBase,
                       mode: str, supported: bool, case_id: str | None) -> tuple[str | None, bool]:
        """(answer, force). `force` means the answer is used even when a model is available (it is a computation or an honest 'not documented')."""
        res = dict(results)
        if intent == "next_steps":
            if "recommend_next_steps" in res:
                return render.md_next_steps(res["recommend_next_steps"]["steps"]), True
            return "Open a case first: next steps are computed from a case's stored data. In the meantime: " + render.md_docs(kb.search("first search create case", 2), kb, 2), True
        if intent == "conflicts" and "find_conflicts" in res:
            return render.md_conflicts(res["find_conflicts"]), True
        if intent == "timeline" and "timeline" in res:
            return render.md_timeline(res["timeline"]), True
        if intent in ("diagnose", "tools"):
            parts = []
            for n in ("tool_status", "run_status"):
                for name, r in results:
                    if name == n:
                        parts.append(render.md_diagnosis(r))
            if "list_tools" in res and not parts:
                parts.append(render.md_tools(res["list_tools"]))
            if parts:
                return "\n\n".join(parts), True
        if intent == "summary" and "case_summary" in res:
            findings: list[dict[str, Any]] = []
            with self.st.sm() as db:
                if case_id:
                    findings, _ = cx.findings_for_reasoning(db, case_id)
            return render.md_summary(res["case_summary"], cx.corroboration(findings)), False
        if not supported and render.is_app_question(text):
            return render.md_docs(hits, kb), True
        concept = supported and re.match(r"\s*(what('s| is| are)|define|explain|how does)\b", text, re.IGNORECASE) is not None
        if mode == "investigation" and case_id and not concept:
            if not evidence:
                return ("This case has no stored findings or notes that match, so I can't answer from evidence. "
                        "Nothing is assumed. Run a search from the Search tab (I can preview which sources would run), or ask for next steps."), True
            lines = ["Stored records that match your question (I am not interpreting them without a model):", ""]
            for i, c in enumerate(evidence[:8], 1):
                lines.append(f"- [c{i}] {c['text']} — confidence: {c['confidence']}")
            return "\n".join(lines), False
        if mode == "tutor" and not supported:
            return render.md_docs(hits, kb), True
        if supported:
            return render.md_docs(hits, kb), False
        return None, False
