"""Structured tools the Copilot may call.

* READ tools run immediately: they only read local state (no network, no writes) and their output is real data from the app.
* ACTION tools never run from a model call. They become a `CopilotProposal` (with a preview of exactly what would happen) and execute only
  when the signed-in user approves it in the UI. Execution re-checks role, case status and policy, uses the stored arguments (not anything
  the client sends at approval time), and is audited. The model cannot approve, widen, or edit a proposal.
* Hardware capture and credential/key tools are deliberately not exposed: the assistant can explain them and link to the page, nothing more.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai import service as ai
from ..db.models import Case, CaseMember, CopilotProposal, Note, ReportRun, Requirement, Subject, Workflow
from ..policy.targets import TargetError
from ..search import service
from ..telemetry import audit
from . import context as cx
from . import profile_tools as pt
from .kb import KnowledgeBase

ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}


class ToolRefused(Exception):
    """A tool call was rejected before anything happened (bad arguments, no access, policy). The message is shown as-is."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str                       # read | action
    description: str
    params: dict[str, str] = field(default_factory=dict)
    needs_case: bool = True
    sensitive: str = ""             # why an action needs approval, shown on the card


TOOLS: dict[str, ToolSpec] = {t.name: t for t in [
    ToolSpec("list_tools", "read", "List every registered collection tool with its live status.", needs_case=False),
    ToolSpec("tool_status", "read", "Explain one tool: what it does, whether it is installed/configured, recent errors and alternatives.",
             {"tool_id": "tool id, e.g. subfinder"}, needs_case=False),
    ToolSpec("search_docs", "read", "Search the application documentation, glossary and error explanations.", {"query": "what to look up"}, needs_case=False),
    ToolSpec("case_summary", "read", "Counts and state of the open case: targets, findings, claims, requirements, recent runs."),
    ToolSpec("search_evidence", "read", "Search this case's stored findings, notes, evidence and observations.", {"query": "keywords"}),
    ToolSpec("find_conflicts", "read", "List findings where sources disagree about the same thing."),
    ToolSpec("timeline", "read", "Findings in time order with the basis (published or observed)."),
    ToolSpec("recommend_next_steps", "read", "Prioritised, explained next steps computed from the case state."),
    ToolSpec("preview_search", "read", "Show which sources would run for a target and what they would contact. Sends nothing.",
             {"target": "domain, IP, URL, email or username", "target_type": "optional: set 'username' for usernames", "adapters": "optional list of tool ids"}),
    ToolSpec("run_status", "read", "Status and per-source errors of a search run, with causes and alternatives.", {"run_id": "run id"}),
    ToolSpec("start_search", "action", "Start a collection run against a target using the chosen sources. Contacts external services.",
             {"target": "domain, IP, URL, email or username", "target_type": "optional: set 'username' for usernames", "adapters": "list of tool ids (required)"}, sensitive="Sends requests to the listed external services."),
    ToolSpec("create_note", "action", "Add an analyst note to the case.", {"body": "Markdown text"}, sensitive="Writes to the case."),
    ToolSpec("create_requirement", "action", "Add an intelligence requirement (a question the case must answer).",
             {"question": "the question", "priority": "low|medium|high"}, sensitive="Writes to the case."),
    ToolSpec("generate_report", "action", "Generate a report (restricted items withheld).", {"profile": "executive|technical|evidence_pack|multi_int", "format": "html|markdown|json|pdf"},
             sensitive="Writes an encrypted export file."),
    ToolSpec("run_workflow", "action", "Run a saved workflow of this case on a target.", {"workflow_id": "workflow id", "target": "target"},
             sensitive="May contact external services."),
    # ---- Target profile (addendum TP-1.0): nothing here can verify, confirm, reject or merge anything
    ToolSpec("summarize_profile", "read", "What is actually known about the case's target: verified items with evidence, unverified leads, contradictions, what is not assessed."),
    ToolSpec("recommend_research_plan", "read", "Rank the permitted research sources that have not run yet, and list what is blocked and why. Runs nothing."),
    ToolSpec("explain_claim", "read", "Explain one profile claim: sources, confidence rationale, contradictions and its review history.", {"claim_id": "claim id"}),
    ToolSpec("create_verification_queue", "read", "Group unresolved account leads for review. Changes nothing and merges nothing."),
    ToolSpec("explain_exposure", "read", "Explain recorded exposure indicators and the remediation checklist. Never shows secrets."),
    ToolSpec("guide_image_search", "read", "Walk through the manual reverse-image search steps for an imported image.", {"image_id": "optional image id"}),
    ToolSpec("why_not_searched", "read", "Explain why a source has not been searched for this target.", {"source": "tool id or name, e.g. sherlock"}),
    ToolSpec("explain_image_match", "read", "Explain an image match and its limits.", {"match_id": "optional match id"}),
    ToolSpec("propose_enrichment_workflow", "action", "Propose installing one Target-profile workflow template (TP-01..TP-12) as a DISABLED draft for this target.",
             {"slug": "template key such as TP-01", "inputs": "optional object of template inputs"}, sensitive="Creates a disabled automation draft; running it later needs its own approval."),
    ToolSpec("draft_subject_report", "action", "Draft a redacted subject report or analyst package for human review. Exports nothing.", {"audience": "subject|analyst"},
             sensitive="Builds a draft from the target's records; nothing is exported."),
    ToolSpec("aiv_status", "read", "Active verification state for this case: live asset authorizations, plans, runs and observations by severity. Reads only."),
    ToolSpec("explain_aiv_plan", "read", "Explain a verification plan in plain language: exactly what each step would send, the budgets, the authorization and what approval is still needed.",
             {"plan_id": "optional plan id (default: the latest plan)"}),
    ToolSpec("explain_aiv_observation", "read", "Explain verification observations that still need review: what was seen, how sure, what it does not prove, and a suggested remedy.",
             {"observation_id": "optional observation id (default: the most severe unreviewed ones)"}),
    ToolSpec("darkint_summary", "read", "Exposure coverage and reported incidents for the case's target: which providers were asked and when, what was reported, and what is not checked. Reads stored, redacted records only."),
    ToolSpec("explain_exposure_event", "read", "Explain one reported exposure event: what the source claims, what it does not prove, and practical next steps. No leaked content exists to show.",
             {"event_id": "optional event id (default: the newest unreviewed one)"}),
    ToolSpec("propose_darkint_workflow", "action", "Propose installing one exposure template (DARK-01..DARK-05) as a DISABLED draft for this target.",
             {"slug": "template key such as DARK-01", "inputs": "optional object, e.g. {monitor_id: ...}"}, sensitive="Creates a disabled automation draft; running it later needs its own approval and a live authorization."),
    ToolSpec("associated_emails_summary", "read", "Email addresses that sources associate with the target, kept apart as confirmed facts, hypotheses (likely / possible) and rejected matches, with evidence ids, conflicts and gaps."),
    ToolSpec("plan_cross_int", "read", "The prioritized, inspectable cross-discipline research plan for the target: what is ready to run, what needs a person first, what is blocked and why. Runs nothing."),
    ToolSpec("propose_expansion_run", "action", "Propose ONE bounded expansion pass: passive, authorized steps from the cross-INT plan. Cannot confirm anything, start exposure checks or active verification.",
             {"keys": "optional list of plan step keys (default: the top ready steps)"}, sensitive="Contacts the public sources shown in the preview, within the plan's budget, for identifiers the authorization already covers."),
    ToolSpec("propose_aiv_plan", "action", "Propose a DRAFT verification plan for an existing asset authorization. It cannot create or widen an authorization, approve, or run anything.",
             {"authorization_id": "id of an asset authorization in this case", "steps": "list of typed steps, e.g. {kind:'tls_handshake', host:'example.org', port:443}"},
             sensitive="Stores a draft plan only; a person must approve the exact plan in the Verification workspace before any request is sent."),
]}
ACTIONS = {n for n, t in TOOLS.items() if t.kind == "action"}


def tool_prompt() -> str:
    """The tool list shown to the model, generated from TOOLS so the prompt cannot drift from what exists."""
    lines = []
    for t in TOOLS.values():
        args = ", ".join(f"{k}: {v}" for k, v in t.params.items())
        lines.append(f"- {t.name} [{'runs now' if t.kind == 'read' else 'needs user approval'}]: {t.description}" + (f" Args: {args}." if args else ""))
    return "\n".join(lines)


_BLOCK = re.compile(r"```osintcc-tools\s*(\{.*?\})\s*```", re.DOTALL)


def parse_calls(text: str) -> tuple[list[dict[str, Any]], str]:
    """Extract tool calls from a reply. Returns (calls, text-without-the-block). Unknown tools / malformed JSON yield no call."""
    calls: list[dict[str, Any]] = []
    for m in _BLOCK.finditer(text):
        try:
            obj = json.loads(m.group(1))
        except ValueError:
            continue
        for c in (obj.get("calls") if isinstance(obj, dict) else None) or []:
            if isinstance(c, dict) and c.get("tool") in TOOLS and isinstance(c.get("args", {}), dict):
                calls.append({"tool": c["tool"], "args": c.get("args", {})})
    return calls[:4], _BLOCK.sub("", text).strip()


def _text(args: dict[str, Any], name: str, maxlen: int = 2000) -> str:
    v = args.get(name)
    if not isinstance(v, str) or not v.strip() or len(v) > maxlen:
        raise ToolRefused(f"argument '{name}' is missing or invalid")
    return v.strip()


def _ttype(args: dict[str, Any]) -> str | None:
    t = args.get("target_type")
    if t is None or t == "":
        return None
    if not isinstance(t, str) or not re.fullmatch(r"[a-z_]{2,20}", t):
        raise ToolRefused("target_type must be a short lowercase name such as 'username'")
    return t


def case_access(db: Session, user_id: str, case_id: str | None, need: str = "viewer") -> Case:
    if not case_id:
        raise ToolRefused("this needs an open case; open a case first")
    m = db.get(CaseMember, (case_id, user_id))
    case = db.get(Case, case_id)
    if not case or not m or ROLE_RANK[m.access_role] < ROLE_RANK[need]:
        raise ToolRefused("case not found or you do not have the needed role on it")
    return case


class Toolbox:
    def __init__(self, st, user_id: str, kb: KnowledgeBase, case_id: str | None, include_restricted: bool = False):
        self.st, self.user, self.kb, self.case_id, self.restricted = st, user_id, kb, case_id, include_restricted
        self._tools: dict[str, dict[str, Any]] | None = None

    async def tools(self) -> dict[str, dict[str, Any]]:
        if self._tools is None:
            self._tools = await cx.tool_status(self.st)
        return self._tools

    # ------------------------------------------------------------------ read tools
    async def call_read(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = TOOLS.get(name)
        if not spec or spec.kind != "read":
            raise ToolRefused(f"'{name}' is not a read tool")
        tools = await self.tools()
        with self.st.sm() as db:
            if spec.needs_case:
                case_access(db, self.user, self.case_id)
            if name == "list_tools":
                return {"tools": [{k: t[k] for k in ("id", "name", "class", "status", "targets", "endpoints", "key_set")} for t in tools.values()]}
            if name == "tool_status":
                return cx.diagnose_tool(db, self.kb, tools, _text(args, "tool_id", 80), self.case_id)
            if name == "search_docs":
                hits = self.kb.search(_text(args, "query", 300), 5)
                return {"supported": self.kb.supported(hits), "results": [{"source": h.chunk.source, "title": h.chunk.title, "text": h.chunk.text[:600]} for h in hits]}
            assert self.case_id
            if name in pt.READ_TOOLS:
                try:
                    return pt.read(db, self.st, self.user, self.case_id, name, args, tools)
                except pt.Refused as exc:
                    raise ToolRefused(str(exc)) from exc
            if name == "case_summary":
                return cx.case_facts(db, self.case_id)
            if name == "search_evidence":
                chunks, withheld = ai.retrieve(db, self.case_id, _text(args, "query", 500), self.restricted)
                return {"results": chunks, "withheld_restricted": withheld}
            findings, withheld = cx.findings_for_reasoning(db, self.case_id, self.restricted)
            if name == "find_conflicts":
                return {"conflicts": cx.contradictions(findings), "withheld_restricted": withheld, "note": "Disagreement between sources is shown, never resolved automatically."}
            if name == "timeline":
                return {"events": cx.timeline(findings), "withheld_restricted": withheld}
            if name == "recommend_next_steps":
                return {"steps": cx.next_steps(self.st, db, tools, self.case_id, self.restricted)}
            if name == "preview_search":
                case = case_access(db, self.user, self.case_id)
                sel = args.get("adapters")
                if sel is not None and (not isinstance(sel, list) or not all(isinstance(x, str) for x in sel)):
                    raise ToolRefused("adapters must be a list of tool ids")
                try:
                    _, plan = service.preview(db, case, _text(args, "target", 2048), _ttype(args), self.st.adapters, self.st.settings, sel)
                except (TargetError, service.PlanError) as exc:
                    raise ToolRefused(f"policy or target problem: {exc}") from exc
                return {**plan, "executed": False}
            if name == "run_status":
                return cx.diagnose_run(db, self.kb, tools, _text(args, "run_id", 64))
        raise ToolRefused(f"'{name}' is not implemented")

    # ------------------------------------------------------------------ proposals
    def propose(self, db: Session, conversation_id: str, name: str, args: dict[str, Any]) -> CopilotProposal:
        spec = TOOLS.get(name)
        if not spec or spec.kind != "action":
            raise ToolRefused(f"'{name}' is not an action tool")
        case = case_access(db, self.user, self.case_id, "editor")
        if case.status != "open" and name in ("start_search", "run_workflow"):
            raise ToolRefused("the case must be open to collect")
        clean: dict[str, Any]
        preview: dict[str, Any]
        if name == "start_search":
            sel = args.get("adapters")
            if not isinstance(sel, list) or not sel or not all(isinstance(x, str) for x in sel):
                raise ToolRefused("start_search needs 'adapters': the list of tool ids to use (see preview_search)")
            target = _text(args, "target", 2048)
            try:
                parsed, plan = service.preview(db, case, target, _ttype(args), self.st.adapters, self.st.settings, sel)
            except (TargetError, service.PlanError) as exc:
                raise ToolRefused(f"not proposed: {exc}") from exc
            runnable = [s for s in plan["steps"] if s["runnable"]]
            if not runnable:
                raise ToolRefused("not proposed: none of those sources can run now (" + "; ".join(f"{s['adapter_id']}: {s['reason']}" for s in plan["steps"]) + ")")
            clean = {"target": parsed.raw, "target_type": parsed.type, "adapters": [s["adapter_id"] for s in runnable]}
            preview = {"target": plan["target"], "steps": [{k: s.get(k) for k in ("adapter_id", "name", "operation_class", "runnable", "reason", "requires_confirmation", "endpoints")}
                                                         for s in plan["steps"]], "warnings": plan["warnings"], "needs_confirmation": [s["adapter_id"] for s in runnable if s.get("requires_confirmation")]}
        elif name == "create_note":
            clean = {"body": _text(args, "body", 20000)}
            preview = {"body": clean["body"][:2000]}
        elif name == "create_requirement":
            pr = args.get("priority", "medium")
            if pr not in ("low", "medium", "high"):
                raise ToolRefused("priority must be low, medium or high")
            clean = {"question": _text(args, "question", 1000), "priority": pr}
            preview = dict(clean)
        elif name == "generate_report":
            prof, fmt = args.get("profile", "technical"), args.get("format", "html")
            if prof not in ("executive", "technical", "evidence_pack", "multi_int") or fmt not in ("html", "markdown", "json", "pdf"):
                raise ToolRefused("unknown report profile or format")
            clean = {"profile": prof, "format": fmt}
            preview = {**clean, "restricted_items": "withheld (the Copilot cannot include them; use the Reports tab)"}
        elif name in pt.ACTION_TOOLS:
            try:
                clean, preview = pt.propose(db, self.st, self.user, case.id, name, args)
            except pt.Refused as exc:
                raise ToolRefused(str(exc)) from exc
        else:  # run_workflow
            wid = _text(args, "workflow_id", 64)
            wf = db.get(Workflow, wid)
            if not wf or wf.case_id not in (None, case.id) or not wf.enabled:
                raise ToolRefused("workflow not found, not part of this case, or disabled")
            clean = {"workflow_id": wid, "target": _text(args, "target", 2048)}
            preview = {"workflow": wf.name, "target": clean["target"], "note": "policy is evaluated for every step when it runs"}
        p = CopilotProposal(conversation_id=conversation_id, case_id=case.id, tool=name, args_json=clean, preview_json=preview, status="pending")
        db.add(p)
        db.flush()
        audit.record(db, "copilot.propose", actor=self.user, case_id=case.id, resource_type="copilot_proposal", resource_id=p.id, metadata={"tool": name})
        return p

    # ------------------------------------------------------------------ execution (after approval only)
    async def execute(self, proposal_id: str, confirmed_adapters: list[str] | None = None) -> dict[str, Any]:
        confirmed = [c for c in (confirmed_adapters or []) if isinstance(c, str)]
        with self.st.sm() as db:
            p = db.get(CopilotProposal, proposal_id)
            if p is None:
                raise ToolRefused("proposal not found")
            if p.status != "pending":
                raise ToolRefused(f"this proposal is already {p.status}")
            case = case_access(db, self.user, p.case_id, "editor")
            a = p.args_json
            try:
                result = await self._run(db, p, case, a, confirmed)
            except ToolRefused as exc:
                p.status, p.result_json, p.decided_at, p.decided_by = "failed", {"error": str(exc)}, datetime.now(UTC), self.user
                audit.record(db, "copilot.refused", actor=self.user, case_id=case.id, decision="deny", resource_id=p.id, metadata={"tool": p.tool, "reason": str(exc)[:200]})
                db.commit()
                raise
            p.status, p.result_json, p.decided_at, p.decided_by = "executed", result, datetime.now(UTC), self.user
            audit.record(db, "copilot.execute", actor=self.user, case_id=case.id, resource_id=p.id, metadata={"tool": p.tool})
            db.commit()
            return result

    async def _run(self, db: Session, p: CopilotProposal, case: Case, a: dict[str, Any], confirmed: list[str]) -> dict[str, Any]:
        if p.tool == "start_search":
            if case.status != "open":
                raise ToolRefused("the case must be open to run searches")
            try:    # policy is evaluated again now, not trusted from the proposal
                parsed, plan = service.preview(db, case, a["target"], a.get("target_type"), self.st.adapters, self.st.settings, a["adapters"])
                run = service.create_run(db, case, parsed, plan, confirmed=confirmed)
            except (TargetError, service.PlanError) as exc:
                raise ToolRefused(f"policy refused at execution time: {exc}") from exc
            db.flush()
            run_id = run.id
            db.commit()
            t = asyncio.create_task(self.st.runner.run_until_idle(run_id))
            self.st.tasks.add(t)
            t.add_done_callback(self.st.tasks.discard)
            return {"executed": True, "run_id": run_id, "status": "queued", "adapters": run.selected_adapters_json,
                    "note": "The run was started. Results appear in Findings as sources finish; ask me for its status."}
        if p.tool == "create_note":
            n = Note(case_id=case.id, body_markdown=a["body"])
            db.add(n)
            db.flush()
            return {"executed": True, "note_id": n.id}
        if p.tool == "create_requirement":
            r = Requirement(case_id=case.id, question=a["question"], priority=a["priority"], created_by=f"copilot:{self.user}"[:80])
            db.add(r)
            db.flush()
            return {"executed": True, "requirement_id": r.id}
        if p.tool == "generate_report":
            from ..reporting import build as report_build
            from ..reporting import store as report_store
            data = report_build.collect(db, case.id, a["profile"], redact_sensitive=True)
            rr = ReportRun(case_id=case.id, template=a["profile"], redaction_profile="default", evidence_manifest_sha256=data["evidence_manifest_sha256"], status="running")
            db.add(rr)
            db.flush()
            try:
                path = await asyncio.to_thread(report_build.write_report, data, a["format"], self.st.settings.export_dir, f"report-{case.id[:8]}-{rr.id[:8]}")
                path, digest = await asyncio.to_thread(report_store.seal, self.st.vault, rr.id, path)
            except Exception as exc:
                rr.status = "failed"
                raise ToolRefused(f"report failed: {type(exc).__name__}") from exc
            rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
            return {"executed": True, "report_id": rr.id, "file": path.name, "sha256": digest}
        if p.tool == "propose_expansion_run":
            from ..profile import emails as pemails
            from ..profile import expansion as pexp
            from ..profile import research as presearch
            from ..profile.service import ProfileError
            subject = db.get(Subject, a["subject_id"])
            if subject is None or subject.case_id != case.id:
                raise ToolRefused("the subject no longer exists in this case")
            presearch.refresh_tasks(db, subject)
            pemails.sweep(db, subject, f"copilot:{self.user}"[:80])
            try:
                out = pexp.run(db, subject, case, self.st.adapters, self.st.settings, actor=f"copilot:{self.user}"[:80], keys=a["keys"], confirmed_sources=confirmed)
            except ProfileError as exc:
                raise ToolRefused(f"policy refused at execution time: {exc.message}") from exc
            db.flush()
            db.commit()
            for rid in out["run_ids"]:
                t = asyncio.create_task(self.st.runner.run_until_idle(rid))
                self.st.tasks.add(t)
                t.add_done_callback(self.st.tasks.discard)
            return {"executed": True, "status": out["status"], "started_runs": out["started_runs"], "stop_reason": out["stop_reason"],
                    "note": "Started the passive steps in the preview. New addresses will appear as candidates; none is confirmed, researched further or checked for exposure automatically."}
        if p.tool == "propose_aiv_plan":
            from ..aiv import service as aivs
            from ..db.models import AssetAuthorization
            case_access(db, self.user, case.id, "editor")
            from . import aiv_tools
            if not aiv_tools.enabled(db) or case.status != "open":
                raise ToolRefused("active verification is switched off or the case is not open")
            auth = db.get(AssetAuthorization, a["authorization_id"])
            if auth is None or auth.case_id != case.id:
                raise ToolRefused("the asset authorization no longer exists in this case")
            try:
                plan = await aivs.create_plan(db, self.st, case, auth, a["steps"], None, f"copilot:{self.user}"[:80])
            except aivs.AivError as exc:
                raise ToolRefused(f"policy refused at execution time: {exc.message}") from exc
            return {"executed": True, "plan_id": plan.id, "status": plan.status, "note": "Stored as a DRAFT. It is not approved and nothing was sent. Open Verification to review the exact plan and approve it yourself."}
        if p.tool in pt.ACTION_TOOLS:
            try:
                return pt.execute(db, self.st, self.user, case.id, p.tool, a)
            except pt.Refused as exc:
                raise ToolRefused(str(exc)) from exc
        if p.tool == "run_workflow":
            from ..workflows import WorkflowError, execute
            try:
                res = await execute(self.st, a["workflow_id"], case.id, a["target"], None, confirmed, "manual", None, f"copilot:{self.user}"[:80])
            except (WorkflowError, TargetError, service.PlanError) as exc:
                raise ToolRefused(f"policy refused at execution time: {exc}") from exc
            return {"executed": True, **{k: v for k, v in res.items() if k in ("status", "workflow_run_id", "run_ids")}}
        raise ToolRefused("unknown action")

    def reject(self, proposal_id: str) -> None:
        with self.st.sm() as db:
            p = db.get(CopilotProposal, proposal_id)
            if p is None or p.status != "pending":
                raise ToolRefused("proposal not found or already decided")
            case_access(db, self.user, p.case_id, "viewer")
            p.status, p.decided_at, p.decided_by = "rejected", datetime.now(UTC), self.user
            audit.record(db, "copilot.reject", actor=self.user, case_id=p.case_id, resource_id=p.id, metadata={"tool": p.tool})
            db.commit()


def proposal_dict(p: CopilotProposal) -> dict[str, Any]:
    return {"id": p.id, "tool": p.tool, "case_id": p.case_id, "status": p.status, "args": p.args_json, "preview": p.preview_json, "result": p.result_json,
            "sensitive": TOOLS[p.tool].sensitive if p.tool in TOOLS else "", "description": TOOLS[p.tool].description if p.tool in TOOLS else "",
            "created_at": p.created_at.isoformat() if p.created_at else None}


def pending_in(db: Session, conversation_id: str) -> list[CopilotProposal]:
    return list(db.scalars(select(CopilotProposal).where(CopilotProposal.conversation_id == conversation_id).order_by(CopilotProposal.created_at)))
