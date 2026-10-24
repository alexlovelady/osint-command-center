"""Where a PERSON approves or denies MCP write requests. The MCP transport has no way to reach these routes."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from sqlalchemy import select

from ...db.models import McpApproval
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, case_for

router: APIRouter = APIRouter()


def _d(a: McpApproval) -> dict:
    args = {k: v for k, v in a.args_json.items() if not k.startswith("_")}
    return {"id": a.id, "tool": a.tool, "case_id": a.case_id, "client": a.client, "status": a.status, "created_at": a.created_at,
            "arguments": args, "decided_at": a.decided_at}


@router.get("/mcp/approvals")
async def list_approvals(request: Request, status: str | None = "pending"):
    with S(request).sm() as db:
        q = select(McpApproval).order_by(McpApproval.created_at.desc()).limit(100)
        if status:
            q = q.where(McpApproval.status == status)
        out = []
        for a in db.scalars(q):
            try:
                if a.case_id:
                    case_for(db, request, a.case_id, "editor")
                elif a.args_json.get("_user") != actor(request):
                    continue
            except ApiError:
                continue
            out.append(_d(a))
        return {"items": out}


def _decide(request: Request, aid: str, approve: bool):
    with S(request).sm() as db:
        a = db.get(McpApproval, aid)
        if not a:
            raise ApiError(404, "not_found", "approval not found")
        if a.case_id:
            case_for(db, request, a.case_id, "owner")
        elif a.args_json.get("_user") != actor(request):
            # No case to check membership against (create_case): only the user the MCP session acts as may decide.
            raise ApiError(404, "not_found", "approval not found")
        if a.status != "pending":
            raise ApiError(409, "already_decided", f"approval is {a.status}")
        a.status, a.decided_at = ("approved" if approve else "denied"), datetime.now(UTC)
        audit.record(db, "mcp.approval", actor=actor(request), case_id=a.case_id, resource_id=aid, decision="allow" if approve else "deny",
                     metadata={"tool": a.tool})
        db.commit()
        return _d(a)


@router.post("/mcp/approvals/{aid}/approve")
async def approve(request: Request, aid: str):
    return _decide(request, aid, True)


@router.post("/mcp/approvals/{aid}/deny")
async def deny(request: Request, aid: str):
    return _decide(request, aid, False)
