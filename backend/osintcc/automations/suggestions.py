"""Opt-in suggestions from APPLICATION events only (searches and reports the user ran in this app). No keystrokes, no screen reading, nothing outside the
app. Off by default; a suggestion only proposes a template: it never creates or activates anything."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AutomationSuggestion,
    AutomationWorkflow,
    Case,
    ReportRun,
    SearchRun,
    Target,
)
from . import settings as aset
from .permissions import aware

WINDOW_DAYS = 7
MIN_REPEATS = 3
TYPE_TO_TEMPLATE = {"domain": ("cy-02-domain-change-watch", "Domain Change Watch"), "username": ("id-02-public-profile-changes", "Public Profile Changes"),
                    "cik": ("co-03-sec-filing-monitor", "SEC Filing Monitor")}
SENSITIVE_CATEGORIES = ("people", "identity")


def refresh(db: Session, owner_id: str, now: datetime | None = None) -> list[AutomationSuggestion]:
    """Look for repeated manual actions and create (at most one open) suggestion per pattern. Returns the new ones."""
    cfg = aset.load(db)["suggestions"]
    if not cfg["enabled"]:
        return []
    now = now or datetime.now(UTC)
    since = now - timedelta(days=WINDOW_DAYS)
    created: list[AutomationSuggestion] = []

    def exists(key: str, case_id: str | None) -> bool:
        for s in db.scalars(select(AutomationSuggestion).where(AutomationSuggestion.owner_id == owner_id, AutomationSuggestion.proposed_template_key == key,
                                                               AutomationSuggestion.case_id == case_id)):
            snooze = aware(s.snooze_until)
            if s.state in ("open", "accepted", "dismissed") or (s.state == "snoozed" and snooze is not None and snooze > now):
                return True
        return False
    rows = db.execute(select(SearchRun.case_id, SearchRun.target_id, func.count()).where(SearchRun.started_at >= since).group_by(SearchRun.case_id, SearchRun.target_id)
                      .having(func.count() >= MIN_REPEATS)).all()
    for case_id, target_id, n in rows:
        case = db.get(Case, case_id)
        tgt = db.get(Target, target_id)
        if case is None or tgt is None or tgt.type not in TYPE_TO_TEMPLATE:
            continue
        if case.category in SENSITIVE_CATEGORIES and not cfg["include_sensitive"]:
            continue                                                              # personal investigations are excluded from profiling unless opted in
        if "repeat_search" in cfg["disabled_categories"]:
            continue
        key, nice = TYPE_TO_TEMPLATE[tgt.type]
        if exists(key, case_id):
            continue
        has_wf = db.scalar(select(func.count()).select_from(AutomationWorkflow).where(AutomationWorkflow.case_id == case_id, AutomationWorkflow.template_slug == key,
                                                                                       AutomationWorkflow.deleted_at.is_(None)))
        if has_wf:
            continue
        s = AutomationSuggestion(owner_id=owner_id, case_id=case_id, proposed_template_key=key, category="repeat_search",
                                 rationale=f"You ran {n} searches on the same {tgt.type} in the last {WINDOW_DAYS} days. '{nice}' can repeat the comparison on a schedule you approve "
                                           f"and tell you only when something changes (about {n * 5} minutes of manual work per week).",
                                 basis_json={"search_runs": n, "window_days": WINDOW_DAYS, "target_type": tgt.type, "case_category": case.category})
        db.add(s)
        created.append(s)
    reports = db.execute(select(ReportRun.case_id, func.count()).where(ReportRun.generated_at >= since).group_by(ReportRun.case_id).having(func.count() >= MIN_REPEATS)).all()
    for case_id, n in reports:
        case = db.get(Case, case_id)
        if case is None or (case.category in SENSITIVE_CATEGORIES and not cfg["include_sensitive"]) or "repeat_report" in cfg["disabled_categories"]:
            continue
        key = "case-05-investigation-brief"
        if exists(key, case_id):
            continue
        s = AutomationSuggestion(owner_id=owner_id, case_id=case_id, proposed_template_key=key, category="repeat_report",
                                 rationale=f"You generated {n} reports for this case in {WINDOW_DAYS} days. 'Investigation Brief' can prepare one when the findings change.",
                                 basis_json={"reports": n, "window_days": WINDOW_DAYS})
        db.add(s)
        created.append(s)
    db.flush()
    return created
