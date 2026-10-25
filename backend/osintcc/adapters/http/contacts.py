"""Public contact-address discovery (Associated Email Discovery).

Two read-only adapters that only report addresses a public source explicitly shows:
  * `github_public`  - GitHub's public API: the contact address a developer chose to list on their profile, and the author addresses on commits they pushed
                       (publicly visible, but self-declared and not proof of ownership). GitHub's anonymous `noreply` addresses are dropped.
  * `page_contacts`  - one public web page: mailto links and addresses written in the page text, each with the sentence around it.
Neither guesses an address, neither tries a pattern, neither contacts a mail server. A finding says "this source shows this address here"; whether the address
belongs to the subject is decided later, from the evidence, by `profile.emails`.
"""
from __future__ import annotations

import html
import json
import re
from typing import Any
from urllib.parse import quote, urlsplit

from ...policy.ssrf import DestinationDenied
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
)

EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5})(?![A-Za-z0-9-])")
OBFUSCATED = re.compile(r"([A-Za-z0-9._%+-]{1,64})\s*[\[(]\s*at\s*[\])]\s*([A-Za-z0-9-]{1,63})\s*[\[(]\s*dot\s*[\])]\s*([A-Za-z]{2,24})", re.IGNORECASE)
MAX_EMAILS = 50
NOREPLY = ("noreply", "no-reply", "donotreply", "do-not-reply")
TAG = re.compile(r"<[^>]+>")
SCRIPT = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")
SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".woff2")


def valid_address(addr: str) -> bool:
    a = addr.lower()
    if any(a.endswith(s) for s in SKIP_SUFFIX) or a.endswith("@users.noreply.github.com") or any(n in a.split("@")[0] for n in NOREPLY):
        return False
    return 3 < len(a) <= 254 and a.count("@") == 1 and ".." not in a


def sentence(text: str, start: int, end: int) -> str:
    """The sentence that contains the address (not the neighbouring ones): what a page says ABOUT an address is in its own sentence."""
    left = max((text.rfind(b, 0, start) for b in (". ", "? ", "! ", " | ", " • ")), default=-1)
    rights = [i for i in (text.find(b, end) for b in (". ", "? ", "! ", " | ", " • ")) if i != -1]
    right = min(rights) if rights else len(text)
    return text[(left + 2 if left >= 0 else 0): right + 1].strip()[:240]


class GithubPublicAdapter:
    manifest = AdapterManifest(
        id="github_public", name="GitHub public profile and commit authors", version="1.0.0", supported_target_types=["username"], operation_class="public_site_query",
        needs_network=True, profile_only=True, rate_limit_per_minute=10, timeout_seconds=45, license="GitHub REST API (anonymous, public data); GitHub terms apply",
        terms_url="https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
        endpoints=["https://api.github.com/users/<username>", "https://api.github.com/users/<username>/events/public"], default_selected=False,
        description="Contact address a developer lists on their public GitHub profile, and author addresses on commits they recently pushed. Commit author fields are "
                    "self-declared; the handle existing on GitHub does not show it belongs to the subject. Unauthenticated: 60 requests per hour per address.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter; remote availability and rate limits are not guaranteed"}

    async def _get(self, ctx: AdapterContext, url: str) -> Any:
        res = await ctx.http.get(url, headers={"Accept": "application/vnd.github+json"})
        return res

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, user = self.manifest.id, target.canonical
        try:
            prof = await self._get(ctx, f"https://api.github.com/users/{quote(user, safe='')}")
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True, warnings=[f"{type(exc).__name__}: {exc}"])
        if prof.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["No GitHub account with that handle. That says nothing about the subject."])
        if prof.status in (403, 429):
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True, retry_after_seconds=600,
                                 warnings=["GitHub's anonymous rate limit was reached; try again later. This is not a negative result."])
        if prof.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{prof.status}", retryable=prof.status >= 500, warnings=[f"GitHub HTTP {prof.status}"])
        try:
            p = json.loads(prof.body)
            assert isinstance(p, dict)
        except (ValueError, AssertionError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["GitHub's answer was not the expected JSON object"])
        artifacts = [RawArtifact(name=f"github-profile-{user}.json", content=prof.body, source_url=prof.url, http_status=200)]
        subject = EntityRef(type="username", key=user, display=user)
        page = str(p.get("html_url") or f"https://github.com/{user}")
        findings: list[FindingDraft] = []
        rels: list[RelationshipDraft] = []
        warnings: list[str] = []
        name = str(p.get("name") or "")[:120]
        seen: set[str] = set()

        def add(addr: str, kind: str, context: str, owner_hint: str, art: int, conf: str, why: str) -> None:
            a = addr.strip().lower()
            if a in seen or not valid_address(a):
                return
            seen.add(a)
            e = EntityRef(type="email", key=a, display=a)
            findings.append(FindingDraft(subject=e, predicate="email.observed", artifact_index=art, confidence=conf, confidence_reason=why,
                                         value={"address": a, "via_kind": kind, "via": user, "url": page, "context": context[:200], "owner_hint": owner_hint[:120],
                                                "explicit": True, "group": "github"}))
            rels.append(RelationshipDraft(from_entity=subject, to_entity=e, relation_type="lists_contact_address", confidence=conf, confidence_reason=why))

        if p.get("email"):
            add(str(p["email"]), "profile_field", f"Contact address listed on the public GitHub profile of '{user}'" + (f" ({name})" if name else ""), name, 0, "medium",
                "The profile owner chose to publish this address on their GitHub profile; it shows the handle and address are connected, not who operates the handle")
        try:
            ev = await self._get(ctx, f"https://api.github.com/users/{quote(user, safe='')}/events/public?per_page=30")
        except Exception as exc:
            warnings.append(f"commit authors could not be read ({type(exc).__name__}); the profile field was still checked")
            ev = None
        if ev is not None and ev.status == 200:
            artifacts.append(RawArtifact(name=f"github-events-{user}.json", content=ev.body, source_url=ev.url, http_status=200))
            try:
                events = json.loads(ev.body)
                assert isinstance(events, list)
            except (ValueError, AssertionError):
                events = []
                warnings.append("GitHub's event list could not be read")
            for e in events[:30]:
                if not isinstance(e, dict) or e.get("type") != "PushEvent":
                    continue
                for c in ((e.get("payload") or {}).get("commits") or [])[:20]:
                    au = c.get("author") or {}
                    add(str(au.get("email") or ""), "commit_author", f"Author address on a commit pushed by '{user}' to {(e.get('repo') or {}).get('name', 'a public repository')}",
                        str(au.get("name") or ""), 1, "low", "Git author fields are self-declared and can name someone else (co-authors, bots, other people's commits)")
        elif ev is not None and ev.status in (403, 429):
            warnings.append("GitHub's rate limit was reached before commit authors could be read; only the profile field was checked (partial)")
        status = "partial" if any("partial" in w or "could not be read" in w for w in warnings) else "success"
        if not findings:
            warnings.append("No public contact address was shown on this profile or in its recent public commits. That says nothing about other sources.")
        return AdapterResult(adapter_id=aid, status=status, artifacts=artifacts, findings=findings, relationships=rels, warnings=warnings)


class PageContactsAdapter:
    manifest = AdapterManifest(
        id="page_contacts", name="Public page contact addresses", version="1.0.0", supported_target_types=["url"], operation_class="passive", needs_network=True, profile_only=True,
        rate_limit_per_minute=20, timeout_seconds=45, license="Fetches one public page; the page's own terms apply",
        endpoints=["<the page URL>"], default_selected=False,
        description="Reads ONE public web page (a confirmed profile, a business site or a contact page) and lists the addresses it shows, each with the sentence around it. "
                    "It does not crawl, log in, follow links or guess addresses.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter; the page may change or disappear"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, url = self.manifest.id, target.canonical
        try:
            res = await ctx.http.get(url, headers={"Accept": "text/html, text/plain;q=0.8"})
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True, warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status == 429:
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True, retry_after_seconds=120)
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500, warnings=[f"the page answered HTTP {res.status}"])
        raw = res.body.decode("utf-8", "replace")
        ctype = res.headers.get("content-type", "")
        if "html" not in ctype and "text" not in ctype:
            return AdapterResult(adapter_id=aid, status="skipped", error_code="not_text", warnings=[f"the page is {ctype or 'not text'}; only HTML and text are read"])
        art = RawArtifact(name="page-contacts.html", content=res.body, mime_type="text/html", source_url=res.url, http_status=200)
        title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw)
        title = html.unescape(TAG.sub("", title_m.group(1))).strip()[:160] if title_m else ""
        body = SCRIPT.sub(" ", raw)
        mailtos = [html.unescape(m).split("?")[0] for m in re.findall(r"""(?i)href\s*=\s*["']mailto:([^"'>\s]+)""", body)]
        text = html.unescape(TAG.sub(" ", body))
        text = re.sub(r"\s+", " ", text)
        host = (urlsplit(url).hostname or "").lower()
        subject = EntityRef(type="url", key=url, display=url)
        findings: list[FindingDraft] = []
        rels: list[RelationshipDraft] = []
        seen: set[str] = set()

        def add(addr: str, how: str, ctx_text: str) -> None:
            a = addr.strip().lower().strip(".,;:")
            if a in seen or not valid_address(a) or len(seen) >= MAX_EMAILS:
                return
            seen.add(a)
            e = EntityRef(type="email", key=a, display=a)
            findings.append(FindingDraft(subject=e, predicate="email.observed", confidence="low", confidence_reason="Written on this public page; the page may be about someone else",
                                         value={"address": a, "via_kind": how, "via": host, "url": url, "context": ctx_text[:200], "page_title": title, "owner_hint": "",
                                                "explicit": False, "group": f"web:{host}"}))
            rels.append(RelationshipDraft(from_entity=subject, to_entity=e, relation_type="lists_contact_address", confidence="low", confidence_reason="Shown on this page"))

        for mt in mailtos:
            if "@" in mt:
                i = text.lower().find(mt.lower())
                add(mt, "mailto_link", sentence(text, i, i + len(mt)) if i >= 0 else f"mailto link on {host}")
        for em in EMAIL.finditer(text):
            add(em.group(0), "page_text", sentence(text, em.start(), em.end()))
        for ob in OBFUSCATED.finditer(text):
            add(f"{ob.group(1)}@{ob.group(2)}.{ob.group(3)}", "obfuscated_text", sentence(text, ob.start(), ob.end()))
        warnings = [] if findings else ["No address is shown on this page. That says nothing about other pages."]
        if len(seen) >= MAX_EMAILS:
            warnings.append(f"Capped at {MAX_EMAILS} addresses; the page shows more.")
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=findings, relationships=rels, warnings=warnings)
