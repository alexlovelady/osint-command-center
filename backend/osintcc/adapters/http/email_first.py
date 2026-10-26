"""Exact-email public-reference discovery (Master Target Profile, TPM2).

Four read-only adapters ask a source that publishes data keyed by an EXACT address whether it holds anything for that address. They never try variants, never guess an
address, never use password-reset or login-error behaviour to learn whether an account exists, and never contact a mail server. What comes back is a LEAD with its source,
the exact evidence and the reason it matched; whether the lead belongs to the person is decided later by a human.

  gravatar_email        a profile the address's owner chose to publish on Gravatar (the request carries only the SHA-256 of the address)
  github_email_search   public GitHub profiles listing the address, and commits authored with it (the address is sent to GitHub)
  keyserver_email       an OpenPGP key whose owner verified the address on keys.openpgp.org (the address is sent to the keyserver)
  web_search_email      pages a web search engine returns for the quoted address (Brave Search API; needs the operator's own key; the address is sent to Brave)

Every one sends the identifier to a third party, so each is classed as a public-site query: it needs explicit confirmation and the preview names where the address goes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import quote

from ...policy.ssrf import DestinationDenied
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    Target,
    skipped,
)

MAX_LEADS = 25


def _norm(addr: str) -> str:
    return addr.strip().lower()


def _san(text: str, limit: int = 240) -> str:
    from ...darkint.sanitize import sanitize_text
    return sanitize_text(text, limit)[0]


async def _get(ctx: AdapterContext, aid: str, url: str, headers: dict[str, str] | None = None):
    try:
        res = await ctx.http.get(url, headers=headers)
    except DestinationDenied as exc:
        return None, AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
    except Exception as exc:
        return None, AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True, warnings=[f"{type(exc).__name__}: {exc}"])
    if res.status == 429:
        ra = res.headers.get("retry-after", "")
        return None, AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True, retry_after_seconds=int(ra) if ra.isdigit() else 120,
                                   warnings=["The source is rate limiting requests. This is not a negative result."])
    return res, None


def reference(email: str, source: str, kind: str, url: str, title: str, snippet: str, *, why: str, leads: dict[str, list[str]] | None = None, art: int = 0, conf: str = "low") -> FindingDraft:
    """One cited exact-match reference. `leads` are identifiers the source shows next to the address; they are candidates, never inputs."""
    return FindingDraft(subject=EntityRef(type="email", key=email, display=email), predicate="email.reference", artifact_index=art, confidence=conf, confidence_reason=why,
                        value={"address": email, "source": source, "via_kind": kind, "url": url[:300], "title": _san(title, 160), "snippet": _san(snippet, 240), "match": "exact address",
                               "leads": {k: [_san(x, 160) for x in v[:MAX_LEADS]] for k, v in (leads or {}).items() if v}})


class GravatarEmailAdapter:
    manifest = AdapterManifest(
        id="gravatar_email", name="Gravatar profile (exact address)", version="1.0.0", supported_target_types=["email"], operation_class="public_site_query", needs_network=True, profile_only=True,
        default_selected=False, rate_limit_per_minute=1, timeout_seconds=30, license="Gravatar REST API; unauthenticated 100 requests per hour", terms_url="https://docs.gravatar.com/",
        endpoints=["https://api.gravatar.com/v3/profiles/<sha256 of the address>"],
        description="Asks Gravatar whether the owner of this exact address published a profile. Only the SHA-256 of the address is sent. A profile exists only if its owner made one; "
                    "its absence says nothing about the person.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter; fixture-tested, not verified against the live service"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, email = self.manifest.id, _norm(target.canonical)
        h = hashlib.sha256(email.encode()).hexdigest()
        res, err = await _get(ctx, aid, f"https://api.gravatar.com/v3/profiles/{h}", {"Accept": "application/json"})
        if err:
            return err
        assert res is not None
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["No Gravatar profile exists for this address. That says nothing about the person."])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500, warnings=[f"Gravatar HTTP {res.status}"])
        try:
            p = json.loads(res.body)
            assert isinstance(p, dict)
        except (ValueError, AssertionError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["Gravatar's answer was not the expected JSON object"])
        accounts = [str(a.get("url")) for a in (p.get("verified_accounts") or []) if isinstance(a, dict) and a.get("url")]
        leads = {"name": [str(p["display_name"])] if p.get("display_name") else [], "url": accounts, "employer": [str(p["company"])] if p.get("company") else [],
                 "role": [str(p["job_title"])] if p.get("job_title") else [], "location": [str(p["location"])] if p.get("location") else []}
        f = reference(email, "Gravatar", "gravatar_profile", str(p.get("profile_url") or ""), str(p.get("display_name") or "Gravatar profile"), str(p.get("description") or ""),
                      why="The address's owner published this profile on Gravatar; the lookup used the hash of this exact address", leads=leads, conf="medium")
        return AdapterResult(adapter_id=aid, status="success", artifacts=[RawArtifact(name="gravatar-profile.json", content=res.body, source_url=res.url, http_status=200)], findings=[f],
                             warnings=["Unauthenticated Gravatar answers cap verified accounts at 4 and omit links."])


class GithubEmailSearchAdapter:
    manifest = AdapterManifest(
        id="github_email_search", name="GitHub search (exact address)", version="1.0.0", supported_target_types=["email"], operation_class="public_site_query", needs_network=True, profile_only=True,
        default_selected=False, rate_limit_per_minute=6, timeout_seconds=45, license="GitHub REST API (anonymous, public data); GitHub terms apply",
        terms_url="https://docs.github.com/en/rest/search/search", endpoints=["https://api.github.com/search/users?q=<address>+in:email", "https://api.github.com/search/commits?q=author-email:<address>"],
        description="Public GitHub profiles that list this address as their public email, and public commits authored with it. The address is sent to GitHub. Anonymous search is limited to "
                    "10 requests per minute. A commit author field is self-declared.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter; fixture-tested, not verified against the live service"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, email = self.manifest.id, _norm(target.canonical)
        hdr = {"Accept": "application/vnd.github+json"}
        users, err = await _get(ctx, aid, f"https://api.github.com/search/users?q={quote(email, safe='')}+in:email&per_page=5", hdr)
        if err:
            return err
        assert users is not None
        if users.status in (401, 403, 422):
            return AdapterResult(adapter_id=aid, status="rate_limited" if users.status == 403 else "error", error_code="rate_limited" if users.status == 403 else f"http_{users.status}",
                                 retryable=users.status == 403, retry_after_seconds=60,
                                 warnings=["GitHub refused the search (anonymous limit reached or query rejected). This is not a negative result."])
        if users.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{users.status}", retryable=users.status >= 500, warnings=[f"GitHub HTTP {users.status}"])
        arts = [RawArtifact(name="github-user-search.json", content=users.body, source_url=users.url, http_status=200)]
        findings: list[FindingDraft] = []
        warnings: list[str] = []
        try:
            items = json.loads(users.body).get("items", [])
        except (ValueError, AttributeError):
            items = []
            warnings.append("GitHub's user search answer could not be read")
        for it in items[:5]:
            if isinstance(it, dict) and it.get("login"):
                findings.append(reference(email, "GitHub", "github_profile_email", str(it.get("html_url") or f"https://github.com/{it['login']}"), f"GitHub user {it['login']}",
                                          "Public GitHub profile whose listed email matches this exact address", why="The profile owner chose to list this address as their public email",
                                          leads={"username": [str(it["login"])], "url": [str(it.get("html_url") or "")]}, conf="medium"))
        commits, err2 = await _get(ctx, aid, f"https://api.github.com/search/commits?q=author-email:{quote(email, safe='')}&per_page=5", hdr)
        if err2 is not None or commits is None or commits.status != 200:
            warnings.append("commit search was not available (rate limit or refusal); only the profile search was checked (partial)")
        else:
            arts.append(RawArtifact(name="github-commit-search.json", content=commits.body, source_url=commits.url, http_status=200))
            try:
                citems = json.loads(commits.body).get("items", [])
            except (ValueError, AttributeError):
                citems = []
            for c in citems[:5]:
                if not isinstance(c, dict):
                    continue
                au = (c.get("commit") or {}).get("author") or {}
                repo = (c.get("repository") or {}).get("html_url") or str(c.get("html_url") or "")
                findings.append(reference(email, "GitHub", "github_commit_author", repo, f"Commit in {(c.get('repository') or {}).get('full_name', 'a public repository')}",
                                          str((c.get("commit") or {}).get("message", "")).splitlines()[0] if (c.get("commit") or {}).get("message") else "", why="Git author fields are self-declared and can name someone else",
                                          leads={"name": [str(au.get("name") or "")], "url": [repo]}))
        if not findings:
            warnings.append("GitHub holds no public profile or commit for this exact address. That says nothing about the person.")
        return AdapterResult(adapter_id=aid, status="partial" if any("partial" in w for w in warnings) else "success", artifacts=arts, findings=findings, warnings=warnings)


def pgp_user_ids(armored: str) -> list[str]:
    """User ID strings from an ASCII-armored OpenPGP public key (packet tag 13). A tiny reader: it does not validate signatures."""
    body = [ln for ln in armored.splitlines() if ln and not ln.startswith(("-----", "=", "Version", "Comment")) and ":" not in ln[:12]]
    try:
        data = base64.b64decode("".join(body) + "===")
    except ValueError:
        return []
    out, i = [], 0
    while i < len(data):
        h = data[i]
        if not h & 0x80:
            break
        if h & 0x40:                                  # new-format packet
            tag = h & 0x3F
            i += 1
            if i >= len(data):
                break
            n = data[i]
            if n < 192:
                ln, i = n, i + 1
            elif n < 224:
                ln, i = ((n - 192) << 8) + data[i + 1] + 192, i + 2
            elif n == 255:
                ln, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
            else:
                break
        else:                                         # old-format packet
            tag, lt = (h >> 2) & 0x0F, h & 0x03
            i += 1
            size = {0: 1, 1: 2, 2: 4}.get(lt)
            if size is None:
                break
            ln, i = int.from_bytes(data[i:i + size], "big"), i + size
        if tag == 13:
            out.append(data[i:i + ln].decode("utf-8", "replace"))
        i += ln
    return out[:20]


class KeyserverEmailAdapter:
    manifest = AdapterManifest(
        id="keyserver_email", name="OpenPGP keyserver (exact address)", version="1.0.0", supported_target_types=["email"], operation_class="public_site_query", needs_network=True, profile_only=True,
        default_selected=False, rate_limit_per_minute=1, timeout_seconds=30, license="keys.openpgp.org public lookup", terms_url="https://keys.openpgp.org/about/api",
        endpoints=["https://keys.openpgp.org/vks/v1/by-email/<address>"],
        description="Whether the owner of this exact address verified it on the keys.openpgp.org keyserver. The address is sent to the keyserver. Lookups are opt-in by the owner and limited to "
                    "one per minute. The name and any other verified addresses on the key are returned as leads.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter; fixture-tested, not verified against the live service"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, email = self.manifest.id, _norm(target.canonical)
        res, err = await _get(ctx, aid, f"https://keys.openpgp.org/vks/v1/by-email/{quote(email, safe='')}", {"Accept": "application/pgp-keys"})
        if err:
            return err
        assert res is not None
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["No verified key for this address. Most people never publish one; this says nothing about the person."])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500, warnings=[f"keyserver HTTP {res.status}"])
        uids = pgp_user_ids(res.body.decode("ascii", "replace"))
        names, others = [], []
        for u in uids:
            m = re.match(r"^(.*?)\s*<([^<>]+@[^<>]+)>\s*$", u)
            addr, nm = (_norm(m.group(2)), m.group(1).strip()) if m else (_norm(u) if "@" in u else "", "" if "@" in u else u)
            if nm:
                names.append(nm)
            if addr and addr != email:
                others.append(addr)
        f = [reference(email, "keys.openpgp.org", "openpgp_key", f"https://keys.openpgp.org/search?q={quote(email, safe='')}", "Verified OpenPGP key", "; ".join(uids[:3]),
                       why="The key's owner verified control of this exact address with the keyserver", leads={"name": names}, conf="medium")]
        for o in others[:10]:
            f.append(FindingDraft(subject=EntityRef(type="email", key=o, display=o), predicate="email.observed", confidence="medium",
                                  confidence_reason="Listed as another verified identity on the same OpenPGP key",
                                  value={"address": o, "via_kind": "openpgp_identity", "via": "keys.openpgp.org", "url": "https://keys.openpgp.org/", "context": "another verified user ID on the key that verifies "
                                         "the starting address", "owner_hint": names[0] if names else "", "explicit": True, "group": "openpgp"}))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[RawArtifact(name="openpgp-key.asc", content=res.body, mime_type="application/pgp-keys", source_url=res.url, http_status=200)], findings=f)


class WebSearchEmailAdapter:
    manifest = AdapterManifest(
        id="web_search_email", name="Web search for the exact address (Brave Search API)", version="1.0.0", supported_target_types=["email"], operation_class="public_site_query", needs_network=True,
        profile_only=True, default_selected=False, api_key_name="brave_search", rate_limit_per_minute=10, timeout_seconds=30, license="Brave Search API; your own subscription key, provider terms apply",
        terms_url="https://brave.com/search/api/", endpoints=["https://api.search.brave.com/res/v1/web/search?q=\"<address>\""],
        install_hint="Store a Brave Search API key via the secrets endpoint (name: brave_search).",
        description="Pages a web search engine returns for the quoted address. The address is sent to Brave. Only results whose title or snippet literally contains the address are kept; "
                    "search results are leads and can be about someone else.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "needs your own Brave Search API key; fixture-tested, not verified against the live service"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid, email = self.manifest.id, _norm(target.canonical)
        key = ctx.secret("brave_search")
        if not key:
            return skipped(aid, "requires_key", "No 'brave_search' API key is stored in the OS credential store; no request was made. Add one in Settings (POST /secrets/brave_search).")
        res, err = await _get(ctx, aid, f"https://api.search.brave.com/res/v1/web/search?q={quote(chr(34) + email + chr(34), safe='')}&count=20", {"Accept": "application/json", "X-Subscription-Token": key})
        if err:
            return err
        assert res is not None
        if res.status in (401, 403):
            return AdapterResult(adapter_id=aid, status="skipped", error_code="requires_key", warnings=[f"Brave rejected the API key (HTTP {res.status}); it may be wrong, expired or out of quota."])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500, warnings=[f"Brave HTTP {res.status}"])
        try:
            rows = (json.loads(res.body).get("web") or {}).get("results") or []
        except (ValueError, AttributeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["Brave's answer could not be read"])
        findings = []
        for r in rows[:20]:
            if not isinstance(r, dict):
                continue
            text = f"{r.get('title', '')} {r.get('description', '')}".lower()
            if email in text:
                findings.append(reference(email, "Brave Search", "web_search_result", str(r.get("url") or ""), str(r.get("title") or ""), str(r.get("description") or ""),
                                          why="A search result whose title or snippet literally contains this exact address", leads={"url": [str(r.get("url") or "")]}))
        warnings = [] if findings else ["No result literally contains this exact address. Search engines cover a fraction of the web; this says nothing about the person."]
        return AdapterResult(adapter_id=aid, status="success", artifacts=[RawArtifact(name="web-search.json", content=res.body, source_url=res.url, http_status=200)], findings=findings, warnings=warnings)
