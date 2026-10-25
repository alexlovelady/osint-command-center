"""Category-aware source registry (addendum 4.1). Describes, for each collection method, what it needs and what it produces.

Technical facts (target types, operation class, key name, rate limit, endpoints) come from the adapter manifests; only the profile-level
facts the manifests do not carry (category, privacy class, consent class, data classes, maturity, legal note) are kept here. A source that is
not listed here is not offered for subject research, so a new adapter never becomes reachable from a profile by accident.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# kind of subject identifier -> target type understood by policy.targets / adapters
KIND_TO_TARGET = {"username": "username", "email": "email", "domain": "domain", "url": "url", "organization": "company"}

CATEGORIES = {
    "username_footprint": "Public username footprint",
    "domain_infrastructure": "Owned domains and infrastructure",
    "organization_filings": "Corporate filings and registries",
    "public_mentions": "Public news mentions",
    "professional_history": "Professional history (cited, manual)",
    "published_documents": "Published documents and metadata",
    "images": "Images (duplicates and publication)",
    "exposure": "Privacy exposure indicators",
}


@dataclass(frozen=True)
class Source:
    id: str
    category: str
    label: str
    identifier_kinds: tuple[str, ...]          # which subject identifiers it can use ( () => manual/import, not an adapter run )
    source_class: str                          # consent class (profile.consent.SOURCE_CLASSES)
    data_classes: tuple[str, ...]              # what it produces
    privacy: str                               # public_org | public_personal | personal_sensitive
    maturity: str                              # live_tested | mocked_only | partially_verified | manual
    legal_note: str
    commercial_use: str = "check provider terms"
    manual: bool = False
    extra: dict = field(default_factory=dict)


S = Source
SOURCES: dict[str, Source] = {s.id: s for s in [
    S("sherlock", "username_footprint", "Sherlock", ("username",), "public_site_query", ("account_candidate",), "public_personal", "live_tested",
      "Contacts many third-party public sites with the handle. A hit is a lead only. Respect each site's terms.", "MIT tool; sites' terms apply"),
    S("maigret", "username_footprint", "Maigret", ("username",), "public_site_query", ("account_candidate",), "public_personal", "live_tested",
      "Broader username check; recursion and extraction of other identities are switched off.", "MIT tool; sites' terms apply"),
    S("rdap", "domain_infrastructure", "RDAP registration data", ("domain", "email"), "public_passive", ("registration",), "public_org", "live_tested",
      "Public registry data; registrant personal data is usually redacted by registries."),
    S("dns", "domain_infrastructure", "DNS records", ("domain", "email"), "public_passive", ("dns",), "public_org", "live_tested", "Public DNS queries."),
    S("crtsh", "domain_infrastructure", "Certificate transparency (crt.sh)", ("domain", "email"), "public_passive", ("hostnames",), "public_org", "live_tested",
      "Public log search; the service is sometimes unavailable and the run is then partial."),
    S("wayback", "domain_infrastructure", "Internet Archive index", ("domain", "url"), "public_passive", ("archive_index",), "public_org", "live_tested",
      "Public archive index; polite rate limits apply."),
    S("subfinder", "domain_infrastructure", "Subfinder (passive)", ("domain",), "public_passive", ("hostnames",), "public_org", "live_tested",
      "Passive sources only; results are capped at 2000 names."),
    S("amass", "domain_infrastructure", "OWASP Amass (passive)", ("domain",), "public_passive", ("hostnames",), "public_org", "partially_verified",
      "Returns names only if data sources are configured in Amass itself; parsing is unverified."),
    S("theharvester", "domain_infrastructure", "theHarvester", ("domain",), "public_passive", ("hostnames", "emails"), "public_org", "partially_verified",
      "May surface email addresses on the domain; they become unresolved leads, never automatic inputs. Linux only."),
    S("opencorporates", "organization_filings", "OpenCorporates", ("organization",), "professional_history", ("company_record",), "public_org", "mocked_only",
      "Needs an API token; commercial use restricted by licence tier.", "restricted by tier"),
    S("sec_edgar", "organization_filings", "SEC EDGAR", ("organization",), "professional_history", ("filings",), "public_org", "mocked_only",
      "Official interface; needs a contact string in Setup; takes a CIK number rather than a name."),
    S("gdelt", "public_mentions", "GDELT news mentions", ("domain",), "public_passive", ("news_mentions",), "public_org", "mocked_only",
      "Matches by domain; mentions are not verified facts."),
    S("manual_professional", "professional_history", "Cited professional history (manual)", (), "professional_history", ("claims",), "public_personal", "manual",
      "Enter published biographies, registry entries and public profiles with a citation. Employers and schools are claimed until corroborated. No scraping behind authentication.",
      manual=True),
    S("manual_documents", "published_documents", "Published documents (import)", (), "documents", ("document_metadata",), "public_personal", "manual",
      "Import files you own or that are public; they are inspected statically and never executed or fetched.", manual=True),
    S("manual_images", "images", "Image workbench", (), "image_analysis", ("image_assets",), "public_personal", "manual",
      "Import images you own or are authorised to use; matching is local. Provider reverse-image search is manual link-out only.", manual=True),
    S("manual_exposure", "exposure", "Owner-verified exposure checks", (), "exposure_check", ("exposure_status",), "personal_sensitive", "manual",
      "Status, category, date and remediation only; no secrets, dumps or government identifiers are ever stored.", manual=True),
]}


def adapter_sources() -> list[Source]:
    return [s for s in SOURCES.values() if not s.manual]


def sources_for(kind: str) -> list[Source]:
    return [s for s in adapter_sources() if kind in s.identifier_kinds]


def capability_matrix(adapters: dict) -> list[dict]:
    """The profile view of the adapter registry for docs and the planner: one row per source with technical facts taken from the manifests."""
    rows = []
    for s in SOURCES.values():
        m = adapters[s.id].manifest if s.id in adapters else None
        rows.append({"id": s.id, "label": s.label, "category": s.category, "identifier_kinds": list(s.identifier_kinds), "consent_class": s.source_class,
                     "data_classes": list(s.data_classes), "privacy": s.privacy, "maturity": s.maturity, "operation_class": m.operation_class if m else "manual",
                     "needs_key": (m.api_key_name if m else None), "rate_limit_per_minute": m.rate_limit_per_minute if m else None,
                     "cost": "key required" if (m and m.api_key_name) else "free", "legal_note": s.legal_note, "commercial_use": s.commercial_use,
                     "registered": bool(m) or s.manual})
    return rows
