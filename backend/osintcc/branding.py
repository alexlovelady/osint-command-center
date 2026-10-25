"""One typed definition of the product's display name. Display metadata only.

Nothing that identifies an installation reads from here: the repository, the `osintcc` package, the data directory, environment variables, the Tauri bundle
identifier, update keys, API routes and automation ids are untouched by a name change (addendum v1.1 sections 0 and 1).
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_INTEL_AS_BRAND = re.compile(r"(^|\s)intel(\s|$)", re.IGNORECASE)


class Branding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    productName: str = Field(min_length=3, max_length=60)
    shortName: str = Field(min_length=3, max_length=40)
    tagline: str = Field(min_length=3, max_length=160)
    edition: str = Field(default="Community", min_length=2, max_length=30)
    legacyNames: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("productName", "shortName")
    @classmethod
    def _no_intel_brand(cls, v: str) -> str:
        v = " ".join(v.split())
        if _INTEL_AS_BRAND.search(v) or v.lower() == "intel":
            raise ValueError("'Intel' is not used as a brand (it is another company's trademark); 'Intelligence' is fine")
        if any(c in v for c in "<>&\"'`") or any(ord(c) < 32 for c in v):
            raise ValueError("the name may not contain markup or control characters")
        return v

    @field_validator("tagline", "edition")
    @classmethod
    def _plain(cls, v: str) -> str:
        v = " ".join(v.split())
        if any(c in v for c in "<>`") or any(ord(c) < 32 for c in v):
            raise ValueError("plain text only")
        return v


PRESETS: dict[str, dict] = {
    "current": {"label": "Current name (default)", "status": "in use",
                "branding": Branding(productName="OSINT Command Center", shortName="OSINT Command Center", tagline="Local-first, evidence-grounded analysis workstation", edition="Community")},
    "fusion": {"label": "Fusion Intelligence Command Center (provisional)", "status": "provisional: not a cleared trademark, domain or unique brand; the owner has not approved it",
               "branding": Branding(productName="Fusion Intelligence Command Center", shortName="Fusion Command Center",
                                    tagline="Multi-INT analysis, evidence fusion and authorized exposure assessment", edition="Community", legacyNames=["OSINT Command Center"])},
}
UNCHANGED = ["GitHub repository (alexlovelady/osint-command-center)", "Python package `osintcc`", "Tauri bundle identifier and executable names", "data directory, encrypted database, vault and backups",
             "environment variables (OSINTCC_*) and configuration keys", "API routes, MCP methods, plugin and automation identifiers", "update signing keys and manifests"]
NOTICE = ("This changes the text shown inside the application and in new reports. It does not rename the window title, installer or launcher, and it is not a trademark, domain or "
          "business-name clearance. Check availability before any public launch.")


def active(stored: dict | None) -> tuple[str, Branding]:
    if stored:
        try:
            return stored.get("preset", "custom"), Branding.model_validate(stored["branding"])
        except (ValueError, KeyError, TypeError):
            pass
    return "current", PRESETS["current"]["branding"]
