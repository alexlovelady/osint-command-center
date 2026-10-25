"""Generate the 52 bundled automation templates (30 general + 12 Target-profile + 5 AIV + 5 DARKINT) into backend/osintcc/automations/templates/*.json.

    uv run python scripts/build_automation_templates.py [--check]

Every template is validated here with the SAME validator the application uses, against the real adapter registry. Templates ship DISABLED; scheduled ones
are never active until a person approves and activates them. `capability_gaps` states plainly what a template cannot do yet.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from osintcc.adapters.registry import default_adapters
from osintcc.automations.graph_validator import validate

OUT = ROOT / "backend" / "osintcc" / "automations" / "templates"
ADAPTERS = default_adapters()

ROWS: dict[str, list[dict[str, Any]]] = {
    "rdap": [{"predicate": "rdap.registrar", "value": "Example Registrar Inc", "confidence": "high"}, {"predicate": "rdap.nameserver", "value": "ns1.example.net", "confidence": "high"}],
    "dns": [{"predicate": "dns.a", "value": "192.0.2.10", "confidence": "high"}, {"predicate": "dns.mx", "value": "mail.example.org", "confidence": "high"}],
    "crtsh": [{"predicate": "cert.subdomain", "value": "www.example.org", "confidence": "medium"}, {"predicate": "cert.subdomain", "value": "mail.example.org", "confidence": "medium"}],
    "wayback": [{"predicate": "archive.first_seen", "value": "2001-03-05", "confidence": "medium"}, {"predicate": "archive.snapshot_count", "value": 412, "confidence": "medium"}],
    "subfinder": [{"predicate": "subdomain", "value": "api.example.org", "confidence": "medium"}],
    "urlscan": [{"predicate": "web.server", "value": "nginx", "confidence": "low"}],
    "lookalike": [{"predicate": "lookalike.candidate", "value": "examp1e.org", "confidence": "low", "entity": "examp1e.org"}, {"predicate": "lookalike.candidate", "value": "exarnple.org", "confidence": "low", "entity": "exarnple.org"}],
    "sherlock": [{"entity_type": "account", "predicate": "account.profile", "value": "https://social.example/alice", "confidence": "low"}],
    "maigret": [{"entity_type": "account", "predicate": "account.profile", "value": "https://forum.example/u/alice", "confidence": "low"}],
    "sec_edgar": [{"entity_type": "org", "predicate": "edgar.filing", "value": "10-K 2026-02-14", "confidence": "high"}, {"entity_type": "org", "predicate": "edgar.filing", "value": "8-K 2026-03-01", "confidence": "high"}],
    "opencorporates": [{"entity_type": "org", "predicate": "company.jurisdiction", "value": "us_de", "confidence": "medium"}],
    "gdelt": [{"predicate": "news.mention", "value": "Example Org announces new service (2026-03-02)", "confidence": "low"}],
    "overpass": [{"entity_type": "place", "predicate": "osm.feature", "value": "amenity=cafe name=Example Cafe", "confidence": "medium"}],
}
LOOKALIKE_NOTE = "generated offline from the owned brand domain; a hit in DNS later is a lead, not proof of abuse"


def N(id: str, type: str, deps: list[str] | None = None, *, optional: bool = False, when: dict[str, Any] | None = None, run_on: str = "success", label: str | None = None, **cfg: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"id": id, "type": type, "depends_on": deps or [], "config": cfg}
    if optional:
        d["optional"] = True
    if when:
        d["when"] = when
    if run_on != "success":
        d["run_on"] = run_on
    if label:
        d["label"] = label
    return d


def out(n: str, field: str | None = None) -> str:
    return f"$nodes.{n}.output" + (f".{field}" if field else "")


def scope(ref: str, ttype: str | None = None, id: str = "scope", deps: list[str] | None = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {"target_ref": ref}
    if ttype:
        cfg["target_type"] = ttype
    return N(id, "authorization_check", deps, **cfg)


def q(id: str, adapter: str, scope_id: str = "scope", ref: str = "$inputs.domain", ttype: str | None = None, optional: bool = False) -> dict[str, Any]:
    cfg: dict[str, Any] = {"adapter": adapter, "target_ref": ref}
    if ttype:
        cfg["target_type"] = ttype
    return N(id, "adapter_query", [scope_id], optional=optional, **cfg)


def merge(id: str, parts: list[str]) -> dict[str, Any]:
    return N(id, "transform", parts, ref=out(parts[0]), extra_refs=[out(p) for p in parts[1:]], op="merge")


def dedupe(id: str, src: str) -> dict[str, Any]:
    return N(id, "deduplicate", [src], ref=out(src))


def diff(id: str, src: str) -> dict[str, Any]:
    return N(id, "snapshot_diff", [src], dataset_ref=out(src))


def notify(id: str, dep: str, title: str, sev: str = "info", field: str | None = None) -> dict[str, Any]:
    return N(id, "notification", [dep], change_ref=out(dep, field), title=title, severity=sev, channel="local_desktop", only_if_changed=True)


def onfail(id: str, deps: list[str], title: str) -> dict[str, Any]:
    return N(id, "error_handler", deps[:8], run_on="failure", title=title)


def consent(prompt: str) -> dict[str, Any]:
    return N("consent", "analyst_review", [], prompt=prompt, timeout_hours=72)


def sched(cron: str) -> dict[str, Any]:
    return {"type": "schedule", "schedule": cron, "timezone": "UTC", "enabled": False, "missed_run_policy": "coalesce"}


def fixture_for(nodes: list[dict[str, Any]], inputs: dict[str, Any], *, watch: bool, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    target = next((str(v) for v in inputs.values() if v), "example.org")
    adapter_rows: dict[str, list[dict[str, Any]]] = {}
    flat: list[dict[str, Any]] = []
    for n in nodes:
        if n["type"] in ("adapter_query", "enrich"):
            a = n["config"]["adapter"]
            rows = []
            for r in ROWS.get(a, []):
                rows.append({"entity": r.get("entity", target), "entity_type": r.get("entity_type", "domain"), **{k: v for k, v in r.items() if k not in ("entity", "entity_type")}})
            adapter_rows[a] = rows
            flat += [{**r, "adapter": a} for r in rows]
    fx: dict[str, Any] = {"inputs": dict(inputs), "adapter_findings": adapter_rows}
    if watch and flat:
        prev = [dict(r) for r in flat[:-1]]
        if prev:
            prev[0] = {**prev[0], "value": "previous-value"}                 # one changed and one added item
        fx["previous_snapshot"] = [{"id": f"p{i}", **r} for i, r in enumerate(prev)]
    fx |= extra or {}
    return fx


T: list[dict[str, Any]] = []


def add(key: str, name: str, category: str, catalog_trigger: str, description: str, nodes: list[dict[str, Any]], inputs_spec: list[dict[str, Any]],
        *, trigger: dict[str, Any] | None = None, inputs: dict[str, Any] | None = None, legal: str = "", gaps: list[str] | None = None, tags: list[str] | None = None,
        watch: bool = False, fixture_extra: dict[str, Any] | None = None, example: str = "", policy: dict[str, Any] | None = None, instructions: str = "",
        runtime_tested: bool = False) -> None:
    slug = f"{key.lower()}-{name.lower().replace(' & ', '-').replace(' ', '-')}"
    inputs = inputs if inputs is not None else {s["name"]: s.get("example") for s in inputs_spec}
    definition = {"schema_version": 1, "workflow_key": slug, "name": name, "description": description, "owner_scope": "investigation", "status": "draft", "tags": tags or [],
                  "trigger": trigger or {"type": "manual", "enabled": False}, "inputs": inputs,
                  "policy": {"network_mode": "passive_only", "max_requests_per_provider_per_run": 50, "max_duration_seconds": 600, "max_concurrent_nodes": 2, "reentrancy": "skip"} | (policy or {}),
                  "nodes": nodes, "error_policy": {"transient_retries": 2, "backoff": "exponential_jitter", "fail_closed_on_scope_error": True}}
    used = [n["config"]["adapter"] for n in nodes if n["type"] in ("adapter_query", "enrich") and not n.get("optional")]
    opt = [n["config"]["adapter"] for n in nodes if n["type"] in ("adapter_query", "enrich") and n.get("optional")]
    requests = sum(n["config"].get("max_targets", 1) if n["type"] == "enrich" else 1 for n in nodes if n["type"] in ("adapter_query", "enrich"))
    T.append({"slug": slug, "key": key, "version": 1, "category": category, "name": name, "description": description, "catalog_trigger": catalog_trigger,
              "tags": tags or [], "dependencies": sorted(set(used)), "optional_dependencies": sorted(set(opt) - set(used)), "inputs": inputs_spec,
              "legal_notes": legal or "Public, passive sources only. Respect each source's terms and keep to targets you own or have a documented reason to examine.",
              "quota_note": f"About {requests} source request(s) per run" if requests else "No network requests (works on local data)",
              "example_output": example or "A de-duplicated dataset saved as evidence, with every finding linked to its source response.",
              "capability_gaps": gaps or [], "instructions": instructions or description, "maturity": "runtime_tested" if runtime_tested else "fixture_tested",
              "definition": definition, "fixture": fixture_for(nodes, inputs, watch=watch, extra=fixture_extra)})


DOMAIN = [{"name": "domain", "label": "Domain you own or are authorised to examine", "type": "domain", "required": True, "example": "example.org"}]
USERNAME = [{"name": "username", "label": "Username (with consent or a documented case basis)", "type": "username", "required": True, "example": "alice"}]
CIK = [{"name": "cik", "label": "SEC CIK number", "type": "cik", "required": True, "example": "0000000001"}]
COMPANY = [{"name": "company", "label": "Company name", "type": "company", "required": True, "example": "Example Holdings"}]
FILE_IN = [{"name": "evidence_id", "label": "Supplied by the 'Run with file' action", "type": "evidence", "required": False, "example": None}]

# ---------------------------------------------------------------------------------------------------------------------- Cyber
add("CY-01", "Domain Recon", "Cyber", "Manual", "RDAP, DNS, certificate transparency and passive subdomain sources for a domain; normalise, de-duplicate and save as evidence.",
    [scope("$inputs.domain"), q("rdap", "rdap"), q("dns", "dns"), q("crtsh", "crtsh", optional=True), q("wayback", "wayback", optional=True), q("subfinder", "subfinder", optional=True),
     merge("merged", ["rdap", "dns", "crtsh", "wayback", "subfinder"]), dedupe("unique", "merged"),
     N("save", "evidence_save", ["unique"], ref=out("unique"), title="Domain recon dataset")], DOMAIN, tags=["recon", "passive"],
    example="Registrar, nameservers, DNS records, certificate-logged hostnames and archive history for the domain, each linked to its raw response.", runtime_tested=True)
add("CY-02", "Domain Change Watch", "Cyber", "Daily, disabled", "Compares DNS, registrar and certificate data with the previous run and notifies only on material change.",
    [scope("$inputs.domain"), q("rdap", "rdap"), q("dns", "dns"), q("crtsh", "crtsh", optional=True), merge("merged", ["rdap", "dns", "crtsh"]), dedupe("unique", "merged"), diff("diff", "unique"),
     notify("notify", "diff", "Domain change detected", "warning"), onfail("fail", ["unique", "diff"], "Domain change watch failed")],
    DOMAIN, trigger=sched("0 8 * * *"), tags=["monitor", "passive"], watch=True,
    example="One notification per window listing new, changed and no-longer-observed records; the first run only records a baseline.")
add("CY-03", "Attack Surface Watch", "Cyber", "Daily, disabled", "Compares the passive, public-facing asset inventory with the previous run. Active probing is NOT included.",
    [scope("$inputs.domain"), q("crtsh", "crtsh", optional=True), q("subfinder", "subfinder", optional=True), merge("found", ["crtsh", "subfinder"]),
     N("resolve", "enrich", ["found"], adapter="dns", from_ref=out("found"), entity_types=["domain"], max_targets=5), merge("all", ["found", "resolve"]), dedupe("unique", "all"),
     diff("diff", "unique"), notify("notify", "diff", "New or changed public-facing assets", "warning"), onfail("fail", ["unique", "diff"], "Attack surface watch failed")],
    DOMAIN, trigger=sched("0 7 * * *"), tags=["monitor", "passive"], watch=True,
    gaps=["Active probes (port or service checks) are not part of this template; they need a separate scope authorization and the active module."],
    example="Newly seen hostnames and their addresses since the last run.")
add("CY-04", "CVE Intelligence", "Cyber", "Daily, disabled", "Ingests an SBOM and routes the component list to analyst review against advisories you obtained.",
    [N("sbom", "file_ingest", [], evidence_ref="$inputs.evidence_id"), N("review", "analyst_review", ["sbom"], prompt="Compare the listed components with the advisories you hold; record what applies.", timeout_hours=72),
     N("report", "report", ["review"], profile="technical", format="html")], FILE_IN, trigger={"type": "manual", "enabled": False}, inputs={"evidence_id": None}, tags=["vulnerability"],
    gaps=["No CVE or advisory feed connector exists, so advisories are not fetched and versions are not matched automatically. Only the SBOM import and the review/report steps work."],
    fixture_extra={"file": {"kind": "sbom", "count": 3, "preview": [{"kind": "sbom.component", "data": {"name": "libexample", "version": "1.2.3"}}]}})
add("CY-05", "Phishing Domain Watch", "Cyber", "Daily, disabled", "Generates look-alike names of a brand domain you own and checks which resolve in public DNS. Nothing is registered or contacted.",
    [scope("$inputs.domain"), q("look", "lookalike"), N("resolve", "enrich", ["look"], adapter="dns", from_ref=out("look"), entity_types=["domain"], max_targets=10),
     dedupe("unique", "resolve"), diff("diff", "unique"), notify("notify", "diff", "Look-alike domain activity", "warning"), onfail("fail", ["unique", "diff"], "Phishing domain watch failed")],
    DOMAIN, trigger=sched("0 6 * * *"), tags=["brand", "monitor"], watch=True,
    legal="Only for brands you own. Look-alike candidates are leads: a resolving name is not proof of abuse.", example="Look-alike names that now resolve, with their addresses.")
add("CY-06", "Website History", "Cyber", "Weekly, disabled", "Queries the Internet Archive index for a domain and reports changes in what the archive holds.",
    [scope("$inputs.domain"), q("wayback", "wayback"), dedupe("unique", "wayback"), diff("diff", "unique"), notify("notify", "diff", "Website archive changed"), onfail("fail", ["unique", "diff"], "Website history failed")],
    DOMAIN, trigger=sched("0 9 * * 1"), tags=["history", "monitor"], watch=True,
    gaps=["Compares the archive's snapshot index, not the content of fetched pages."], example="New or changed archive index entries since last week.")
add("CY-07", "Technology Profiler", "Cyber", "Manual", "Collects public certificate and scan-service signals about a domain's technology with a minimal number of requests.",
    [scope("$inputs.domain"), q("crtsh", "crtsh", optional=True), q("dns", "dns"), q("urlscan", "urlscan", optional=True), merge("merged", ["crtsh", "dns", "urlscan"]), dedupe("unique", "merged"),
     N("save", "evidence_save", ["unique"], ref=out("unique"), title="Technology signals")], DOMAIN, tags=["recon", "passive"],
    gaps=["No HTTP response-header fingerprinting adapter exists yet; signals come from certificates, DNS and the optional urlscan.io service."], example="Hosts, addresses and any technology hints urlscan returns, with confidence labels.")

# ---------------------------------------------------------------------------------------------------------------------- Identity
CONSENT = "Confirm that the person consented, or that this is a legitimate documented case, and that the case purpose is written."
add("ID-01", "Username Footprint", "Identity", "Manual", "Checks many public sites for accounts with a username. Name collisions are labelled unconfirmed.",
    [consent(CONSENT), scope("$inputs.username", "username", deps=["consent"]), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"),
     q("maigret", "maigret", ref="$inputs.username", ttype="username", optional=True), merge("merged", ["sherlock", "maigret"]), dedupe("unique", "merged"),
     N("save", "evidence_save", ["unique"], ref=out("unique"), title="Username footprint (unconfirmed candidates)")], USERNAME, tags=["identity", "consent"],
    legal="A hit only shows that a name exists on a site, not that it is the same person. Needs consent or a documented case basis.",
    example="Candidate profile URLs, all labelled low confidence until you confirm them.")
add("ID-02", "Public Profile Changes", "Identity", "Weekly, disabled", "Re-checks which public profiles exist for an opted-in username and reports changes.",
    [scope("$inputs.username", "username"), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"), dedupe("unique", "sherlock"), diff("diff", "unique"),
     notify("notify", "diff", "Public profile change"), onfail("fail", ["unique", "diff"], "Profile change watch failed")], USERNAME, trigger=sched("0 10 * * 1"), tags=["identity", "monitor"], watch=True,
    legal="Recurring monitoring of a person needs a documented purpose and their consent or a legitimate basis. It never logs in or bypasses access controls.")
add("ID-03", "Digital Footprint Audit", "Identity", "Manual", "Consent-based review of public accounts and exposure for a username, ending in a report.",
    [consent(CONSENT), scope("$inputs.username", "username", deps=["consent"]), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"),
     q("maigret", "maigret", ref="$inputs.username", ttype="username", optional=True), merge("merged", ["sherlock", "maigret"]), dedupe("unique", "merged"),
     N("report", "report", ["unique"], profile="technical", format="html")], USERNAME, tags=["identity", "consent"],
    gaps=["Document and breach-exposure checks are not implemented; the audit covers public username presence only."])
add("ID-04", "Public Mention Monitor", "Identity", "Daily, disabled", "Watches public news mentions of a brand or organisation domain and reports new ones.",
    [scope("$inputs.domain"), q("gdelt", "gdelt"), dedupe("unique", "gdelt"), diff("diff", "unique"), notify("notify", "diff", "New public mentions"), onfail("fail", ["unique", "diff"], "Mention monitor failed")],
    DOMAIN, trigger=sched("0 6 * * *"), tags=["media", "monitor"], watch=True, legal="For brands and organisations. Matching is by domain, which is conservative; mentions are not verified facts.")
add("ID-05", "Document Metadata", "Identity", "File upload", "Parses a file you supply offline (ExifTool when installed), stores it hashed and summarises its metadata with sensitive values withheld.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id"), N("summary", "evidence_save", ["ingest"], ref=out("ingest"), title="Document metadata summary")],
    FILE_IN, trigger={"type": "file", "enabled": False}, inputs={"evidence_id": None}, tags=["files", "metadata"], runtime_tested=True,
    fixture_extra={"file": {"kind": "jpeg_exif", "count": 2, "sha256": "a" * 64, "preview": [{"kind": "exif.camera", "data": {"make": "ExampleCam"}}, {"kind": "exif.gps", "data": {"withheld": "restricted"}}]}},
    legal="Only files you own or are authorised to analyse. GPS and similar values are RESTRICTED and shown only in the Imports tab.",
    example="File type, hash, camera/author metadata and counts; GPS withheld in the summary.")
add("ID-06", "Identity Correlation Review", "Identity", "Manual", "Suggests links between accounts and emails already in the case and waits for a person to confirm each one.",
    [N("accounts", "case_findings", [], entity_types=["account"]), N("emails", "case_findings", [], entity_types=["email"]), N("corr", "correlate", ["accounts", "emails"], refs=[out("accounts"), out("emails")]),
     N("review", "analyst_review", ["corr"], prompt="Review every suggested link. Nothing is merged automatically; merge in the Graph tab only what you can support.", timeout_hours=72),
     N("save", "evidence_save", ["review", "corr"], ref=out("corr"), title="Suggested identity links (unconfirmed)")], [], inputs={}, tags=["identity", "review"],
    fixture_extra={"case_findings": [{"entity": "alice@example.org", "entity_type": "email", "predicate": "email.address", "value": "alice"}, {"entity": "alice", "entity_type": "account", "predicate": "email.address", "value": "alice"}]},
    legal="Suggestions only. A shared name or handle is not an identity.")

# ---------------------------------------------------------------------------------------------------------------------- Corporate
add("CO-01", "Company Research", "Corporate", "Manual", "Public SEC filings and registry data for a company, de-duplicated and reported with citations.",
    [scope("$inputs.cik", "cik", id="scope_cik"), q("edgar", "sec_edgar", scope_id="scope_cik", ref="$inputs.cik", ttype="cik"), scope("$inputs.company", "company", id="scope_co"),
     q("opencorp", "opencorporates", scope_id="scope_co", ref="$inputs.company", ttype="company", optional=True), merge("merged", ["edgar", "opencorp"]), dedupe("unique", "merged"),
     N("report", "report", ["unique"], profile="technical", format="html")], CIK + COMPANY, tags=["corporate"],
    legal="SEC EDGAR needs your contact set in Setup and is rate limited. OpenCorporates needs a (free-tier) API token.")
add("CO-02", "Corporate Change Watch", "Corporate", "Weekly, disabled", "Compares public registry/filing data with the previous run. No paid API is assumed.",
    [scope("$inputs.cik", "cik"), q("edgar", "sec_edgar", ref="$inputs.cik", ttype="cik"), dedupe("unique", "edgar"), diff("diff", "unique"), notify("notify", "diff", "Corporate record changed"),
     onfail("fail", ["unique", "diff"], "Corporate change watch failed")], CIK, trigger=sched("0 7 * * 1"), tags=["corporate", "monitor"], watch=True)
add("CO-03", "SEC Filing Monitor", "Corporate", "Daily, disabled", "Checks EDGAR for new filings by a company and notifies when one appears.",
    [scope("$inputs.cik", "cik"), q("edgar", "sec_edgar", ref="$inputs.cik", ttype="cik"), dedupe("unique", "edgar"), diff("diff", "unique"), notify("notify", "diff", "New SEC filing"),
     onfail("fail", ["unique", "diff"], "SEC filing monitor failed")], CIK, trigger=sched("30 6 * * *"), tags=["corporate", "monitor"], watch=True,
    legal="Uses the official EDGAR interface with the User-Agent contact you set in Setup and the agency's rate limit.")
add("CO-04", "Ownership Mapping", "Corporate", "Manual", "Builds sourced organisation relationships from filings and registries and records what is missing.",
    [scope("$inputs.cik", "cik", id="scope_cik"), q("edgar", "sec_edgar", scope_id="scope_cik", ref="$inputs.cik", ttype="cik"), scope("$inputs.company", "company", id="scope_co"),
     q("opencorp", "opencorporates", scope_id="scope_co", ref="$inputs.company", ttype="company", optional=True), merge("merged", ["edgar", "opencorp"]), dedupe("unique", "merged"),
     N("review", "analyst_review", ["unique"], prompt="Beneficial ownership is usually NOT in public filings. Record what is missing before relying on this map.", timeout_hours=72),
     N("report", "report", ["review"], profile="technical", format="html")], CIK + COMPANY, tags=["corporate"],
    gaps=["Beneficial-ownership data is not available from the implemented sources; the template says so in the review step."])
add("CO-05", "News & Reputation Watch", "Corporate", "Daily, disabled", "Watches public news mentions of a company domain. Mentions are shown as mentions, never as sentiment facts.",
    [scope("$inputs.domain"), q("gdelt", "gdelt"), dedupe("unique", "gdelt"), diff("diff", "unique"), notify("notify", "diff", "New public news mentions"), onfail("fail", ["unique", "diff"], "News watch failed")],
    DOMAIN, trigger=sched("0 6 * * *"), tags=["media", "monitor"], watch=True)

# ---------------------------------------------------------------------------------------------------------------------- GEOINT / sensors
EV_A_B = [{"name": "evidence_a", "label": "Earlier image (evidence id)", "type": "evidence", "required": True, "example": None},
          {"name": "evidence_b", "label": "Later image (evidence id)", "type": "evidence", "required": True, "example": None}]
add("GEO-01", "Imagery Change Review", "GEOINT", "Manual", "Processes two imported images (dates, coordinates, resolution) and routes the comparison to a person.",
    [N("a", "file_ingest", [], evidence_ref="$inputs.evidence_a"), N("b", "file_ingest", [], evidence_ref="$inputs.evidence_b"),
     N("review", "analyst_review", ["a", "b"], prompt="Compare dates, registration and resolution of the two images before judging any change.", timeout_hours=72),
     N("report", "report", ["review"], profile="technical", format="html")], EV_A_B, inputs={"evidence_a": None, "evidence_b": None}, tags=["imagery"],
    gaps=["No automatic image registration or change detection: the comparison is a documented manual review."],
    fixture_extra={"file": {"kind": "geotiff", "count": 1, "preview": [{"kind": "geotiff.metadata", "data": {"resolution_m": 10}}]}})
add("GEO-02", "Geographic Data Update", "GEOINT", "Weekly, disabled", "Re-queries OpenStreetMap (Overpass) for features around a coordinate and reports additions and removals.",
    [scope("$inputs.coordinates", "coordinates"), q("osm", "overpass", ref="$inputs.coordinates", ttype="coordinates"), dedupe("unique", "osm"), diff("diff", "unique"),
     notify("notify", "diff", "Map data changed nearby"), onfail("fail", ["unique", "diff"], "Geographic update failed")],
    [{"name": "coordinates", "label": "Latitude,longitude", "type": "coordinates", "required": True, "example": "51.5007,-0.1246"}], trigger=sched("0 5 * * 0"), tags=["geo", "monitor"], watch=True,
    legal="Overpass has usage limits; keep radii small, or use a local extract.")
add("GEO-03", "Aircraft Data Import", "GEOINT", "File import", "Analyses ADS-B data you lawfully obtained. No live feed is used.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id", kind="adsb"), N("summary", "evidence_save", ["ingest"], ref=out("ingest"), title="ADS-B import summary")],
    FILE_IN, trigger={"type": "file", "enabled": False}, inputs={"evidence_id": None}, tags=["files", "geo"],
    fixture_extra={"file": {"kind": "adsb", "count": 120, "preview": [{"kind": "adsb.position", "data": {"icao": "ABC123"}}]}})
add("GEO-04", "Vessel Data Import", "GEOINT", "File import", "Analyses AIS data you lawfully obtained. No live provider is used.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id", kind="ais"), N("summary", "evidence_save", ["ingest"], ref=out("ingest"), title="AIS import summary")],
    FILE_IN, trigger={"type": "file", "enabled": False}, inputs={"evidence_id": None}, tags=["files", "geo"],
    fixture_extra={"file": {"kind": "ais", "count": 80, "preview": [{"kind": "ais.position", "data": {"mmsi": "000000001"}}]}})
add("GEO-05", "Sensor Health Monitor", "Sensors", "Hourly, disabled", "Reads the status of devices registered in the Hardware module and notifies on change. Health only.",
    [N("devices", "sensor_health", [], include_simulated=True), diff("diff", "devices"), notify("notify", "diff", "Sensor status changed", "warning"), onfail("fail", ["devices", "diff"], "Sensor health monitor failed")],
    [], trigger=sched("0 * * * *"), inputs={}, tags=["sensors", "monitor"], watch=True,
    gaps=["Only simulated and replay devices have been exercised; no physical receiver has been tested. It reads registration status, it does not poll hardware."],
    fixture_extra={"devices": [{"name": "Replay device", "status": "present"}, {"name": "Simulated SDR", "status": "present"}], "previous_snapshot": [{"id": "d0", "entity": "Replay device", "entity_type": "device", "predicate": "device.status", "value": "absent", "confidence": "high"}]})
add("GEO-06", "RF Spectrum Baseline", "Sensors", "Manual", "Processes a spectrum recording you own or are authorised to analyse and records it with a review step.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id", kind="sigmf"), N("review", "analyst_review", ["ingest"], prompt="Confirm the recording is yours or authorised and note the baseline conditions.", timeout_hours=72),
     N("summary", "evidence_save", ["review", "ingest"], ref=out("ingest"), title="Spectrum recording summary")], FILE_IN, inputs={"evidence_id": None}, tags=["rf", "files"],
    legal="Analysis of recordings you own or are authorised to use. Private communications are never intercepted or decoded.",
    gaps=["Baseline comparison between recordings is not automated; use the Imports tab's spectrum view."],
    fixture_extra={"file": {"kind": "sigmf", "count": 1, "preview": [{"kind": "sigmf.capture", "data": {"sample_rate": 2000000}}]}})

# ---------------------------------------------------------------------------------------------------------------------- Case / evidence
add("CASE-01", "Evidence Processing", "Evidence", "File upload", "Hashes, timestamps and parses a supplied file, extracts metadata, classifies it by discipline and indexes it for search.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id"), N("summary", "evidence_save", ["ingest"], ref=out("ingest"), title="Evidence processing summary")],
    FILE_IN, trigger={"type": "file", "enabled": False}, inputs={"evidence_id": None}, tags=["files", "evidence"], runtime_tested=True,
    fixture_extra={"file": {"kind": "eml", "count": 3, "sha256": "b" * 64, "preview": [{"kind": "email.header", "data": {"subject": "Example"}}]}},
    example="Hash, size, import time, discipline, observation count and a preview; the file is searchable in the case.")
add("CASE-02", "Entity Correlation", "Evidence", "New finding", "When new findings arrive, suggests links between domains and addresses that share values and tells you how many to review.",
    [N("domains", "case_findings", [], entity_types=["domain"]), N("ips", "case_findings", [], entity_types=["ip"]), N("corr", "correlate", ["domains", "ips"], refs=[out("domains"), out("ips")]),
     N("any", "condition", ["corr"], ref=out("corr", "count"), op="gt", value=0), N("notify", "notification", ["any"], change_ref=out("any"), title="Suggested entity links to review", severity="info", channel="local_desktop", only_if_changed=True)],
    [], trigger={"type": "event", "event": "new_finding", "enabled": False}, inputs={}, tags=["correlation"],
    fixture_extra={"case_findings": [{"entity": "example.org", "entity_type": "domain", "predicate": "dns.a", "value": "192.0.2.10"}, {"entity": "192.0.2.10", "entity_type": "ip", "predicate": "dns.a", "value": "192.0.2.10"}]},
    legal="Suggestions only; the verification gate is you: nothing is merged.")
add("CASE-03", "Duplicate Finder", "Evidence", "File import", "Detects when an imported file is already in the case (same content hash) and tells you.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id"), N("dup", "condition", ["ingest"], ref=out("ingest", "duplicate"), op="truthy"),
     N("notify", "notification", ["dup"], change_ref=out("dup"), title="Duplicate file already in this case", severity="info", channel="local_desktop", only_if_changed=True)],
    FILE_IN, trigger={"type": "file", "enabled": False}, inputs={"evidence_id": None}, tags=["files", "evidence"],
    fixture_extra={"file": {"kind": "eml", "count": 1, "duplicate": True}}, gaps=["Detection is by exact content hash; near-duplicate (fuzzy) matching is not implemented."])
add("CASE-04", "Intelligence Gap Analysis", "Investigation", "Manual", "Compares your requirements and claims with the evidence and lists the open gaps for a report.",
    [N("gaps", "case_gaps", []), N("review", "analyst_review", ["gaps"], prompt="Decide which gaps to collect for next; the list is in the run details.", timeout_hours=72),
     N("report", "report", ["review"], profile="technical", format="html")], [], inputs={}, tags=["analysis"],
    fixture_extra={"gaps": ["Who operates the domain? (unanswered, high)"]})
add("CASE-05", "Investigation Brief", "Investigation", "Daily, disabled", "Compares today's case findings with the last run and, if something changed, writes an executive brief.",
    [N("findings", "case_findings", []), diff("diff", "findings"), N("brief", "report", ["diff"], when={"ref": out("diff", "changed"), "op": "truthy"}, profile="executive", format="html"),
     notify("notify", "diff", "Investigation brief ready")], [], trigger=sched("0 18 * * *"), inputs={}, tags=["reporting"], watch=True,
    fixture_extra={"case_findings": [{"entity": "example.org", "entity_type": "domain", "predicate": "rdap.registrar", "value": "Example Registrar Inc"}, {"entity": "example.org", "entity_type": "domain", "predicate": "dns.a", "value": "192.0.2.10"}],
                   "previous_snapshot": [{"id": "p0", "entity": "example.org", "entity_type": "domain", "predicate": "rdap.registrar", "value": "Old Registrar LLC", "confidence": "medium"}]})
add("CASE-06", "Report Generator", "Investigation", "Manual", "Produces a cited report (methods, limitations, evidence manifest and automation audit references).",
    [N("report", "report", [], profile="technical", format="html")], [], inputs={}, tags=["reporting"])


# ---------------------------------------------------------------------------------------------------------------------- Target profile (addendum TP-1.0)
TP_AUTH = ("Open Target profile > Authorization. Confirm the authorization is current, covers the sources and identities this workflow uses, and matches the purpose. "
           "Expired or revoked authorization blocks every run.")
TP_LEGAL = ("Applies to verified self-audits and consent-based engagements. Results are leads, not facts; nothing is verified automatically. "
            "Every run re-checks the subject's authorization, and revoking it switches the schedule off.")
TP_GAPS_MANUAL = "Steps marked as review are carried out by a person in the Target Profile screens; the automation does not perform them."
add("TP-01", "Self Digital Footprint Baseline", "Target profile", "Manual", "Baseline of a person's own public username footprint, queued for ownership review and ended with a report.",
    [consent(TP_AUTH), scope("$inputs.username", "username", deps=["consent"]), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"),
     q("maigret", "maigret", ref="$inputs.username", ttype="username", optional=True), merge("merged", ["sherlock", "maigret"]), dedupe("unique", "merged"),
     N("save", "evidence_save", ["unique"], ref=out("unique"), title="Username footprint baseline (unconfirmed candidates)"),
     N("queue", "analyst_review", ["save"], prompt="Open Target profile > Review queue and mark each account Mine, Not mine or Unsure with a reason.", timeout_hours=168),
     N("report", "report", ["queue"], profile="technical", format="html")], USERNAME, tags=["target-profile", "self"], legal=TP_LEGAL,
    gaps=["Published profile pages, documents and professional history are entered or imported by hand (see TP-05, TP-06); this template covers username presence only.", TP_GAPS_MANUAL])
add("TP-02", "Consent Client Baseline", "Target profile", "Manual", "Client baseline that starts by validating the consent proof and scope, then runs the username footprint.",
    [consent("Open Target profile > Authorization. Verify the signed proof is attached as evidence, names the identities and purposes, and has an end date. A checkbox is not proof."),
     scope("$inputs.username", "username", deps=["consent"]), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"),
     q("maigret", "maigret", ref="$inputs.username", ttype="username", optional=True), merge("merged", ["sherlock", "maigret"]), dedupe("unique", "merged"),
     N("queue", "analyst_review", ["unique"], prompt="Review each account with the client where possible; record the client's confirmation as an attestation.", timeout_hours=168),
     N("report", "report", ["queue"], profile="executive", format="html")], USERNAME, tags=["target-profile", "client"], legal=TP_LEGAL,
    gaps=["The workflow cannot validate a signed document: proof checking is a person's step in the Authorization panel.", TP_GAPS_MANUAL])
add("TP-03", "Public Account Confirmation Queue", "Target profile", "Manual", "Offline: clusters candidate accounts already found in the case by canonical URL and routes them to ownership review.",
    [N("cands", "case_findings", [], entity_types=["url"], predicates=["profile.candidate"]), dedupe("unique", "cands"),
     N("queue", "analyst_review", ["unique"], prompt="Open Target profile > Review queue. Nothing is merged automatically; decide each account on evidence.", timeout_hours=168),
     N("save", "evidence_save", ["queue", "unique"], ref=out("unique"), title="Candidate accounts queued for review (unconfirmed)")], [], inputs={}, tags=["target-profile", "review"],
    fixture_extra={"case_findings": [{"entity": "https://social.example/alice", "entity_type": "url", "predicate": "profile.candidate", "value": "Social"},
                                     {"entity": "https://forum.example/u/alice", "entity_type": "url", "predicate": "profile.candidate", "value": "Forum"}]},
    legal="No network. A matching handle is never treated as the same person.")
add("TP-04", "Owned Domain and Company Linkage", "Target profile", "Manual", "Passive registry and DNS data for a domain the subject owns, plus an optional company record. Affiliation stays claimed until corroborated.",
    [scope("$inputs.domain"), q("rdap", "rdap"), q("dns", "dns"), q("crtsh", "crtsh", optional=True), scope("$inputs.company", "company", id="scope_co"),
     q("opencorp", "opencorporates", scope_id="scope_co", ref="$inputs.company", ttype="company", optional=True), merge("merged", ["rdap", "dns", "crtsh", "opencorp"]),
     dedupe("unique", "merged"), N("review", "analyst_review", ["unique"], prompt="Registrant data is often redacted. Treat any company link as claimed until a second independent source supports it.", timeout_hours=168),
     N("save", "evidence_save", ["review", "unique"], ref=out("unique"), title="Domain and company linkage (claims)")], DOMAIN + COMPANY, tags=["target-profile", "domain"], legal=TP_LEGAL,
    gaps=["OpenCorporates needs an API token. Beneficial ownership is not available from these sources."])
add("TP-05", "Published Document Metadata and Disclosure Review", "Target profile", "File upload", "Statically inspects a document the subject published or owns and lists what it discloses (author, software, GPS, URLs). Nothing is opened or executed.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id"),
     N("review", "analyst_review", ["ingest"], prompt="Check the disclosure list: author names, device or software identifiers, GPS, embedded URLs and emails. Record which the subject should remove.", timeout_hours=168),
     N("summary", "evidence_save", ["review", "ingest"], ref=out("ingest"), title="Document disclosure summary")], FILE_IN, trigger={"type": "file", "enabled": False},
    inputs={"evidence_id": None}, tags=["target-profile", "files"], legal="Only files the subject owns, published, or that are provided with documented authorization. GPS values are RESTRICTED.",
    fixture_extra={"file": {"kind": "pdf", "count": 3, "sha256": "c" * 64, "preview": [{"kind": "pdf.metadata", "data": {"author": "withheld"}}]}},
    gaps=["Public-document URL import is not automated: download the file yourself and import it."])
add("TP-06", "Public Professional Footprint Summary", "Target profile", "Manual", "Collects the professional claims you entered with citations and writes a summary that separates verified from claimed.",
    [N("claims", "case_findings", []), N("review", "analyst_review", ["claims"], prompt="Confirm every employer, role and education entry has a citation and is marked claimed until a second source corroborates it.", timeout_hours=168),
     N("report", "report", ["review"], profile="executive", format="html")], [], inputs={}, tags=["target-profile", "professional"], legal=TP_LEGAL,
    fixture_extra={"case_findings": [{"entity": "example.org", "entity_type": "domain", "predicate": "rdap.registrar", "value": "Example Registrar Inc"}]},
    gaps=["There is no automated retrieval of professional profiles: sites that require sign-in are never scraped. Enter cited claims by hand.", TP_GAPS_MANUAL])
add("TP-07", "Authorized Exposure Indicators", "Target profile", "Manual", "Guides the owner-verified exposure checks and records only status, category, date and remediation. Never stores secrets.",
    [consent("Confirm the person verified ownership of each account or domain checked (email confirmation, provider verification or signed document). A self-attestation is not enough for exposure checks."),
     N("checks", "analyst_review", ["consent"], prompt="Open Target profile > Exposure. Run the owner-verified checks. Record yes/no/unknown, category and date only; never paste passwords or leaked data.", timeout_hours=168),
     N("gaps", "case_gaps", ["checks"]), N("report", "report", ["gaps"], profile="executive", format="html")], [], inputs={}, tags=["target-profile", "exposure"],
    legal="Sensitive. Needs verifiable authorization. No raw credentials, breach dumps or government identifiers are collected or stored.",
    gaps=["The breach provider integration (Have I Been Pwned) needs the owner's API key and was not verified against the live service.", TP_GAPS_MANUAL],
    fixture_extra={"gaps": ["Exposure checks not yet assessed for the primary email (unassessed)"]})
add("TP-08", "Image Publication and Duplicate Review", "Target profile", "File upload", "Imports an image the subject owns, then routes duplicate and publication review to the Images workbench.",
    [N("ingest", "file_ingest", [], evidence_ref="$inputs.evidence_id"),
     N("review", "analyst_review", ["ingest"], prompt="Open Target profile > Images. Review local duplicate matches, then use the manual provider links (Google Lens, Bing Visual Search, TinEye). A provider result is a page candidate, not an identification of anyone.", timeout_hours=168),
     N("summary", "evidence_save", ["review", "ingest"], ref=out("ingest"), title="Image import summary")], FILE_IN, trigger={"type": "file", "enabled": False},
    inputs={"evidence_id": None}, tags=["target-profile", "images"], legal="Images the subject owns or has authorised. No facial recognition or identification of people is performed.",
    fixture_extra={"file": {"kind": "jpeg_exif", "count": 2, "sha256": "d" * 64, "preview": [{"kind": "exif.camera", "data": {"make": "ExampleCam"}}, {"kind": "exif.gps", "data": {"withheld": "restricted"}}]}},
    gaps=["Reverse-image search cannot be automated: providers offer interactive or commercial access only. The review step is manual."])
add("TP-09", "Source Freshness and Profile Change Alert", "Target profile", "Weekly, disabled (opt-in)", "Re-checks the public username footprint of an authorised subject and reports changes. Opt-in; needs activation approval.",
    [scope("$inputs.username", "username"), q("sherlock", "sherlock", ref="$inputs.username", ttype="username"), dedupe("unique", "sherlock"), diff("diff", "unique"),
     notify("notify", "diff", "Public profile change for a monitored subject"), onfail("fail", ["unique", "diff"], "Profile change alert failed")], USERNAME,
    trigger=sched("0 10 * * 1"), tags=["target-profile", "monitor"], watch=True, legal=TP_LEGAL + " Recurring monitoring of a person needs a documented purpose.",
    gaps=["Changes are reported as new or missing candidate URLs; a vanished account is not proof of anything."])
add("TP-10", "Client Privacy Remediation and Retest", "Target profile", "Manual", "Walks through open remediation tasks, asks for resolution evidence and ends with a retest brief.",
    [N("work", "analyst_review", [], prompt="Open Target profile > Remediation. For each task record what was done and attach evidence. Mark a task resolved only after a retest.", timeout_hours=168),
     N("gaps", "case_gaps", ["work"]), N("report", "report", ["gaps"], profile="executive", format="html")], [], inputs={}, tags=["target-profile", "remediation"],
    legal=TP_LEGAL, gaps=[TP_GAPS_MANUAL], fixture_extra={"gaps": ["Two remediation tasks have no resolution evidence"]})
add("TP-11", "Research Gaps and Next-Action Brief", "Target profile", "Manual", "Lists which approved research methods have not run, are outdated or were blocked, and why.",
    [N("gaps", "case_gaps", []), N("review", "analyst_review", ["gaps"], prompt="Open Target profile > Research. Decide which uncovered method to approve next. Absence of results is not evidence of absence.", timeout_hours=168),
     N("report", "report", ["review"], profile="technical", format="html")], [], inputs={}, tags=["target-profile", "planning"], legal=TP_LEGAL,
    fixture_extra={"gaps": ["Domain infrastructure checks have not run (eligible)", "Cited professional history not entered (manual)"]})
add("TP-12", "Redacted Client Report and Citation Check", "Target profile", "Manual", "Prepares the redacted subject report and requires a human check that every statement cites case evidence.",
    [N("facts", "case_findings", []), N("review", "analyst_review", ["facts"], prompt="Open Target profile > Reports. Generate the subject report preview, run the citation check, and confirm no speculative or sensitive associations are included.", timeout_hours=168),
     N("report", "report", ["review"], profile="evidence_pack", format="html")], [], inputs={}, tags=["target-profile", "report"], legal=TP_LEGAL,
    fixture_extra={"case_findings": [{"entity": "example.org", "entity_type": "domain", "predicate": "dns.a", "value": "192.0.2.10"}]},
    gaps=["The citation check runs in the Reports screen; this workflow only enforces that a person performed it."])


# ---------------------------------------------------------------------------------------------------------------------- AIV (Active Intelligence & Verification)
AIV_LEGAL = ("Only for assets you own or hold written authorization to test. This workflow never sends a request itself: it reads authorization and observation records, and a person "
             "creates, approves and starts every exact plan in the Verification workspace. Findings are observations to verify, not proof of compromise.")
AIV_GAPS = ["This workflow is manual only and cannot send requests: checks run from the Verification workspace after a person approves the exact plan.",
            "Not verified against third-party sites: every check was exercised against local lab servers only."]
AIV_OBS_FIXTURE = {"aiv_authorizations": [{"scope": "example.org", "status": "live"}],
                   "aiv_observations": [{"asset": "example.org", "check": "http_metadata", "title": "Content-Security-Policy header missing", "severity": "low"},
                                        {"asset": "example.org", "check": "tls_handshake", "title": "Certificate expires in 21 days", "severity": "medium"}]}


def aiv_flow(plan_prompt: str, review_prompt: str, *, report_profile: str = "technical") -> list[dict[str, Any]]:
    return [consent("Confirm you own the asset or hold written authorization to test it, and that the authorization names the host, ports and checks. Consent from a person is not authorization for their domains."),
            N("auth", "aiv_authorizations", ["consent"], only_live=True),
            N("has_auth", "condition", ["auth"], ref=out("auth", "count"), op="gt", value=0),
            N("plan", "analyst_review", ["has_auth"], when={"ref": out("has_auth", "value"), "op": "truthy"}, prompt=plan_prompt, timeout_hours=72),
            N("observed", "aiv_observations", ["plan"], min_severity="info", exclude_reviewed=["false_positive"]),
            N("review", "analyst_review", ["observed"], prompt=review_prompt, timeout_hours=168),
            N("report", "report", ["review"], profile=report_profile, format="html")]


add("AIV-01", "Website Exposure Assessment", "Verification", "Manual", "Scoped web asset: HEAD/GET metadata, TLS check and a security-header comparison. Reads results; a person approves and starts the checks.",
    aiv_flow("Open Verification. Create a plan for the authorized web asset: one HTTP metadata check (HEAD) and one TLS handshake. Review the preview, approve the exact plan and start it.",
             "Review each observation: confirm, mark false positive or accept the risk, with a reason. Header findings are improvement suggestions, not vulnerabilities."), [],
    inputs={}, tags=["aiv", "verification", "web"], legal=AIV_LEGAL, gaps=AIV_GAPS, fixture_extra=AIV_OBS_FIXTURE,
    example="Verified headers and TLS observations with prioritised improvement suggestions, each linked to the stored response.")
add("AIV-02", "Infrastructure Verification", "Verification", "Manual", "Approved host: certificate baseline and a few selected ports at a low rate; reconcile what you found against what you expected to own.",
    aiv_flow("Open Verification. Create a plan for the authorized host: a TLS handshake and a connect check of at most 10 listed ports (optionally Nmap or Naabu if installed). Approve the exact plan and start it.",
             "Compare open ports and certificates with your asset inventory. Note anything you did not expect, and record what you could not determine."), [],
    inputs={}, tags=["aiv", "verification", "infrastructure"], legal=AIV_LEGAL, gaps=AIV_GAPS + ["Nmap and Naabu are optional and used only if installed and version-verified; the built-in connect check always works."],
    fixture_extra={"aiv_authorizations": [{"scope": "example.org", "status": "live"}],
                   "aiv_observations": [{"asset": "example.org", "check": "tcp_connect", "title": "TCP port 8080 is open", "severity": "info"}]},
    example="An inventory delta: ports and certificates observed against the authorization, with notes about what is uncertain.")
add("AIV-03", "Sensitive Exposure Indicator Review", "Verification", "Manual", "Reviews owner-confirmed exposure indicators for an authorized asset. Records category, confidence and remediation; never raw secrets.",
    aiv_flow("Confirm which exposure indicators were reported for the authorized asset (for example by the Exposure workspace). Record category and confidence only; never paste secrets or leaked data.",
             "Check each indicator against the owned asset it affects, mark it confirmed or false positive with a reason, and write the remediation.", report_profile="executive"), [],
    inputs={}, tags=["aiv", "verification", "exposure"], legal=AIV_LEGAL + " Raw credentials and breach dumps are never collected or stored.",
    gaps=AIV_GAPS + ["Document and search-result indicators are entered by a person; there is no automated secret scanner in this version."], fixture_extra=AIV_OBS_FIXTURE,
    example="Exposure category, confidence, affected owned asset and remediation; no raw secrets.")
add("AIV-04", "Security Misconfiguration Review", "Verification", "Manual", "Authorized scope: approved, reviewed signature templates (read-only GET/HEAD fingerprints) and built-in checks, then analyst review.",
    aiv_flow("Open Verification > Templates and confirm the signature templates you intend to use are reviewed and approved by id and hash. Create a plan with a signature check, approve the exact plan and start it.",
             "Treat every match as a lead. Confirm it by hand, mark false positives, and record low-impact remediation. No exploitation is attempted or implied."), [],
    inputs={}, tags=["aiv", "verification", "misconfiguration"], legal=AIV_LEGAL,
    gaps=AIV_GAPS + ["Nuclei is optional. Only templates you approved by id and content hash are ever run; the bundled community template library is not used."],
    fixture_extra={"aiv_authorizations": [{"scope": "example.org", "status": "live"}],
                   "aiv_observations": [{"asset": "example.org", "check": "signature", "title": "Apache version banner disclosed", "severity": "low"}]},
    example="Evidence-linked low-impact findings for analyst review, with no exploitation claims.")
add("AIV-05", "Client Exposure Report", "Verification", "Manual", "Combines verified profile evidence with authorized AIV observations and requires analyst approval before the redacted report is written.",
    [consent("Confirm the client authorized the assets in scope and approved the report recipients."),
     N("auth", "aiv_authorizations", ["consent"], only_live=False),
     N("observed", "aiv_observations", ["auth"], min_severity="info", exclude_reviewed=["false_positive"]),
     N("facts", "case_findings", ["auth"]),
     merge("all", ["observed", "facts"]),
     N("review", "analyst_review", ["all"], prompt="Approve the findings that go into the client report. Remove anything speculative or sensitive; confirm redactions and that every statement cites evidence.", timeout_hours=168),
     N("save", "evidence_save", ["review", "all"], ref=out("all"), title="Client exposure report dataset"),
     N("report", "report", ["review"], profile="executive", format="html")], [], inputs={}, tags=["aiv", "verification", "report"], legal=AIV_LEGAL, gaps=AIV_GAPS,
    fixture_extra={**AIV_OBS_FIXTURE, "case_findings": [{"entity": "example.org", "entity_type": "domain", "predicate": "dns.a", "value": "192.0.2.10"}]},
    example="An executive and technical report with redactions and an audit appendix.")


# ---------------------------------------------------------------------------------------------------------------------- DARKINT (exposure intelligence)
DARK_LEGAL = ("Defensive exposure assessment for yourself, a verified consenting client, or an organization you are authorized to assess. Every lookup passes the consent, provider and domain-control gates "
              "and is audited. A report that data leaked is a lead, not proof that the record exists, is accurate or is still reachable. No passwords, hashes, tokens, identity documents, card numbers or leaked records "
              "are collected, stored or shown.")
DARK_GAPS = ["No provider was exercised against its live service in this build (fixture-tested). Have I Been Pwned needs your paid API key; Ransomware.live's free v2 interface is labelled personal use only.",
             "The automation reads the monitor you created in the Exposure tab; it cannot widen its scope, and revoking the consent stops it."]
DARK_MONITOR = [{"name": "monitor_id", "label": "Exposure monitor id (create one in the Exposure tab)", "type": "monitor", "required": True, "example": None}]
DARK_FIXTURE = {"darkint_events": [{"type": "breach", "title": "Breach: Example Forum", "provider": "hibp", "categories": ["email addresses", "credential indicator"], "confidence": "medium"},
                                   {"type": "ransomware_listing", "title": "Named on a leak site by group examplegroup (an unverified claim by the actor)", "provider": "ransomware_live",
                                    "categories": ["organization named on a leak site"], "confidence": "low"}]}


def dark_check(id: str = "check", deps: list[str] | None = None) -> dict[str, Any]:
    return N(id, "darkint_check", deps or [], monitor_ref="$inputs.monitor_id")


add("DARK-01", "Breach Exposure Check", "Exposure", "Manual", "Manual self or verified-client check of the approved email or domain identifiers in one monitor. Reports provider incident names and data categories only, with redacted findings.",
    [consent("Confirm you have verified consent (not a self-attestation for a client) covering exactly these identifiers and providers, and that you accept the provider's terms."),
     dark_check("check", ["consent"]), dedupe("unique", "check"),
     N("review", "analyst_review", ["unique"], prompt="Open Target profile > Exposure. For each reported incident record whether it is relevant, and the data categories only. Never paste leaked content.", timeout_hours=168),
     N("save", "evidence_save", ["review", "unique"], ref=out("unique"), title="Reported breach exposure (categories only)"), N("report", "report", ["save"], profile="executive", format="html")],
    DARK_MONITOR, inputs={"monitor_id": None}, tags=["darkint", "exposure"], legal=DARK_LEGAL, gaps=DARK_GAPS, fixture_extra=DARK_FIXTURE,
    example="Provider breach names, dates and data categories, grouped by incident, with a plain statement of what was and was not checked.")
add("DARK-02", "Dark-Web Mention Monitor", "Exposure", "Weekly, disabled (opt-in)", "Periodically queries the permitted threat-intelligence sources named in a monitor for authorized company names or domains and alerts only on newly reported items. Nothing is downloaded.",
    [dark_check("check"), dedupe("unique", "check"), diff("diff", "unique"), notify("notify", "diff", "Newly reported mention of a monitored organization (a claim, not proof)", "warning"),
     onfail("fail", ["unique", "diff"], "Exposure monitor run failed")],
    DARK_MONITOR, inputs={"monitor_id": None}, trigger=sched("0 9 * * 1"), tags=["darkint", "monitor"], legal=DARK_LEGAL, watch=True, gaps=DARK_GAPS + ["Intelligence X has no automated integration here: record what you find in its own interface with manual intake."],
    fixture_extra=DARK_FIXTURE, example="One notification per run listing newly reported items; the first run only records a baseline.")
add("DARK-03", "Credential Exposure Alert", "Exposure", "Manual", "Detects a provider-reported credential-exposure category for the authorized identifiers and recommends account protections. Never collects raw credentials.",
    [consent("Confirm the account owner's verified consent. The password exposure checker is a separate, owner-initiated step in the Exposure tab and is never scheduled."),
     dark_check("check", ["consent"]), N("creds", "transform", ["check"], ref=out("check"), op="pick_predicates", values=["darkint.breach"]),
     N("review", "analyst_review", ["creds"], prompt="Decide which accounts need action. Recommended: change the password where it was reused, turn on multi-factor authentication or passkeys, use a password manager. The owner runs the Pwned Passwords check by hand if wanted.", timeout_hours=168),
     N("tasks", "darkint_remediation", ["review"], actions=["password_reset", "mfa", "follow_up_check"], max_tasks=20), N("report", "report", ["tasks"], profile="executive", format="html")],
    DARK_MONITOR, inputs={"monitor_id": None}, tags=["darkint", "credentials"], legal=DARK_LEGAL, gaps=DARK_GAPS, fixture_extra=DARK_FIXTURE,
    example="A list of accounts to protect, with tasks for password changes and multi-factor authentication. No password or hash is ever shown.")
add("DARK-04", "Ransomware Leak Watch", "Exposure", "Daily, disabled (opt-in)", "Tracks publicly reported ransomware-victim listings for authorized organizations from the allowed feed, de-duplicates re-posts and labels every listing as an unverified claim.",
    [dark_check("check"), dedupe("unique", "check"), diff("diff", "unique"), notify("notify", "diff", "New ransomware-victim listing reported (unverified claim by the actor)", "warning"),
     onfail("fail", ["unique", "diff"], "Ransomware leak watch failed")],
    DARK_MONITOR, inputs={"monitor_id": None}, trigger=sched("0 7 * * *"), tags=["darkint", "ransomware", "monitor"], legal=DARK_LEGAL, watch=True,
    gaps=DARK_GAPS + ["A listing is an unverified claim by the actor. Corroborate it (press, regulator, the organization itself) before treating it as a confirmed incident."],
    fixture_extra=DARK_FIXTURE, example="Newly reported listings since the last run, each labelled as an unverified claim with its source reference.")
add("DARK-05", "Exposure Remediation Tracker", "Exposure", "Manual", "Creates tasks for MFA, password resets, domain and email hygiene, takedown requests, notification and follow-up checks. Sends no email and submits no takedown.",
    [N("events", "darkint_events", [], exclude_dismissed=True), N("tasks", "darkint_remediation", ["events"], actions=["password_reset", "mfa", "domain_hygiene", "takedown", "notify", "follow_up_check"], max_tasks=30),
     N("review", "analyst_review", ["tasks"], prompt="Review the new tasks. Anything that contacts a person, a host or a provider (a notification, a takedown request) is done by you outside this application, after you decide to.", timeout_hours=168),
     N("gaps", "case_gaps", ["review"]), N("report", "report", ["gaps"], profile="executive", format="html")],
    [], inputs={}, tags=["darkint", "remediation"], legal=DARK_LEGAL, gaps=["Nothing is sent from this application: notifications and takedown requests are tracked as tasks and carried out by a person."], fixture_extra=DARK_FIXTURE,
    example="Open tasks per reported incident with practical guidance and a follow-up re-check.")


def main(check: bool) -> int:
    assert len(T) == 52, len(T)
    problems = []
    for t in T:
        rep = validate(t["definition"], ADAPTERS)
        if not rep["valid"]:
            problems.append((t["key"], rep["errors"]))
    if problems:
        for k, e in problems:
            print("INVALID", k, json.dumps(e, indent=1)[:600])
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    stale = []
    keep = set()
    for t in T:
        p = OUT / f"{t['slug']}.json"
        keep.add(p.name)
        text = json.dumps(t, indent=1, ensure_ascii=False) + "\n"
        if not p.exists() or p.read_text(encoding="utf8") != text:
            stale.append(p.name)
            if not check:
                p.write_text(text, encoding="utf8")
    for old in OUT.glob("*.json"):
        if old.name not in keep:
            stale.append(old.name)
            if not check:
                old.unlink()
    print(("stale: " if check else "wrote: ") + (", ".join(stale) or "none"), f"({len(T)} templates valid)")
    return 1 if (check and stale) else 0


if __name__ == "__main__":
    raise SystemExit(main("--check" in sys.argv))
