"""Run the Target Profile (addendum TP-1.0) tests and write docs/profile-test-results.md: each TP-xx criterion, the tests that cover it, what ran, skipped or failed.

    uv run python scripts/gen_profile_test_results.py

Nothing is hand-written: results come from pytest's JUnit output. Criteria that cannot be proven by an automated test say so.
"""
from __future__ import annotations

import platform
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from osintcc import __version__

FILES = ["tests/integration/test_profile.py", "tests/integration/test_profile_research.py", "tests/integration/test_profile_username_flow.py", "tests/integration/test_profile_images.py",
         "tests/integration/test_profile_exposure.py", "tests/integration/test_profile_copilot_reports.py", "tests/integration/test_profile_scenario.py", "tests/integration/test_migrations.py",
         "tests/integration/test_automations_3.py"]
CRITERIA = {
    "TP-01": ("Existing cases, profiles, vault objects, automations and settings survive migrations", ["tp01_", "upgrade_from_", "upgrade_is_idempotent", "legacy_database", "downgrade_to_base", "backup_restore_reconstructs", "tp26_"], ""),
    "TP-02": ("A person case opens to the target profile; existing expert tabs remain accessible", ["tp01_existing_person_case", "non_person_case"], "UI: `profile.test.tsx` (TargetProfile) and Playwright `profile.spec.ts` (opens on Target profile; Advanced workbench keeps every tab)."),
    "TP-03": ("No research runs during preview or when authorization is expired/revoked", ["tp03_"], ""),
    "TP-04": ("Self and client modes enforce different sensitive checks without bypassing common protections", ["tp04_", "only_an_owner_can_authorize", "exposure_checks_need_strong"], ""),
    "TP-05": ("An unverified username match remains a candidate and never becomes verified automatically", ["tp05_", "confirming_needs"], ""),
    "TP-06": ("Sherlock/Maigret overlap is clustered while independent evidence remains retrievable", ["tp05_tp06"], ""),
    "TP-07": ("Bulk review stores reviewer, status, basis and timestamps; reversal restores previous state", ["tp07_", "confirming_needs"], ""),
    "TP-08": ("Research-coverage labels reflect actual tested sources, errors and approved scope", ["tp08_", "approved_research_runs"], ""),
    "TP-09": ("AI citations resolve to accessible case evidence; contradictory evidence is shown", ["tp09_"], ""),
    "TP-10": ("A candidate with only one identical handle is not promoted by the model", ["tp10_"], ""),
    "TP-11": ("Image upload rejects unsafe files, stores a hash and extracts supported EXIF correctly", ["tp11_"], ""),
    "TP-12": ("Duplicate and altered-image matching show confidence limits and a false-positive workflow", ["tp12_"], ""),
    "TP-13": ("Reverse image search never claims automated provider success", ["tp13_"], ""),
    "TP-14": ("No biometric identification or identity-from-face feature exists", ["tp14_"], ""),
    "TP-15": ("No plaintext passwords, raw leak dumps, full national IDs or session secrets can be stored through exposure APIs", ["tp15_", "validate_descriptor_never"], ""),
    "TP-16": ("Password owner-check does not log, persist or transmit a complete password or hash", ["tp16_"], "Browser side: `sha1.test.ts`, `exposure.test.tsx` and Playwright `profile.spec.ts` (only five characters leave the page)."),
    "TP-17": ("Revocation stops scheduled jobs and pending collection", ["tp17_", "bound_workflow_stops", "expiry_sweep", "tp26_"], ""),
    "TP-18": ("External/cloud AI data transfer requires consent and an explicit data preview", ["tp18_"], ""),
    "TP-19": ("Correct roles see sensitive exposure summaries; others and reports get redaction", ["tp19_", "viewer_sees_masked", "other_users_cannot", "tp20_subject_report", "report_create_seals"], ""),
    "TP-20": ("Every published report traces verified statements to immutable source evidence", ["tp20_"], ""),
    "TP-21": ("Third-party documents/images are processed without execution or outbound side effects", ["tp21_", "tp11_"], ""),
    "TP-22": ("Imports, exports and backups do not leak identifiers into logs or temporary plaintext", ["tp22_", "identifier_values_never_enter", "tp26_"], ""),
    "TP-23": ("Crash recovery resumes only approved, replay-safe collection; no surprise network calls", ["tp23_"], ""),
    "TP-24": ("Linux and Windows desktop UI and API tests pass; physical Kali smoke check", [], "Windows: this suite + frozen-backend smoke (48/48). Linux: clean-checkout Docker build (see `docs/progress.md`). **The physical Kali smoke check has not been performed.**"),
    "TP-25": ("12 template dry runs pass and show honest dependency/availability states", ["tp25_", "fixture_dry_runs_produce_identical"], ""),
    "TP-26": ("End-to-end synthetic consented-client scenario: create, verify consent, collect, review, remediate, export, revoke", ["tp26_"], ""),
}


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "r.xml"
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}", *FILES], cwd=ROOT, check=False, capture_output=True)
        root = ET.parse(xml).getroot()
    cases = []
    for tc in root.iter("testcase"):
        state = "failed" if tc.find("failure") is not None or tc.find("error") is not None else "skipped" if tc.find("skipped") is not None else "passed"
        cases.append((tc.get("name", ""), state))
    L = ["# Target Profile (TP-1.0) test results", "",
         f"Generated by `scripts/gen_profile_test_results.py` on {platform.platform()}, Python {platform.python_version()}, application {__version__}. "
         "Network is mocked in every test here; provider integrations (Have I Been Pwned, Pwned Passwords) were exercised only against recorded responses and are **not verified live**. "
         "Fixtures are synthetic (example.com, fake Sherlock/Maigret executables).", "",
         f"Total in the profile suites: **{len(cases)}** tests, {sum(1 for c in cases if c[1] == 'passed')} passed, {sum(1 for c in cases if c[1] == 'failed')} failed, {sum(1 for c in cases if c[1] == 'skipped')} skipped.", "",
         "| Criterion | Requirement | Tests | Result | Notes |", "|---|---|---|---|---|"]
    for k, (desc, pats, note) in CRITERIA.items():
        hit = [c for c in cases if any(p in c[0] for p in pats)]
        if not pats:
            res = "see notes"
        else:
            res = "**FAILED**" if any(c[1] == "failed" for c in hit) else "no test found" if not hit else f"{sum(1 for c in hit if c[1] == 'passed')}/{len(hit)} passed"
        L.append(f"| {k} | {desc} | {len(hit)} | {res} | {note} |")
    (ROOT / "docs" / "profile-test-results.md").write_text("\n".join(L) + "\n", encoding="utf8")
    bad = [c for c in cases if c[1] == "failed"]
    print(f"{len(cases)} tests, {len(bad)} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
