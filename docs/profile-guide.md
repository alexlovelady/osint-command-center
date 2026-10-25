# Target Profile and Exposure Assessment (addendum TP-1.0)

A people case now opens on the **Target profile**. The older tabs are unchanged and live under **Advanced workbench**. Gap analysis and design choices: `docs/profile-enhancement-gap-analysis.md`; acceptance evidence: `docs/profile-test-results.md`.

## What it is for

Verified self-audits, consent-based client assessments and public-source diligence on organisations. It is **not** a people-search tool. It will not guess relatives or addresses, scrape sign-in-only sites, identify anyone from a face, or store passwords, tokens, recovery secrets, government identifiers or breach dumps.

## The workflow

1. **Create target** (display label, mode, purpose). Existing people cases get a target automatically the first time you open them; nothing in the old tables changes.
2. **Authorization** (case owner). Record who verified consent, the source classes it covers, the identities (required for clients), the permitted purposes and an end date. Client mode needs proof attached as evidence and a verifiable method; sensitive checks (exposure, reverse image) need more than a self-attestation. Revoke at any time: pending work is cancelled at once, bound automations are switched off, queued jobs are refused when they would start.
3. **Research**. *Preview* shows every source, what it contacts, cost, limits, maturity and why it is blocked. Nothing is preselected. Approve a bounded plan (at most 40 source runs); public-site tools also need their own confirmation. Runs go through the same pipeline as every other search (SSRF guard, rate limits, evidence hashing, execution-time policy re-check).
4. **Review queue**. Sherlock/Maigret hits are leads, clustered by canonical URL (two tools agreeing is still one signal). Mine / Not mine / Unsure with a reason; *Mine* needs the subject's attestation or independent evidence. Bulk decisions are reversible; the history is kept.
5. **Profile**. Claims show verified, subject-confirmed, candidate, conflicting, rejected or not assessed, each linked to evidence. "Not assessed" never means "does not exist".
6. **Images**. Local import (Pillow only), EXIF, perceptual hashes, duplicate/resized/cropped matching inside the case, a false-positive workflow, and manual reverse-image search guidance. Precise GPS is shown to editors/owners only; reports use about 10 km precision.
7. **Exposure, Remediation**. Record status/category/date; run the in-browser password check; optionally the Have I Been Pwned account check (needs your key). Tasks close only with evidence of a fix or retest.
8. **Reports**. Draft, citation-check (every verified statement must resolve to evidence whose stored bytes still match its hash), then create a sealed file. The subject report is redacted; the analyst package is private.
9. **Privacy & data**. Correction requests, a purge preview, and a purge with a typed confirmation.

## Copilot

Ask "What do we actually know?", "What information is publicly exposed?", "What should I check next?", "Why wasn't sherlock searched?", "Group the account leads", "Explain this image match". These answers are computed from stored records without a model. The Copilot has no tool that can verify, confirm, reject or merge anything; its two proposals (install a disabled workflow draft, draft a report) need your approval. A cloud model sees counts and generic text only, never identifiers, URLs, claim text or exposure descriptors, and earlier profile answers are withheld from its history.

## Honest limits

| Area | Status |
|---|---|
| Have I Been Pwned account check | Implemented, **mock-tested only**; needs a paid key; not verified against the live service |
| Pwned Passwords range check | Implemented, **mock-tested only**; free; five-character prefix only |
| Sherlock, Maigret, RDAP, DNS, crt.sh, Wayback, Subfinder | Live-tested earlier (see `docs/integration-matrix.md`) |
| OpenCorporates, SEC EDGAR, GDELT | Mock-tested only; EDGAR needs a CIK |
| Reverse image search (Google Lens, Bing, TinEye) | Manual link-out and manual result entry; never automated |
| Image matching | Resized, recompressed and many cropped copies; **not** rotated, mirrored or composited copies; false positives exist |
| OCR, image description | Not implemented |
| Professional history, documents, public locations | Entered or imported by hand with citations; no automated retrieval |
| Subject-facing portal | None: corrections are recorded by an editor on the subject's behalf |
| Template workflows (TP-01..12) | Fixture-tested dry runs; several are review checklists, not automation (each says so) |
| Physical Kali desktop check | **Not performed** |
