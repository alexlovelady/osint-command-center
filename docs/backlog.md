# Backlog

Items agreed to do later. Each says why it is waiting and what finishing it involves.

| ID | Item | Why it waits | What "done" means |
|---|---|---|---|
| B-001 | **Amass data sources in Setup** | Amass v5 passive mode returns nothing until its own config enables API-keyed data sources; none are configured and I have no keys to test with | Setup gets an "Amass data sources" step that writes Amass's `datasources.yaml` from keys the user already entered (kept in the credential store, never in the file at rest longer than a run); the adapter passes `-config`; a real run on a domain with many public subdomains returns names and the name parser is verified against real output |
| B-002 | Apply the WebView2 firewall rule (or ship a fixed-version WebView2 runtime so a rule can be app-specific) | A rule on the shared `msedgewebview2.exe` affects other apps | Decision by the owner; script exists (`scripts/windows/block-webview2-egress.ps1`) |
| B-003 | Real MCP client test (Claude Desktop etc.) | Owner will test later | A real client lists tools, reads a case, and an approval round-trip works |
| B-004 | Clean-machine install tests (Windows installer, Linux tarball) | Owner will test | Install, first-run Setup, a search, update check |
| B-005 | Keyed services (VirusTotal, Shodan, Censys, OpenCorporates, urlscan) against real responses | Needs the owner's keys, entered in Setup | One real call each; mock fixtures replaced or confirmed |
| B-006 | Copilot with llama.cpp, a real cloud provider, and other open-weight models | Only Ollama + `huihui_ai/qwen3-abliterated:8b` was exercised live; llama.cpp/cloud paths are covered by mocks | One real answer each, through `scripts/copilot_live_check.py` |
| B-007 | Embedding-based retrieval for the Copilot | Lexical BM25 is deterministic and testable, but misses synonyms | Optional local embedding model; same "not documented" threshold logic re-validated |
| B-008 | Copilot tool for hardware sessions | Deliberately not exposed (authorisation boundary) | Owner decision, then a proposal type with the existing assessment/acknowledgement steps |
| B-009 | Automation notifications by email and inbound webhook triggers | Needs SMTP credentials / a listener the app deliberately does not run | Owner decision; separate approval-gated implementation |
| B-010 | Live validation of the keyed and CLI-based templates (Sherlock/Maigret/Subfinder/Amass, VirusTotal, Shodan, Censys, OpenCorporates, EDGAR) | Needs installed tools and the owner's keys | One real run per template, results recorded in progress.md |
| B-011 | Real physical-device test for Sensor Health Monitor and RF Spectrum Baseline | No hardware attached | Run against an owned receiver |
| B-012 | Advisory/CVE feed connector, imagery change detection, fuzzy duplicate matching | Not implemented; the templates say so | Connector + handler + tests |
| B-013 | Retire the older `workflows` module once the new engine covers its cases | Existing cases may use it | Migration + removal |
| B-014 | Live check of Have I Been Pwned (account) and Pwned Passwords (range) | Needs the owner's paid HIBP key; both were mock-tested only | One real call each, recorded in `docs/integration-matrix.md`; label changed from mocked to live |
| B-015 | Physical Kali desktop smoke check of the Target Profile screens | Needs the owner's external SSD | Open a person case, run one approved passive plan, import an image, export a subject report, revoke authorization |
| B-016 | OCR and local image description (optional) | Not implemented; no OCR engine is bundled | Optional local engine behind a switch; output labelled a lead; same review rules |
| B-017 | Public-document URL import and published-document disclosure scoring | Not implemented; files are imported by hand | Fetch through the SSRF guard, static inspection only, consent class `documents` |
| B-018 | Link organisation locations (Overpass) to subjects with owner-approved precision | Not implemented | Coarse by default; exact only with an explicit approval |
| B-019 | Subject-facing correction request portal | Needs a design decision: the app runs no inbound listener | A signed, expiring link or exported form; requests land in the same table |
| B-020 | Image matching beyond perceptual hashes (rotation, mirror, composites) | Deliberately omitted: no OpenCV (D-069) | Optional feature matching with documented false-positive rates; still no face features |
