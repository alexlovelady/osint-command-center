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
