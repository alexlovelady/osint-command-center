# Sources, terms and licences (implemented adapters)

Verify again before redistribution; none of these is a guarantee of continued free access. "Live" means the adapter has been run
against the real service on this machine (see `docs/integration-matrix.md`).

| Adapter | Endpoint / tool | Class | Default | Terms / licence note | Rate handling | Verified |
|---|---|---|---|---|---|---|
| `rdap` | IANA bootstrap, then the TLD registry's RDAP server | passive | on | RFC 9083 data; follow each registry's terms (https://www.icann.org/rdap). Registrant data is often redacted | 429 → `rate_limited`, honours `Retry-After` | Live |
| `dns` | system resolver | passive | on | n/a | per-type lookups, 8 s lifetime | Live |
| `crtsh` | https://crt.sh/?q=%.domain&output=json | passive | on | Public CT data; **no SLA** (502s observed) | 3 attempts, backoff | Live |
| `wayback` | https://web.archive.org/cdx/search/cdx | passive | on | https://archive.org/about/terms.php | 429 → deferred 90 s | Live |
| `sec_edgar` | https://data.sec.gov/submissions/CIK##########.json | passive | on | US government data; SEC requires an identifying User-Agent (Settings → EDGAR contact) and ≤10 req/s | 429 → `rate_limited` | Mocked |
| `overpass` | https://overpass-api.de/api/interpreter (bounded query) | passive | on | ODbL 1.0 — attribution "© OpenStreetMap contributors" is carried in the adapter's licence field and the map tab | 6/min | Mocked |
| `virustotal` | https://www.virustotal.com/api/v3/ | passive | off | Needs a key; free keys are non-commercial and 4 req/min; never uploads files | 4/min | Mocked |
| `urlscan` | https://urlscan.io/api/v1/search/ | passive | off | Searches existing public scans only; never submits one | 20/min | Mocked |
| `shodan` | https://api.shodan.io/shodan/host/ | passive | off | Needs a key; does not scan the target; key travels as a query parameter (Shodan's design) and is stripped from stored URLs | 30/min | Mocked |
| `censys` | https://search.censys.io/api/v2/hosts/ | passive | off | Needs `API_ID:API_SECRET` (Basic auth); index data, not a probe | 20/min | Mocked |
| `opencorporates` | https://api.opencorporates.com/v0.4/companies/search | passive | off | Needs a token; share-alike open data licence; name matches are leads. Token is stripped from stored URLs | 10/min | Mocked |
| `gdelt` | https://api.gdeltproject.org/api/v2/doc/doc | passive | off | Open with attribution; machine-collected, tone/coverage unreliable | 10/min | Mocked |
| `lookalike` | none (offline generator) | local_only | off | In-house; inspired by dnstwist, no code copied | n/a | Local |
| `subfinder` | external CLI | passive | on | MIT (ProjectDiscovery); not redistributed; installed by Setup (pinned release) | timeout kills the process tree | Live |
| `sherlock` | external CLI | public_site_query | on | MIT; contacts many third-party sites; confirmation required; installed by Setup | timeout kills the process tree | Output format verified (one account) |
| `maigret` | external CLI | public_site_query | on | MIT; confirmation required; auto-update, recursion and extraction switched off | timeout kills the process tree | Output format verified (one account) |
| `amass` | external CLI | passive | off | Apache-2.0; v5.1.1 installed by Setup | timeout kills the process tree | Starts; name parsing unverified |
| `theharvester` | external CLI | passive | off | GPL-2.0; separate process, never linked or bundled; Linux only | timeout kills the process tree | Live on Linux (2 hosts parsed) |
| `tcp_connect` | direct TCP connect | active | not registered | Needs `OSINTCC_ENABLE_ACTIVE=1` + a scope authorization; only for systems you may test | per-run confirmation | Loopback tests |

"Default on" means pre-ticked in the plan preview; nothing runs without your confirmation either way.

Importer formats are read from files you supply; their specifications are public (SigMF, PCAP/pcapng, STIX 2.1, CycloneDX/SPDX,
CCSDS, NMEA 0183, SEC submissions JSON). No third-party data set is bundled: sanctions lists, ADS-B/AIS captures and geospatial tiles
are always supplied by the user or fetched from the provider the user chooses.

Libraries and their licences are inventoried mechanically in `docs/license-audit.md`.

## Downloads performed by first-run Setup (pinned in `backend/osintcc/setup/catalog.json`)

| Component | Version | Source | Integrity |
|---|---|---|---|
| Subfinder | 2.17.0 | github.com/projectdiscovery/subfinder releases | SHA-256 from the release's `checksums.txt` |
| Amass | 5.1.1 | github.com/owasp-amass/amass releases | SHA-256 from `amass_checksums.txt` |
| ExifTool | 13.59 | SourceForge (the project's official download location) | SHA-256 from exiftool.org `checksums.txt` |
| uv | 0.13.5 | github.com/astral-sh/uv releases | SHA-256 from the release asset digest |
| Sherlock 0.16.2, Maigret 0.6.6 | PyPI | files.pythonhosted.org via `uv pip install --require-hashes` | hash-locked requirement files (`uv pip compile --generate-hashes`) |
| theHarvester | 4.11.1 (Linux) | github.com/laramies/theHarvester source tarball (via codeload.github.com) + hash-locked PyPI wheels | tarball SHA-256 + `--require-hashes` |
| Ollama | 0.40.10 (Windows installer, only if missing) | github.com/ollama/ollama releases | SHA-256 from the release asset digest (**not re-verified by download**: 1.6 GB) |
| Model `huihui_ai/qwen3-abliterated` | 8b / 4b / 1.7b | ollama.com registry through your local Ollama | Ollama verifies each blob's digest |

Regenerate with `scripts/build_catalog.py`; review the diff before shipping a new catalog.
