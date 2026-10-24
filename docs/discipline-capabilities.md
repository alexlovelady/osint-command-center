# Discipline capability matrix (honest status, 2026-10-24)

Columns follow spec §21.7 P0B: working now / needs key / needs hardware / import only / unsupported. "Tests" are automated, offline, on
synthetic fixtures unless stated. Nothing below intercepts, decrypts or identifies anyone; everything is bounded to material the user
owns, has consent for, or that is public.

| Discipline | Status | What exists | Not covered |
|---|---|---|---|
| OSINT — domain / cyber | **working now** (live-verified for RDAP, DNS, crt.sh, Wayback) | those four + lookalike generator, GDELT, urlscan/VirusTotal/Shodan/Censys (keyed, mocked), plans, workflows, graph, timeline, reports | no scraping, no logins, no CAPTCHA handling |
| OSINT — usernames | tool not installed | Sherlock, Maigret adapters, confirmation-gated, `low` confidence leads | never run against the real tools |
| OSINT — documents | **import only** | PDF (active-content flags, links/emails from compressed streams), DOCX (macros, external relationships, metadata *as claims*), SpiderFoot JSON (leads) | no rendering, no OCR, no password-protected files |
| OSINT — business | **needs key / mocked** | SEC EDGAR (contact string), OpenCorporates (token) | live responses never checked |
| COMINT | **import only** | `.eml` (header fields as claims; attachments quarantined; no DKIM/SPF claims) | no mailbox access, no interception, no VoIP/PSTN |
| SIGINT | **import only / simulated hardware** | SigMF → averaged FFT with narrowband peaks and SNR; simulated and replay SDR drivers | no demodulation, no emitter location; real receivers unexercised |
| ELINT | **import only** | pulse-descriptor CSV statistics; the file must declare `provenance: synthetic` or `owned_lab` or it is rejected | no emitter identification, geolocation or library matching |
| FISINT | **import only** | CCSDS primary headers and calibrated telemetry CSV; payload meaning is not asserted without a supplied calibration | proprietary formats |
| HUMINT | **working now** (consent-based) | alias-only sources, consent records (scope/expiry/withdrawal), encrypted reports, analyst-assigned reliability, corroboration view, retention list | no scoring, no real-name fields |
| GEOINT | **working now / import only** | JPEG EXIF GPS (accuracy stated only when the file says so), GeoTIFF metadata, PNG pixel-difference change detection (never reported as a verified event), map layers (Leaflet; basemap opt-in), Overpass (mocked), cross-links | no image-content geolocation, no face matching; pixel changes are not "verified events" |
| MASINT | **import only** | sensor CSV robust-z anomaly intervals, cause always `unknown` | no sensor fusion beyond timing |
| CYBINT | **import only** | PCAP/pcapng summaries (flows, DNS, TLS SNI, protocol stats), STIX 2.1 bundles | no live capture, no payload decryption |
| FININT | **import only / mocked** | EDGAR submissions, sanctions CSV matching (name-similarity *leads*, identifier matches separated), blockchain transaction CSV | no trading, no wallets, no paid KYC data |
| TECHINT | **import only** | CycloneDX/SPDX SBOMs, static firmware inspection (entropy, signatures, strings; credential *markers*, never values) | artifacts are never executed, unpacked-and-run or emulated |
| Position/track data | **import only** | ADS-B, AIS (checksums), NMEA GPS (restricted); tracks; exports hide private positions | owners are never resolved; live receivers unexercised |
| Fusion | **working now** | claims with independence-based labels, contradictions side by side, hypotheses as tallies, intelligence requirements, gap assessment, reversible merges, collection plans, **cross-discipline correlation suggestions and a unified timeline** | no probabilities, no automatic merging |
| Workflows / scheduler | **working now** | data-only DAGs, wave execution, snapshot diffs → alerts, off-by-default schedules | no cron expressions; scheduler tested with a fake clock/tick |
| Reports | **working now** | executive, technical, evidence pack, **multi_int** (annexes, contradictions, methodology, custody note) in HTML/Markdown/JSON/PDF; preview of included/withheld before writing | reports are not encrypted files |
| Local AI | **mock-tested only** | Ollama and OpenAI-compatible clients, case-scoped retrieval, verified citations, cloud consent flow | never answered a real prompt |
| MCP | **tested with a scripted client** | read tools, approval-gated writes, scoping | not run with a real MCP client |
| Plugins | **working now (example)** | two-phase protocol, review/enable/quarantine/upgrade/rollback | one example plugin only |
| Hardware layer | **simulated / replay only** | receive-only protocol, sessions, consent, interruptions | no physical device ever attached |

No hardware, WSL, Docker or network is required for anything marked working or import-only.
