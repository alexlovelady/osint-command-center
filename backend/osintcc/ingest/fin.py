"""FININT importers (spec 21.1, 21.8 #6): SEC EDGAR submissions, public-chain transfers, licence-gated sanctions lists.

Rules encoded here: companies are identified by official IDs (CIK), never by name; a blockchain address is a
pseudonymous identifier, never a person; sanctions data may only be imported with a declared licence basis and is
matched by *name similarity only as a suggestion*, never merged.
"""
from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any

from .parsers import DETECTORS, PARSERS, EntityDraft, IngestError, Obs, ParsedIngest, RelDraft

MAX_FILINGS = 200
ALLOWED_LICENCE_BASES = {"public_domain", "noncommercial", "commercial_licence", "owner_provided"}


def edgar_filing_url(cik: str, accession: str, doc: str | None) -> str:
    acc = accession.replace("-", "")
    return f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{acc}/{doc}" if doc else \
        f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{acc}/"


def parse_edgar(data: bytes) -> ParsedIngest:
    try:
        d = json.loads(data)
    except ValueError as exc:
        raise IngestError("not valid JSON") from exc
    if not isinstance(d, dict) or "cik" not in d or "filings" not in d:
        raise IngestError("not an SEC EDGAR submissions document (needs cik and filings)")
    cik = str(d["cik"]).zfill(10)
    if not cik.isdigit() or len(cik) > 10:
        raise IngestError("invalid CIK")
    recent = (d.get("filings") or {}).get("recent") or {}
    acc, forms, dates, docs = (recent.get(k, []) for k in ("accessionNumber", "form", "filingDate", "primaryDocument"))
    if not (len(acc) == len(forms) == len(dates)):
        raise IngestError("inconsistent filings arrays")
    key = f"cik:{cik}"
    name = str(d.get("name", key))[:200]
    p = ParsedIngest("edgar", "FININT", {"cik": cik, "name": name, "filings": len(acc)}, mime="application/json",
                     access_class="PUBLIC")
    p.entities.append(EntityDraft("company", key, f"{name} ({key})"))
    filings = []
    for i in range(min(len(acc), MAX_FILINGS)):
        if not re.fullmatch(r"\d{10}-\d{2}-\d{6}", str(acc[i])):
            continue
        url = edgar_filing_url(cik, acc[i], docs[i] if i < len(docs) else None)
        filings.append({"accession": acc[i], "form": forms[i], "filed": dates[i], "url": url})
        p.entities.append(EntityDraft("filing", f"sec:{acc[i]}", f"{forms[i]} {dates[i]} ({acc[i]})"))
        p.relationships.append(RelDraft(("company", key), ("filing", f"sec:{acc[i]}"), "filed",
                                        f"listed in the SEC EDGAR submissions record for CIK {cik}; filing URL {url}"))
    profile = {"cik": cik, "name": name, "sic": d.get("sic"), "sic_description": d.get("sicDescription"),
               "state_of_incorporation": d.get("stateOfIncorporation"), "fiscal_year_end": d.get("fiscalYearEnd"),
               "tickers": d.get("tickers", []), "exchanges": d.get("exchanges", []), "former_names": d.get("formerNames", []),
               "filings_listed": len(filings), "filings": filings,
               "identity_note": "Matched by CIK, an official identifier. Companies with similar names are different entities."}
    p.observations.append(Obs("FININT", "fin.company_profile", profile, confidence="high"))
    if len(acc) > MAX_FILINGS:
        p.warnings.append(f"Only the {MAX_FILINGS} most recent of {len(acc)} filings were recorded.")
    return p


def parse_chain_csv(data: bytes) -> ParsedIngest:
    """txid,time,from,to,amount[,asset]. Public-chain explorer export supplied by the analyst."""
    rd = csv.DictReader(io.StringIO(data.decode("utf-8-sig", "replace")))
    if not rd.fieldnames or not {"txid", "from", "to", "amount"} <= {f.strip().lower() for f in rd.fieldnames}:
        raise IngestError("CSV needs txid, from, to and amount columns")
    c = {f.strip().lower(): f for f in rd.fieldnames}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    txs = 0
    for i, row in enumerate(rd):
        if i >= 100_000:
            raise IngestError("more than 100000 transfers; split the file")
        a, b = row[c["from"]].strip(), row[c["to"]].strip()
        try:
            amt = float(row[c["amount"]])
        except (ValueError, TypeError) as exc:
            raise IngestError(f"row {i + 2}: invalid amount") from exc
        if not re.fullmatch(r"[A-Za-z0-9:_\-.]{10,128}", a) or not re.fullmatch(r"[A-Za-z0-9:_\-.]{10,128}", b):
            raise IngestError(f"row {i + 2}: address format not recognised")
        if amt < 0:
            raise IngestError(f"row {i + 2}: negative amount")
        e = edges.setdefault((a, b), {"from": a, "to": b, "transfers": 0, "total": 0.0, "asset": row.get(c.get("asset", ""), "") or "unspecified"})
        e["transfers"] += 1
        e["total"] += amt
        txs += 1
    if not txs:
        raise IngestError("no transfers")
    top = sorted(edges.values(), key=lambda e: -e["total"])[:500]
    p = ParsedIngest("chain_csv", "FININT", {"transfers": txs, "address_pairs": len(edges)}, mime="text/csv",
                     access_class="IMPORTED")
    seen = set()
    for e in top[:300]:
        for addr in (e["from"], e["to"]):
            if addr not in seen:
                seen.add(addr)
                p.entities.append(EntityDraft("crypto_address", addr, addr))
        p.relationships.append(RelDraft(("crypto_address", e["from"]), ("crypto_address", e["to"]), "transferred_to",
                                        f"{e['transfers']} transfer(s), total {e['total']:g} {e['asset']} in the supplied export"))
    p.observations.append(Obs("FININT", "fin.chain_transfers", {"pairs": top, "transfers": txs,
                                                              "note": "addresses are pseudonymous identifiers; a shared or "
                                                                      "linked address does not identify a person"},
                              confidence="medium"))
    p.warnings.append("Addresses are not attributed to individuals; clustering heuristics are not applied.")
    return p


def normalise_name(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"\b(inc|ltd|llc|llp|plc|corp|co|gmbh|sa|ag|the)\b\.?", " ", re.sub(r"[^a-z0-9 ]+", " ", s))
    return re.sub(r"\s+", " ", s).strip()


def parse_sanctions_csv(data: bytes) -> ParsedIngest:
    """id,name[,aliases(;-separated),country,list_name,program]. Call only after the licence gate in the route."""
    rd = csv.DictReader(io.StringIO(data.decode("utf-8-sig", "replace")))
    if not rd.fieldnames or not {"id", "name"} <= {f.strip().lower() for f in rd.fieldnames}:
        raise IngestError("CSV needs id and name columns")
    c = {f.strip().lower(): f for f in rd.fieldnames}
    p = ParsedIngest("sanctions_csv", "FININT", {}, mime="text/csv", access_class="IMPORTED")
    n = 0
    for i, row in enumerate(rd):
        if i >= 20_000:
            raise IngestError("more than 20000 entries; split the file")
        sid, nm = row[c["id"]].strip()[:80], row[c["name"]].strip()[:200]
        if not sid or not nm:
            continue
        aliases = [a.strip() for a in (row.get(c.get("aliases", ""), "") or "").split(";") if a.strip()][:20]
        p.entities.append(EntityDraft("sanctions_entry", f"{(row.get(c.get('list_name', ''), '') or 'list').strip()}:{sid}", nm))
        p.observations.append(Obs("FININT", "fin.sanctions_entry", {
            "id": sid, "name": nm, "aliases": aliases, "country": row.get(c.get("country", ""), ""),
            "list": row.get(c.get("list_name", ""), ""), "program": row.get(c.get("program", ""), ""),
            "match_note": "list entries are suggestions for review; a name match is never an identity match"},
            confidence="unknown"))
        n += 1
    if not n:
        raise IngestError("no usable entries")
    p.summary = {"entries": n}
    return p


def _detect(name: str, head: bytes) -> str | None:
    if name.endswith(".submissions.json") or (name.endswith(".json") and b'"filings"' in head and b'"cik"' in head):
        return "edgar"
    if name.endswith(".chain.csv"):
        return "chain_csv"
    return None


def check_licence(basis: str | None, licensor: str | None) -> str | None:
    """Returns an error message when the sanctions import must be blocked."""
    if basis not in ALLOWED_LICENCE_BASES:
        return ("sanctions data requires a declared licence basis (public_domain, noncommercial, commercial_licence, "
                "owner_provided); free code does not confer data rights")
    if not licensor or len(licensor.strip()) < 2:
        return "name the licensor/source of this dataset"
    return None


PARSERS["edgar"] = parse_edgar
PARSERS["chain_csv"] = parse_chain_csv
PARSERS["sanctions_csv"] = parse_sanctions_csv
DETECTORS.append(_detect)
_ = datetime, UTC
