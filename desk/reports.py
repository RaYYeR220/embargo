"""Turn a free-text vulnerability report into a structured claim.

A report that lands in the intake room is prose a person or a tool wrote. The
desk pulls from it the two things the grounded check needs — the curl version
said to be affected, and the class of bug claimed — plus a stable case id.
"""

from __future__ import annotations

import hashlib
import re

from desk.verifier import classify_text

_VERSION = re.compile(r"\b(?:curl|libcurl)[\s/]*v?(\d+\.\d+(?:\.\d+)?)\b", re.I)
_BARE_VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+)\b")


def extract_version(text: str, default_latest: str) -> str:
    """The curl version the report says is affected. Falls back to 'latest'
    when the report names none — the common shape of a drive-by report."""
    m = _VERSION.search(text or "")
    if m:
        return m.group(1)
    m = _BARE_VERSION.search(text or "")
    if m:
        return m.group(1)
    return default_latest


def case_id_for(report_id: str) -> str:
    h = hashlib.sha256(report_id.encode()).hexdigest()[:6]
    return f"case-{h}"


def title_of(text: str, limit: int = 90) -> str:
    first = (text or "").strip().splitlines()[0] if text.strip() else ""
    return first[:limit]


def parse_report(report_id: str, text: str, latest: str) -> dict:
    return {
        "report_id": report_id,
        "case_id": case_id_for(report_id),
        "title": title_of(text),
        "version": extract_version(text, latest),
        "classes": sorted(classify_text(text)),
        "text": text,
    }
