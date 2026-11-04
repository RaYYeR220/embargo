"""Build the ground-truth corpus for the Embargo triage benchmark.

Two authoritative, public sources, no hand-labelling and no guessing:

  * curl's own OSV feed (``curl-vuln.json``) — every confirmed curl CVE, with
    its affected version ranges, fixed-in version, CWE and the HackerOne
    report that produced it. These are the ``real`` cases.
  * the curl maintainer's own published list of reports that were submitted as
    security vulnerabilities and were not (``slop-gist.md``). These are the
    ``rejected`` cases — the maintainer's disposition is the ground truth.

The manifest stores report identifiers, the public CVE metadata and our label.
It never stores the body a third party wrote; the benchmark fetches that at run
time into an untracked cache.

Usage:
    python bench/build_corpus.py            # from the repo root
"""

from __future__ import annotations

import json
import re
from pathlib import Path

CORPUS = Path(__file__.replace("build_corpus.py", "corpus"))
VULN = CORPUS / "curl-vuln.json"
SLOP = CORPUS / "slop-gist.md"
OUT = CORPUS / "manifest.json"

# Only CVEs published this recently are kept: the benchmark wants reports from
# the window where AI-assisted submissions dominate, and recent curl releases
# are the ones a sandbox can install and probe.
MIN_YEAR = 2024


def _affected(entry: dict) -> dict:
    """Flatten an OSV entry's version ranges to a compact introduced/fixed list."""
    pairs: list[dict] = []
    for aff in entry.get("affected", []):
        for rng in aff.get("ranges", []):
            cur: dict = {}
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    if cur:
                        pairs.append(cur)
                    cur = {"introduced": ev["introduced"]}
                elif "fixed" in ev:
                    cur["fixed"] = ev["fixed"]
            if cur:
                pairs.append(cur)
    return {"ranges": pairs}


def build_real() -> list[dict]:
    data = json.loads(VULN.read_text(encoding="utf-8"))
    out = []
    for e in data:
        ds = e.get("database_specific", {})
        issue = ds.get("issue", "") or ""
        m = re.search(r"reports/(\d+)", issue)
        year = int((e.get("published") or "0")[:4] or 0)
        if year < MIN_YEAR:
            continue
        cve = (e.get("aliases") or [e.get("id")])[0]
        cwe = ds.get("CWE") or {}
        aff = _affected(e)
        fixed = sorted({r["fixed"] for r in aff["ranges"] if r.get("fixed")})
        out.append(
            {
                "id": m.group(1) if m else None,
                "url": issue or ds.get("www"),
                "title": e.get("summary"),
                "truth": "real",
                "cve": cve,
                "affected": aff,
                "fixed_in": fixed,
                "last_affected": ds.get("last_affected"),
                "cwe": cwe.get("id"),
                "cwe_desc": cwe.get("desc"),
                "severity": ds.get("severity"),
                "disposition": "Resolved",
                "why": "Confirmed curl CVE; the maintainer's OSV feed names this report as its origin.",
            }
        )
    return out


def build_rejected() -> list[dict]:
    text = SLOP.read_text(encoding="utf-8")
    out = []
    # Each list line: "N. <title> [#<id>](https://hackerone.com/reports/<id>)"
    row = re.compile(r"^\s*\d+\.\s+(.*?)\s*\[#(\d+)\]\((https://hackerone\.com/reports/\d+)\)")
    for line in text.splitlines():
        m = row.match(line)
        if not m:
            continue
        title, rid, url = m.group(1), m.group(2), m.group(3)
        out.append(
            {
                "id": rid,
                "url": url,
                "title": title.strip(),
                "truth": "rejected",
                "cve": None,
                "affected": None,
                "fixed_in": None,
                "last_affected": None,
                "cwe": None,
                "cwe_desc": None,
                "severity": None,
                "disposition": "Not Applicable / Informative / Spam",
                "why": "Listed by the curl maintainer as a report submitted as a security "
                "vulnerability that was not one.",
            }
        )
    return out


def main() -> None:
    real = build_real()
    rejected = build_rejected()
    # De-dup: a report id can only mean one thing. If a slop id somehow also
    # appears as a CVE origin, the CVE feed wins and we drop it from slop.
    real_ids = {e["id"] for e in real if e["id"]}
    rejected = [e for e in rejected if e["id"] not in real_ids]
    entries = real + rejected
    manifest = {
        "source": {
            "real": "https://curl.se/docs/vuln.json",
            "rejected": "https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd",
        },
        "min_year": MIN_YEAR,
        "counts": {
            "real": len(real),
            "rejected": len(rejected),
            "total": len(entries),
        },
        "entries": entries,
    }
    OUT.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"real={len(real)} rejected={len(rejected)} total={len(entries)} -> {OUT}")


if __name__ == "__main__":
    main()
