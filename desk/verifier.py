"""Grounded verification of a curl vulnerability claim.

The desk does not decide whether a report is real by reading its prose. It
grounds the claim against curl's own authoritative advisory data: a report that
says "version V is vulnerable to a <class> bug" is only credible if curl's
published record actually has a matching flaw whose affected range includes V.

This module is pure and offline. It loads curl's OSV feed once and answers two
questions a triager would otherwise answer by hand and by trust:

  * ground_claim(version, bug_class) -> does a known curl advisory match this
    version and bug class? Returns the matching advisory, or None.
  * verify(claim) -> a verdict (real / invalid / needs_human) with the evidence
    that produced it.

A real memory-safety advisory reproduced in a sandbox is the strongest form of
grounding; this module is the fast, deterministic first pass that stops the
guesswork before any build is attempted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

CORPUS = Path(__file__).resolve().parents[1] / "bench" / "corpus"
VULN = CORPUS / "curl-vuln.json"


# ---- versions --------------------------------------------------------------

def parse_version(v: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) or (0,)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    a = a + (0,) * (3 - len(a))
    b = b + (0,) * (3 - len(b))
    return (a > b) - (a < b)


def version_in_ranges(version: str, ranges: list[dict]) -> bool:
    """True if `version` falls in any [introduced, fixed) interval."""
    v = parse_version(version)
    for r in ranges:
        intro = parse_version(r.get("introduced", "0")) if r.get("introduced") else (0,)
        if _cmp(v, intro) < 0:
            continue
        if r.get("fixed"):
            if _cmp(v, parse_version(r["fixed"])) < 0:
                return True
        else:
            return True
    return False


# ---- bug-class normalisation ----------------------------------------------

# Map the words reporters and CWEs use to a small set of comparable classes.
_CLASS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("memory", re.compile(r"overflow|out[- ]?of[- ]?bounds|oob|use[- ]after[- ]free|uaf|double[- ]free|buffer|memory|heap|stack", re.I)),
    ("injection", re.compile(r"injection|smuggl|crlf|traversal|path.*traversal", re.I)),
    ("crypto", re.compile(r"crypto|cipher|tls|certificate|cert|keylog", re.I)),
    ("auth", re.compile(r"auth|credential|password|bypass|session", re.I)),
    ("dos", re.compile(r"denial|dos|exhaust|leak|flood|resource", re.I)),
    ("info", re.compile(r"disclos|exposure|leak|sensitive|info", re.I)),
]

_CWE_CLASS = {
    "memory": {"CWE-122", "CWE-787", "CWE-125", "CWE-416", "CWE-415", "CWE-120", "CWE-119", "CWE-121", "CWE-190"},
    "injection": {"CWE-74", "CWE-88", "CWE-93", "CWE-22", "CWE-113"},
    "crypto": {"CWE-327", "CWE-295", "CWE-311"},
    "auth": {"CWE-287", "CWE-288", "CWE-306", "CWE-384", "CWE-488"},
    "dos": {"CWE-400", "CWE-770", "CWE-404"},
    "info": {"CWE-200", "CWE-201", "CWE-532", "CWE-321"},
}


def classify_text(text: str) -> set[str]:
    return {name for name, pat in _CLASS_PATTERNS if pat.search(text or "")}


# Words too generic to identify a specific flaw by.
_STOP = {
    "curl", "libcurl", "vulnerability", "security", "report", "function",
    "handling", "via", "the", "and", "with", "under", "using", "when",
    "leads", "leading", "risk", "code", "issue", "bug", "exploit", "cve",
}


def significant_tokens(text: str) -> set[str]:
    """Content words that help tell one flaw from another."""
    return {
        t for t in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{3,}", (text or "").lower())
        if t not in _STOP
    }


def classify_cwe(cwe: str | None) -> set[str]:
    if not cwe:
        return set()
    return {cls for cls, ids in _CWE_CLASS.items() if cwe in ids}


# ---- the advisory index ----------------------------------------------------

@dataclass
class Advisory:
    cve: str
    title: str
    cwe: str | None
    ranges: list[dict]
    classes: set[str]


class VulnIndex:
    def __init__(self, advisories: list[Advisory], latest: str) -> None:
        self.advisories = advisories
        self.latest = latest

    @classmethod
    def load(cls, path: Path = VULN) -> "VulnIndex":
        data = json.loads(path.read_text(encoding="utf-8"))
        advisories: list[Advisory] = []
        max_v = (0,)
        for e in data:
            ds = e.get("database_specific", {})
            cwe = (ds.get("CWE") or {}).get("id")
            ranges: list[dict] = []
            for aff in e.get("affected", []):
                for rng in aff.get("ranges", []):
                    # Only semantic-version ranges are comparable; curl's feed
                    # also carries GIT ranges whose bounds are commit hashes.
                    if rng.get("type") != "SEMVER":
                        continue
                    cur: dict = {}
                    for ev in rng.get("events", []):
                        if "introduced" in ev:
                            if cur:
                                ranges.append(cur)
                            cur = {"introduced": ev["introduced"]}
                        elif "fixed" in ev:
                            cur["fixed"] = ev["fixed"]
                            if parse_version(ev["fixed"]) > max_v:
                                max_v = parse_version(ev["fixed"])
                    if cur:
                        ranges.append(cur)
            title = e.get("summary") or ""
            classes = classify_text(title) | classify_cwe(cwe)
            advisories.append(
                Advisory((e.get("aliases") or [e["id"]])[0], title, cwe, ranges, classes)
            )
        latest = ".".join(str(n) for n in max_v)
        return cls(advisories, latest)

    def ground(
        self, version: str, classes: set[str], topic: set[str] | None = None
    ) -> Advisory | None:
        """A known advisory that matches the claim: its affected range includes
        `version`, its bug class overlaps `classes`, and — when `topic` tokens
        are given — its summary shares enough of them that this is plausibly the
        same flaw, not merely another bug of the same broad class in the same
        old version. None means the claim is not grounded."""
        for adv in self.advisories:
            if classes and not (adv.classes & classes):
                continue
            if topic:
                if len(topic & significant_tokens(adv.title)) < 2:
                    continue
            if version_in_ranges(version, adv.ranges):
                return adv
        return None


# ---- the verdict -----------------------------------------------------------

@dataclass
class Claim:
    report_id: str
    title: str
    version: str          # the curl version the report says is affected
    bug_class: set[str]   # normalised classes parsed from the report


@dataclass
class Verdict:
    report_id: str
    verdict: str          # "real" | "invalid" | "needs_human"
    grounded_cve: str | None
    reason: str


def verify(claim: Claim, index: VulnIndex) -> Verdict:
    adv = index.ground(claim.version, claim.bug_class, significant_tokens(claim.title))
    if adv is not None:
        return Verdict(
            claim.report_id,
            "real",
            adv.cve,
            f"{claim.version} is within the affected range of {adv.cve} "
            f"({adv.cwe or 'n/a'}); the claim is grounded.",
        )
    # Not grounded. If the claimed version is at or past the newest fixed
    # release and the bug class has a near-miss advisory already fixed there,
    # this is the classic "latest is still vulnerable" claim about patched code.
    if _cmp(parse_version(claim.version), parse_version(index.latest)) >= 0:
        return Verdict(
            claim.report_id,
            "invalid",
            None,
            f"No advisory covers {claim.version} for this bug class; "
            f"{claim.version} is at or past the newest fixed release "
            f"({index.latest}). A claim that patched code is still vulnerable.",
        )
    return Verdict(
        claim.report_id,
        "needs_human",
        None,
        "No matching advisory and the version predates the newest release; "
        "a human should look rather than auto-dispositioning.",
    )
