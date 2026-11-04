"""Offline tests for the desk's logic. No Switch required.

Run: python -m pytest -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from desk.reports import extract_version, parse_report  # noqa: E402
from desk.verifier import (  # noqa: E402
    Claim,
    VulnIndex,
    classify_text,
    significant_tokens,
    verify,
    version_in_ranges,
)
from guard.app import Case, Registry, decide  # noqa: E402


# ---- verifier --------------------------------------------------------------

def test_version_in_ranges():
    ranges = [{"introduced": "8.9.0", "fixed": "8.14.3"}]
    assert version_in_ranges("8.10.0", ranges)
    assert not version_in_ranges("8.14.3", ranges)   # fixed is exclusive
    assert not version_in_ranges("8.8.0", ranges)    # before introduced


def test_classify_and_tokens():
    assert "memory" in classify_text("heap buffer overflow in parser")
    assert "websocket" in significant_tokens("Use-after-free in libcurl websocket handling")
    assert "curl" not in significant_tokens("curl vulnerability report")  # stopword


def test_grounding_real_and_patched_twin():
    index = VulnIndex.load()
    adv = index.advisories[0]
    if adv.ranges and adv.ranges[0].get("introduced") and adv.ranges[0].get("fixed"):
        intro = adv.ranges[0]["introduced"]
        fixed = adv.ranges[0]["fixed"]
        topic = significant_tokens(adv.title)
        # a version inside the range, same flaw -> grounds -> real
        v_real = verify(Claim("r", adv.title, intro, adv.classes), index)
        assert v_real.verdict == "real"
        # the version that FIXED it, claimed vulnerable -> not that flaw -> not real
        v_twin = verify(Claim("r", adv.title, fixed, adv.classes), index)
        assert v_twin.verdict != "real"


def test_slop_latest_version_is_not_grounded():
    index = VulnIndex.load()
    claim = Claim(
        "slop",
        f"Critical buffer overflow in libcurl {index.latest} leading to RCE",
        index.latest,
        {"memory"},
    )
    assert verify(claim, index).verdict == "invalid"


# ---- reports ---------------------------------------------------------------

def test_extract_version():
    assert extract_version("affects curl 8.11.0 badly", "9.9.9") == "8.11.0"
    assert extract_version("libcurl/8.5.0 crash", "9.9.9") == "8.5.0"
    assert extract_version("no version mentioned at all", "8.23.0") == "8.23.0"


def test_parse_report_shape():
    r = parse_report("id1", "Use-after-free in libcurl 8.11.0 websocket handling", "8.23.0")
    assert r["version"] == "8.11.0"
    assert "memory" in r["classes"]
    assert r["case_id"].startswith("case-")


# ---- guard policy ----------------------------------------------------------

def _registry_with(case: Case) -> None:
    import guard.app as g

    g.REGISTRY = Registry()
    g.REGISTRY.put(case)


def test_guard_blocks_leak_outside_case_room():
    _registry_with(Case("case-x", {"room-case"}, ["SECRETPOC"], None))
    inside = decide("room-case", "patch for SECRETPOC ready")
    outside = decide("room-public", "hey everyone, SECRETPOC is the bug")
    neutral = decide("room-public", "what's for lunch")
    assert inside.outcome == "ok"
    assert outside.outcome == "blocked"
    assert "SECRETPOC" not in (outside.redacted_content or "")
    assert neutral.outcome == "ok"


def test_guard_ignores_expired_embargo():
    _registry_with(Case("case-x", {"room-case"}, ["SECRETPOC"], embargo_until=0.0))
    assert decide("room-public", "SECRETPOC leaks").outcome == "ok"  # expired = no embargo
