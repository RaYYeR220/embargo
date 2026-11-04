"""The triage benchmark: grounded verification vs trusting the write-up.

Every figure the project reports about triage quality comes from this run, over
the public corpus (`corpus/manifest.json`). Two methods decide, for each report,
whether it is a real vulnerability, an invalid one, or something a human should
look at:

  * ``text``  — the status quo. It trusts the report: anything that reads like a
    vulnerability is treated as one. This is what a skim of the title does, and
    it is why slop costs time.
  * ``desk``  — Embargo's grounded check. It verifies the claimed version against
    curl's own advisory record before believing anything.

The corpus carries three kinds of item, each with a known truth:
  * real CVEs, claimed against a version actually in their affected range;
  * the same CVEs as a negative control — claimed against the version that
    fixed them, i.e. "the patched release is still vulnerable" (must be caught);
  * the maintainer's own list of reports that were submitted as vulnerabilities
    and were not, claimed against the latest release (must be caught).

Results are written to ``results/triage.json``; nothing is typed by hand.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desk.verifier import Claim, VulnIndex, classify_text, parse_version, verify  # noqa: E402

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "corpus" / "manifest.json"
OUT = ROOT / "results"
MINUTES_PER_REPORT = 30  # the curl maintainer's own figure for a human review


def build_items(index: VulnIndex) -> list[dict]:
    """Each item: {report_id, title, version, classes, truth, kind}."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    items: list[dict] = []
    for e in manifest["entries"]:
        if e["truth"] == "real" and e.get("affected"):
            ranges = e["affected"]["ranges"]
            if not ranges:
                continue
            intro = ranges[0].get("introduced")
            fixed = ranges[0].get("fixed")
            classes = sorted(set(classify_text(e["title"])) | _cwe_classes(e.get("cwe")))
            if intro:
                # a version genuinely inside the affected range
                items.append({
                    "report_id": e["id"], "title": e["title"], "version": intro,
                    "classes": classes, "truth": "real", "kind": "real-cve",
                })
            if fixed:
                # negative control: the version that FIXED it, claimed vulnerable
                items.append({
                    "report_id": f"{e['id']}-twin", "title": e["title"], "version": fixed,
                    "classes": classes, "truth": "invalid", "kind": "patched-twin",
                })
        elif e["truth"] in ("rejected", "duplicate"):
            classes = sorted(classify_text(e["title"]))
            items.append({
                "report_id": e["id"], "title": e["title"], "version": index.latest,
                "classes": classes, "truth": "invalid", "kind": "maintainer-slop",
            })
    return items


def _cwe_classes(cwe: str | None) -> set[str]:
    from desk.verifier import classify_cwe
    return classify_cwe(cwe)


def predict_text(item: dict) -> str:
    """Trust the write-up: if it reads like a vulnerability, call it real."""
    return "real" if item["classes"] else "needs_human"


def predict_desk(item: dict, index: VulnIndex) -> str:
    v = verify(
        Claim(item["report_id"], item["title"], item["version"], set(item["classes"])),
        index,
    )
    return v.verdict


def score(items: list[dict], predictions: list[str]) -> dict:
    tp = fp = fn = tn = escalated_real = escalated_invalid = 0
    auto_invalid_correct = 0
    for item, pred in zip(items, predictions):
        truth = item["truth"]
        if pred == "real" and truth == "real":
            tp += 1
        elif pred == "real" and truth == "invalid":
            fp += 1
        elif pred == "invalid" and truth == "invalid":
            tn += 1
            auto_invalid_correct += 1
        elif pred == "invalid" and truth == "real":
            fn += 1
        elif pred == "needs_human":
            if truth == "real":
                escalated_real += 1
            else:
                escalated_invalid += 1
    n = len(items)
    reals = sum(1 for i in items if i["truth"] == "real")
    invalids = n - reals
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / reals if reals else 0.0
    return {
        "n": n, "reals": reals, "invalids": invalids,
        "true_real": tp, "false_real": fp, "caught_invalid": tn, "missed_real": fn,
        "escalated_real": escalated_real, "escalated_invalid": escalated_invalid,
        "false_accept_rate": round(fp / invalids, 4) if invalids else 0.0,
        "recall_on_real": round(recall, 4),
        "precision_on_real": round(precision, 4),
        "auto_dispositioned_invalid": auto_invalid_correct,
        "maintainer_minutes_saved": auto_invalid_correct * MINUTES_PER_REPORT,
    }


def main() -> None:
    index = VulnIndex.load()
    items = build_items(index)
    text = score(items, [predict_text(i) for i in items])
    desk = score(items, [predict_desk(i, index) for i in items])
    result = {
        "corpus": str(MANIFEST.relative_to(ROOT.parent)),
        "latest_curl": index.latest,
        "minutes_per_report": MINUTES_PER_REPORT,
        "items": len(items),
        "by_kind": _kind_counts(items),
        "baseline_text": text,
        "desk_grounded": desk,
        "headline": {
            "false_accept_rate_text": text["false_accept_rate"],
            "false_accept_rate_desk": desk["false_accept_rate"],
            "recall_text": text["recall_on_real"],
            "recall_desk": desk["recall_on_real"],
            "minutes_saved_text": text["maintainer_minutes_saved"],
            "minutes_saved_desk": desk["maintainer_minutes_saved"],
        },
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "triage.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    h = result["headline"]
    print(f"items={len(items)}  latest_curl={index.latest}")
    print(f"  text  false-accept={h['false_accept_rate_text']:.0%}  recall={h['recall_text']:.0%}  minutes_saved={h['minutes_saved_text']}")
    print(f"  desk  false-accept={h['false_accept_rate_desk']:.0%}  recall={h['recall_desk']:.0%}  minutes_saved={h['minutes_saved_desk']}")
    print(f"-> {OUT / 'triage.json'}")


def _kind_counts(items: list[dict]) -> dict:
    out: dict[str, int] = {}
    for i in items:
        out[i["kind"]] = out.get(i["kind"], 0) + 1
    return out


if __name__ == "__main__":
    main()
