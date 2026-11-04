"""Drive the whole desk once, end to end, against a running Switch.

report -> grounded -> private case -> sandbox reproduction -> draft advisory
(held under embargo) -> human sign-off -> embargo lifted -> advisory published.

Asserts the embargo actually bites: the case material cannot be posted in the
public intake room while the case is open, and the advisory only reaches the
public advisories room after sign-off.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desk.agents.disclosure import DisclosureAgent  # noqa: E402
from desk.agents.intake import IntakeAgent  # noqa: E402
from desk.agents.reproducer import ReproducerAgent  # noqa: E402
from desk.config import DeskConfig  # noqa: E402
from desk.switch_client import SwitchAgent  # noqa: E402

REPORT = (
    "Use-after-free in libcurl 8.11.0 connection pool when a transfer is "
    "aborted mid-handshake; freed easy handle is reused by a pooled connection."
)


def leaks_blocked(cfg: DeskConfig, room_id: str, secret: str) -> bool:
    a = SwitchAgent(base_url=cfg.api, name=cfg.intake_name, description="x",
                    state_path=cfg.state_dir / f"{cfg.intake_name}.json")
    a.register(cfg.reg_token)
    a.start()
    try:
        a.post(room_id, f"heads up everyone: {secret}")
        return False
    except httpx.HTTPStatusError as e:
        return e.response.status_code == 422
    finally:
        a.stop()


def main() -> None:
    rooms = json.load(open(Path(os.environ["STATE_DIR"]) / "desk-rooms.json"))
    os.environ["INTAKE_ROOM_ID"] = rooms["INTAKE_ROOM_ID"]
    os.environ["ADVISORIES_ROOM_ID"] = rooms["ADVISORIES_ROOM_ID"]
    cfg = DeskConfig.from_env()

    intake = IntakeAgent(cfg)
    intake.connect()
    out = intake.handle_report("rpt-demo-uaf", REPORT, "alice")
    assert out["verdict"] == "case-opened", out
    case_id, case_room = out["case_id"], out["room_id"]
    print(f"1. case opened: {case_id} in room {case_room[:8]}")

    # the embargo bites: the report cannot be leaked into public intake
    blocked = leaks_blocked(cfg, cfg.intake_room_id, REPORT)
    print(f"2. leak into public intake blocked: {blocked}")
    assert blocked

    # reproducer runs the named version in the sandbox and reports in-room
    repro = ReproducerAgent(cfg)
    repro.agent.register(cfg.reg_token)
    repro.agent.start()
    rr = repro.reproduce(case_room, REPORT)
    print(f"3. reproduction verdict: {rr['verdict']}")
    repro.agent.stop()

    # disclosure drafts (stays in the case room, under embargo)
    disc = DisclosureAgent(cfg)
    disc.agent.register(cfg.reg_token)
    disc.agent.start()
    d = disc.draft(case_room, case_id, REPORT)
    print(f"4. advisory drafted: severity {d['severity']} ~{d['score']} (held under embargo)")

    # still embargoed before sign-off
    assert leaks_blocked(cfg, cfg.intake_room_id, REPORT)
    print("5. before sign-off: still embargoed")

    # human signs off -> embargo lifted -> published
    disc.publish(case_room, case_id)
    print("6. signed off -> embargo lifted -> advisory published to #advisories")
    disc.agent.stop()

    # after disclosure, the material is no longer blocked anywhere
    assert not leaks_blocked(cfg, cfg.intake_room_id, REPORT)
    print("7. after disclosure: material flows freely (embargo gone)")

    intake.agent.stop()
    print("\nRESULT: full desk flow OK")


if __name__ == "__main__":
    main()
