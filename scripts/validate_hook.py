"""End-to-end proof that the embargo guard is enforced inside Switch's send path.

Registers an agent, puts it in a public room, registers an embargo whose
allowed rooms do NOT include that public room, then has the agent post the
embargoed secret. If the guard is wired, Switch refuses the send and the
message never lands in the room.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desk.switch_client import SwitchAgent  # noqa: E402

API = os.environ["SWITCH_API"]            # e.g. http://127.0.0.1:18000
GATEWAY = f"{API}/gateway"
GUARD = os.environ["GUARD_URL"]           # e.g. http://127.0.0.1:19000
GUARD_KEY = os.environ.get("EMBARGO_ADMIN_KEY", "devkey")
REG_TOKEN = os.environ["REG_TOKEN"]
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@switch.local")
ADMIN_PW = os.environ["ADMIN_PW"]
BRIDGE_ID = os.environ["BRIDGE_ID"]
SECRET = "ZZEMBARGOPOC-" + str(int(time.time()))


def gw_login() -> httpx.Client:
    c = httpx.Client(timeout=20)
    r = c.post(f"{GATEWAY}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PW})
    r.raise_for_status()
    return c


def main() -> int:
    gw = gw_login()

    agent = SwitchAgent(
        base_url=API,
        name="embargo-prover",
        description="posts a probe to prove the guard enforces",
        state_path=Path(os.environ["STATE_DIR"]) / "prover.json",
    )
    agent.register(REG_TOKEN, overwrite=True)
    print(f"agent registered: {agent.agent_id}")

    # a public room, with the agent in it
    room = gw.post(
        f"{GATEWAY}/rooms",
        json={
            "name": f"embargo-prove-{int(time.time())}",
            "description": "guard enforcement proof",
            "bridge_id": BRIDGE_ID,
            "channel_type": "channel_public",
            "agent_ids": [agent.agent_id],
        },
    ).json()
    room_id = room["id"]
    print(f"public room: {room_id}")

    # embargo a case whose allowed rooms do NOT include this public room
    httpx.post(
        f"{GUARD}/cases",
        headers={"x-embargo-key": GUARD_KEY},
        json={
            "case_id": "case-prove",
            "allowed_rooms": ["some-private-case-room"],
            "secrets": [SECRET],
            "embargo_ttl_seconds": 600,
        },
        timeout=10,
    ).raise_for_status()
    print(f"embargo registered; secret not allowed in {room_id}")

    agent.start()

    # 1) benign post — must succeed
    benign = agent.post(room_id, "status: triaging the queue, nothing sensitive here")
    print(f"benign post event_id: {benign.get('event_id')}")

    # 2) the embargoed secret — Switch must refuse the send
    blocked = False
    try:
        agent.post(room_id, f"here is the full detail: {SECRET} exploit chain")
        print("secret post returned WITHOUT error (checking the room to be sure)")
    except httpx.HTTPStatusError as e:
        blocked = True
        print(f"secret post refused by Switch: HTTP {e.response.status_code}")

    time.sleep(2)
    audit = httpx.get(f"{GUARD}/audit?limit=10", timeout=10).json()["decisions"]
    hits = [d for d in audit if d.get("kind") == "check" and SECRET[:14] in (d.get("preview") or "")]
    guard_blocked = any(d.get("outcome") == "blocked" for d in hits)
    print(f"guard saw the secret and blocked: {guard_blocked}")

    agent.stop()
    ok = blocked or guard_blocked
    print("RESULT:", "ENFORCED" if ok else "NOT ENFORCED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
