"""Stand the desk up on a running Switch deployment.

Registers the desk's agents and creates the two standing rooms — the public
intake room and the advisories room — with the right agents and roles in each.
Prints the room ids to put in the environment for the agent processes.

This is the scripted equivalent of running the Switch template; the template
(desk/templates/embargo-desk.template.yaml) is what a reviewer runs by hand.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desk.switch_client import SwitchAgent  # noqa: E402

API = os.environ["SWITCH_API"]
GATEWAY = f"{API}/gateway"
REG = os.environ["REG_TOKEN"]
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@switch.local")
ADMIN_PW = os.environ["ADMIN_PW"]
BRIDGE_ID = os.environ["BRIDGE_ID"]
STATE = Path(os.environ.get("STATE_DIR", "work"))
STATE.mkdir(parents=True, exist_ok=True)

AGENTS = {
    "embargo-intake": "Grounds incoming vulnerability reports and opens cases",
    "embargo-disclosure": "Drafts the advisory and holds the embargo timer",
    "embargo-reproducer": "Reproduces a claim against the named version in a sandbox",
    "embargo-fixer": "Prepares a fix and a regression test for an accepted case",
}


def gw() -> httpx.Client:
    c = httpx.Client(timeout=30)
    c.post(f"{GATEWAY}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PW}).raise_for_status()
    return c


def register_all() -> dict[str, str]:
    ids = {}
    for name, desc in AGENTS.items():
        a = SwitchAgent(base_url=API, name=name, description=desc, state_path=STATE / f"{name}.json")
        ids[name] = a.register(REG, overwrite=True)
        print(f"registered {name}: {ids[name]}")
    return ids


def make_room(c: httpx.Client, **body) -> dict:
    r = c.post(f"{GATEWAY}/rooms", json=body)
    r.raise_for_status()
    return r.json()


def main() -> None:
    register_all()
    c = gw()
    intake = make_room(
        c,
        name="security-intake",
        description="Report a vulnerability in curl here. Grounded on arrival.",
        bridge_id=BRIDGE_ID,
        channel_type="channel_public",
        agent_names=["embargo-intake"],
    )
    advisories = make_room(
        c,
        name="advisories",
        description="Published advisories. Nothing lands here before sign-off and embargo end.",
        bridge_id=BRIDGE_ID,
        channel_type="channel_public",
        agent_names=["embargo-disclosure"],
    )
    env = {
        "INTAKE_ROOM_ID": intake["id"],
        "ADVISORIES_ROOM_ID": advisories["id"],
    }
    (STATE / "desk-rooms.json").write_text(json.dumps(env, indent=2))
    print(json.dumps(env, indent=2))
    print(f"-> {STATE / 'desk-rooms.json'}")


if __name__ == "__main__":
    main()
