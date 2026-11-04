"""Desk configuration, from the environment.

One place that reads the handful of values the agents need, so a deployment is
configured by env vars and nothing is hard-coded in an agent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DeskConfig:
    api: str
    reg_token: str
    intake_room_id: str
    guard_url: str
    guard_key: str
    advisories_room_id: str = ""
    state_dir: Path = Path("work")
    intake_name: str = "embargo-intake"
    disclosure_name: str = "embargo-disclosure"
    reproducer_name: str = "embargo-reproducer"
    fixer_name: str = "embargo-fixer"

    @classmethod
    def from_env(cls) -> "DeskConfig":
        state_dir = Path(os.environ.get("STATE_DIR", "work"))
        state_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            api=os.environ["SWITCH_API"],
            reg_token=os.environ["REG_TOKEN"],
            intake_room_id=os.environ.get("INTAKE_ROOM_ID", ""),
            guard_url=os.environ.get("GUARD_URL", "http://127.0.0.1:19000"),
            guard_key=os.environ.get("EMBARGO_ADMIN_KEY", ""),
            advisories_room_id=os.environ.get("ADVISORIES_ROOM_ID", ""),
            state_dir=state_dir,
            intake_name=os.environ.get("INTAKE_NAME", "embargo-intake"),
            disclosure_name=os.environ.get("DISCLOSURE_NAME", "embargo-disclosure"),
            reproducer_name=os.environ.get("REPRODUCER_NAME", "embargo-reproducer"),
            fixer_name=os.environ.get("FIXER_NAME", "embargo-fixer"),
        )
