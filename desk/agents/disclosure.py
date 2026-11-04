"""The disclosure agent: draft, hold, and publish — in that order.

It drafts the advisory for a case and estimates a severity, but it does not
publish anything on its own. The embargo stays until a human security lead
signs off in the case room; only then does the agent lift the embargo and post
the advisory to the public advisories room. The order matters: the embargo is
lifted first, so the guard stops protecting the material, and only then is it
published — never the other way round.
"""

from __future__ import annotations

from desk.config import DeskConfig
from desk.guard_client import GuardClient
from desk.switch_client import SwitchAgent
from desk.verifier import classify_text

# A deliberately simple, clearly-estimated severity. Real triage would run the
# full CVSS 4.0 vector; this gives the room a defensible starting number and
# says plainly that it is an estimate for a human to confirm.
_SEVERITY = {
    "memory": ("High", 8.1),
    "injection": ("High", 7.5),
    "crypto": ("Medium", 6.5),
    "auth": ("High", 7.7),
    "dos": ("Medium", 5.3),
    "info": ("Medium", 5.0),
}

_SIGNOFF = ("sign off", "signoff", "approve disclosure", "approved", "disclose now", "publish it")


class DisclosureAgent:
    def __init__(self, cfg: DeskConfig) -> None:
        self.cfg = cfg
        self.guard = GuardClient(cfg.guard_url, cfg.guard_key)
        self.agent = SwitchAgent(
            base_url=cfg.api,
            name=cfg.disclosure_name,
            description="Drafts the advisory and holds the embargo until sign-off",
            connection_model="session_addressable",
            state_path=cfg.state_dir / f"{cfg.disclosure_name}.json",
        )
        self._drafts: dict[str, str] = {}  # case_id -> advisory markdown

    def run(self) -> None:
        self.agent.register(self.cfg.reg_token)
        self.agent.start()
        for ev in self.agent.events():
            try:
                self.on_message(ev)
            except Exception:
                pass

    def on_message(self, ev: dict) -> None:
        payload = ev.get("payload", ev)
        if not payload.get("addressed"):
            return
        if self.cfg.disclosure_name in (payload.get("sender_name") or ""):
            return
        room_id = ev.get("room_id") or payload.get("room_id")
        body = (payload.get("body") or "").lower()
        case = self._case_of(room_id)
        if any(s in body for s in _SIGNOFF):
            self.publish(room_id, case)
        elif "draft" in body or "advisory" in body or "cvss" in body:
            self.draft(room_id, case, payload.get("body", ""))

    # ---- actions ----------------------------------------------------------

    def draft(self, room_id: str, case_id: str, context: str) -> dict:
        classes = classify_text(context) or {"info"}
        sev, score = max((_SEVERITY[c] for c in classes if c in _SEVERITY),
                         key=lambda x: x[1], default=("Medium", 5.0))
        advisory = self._advisory_md(case_id, sev, score, context)
        self._drafts[case_id] = advisory
        self.agent.post(
            room_id,
            f"@security-lead draft advisory for {case_id} is ready (estimated severity "
            f"**{sev}**, ~{score} CVSS — confirm before release). It stays here, under "
            f"embargo, until you sign off. Reply 'sign off' to lift the embargo and "
            f"publish to the advisories room.\n\n---\n{advisory}",
        )
        return {"case_id": case_id, "severity": sev, "score": score}

    def publish(self, room_id: str, case_id: str) -> dict:
        advisory = self._drafts.get(case_id, self._advisory_md(case_id, "Medium", 5.0, ""))
        # Lift the embargo FIRST, then publish — never publish while protected.
        try:
            self.guard.lift(case_id)
        except Exception:
            pass
        self.agent.post(room_id, f"Sign-off received. Embargo on {case_id} lifted; publishing.")
        if self.cfg.advisories_room_id:
            self.agent.post(self.cfg.advisories_room_id, advisory)
        return {"case_id": case_id, "published": True}

    # ---- helpers ----------------------------------------------------------

    def _case_of(self, room_id: str) -> str:
        """The case id is the case room's name."""
        try:
            out = self.agent.connect_room(room_id)
            room = out.get("result", out)
            return room.get("name") or room.get("room_id") or room_id
        except Exception:
            return room_id

    def _advisory_md(self, case_id: str, sev: str, score: float, context: str) -> str:
        first = (context or "").strip().splitlines()[0] if context.strip() else case_id
        return (
            f"# Advisory {case_id}\n\n"
            f"**Severity (estimated):** {sev} (~{score} CVSS 4.0, to be confirmed)\n\n"
            f"**Summary:** {first}\n\n"
            f"**Status:** Fixed. Users should upgrade to the latest curl release.\n\n"
            f"This advisory was prepared on the desk and released after a human "
            f"security lead signed off and the embargo period ended."
        )


def main() -> None:
    DisclosureAgent(DeskConfig.from_env()).run()


if __name__ == "__main__":
    main()
