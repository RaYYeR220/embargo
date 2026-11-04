"""The intake agent: the desk's front door.

It sits in the public intake room. When a report is addressed to it, it does
in seconds what a maintainer would otherwise do by hand: grounds the claim
against curl's advisory record, turns away what does not stand up with the
reason it failed, links a duplicate to the case it repeats, and for anything
that might be real opens a private case room — pulling in the reproducer, the
disclosure agent, a human security lead and the reporter — and registers the
embargo that keeps the case inside those rooms.

Run it:
    python -m desk.agents.intake
with SWITCH_API, REG_TOKEN, INTAKE_ROOM_ID, GUARD_URL, EMBARGO_ADMIN_KEY set
(see desk/config.py).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from desk.config import DeskConfig
from desk.guard_client import GuardClient
from desk.reports import parse_report, title_of
from desk.switch_client import SwitchAgent
from desk.verifier import Claim, VulnIndex, significant_tokens, verify

EMBARGO_TTL = 14 * 24 * 3600  # a fortnight, the usual coordinated-disclosure window


@dataclass
class OpenCase:
    case_id: str
    room_id: str
    title: str
    tokens: set[str]


class IntakeAgent:
    def __init__(self, cfg: DeskConfig) -> None:
        self.cfg = cfg
        self.index = VulnIndex.load()
        self.guard = GuardClient(cfg.guard_url, cfg.guard_key)
        self.agent = SwitchAgent(
            base_url=cfg.api,
            name=cfg.intake_name,
            description="Grounds incoming vulnerability reports and opens cases",
            connection_model="session_addressable",
            state_path=cfg.state_dir / f"{cfg.intake_name}.json",
        )
        self.open_cases: list[OpenCase] = []

    # ---- lifecycle --------------------------------------------------------

    def connect(self) -> None:
        self.agent.register(self.cfg.reg_token)
        self.agent.start()
        self.agent.connect_room(self.cfg.intake_room_id)

    def run(self) -> None:
        self.connect()
        self.announce()
        for ev in self.agent.events():
            try:
                self.on_message(ev)
            except Exception as exc:  # a bad report must not take the desk down
                self._say(f"I could not process that report ({exc}).")

    def announce(self) -> None:
        self._say(
            "Intake is open. Post a vulnerability report and address me; I will "
            "ground the claim against curl's advisory record before anyone's time "
            "is spent on it."
        )

    # ---- handling a report ------------------------------------------------

    def on_message(self, ev: dict) -> None:
        payload = ev.get("payload", ev)
        if not payload.get("addressed"):
            return
        sender = payload.get("sender_name") or payload.get("sender") or "reporter"
        body = payload.get("body", "")
        if self._is_self(payload) or not self._looks_like_report(body):
            return
        report_id = payload.get("message_id", str(int(time.time())))
        self.handle_report(report_id, body, sender)

    def handle_report(self, report_id: str, text: str, reporter: str) -> dict:
        report = parse_report(report_id, text, self.index.latest)
        dup = self._duplicate_of(report)
        if dup is not None:
            self._say(
                f"This looks like a duplicate of **{dup.case_id}** ({dup.title}). "
                f"I have linked it there rather than opening a new case."
            )
            return {"verdict": "duplicate", "case_id": dup.case_id}

        verdict = verify(
            Claim(report["report_id"], report["title"], report["version"], set(report["classes"])),
            self.index,
        )
        if verdict.verdict == "invalid":
            self._say(
                f"I am closing this without opening a case. {verdict.reason} "
                f"If you can point to a specific affected version and build, reopen it."
            )
            return {"verdict": "invalid", "reason": verdict.reason}

        # real or needs_human -> open a private case
        return self.open_case(report, reporter, verdict)

    def open_case(self, report: dict, reporter: str, verdict) -> dict:
        case_id = report["case_id"]
        secrets = self._secrets_for(case_id, report)
        room_name = f"{case_id}"
        result = self.agent.op(
            "create_room",
            {
                "name": room_name,
                "description": f"Private case room for {case_id}",
                "agent_names": [self.cfg.reproducer_name, self.cfg.disclosure_name],
                "user_names": self._maybe_user(reporter),
                "channel_type": "channel_private",
                "read_visibility": "private",
                "write_visibility": "private",
                "linked_rooms": [
                    {"target_room_id": self.cfg.intake_room_id, "label": "intake"}
                ],
                "roles": [
                    {
                        "name": "security-lead",
                        "exclusive": True,
                        "instructions": "You gate this case. Nothing is disclosed "
                        "without your explicit sign-off.",
                    }
                ],
                "instructions": self._case_instructions(case_id, report, verdict),
            },
        )
        room = result.get("result", result)
        case_room_id = room.get("id") or room.get("room_id")

        # The embargo: this case's material may travel only in the case room
        # (the reporter's messages arrive there too). Everywhere else, blocked.
        self.guard.open_case(
            case_id=case_id,
            allowed_rooms=[case_room_id],
            secrets=secrets,
            embargo_ttl_seconds=EMBARGO_TTL,
        )
        self.open_cases.append(
            OpenCase(case_id, case_room_id, report["title"], significant_tokens(report["title"]))
        )

        self._say(
            f"Opened **{case_id}** as a private case. {verdict.reason} "
            f"The reproducer and a security lead are in the case room; this report "
            f"is now under embargo and will not surface outside it."
        )
        return {"verdict": "case-opened", "case_id": case_id, "room_id": case_room_id}

    # ---- helpers ----------------------------------------------------------

    def _secrets_for(self, case_id: str, report: dict) -> list[str]:
        """The material the embargo protects — the flaw's description and the
        reporter's proof lines. Deliberately NOT the case id: that is a safe
        handle the desk refers to in the open, so people can talk about the
        existence of a case without exposing what it is."""
        secrets: list[str] = []
        if report["title"]:
            secrets.append(report["title"])
        # Distinctive proof-of-concept lines, if the report carries any.
        for line in (report.get("text") or "").splitlines():
            s = line.strip()
            if len(s) >= 20 and s != report["title"]:
                secrets.append(s)
        return secrets or [report["title"] or case_id]

    def _duplicate_of(self, report: dict):
        tokens = significant_tokens(report["title"])
        for c in self.open_cases:
            if len(tokens & c.tokens) >= 2:
                return c
        return None

    def _case_instructions(self, case_id: str, report: dict, verdict) -> str:
        return (
            f"This is the private case room for {case_id}.\n\n"
            f"Reported claim: {report['title']}\n"
            f"Claimed affected curl version: {report['version']}\n"
            f"Grounding: {verdict.reason}\n\n"
            f"@{self.cfg.reproducer_name}: reproduce the claim against the named "
            f"version in a sandbox and report exactly what you observe — no verdict "
            f"without a run. @security-lead gates disclosure; nothing leaves this "
            f"room until they sign off."
        )

    def _maybe_user(self, reporter: str) -> list[str] | None:
        # A bare reporter name may not resolve on the bridge; pass it through
        # and let Switch ignore an unknown one rather than failing the case.
        return [reporter] if reporter and not reporter.startswith("@") else None

    def _looks_like_report(self, body: str) -> bool:
        if not body:
            return False
        low = body.lower()
        return any(
            w in low
            for w in ("curl", "libcurl", "vuln", "overflow", "cve", "exploit", "report")
        )

    def _is_self(self, payload: dict) -> bool:
        s = (payload.get("sender_name") or "") + (payload.get("sender") or "")
        return self.cfg.intake_name in s

    def _say(self, text: str) -> None:
        self.agent.post(self.cfg.intake_room_id, text)


def main() -> None:
    IntakeAgent(DeskConfig.from_env()).run()


if __name__ == "__main__":
    main()
