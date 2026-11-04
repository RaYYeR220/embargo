"""The reproducer agent: no verdict without a run.

It lives in a case room. When the intake agent hands it a case, it does not
reason about the report — it runs the named curl version in a sandbox and
reports what the binary actually does: whether that release exists, what it is,
and whether the options the report leans on are even present in it. A report
that names a release or an option that does not exist is answered with the
evidence, in the room, addressed to the security lead.

This is the deterministic reproducer that ships with the desk so the whole flow
runs with no external agent. A richer coding agent (Claude Code, Codex) can take
the same seat through Switch and carry a reproduction further.
"""

from __future__ import annotations

import re

from desk.config import DeskConfig
from desk.switch_client import SwitchAgent
from desk.verifier import VulnIndex
from sandbox.probe import probe

_VER = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_OPT = re.compile(r"(--[a-z0-9][a-z0-9-]+)")


class ReproducerAgent:
    def __init__(self, cfg: DeskConfig) -> None:
        self.cfg = cfg
        self.index = VulnIndex.load()
        self.agent = SwitchAgent(
            base_url=cfg.api,
            name=cfg.reproducer_name,
            description="Reproduces a claim against the named curl version in a sandbox",
            connection_model="session_addressable",
            state_path=cfg.state_dir / f"{cfg.reproducer_name}.json",
        )
        self._handled: set[str] = set()

    def run(self) -> None:
        self.agent.register(self.cfg.reg_token)
        self.agent.start()
        for ev in self.agent.events():
            try:
                self.on_message(ev)
            except Exception as exc:
                pass  # a failed probe is reported in-room; never crash the agent

    def on_message(self, ev: dict) -> None:
        payload = ev.get("payload", ev)
        if not payload.get("addressed"):
            return
        room_id = ev.get("room_id") or payload.get("room_id")
        body = payload.get("body", "")
        if self.cfg.reproducer_name in (payload.get("sender_name") or ""):
            return
        key = payload.get("message_id", "")
        if key in self._handled:
            return
        self._handled.add(key)
        self.reproduce(room_id, body)

    def reproduce(self, room_id: str, text: str) -> dict:
        version = self._version(text)
        options = _OPT.findall(text)[:4]
        result = probe(version, options)
        verdict = "inconclusive"
        if not result.image_exists:
            verdict = "could-not-reproduce"
        elif options and not any(result.option_checks.values()):
            verdict = "claim-does-not-stand"
        else:
            verdict = "reproduction-environment-ready"
        self._post(
            room_id,
            f"@security-lead reproduction attempt for the claim against curl {version}:\n\n"
            f"{result.summary()}\n\n"
            f"Verdict: **{verdict}**. "
            + (
                "The release or the option the report relies on does not exist, so the "
                "claim does not stand as written."
                if verdict == "claim-does-not-stand" or verdict == "could-not-reproduce"
                else "The release and options exist; a deeper reproduction can proceed here under embargo."
            ),
        )
        return {"version": version, "verdict": verdict, "summary": result.summary()}

    def _version(self, text: str) -> str:
        m = _VER.search(text or "")
        return m.group(1) if m else self.index.latest

    def _post(self, room_id: str, text: str) -> None:
        self.agent.post(room_id, text)


def main() -> None:
    ReproducerAgent(DeskConfig.from_env()).run()


if __name__ == "__main__":
    main()
