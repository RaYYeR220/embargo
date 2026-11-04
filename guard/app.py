"""Embargo guard — the gate that keeps a security case inside its own rooms.

Switch calls one endpoint, ``POST /guardrails/check``, before it delivers any
message a person or an agent writes into a room. The call carries the message
and, in the ``x-agent-session-id`` header, the id of the room it is bound for.
This service answers whether that message may be sent.

An embargoed case is a vulnerability under coordinated disclosure: its details
live in a fixed set of rooms (the private case room, the reporter's room) and
must not appear anywhere else until the advisory is published. The guard holds,
per case, the rooms the case is allowed in, a set of secrets that identify the
case's material, and the moment the embargo lifts. A message that carries a
case's secret into a room outside that set, before the embargo lifts, is
stopped at the point of sending — not by asking an agent to behave, but in the
delivery path every message already goes through.

The decision is fail-closed: when the guard cannot tell a message is safe it
blocks. (Switch itself fails open if this service is unreachable, which is why
the guard runs beside the server rather than across a network.)

Endpoints:
  POST /guardrails/check     Switch's gate. Returns {outcome, findings}.
  POST /cases                register or update a case's embargo
  GET  /cases                list the live embargo registry
  DELETE /cases/{case_id}    lift an embargo (publication)
  GET  /health
  GET  /audit                every decision, newest first (demo + proof)
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

Outcome = Literal["ok", "blocked", "redacted", "alerted", "errored"]

# Switch reads the verdict from a fixed wire vocabulary (the
# GUARDRAIL_RESULT_OUTCOME_<NAME> convention its Trust client maps against).
# An unrecognised value is treated as an engine error and fails open, so the
# guard must answer in exactly these tokens.
WIRE = {
    "ok": "GUARDRAIL_RESULT_OUTCOME_OK",
    "blocked": "GUARDRAIL_RESULT_OUTCOME_BLOCKED",
    "redacted": "GUARDRAIL_RESULT_OUTCOME_REDACTED",
    "alerted": "GUARDRAIL_RESULT_OUTCOME_ALERTED",
    "errored": "GUARDRAIL_RESULT_OUTCOME_ERRORED",
}

API_KEY = os.environ.get("EMBARGO_ADMIN_KEY", "")  # when set, guards the admin API
REDACTION = "[redacted: under embargo]"


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@dataclass
class Case:
    case_id: str
    allowed_rooms: set[str]
    secrets: list[str]
    embargo_until: float | None  # epoch seconds; None = until explicitly lifted
    created_at: float = field(default_factory=_now)

    def active(self) -> bool:
        if self.embargo_until is None:
            return True
        return _now() < self.embargo_until

    def matches(self, content: str) -> list[str]:
        """Secrets of this case that appear in the content (case-insensitive)."""
        low = content.lower()
        return [s for s in self.secrets if s and s.lower() in low]


class Registry:
    """The set of live embargoes. Thread-safe; one process, a lock is enough."""

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._lock = threading.Lock()

    def put(self, case: Case) -> None:
        with self._lock:
            self._cases[case.case_id] = case

    def drop(self, case_id: str) -> bool:
        with self._lock:
            return self._cases.pop(case_id, None) is not None

    def all(self) -> list[Case]:
        with self._lock:
            return list(self._cases.values())


REGISTRY = Registry()
AUDIT: list[dict] = []
AUDIT_LOCK = threading.Lock()
AUDIT_MAX = 500


def _record(entry: dict) -> None:
    entry["at"] = _iso(_now())
    with AUDIT_LOCK:
        AUDIT.insert(0, entry)
        del AUDIT[AUDIT_MAX:]


# ---- Switch Trust wire contract -------------------------------------------

class _Message(BaseModel):
    role: str
    content: str


class CheckRequest(BaseModel):
    messages: list[_Message] = Field(default_factory=list)


class Finding(BaseModel):
    # Fields Switch's Trust client reads back off each finding.
    category: str
    detector_name: str = "embargo-guard"
    severity: str | None = "high"
    # The exact substring that tripped the finding. Switch uses this to build
    # its own redaction on a REDACTED verdict; for an embargo match it is the
    # case secret that leaked.
    detected_string: str | None = None
    # guard-specific context (ignored by Switch, used by our audit + UI)
    detail: str | None = None
    case_id: str | None = None


class CheckResponse(BaseModel):
    outcome: str  # a GUARDRAIL_RESULT_OUTCOME_* wire token
    findings: list[Finding] = Field(default_factory=list)
    policy_id: str = "embargo"
    policy_name: str = "Embargo guard"
    # Switch builds its own redaction from the findings; we also return the
    # text we would have sent, so the service is usable outside Switch too.
    redacted_content: str | None = None


# ---- admin contract --------------------------------------------------------

class CaseUpsert(BaseModel):
    case_id: str
    allowed_rooms: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    # one of the two; ttl wins if both are given
    embargo_ttl_seconds: int | None = None
    embargo_until_epoch: float | None = None


app = FastAPI(title="Embargo guard", version="1.0")

# The live console reads /cases and /audit from a browser. Those are read-only
# views; the admin routes stay gated by the key regardless of origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


def _authorised(key: str | None) -> bool:
    return not API_KEY or key == API_KEY


def decide(room_id: str, content: str) -> CheckResponse:
    """The whole policy. Pure apart from reading the registry.

    A message carrying a live case's secret into a room outside that case's
    allowed set is blocked. ``outcome`` is the plain word here; the endpoint
    translates it to Switch's wire token.
    """
    hits: list[Finding] = []
    redacted = content
    worst: str = "ok"
    for case in REGISTRY.all():
        if not case.active():
            continue
        if room_id in case.allowed_rooms:
            continue  # this room is inside the embargo — the case may speak here
        leaked = case.matches(content)
        if not leaked:
            continue
        worst = "blocked"
        for s in leaked:
            hits.append(
                Finding(
                    category="embargo",
                    detected_string=s,
                    case_id=case.case_id,
                    detail=f"material for {case.case_id} is not allowed in room {room_id}",
                )
            )
            redacted = re.sub(re.escape(s), REDACTION, redacted, flags=re.IGNORECASE)
    return CheckResponse(
        outcome=worst,
        findings=hits,
        redacted_content=redacted if worst != "ok" else None,
    )


@app.post("/guardrails/check")
async def check(req: CheckRequest, request: Request) -> dict:
    room_id = request.headers.get("x-agent-session-id", "")
    content = "\n".join(m.content for m in req.messages)
    verdict = decide(room_id, content)
    _record(
        {
            "kind": "check",
            "room_id": room_id,
            "outcome": verdict.outcome,
            "cases": sorted({f.case_id for f in verdict.findings if f.case_id}),
            "preview": content[:120],
        }
    )
    # Serialise to Switch's wire vocabulary.
    return {
        "outcome": WIRE[verdict.outcome],
        "policy_id": verdict.policy_id,
        "policy_name": verdict.policy_name,
        "findings": [f.model_dump() for f in verdict.findings],
        "redacted_content": verdict.redacted_content,
    }


@app.post("/cases")
async def upsert_case(
    body: CaseUpsert, x_embargo_key: str | None = Header(default=None)
) -> dict:
    if not _authorised(x_embargo_key):
        return {"error": "unauthorised"}
    until: float | None
    if body.embargo_ttl_seconds is not None:
        until = _now() + body.embargo_ttl_seconds
    else:
        until = body.embargo_until_epoch
    case = Case(
        case_id=body.case_id,
        allowed_rooms=set(body.allowed_rooms),
        secrets=list(body.secrets),
        embargo_until=until,
    )
    REGISTRY.put(case)
    _record({"kind": "case.upsert", "case_id": case.case_id,
             "allowed_rooms": sorted(case.allowed_rooms),
             "secret_count": len(case.secrets),
             "embargo_until": _iso(until) if until else None})
    return {"ok": True, "case_id": case.case_id,
            "embargo_until": _iso(until) if until else None}


@app.get("/cases")
async def list_cases() -> dict:
    return {
        "cases": [
            {
                "case_id": c.case_id,
                "allowed_rooms": sorted(c.allowed_rooms),
                "secret_count": len(c.secrets),
                "embargo_until": _iso(c.embargo_until) if c.embargo_until else None,
                "active": c.active(),
            }
            for c in REGISTRY.all()
        ]
    }


@app.delete("/cases/{case_id}")
async def lift_case(case_id: str, x_embargo_key: str | None = Header(default=None)) -> dict:
    if not _authorised(x_embargo_key):
        return {"error": "unauthorised"}
    dropped = REGISTRY.drop(case_id)
    _record({"kind": "case.lift", "case_id": case_id, "dropped": dropped})
    return {"ok": dropped, "case_id": case_id}


@app.get("/audit")
async def audit(limit: int = 100) -> dict:
    with AUDIT_LOCK:
        return {"decisions": AUDIT[: max(1, min(limit, AUDIT_MAX))]}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "cases": len(REGISTRY.all())}
