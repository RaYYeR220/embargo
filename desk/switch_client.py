"""A small Switch agent-protocol client.

Switch runs no agents of its own: an agent is any program that speaks the
protocol — one SSE stream down for room events, HTTP up for everything it does.
This client implements the slice the Embargo desk needs: register, hold a live
connection, join a room, read what is addressed to it, and post back.

It is deliberately thin and synchronous-friendly: a background thread keeps the
event stream and the heartbeat alive while the caller works in ordinary code.

    agent = SwitchAgent(base_url, name="embargo-intake", description="...")
    agent.register(registration_token)      # once; persists id + key
    agent.start()                            # opens stream + heartbeat
    agent.connect_room(room_id)
    agent.post(room_id, "hello")
    for ev in agent.events():                # addressed messages
        ...
"""

from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import httpx

HEARTBEAT_SECONDS = 2.0


@dataclass
class SwitchAgent:
    base_url: str
    name: str
    description: str
    # How Switch should report this agent's liveness. "session_addressable" =
    # reachable while this client holds a live connection to the room.
    connection_model: str = "session_addressable"
    connector_type: str = "embargo-desk"
    state_path: Path | None = None  # where id+key persist across restarts

    agent_id: str | None = None
    api_key: str | None = None
    connection_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    _cursor: int = 0
    _stop: threading.Event = field(default_factory=threading.Event)
    _ready: threading.Event = field(default_factory=threading.Event)
    _events: "queue.Queue[dict]" = field(default_factory=queue.Queue)
    _threads: list[threading.Thread] = field(default_factory=list)
    _rooms_claimed: set[str] = field(default_factory=set)

    # ---- identity ---------------------------------------------------------

    def _load_state(self) -> None:
        if self.state_path and self.state_path.exists():
            data = json.loads(self.state_path.read_text())
            self.agent_id = data.get("agent_id")
            self.api_key = data.get("api_key")

    def _save_state(self) -> None:
        if self.state_path:
            self.state_path.write_text(
                json.dumps({"agent_id": self.agent_id, "api_key": self.api_key})
            )

    def register(self, registration_token: str, overwrite: bool = False) -> str:
        """Register (idempotent via stored state). Returns the agent id."""
        self._load_state()
        if self.agent_id and self.api_key and not overwrite:
            return self.agent_id
        r = httpx.post(
            f"{self.base_url}/agents",
            headers={"Authorization": f"Bearer {registration_token}"},
            json={
                "name": self.name,
                "description": self.description,
                "connector_type": self.connector_type,
                "integration_profile": {
                    "connection_model": self.connection_model,
                    "message_exchange": True,
                    "pre_invocation_mediation": [],
                    "post_invocation_mediation": [],
                    "event_reporting": [],
                },
                "overwrite": overwrite,
            },
            timeout=20,
        )
        r.raise_for_status()
        body = r.json()
        self.agent_id, self.api_key = body["id"], body["api_key"]
        self._save_state()
        return self.agent_id

    @property
    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    # ---- operations -------------------------------------------------------

    def op(self, operation: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = httpx.post(
            f"{self.base_url}/agents/{self.agent_id}/ops/{operation}",
            headers={**self._auth, "x-switch-connection-id": self.connection_id},
            json=body or {},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def connect_room(self, room_id: str) -> dict[str, Any]:
        out = self.op("connect_to_room", {"room_id": room_id})
        self._rooms_claimed.add(room_id)
        return out

    def post(self, room_id: str, body: str, thread_id: str | None = None) -> dict[str, Any]:
        """Post to a room. Reconnects the session to it first (single-room scope)."""
        if room_id not in self._rooms_claimed or True:
            self.connect_room(room_id)
        return self.op("post_message", {"body": body, "thread_id": thread_id})

    def list_rooms(self) -> list[dict[str, Any]]:
        return self.op("list_rooms").get("rooms", [])

    # ---- the live connection ---------------------------------------------

    def start(self, ready_timeout: float = 15.0) -> None:
        self._stop.clear()
        self._ready.clear()
        t_stream = threading.Thread(target=self._stream_loop, daemon=True)
        t_beat = threading.Thread(target=self._beat_loop, daemon=True)
        t_stream.start()
        # Block until the stream has the connection registered server-side
        # (the first `connection_state` frame). Only then may an op bind a room.
        if not self._ready.wait(ready_timeout):
            raise RuntimeError("Switch connection did not open in time")
        t_beat.start()
        self._threads = [t_stream, t_beat]

    def stop(self) -> None:
        self._stop.set()

    def _beat_loop(self) -> None:
        url = f"{self.base_url}/agents/{self.agent_id}/connection/beat"
        while not self._stop.is_set():
            try:
                httpx.post(
                    url,
                    headers=self._auth,
                    json={"connection_id": self.connection_id, "cursor": self._cursor},
                    timeout=10,
                )
            except httpx.HTTPError:
                pass
            self._stop.wait(HEARTBEAT_SECONDS)

    def _stream_loop(self) -> None:
        url = (
            f"{self.base_url}/agents/{self.agent_id}/events"
            f"?connection_id={self.connection_id}&scope=all&filter=addressed"
        )
        headers = {**self._auth, "Accept": "text/event-stream"}
        while not self._stop.is_set():
            try:
                with httpx.stream("GET", url, headers=headers, timeout=None) as r:
                    event = None
                    for line in r.iter_lines():
                        if self._stop.is_set():
                            break
                        if line.startswith("id:"):
                            try:
                                self._cursor = int(line[3:].strip())
                            except ValueError:
                                pass
                        elif line.startswith("event:"):
                            event = line[6:].strip()
                            if event == "connection_state":
                                self._ready.set()
                        elif line.startswith("data:"):
                            payload = line[5:].strip()
                            try:
                                data = json.loads(payload)
                            except ValueError:
                                continue
                            if event == "message":
                                self._events.put(data)
            except httpx.HTTPError:
                time.sleep(1.0)

    def events(self, timeout: float | None = None) -> Iterator[dict]:
        """Yield addressed message events as they arrive."""
        while not self._stop.is_set():
            try:
                yield self._events.get(timeout=timeout or 1.0)
            except queue.Empty:
                if timeout is not None:
                    return
                continue
