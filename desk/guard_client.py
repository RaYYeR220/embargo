"""Client for the embargo guard's admin API.

The intake agent registers an embargo when it opens a case; the disclosure
agent lifts it when the advisory goes out. Both go through here.
"""

from __future__ import annotations

import os

import httpx


class GuardClient:
    def __init__(self, base_url: str | None = None, admin_key: str | None = None) -> None:
        self.base_url = (base_url or os.environ.get("GUARD_URL", "http://127.0.0.1:19000")).rstrip("/")
        self.admin_key = admin_key or os.environ.get("EMBARGO_ADMIN_KEY", "")

    @property
    def _headers(self) -> dict[str, str]:
        return {"x-embargo-key": self.admin_key} if self.admin_key else {}

    def open_case(
        self,
        case_id: str,
        allowed_rooms: list[str],
        secrets: list[str],
        embargo_ttl_seconds: int | None = None,
    ) -> dict:
        body = {"case_id": case_id, "allowed_rooms": allowed_rooms, "secrets": secrets}
        if embargo_ttl_seconds is not None:
            body["embargo_ttl_seconds"] = embargo_ttl_seconds
        r = httpx.post(f"{self.base_url}/cases", headers=self._headers, json=body, timeout=10)
        r.raise_for_status()
        return r.json()

    def lift(self, case_id: str) -> dict:
        r = httpx.delete(f"{self.base_url}/cases/{case_id}", headers=self._headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def cases(self) -> dict:
        return httpx.get(f"{self.base_url}/cases", timeout=10).json()

    def audit(self, limit: int = 50) -> dict:
        return httpx.get(f"{self.base_url}/audit?limit={limit}", timeout=10).json()
