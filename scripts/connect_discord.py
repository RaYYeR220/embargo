"""Connect a Discord server to the desk as a second platform.

Reporters file in Discord; the maintainers' rooms can stay on another platform.
The embargo still holds across both, because it is enforced in Switch, not in
either chat app.

One-time Discord setup (in the Discord Developer Portal):
  * create an application and a bot; turn on the Server Members and Message
    Content privileged intents; invite the bot to your server with the `bot`
    and `applications.commands` scopes;
  * copy the Bot Token and the Server (guild) ID.

Then:
  DISCORD_BOT_TOKEN=... DISCORD_GUILD_ID=... SWITCH_API=http://127.0.0.1:18000 \
  ADMIN_PW=... python scripts/connect_discord.py

It registers the Discord bridge and creates a public #security-intake room on it
with the intake agent in it. Post a message in that Discord channel to bring the
room to life (Discord creates the room on first message, not on bot invite).
"""

from __future__ import annotations

import os

import httpx

API = os.environ["SWITCH_API"]
GATEWAY = f"{API}/gateway"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@switch.local")
ADMIN_PW = os.environ["ADMIN_PW"]
BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
GUILD_ID = os.environ["DISCORD_GUILD_ID"]


def main() -> None:
    c = httpx.Client(timeout=30)
    c.post(f"{GATEWAY}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PW}).raise_for_status()

    # Already connected? (the listing keys each bridge by `bridge_type` / `bridge_id`)
    existing = c.get(f"{GATEWAY}/collaborations").json()
    rows = existing if isinstance(existing, list) else existing.get("bridges", existing.get("collaborations", []))
    discord = next((b for b in rows if b.get("bridge_type") == "discord"), None)
    if discord:
        bridge_id = discord["bridge_id"]
        print(f"Discord bridge already registered: {bridge_id}")
    else:
        r = c.post(
            f"{GATEWAY}/collaborations",
            json={
                "bridge_type": "discord",
                "display_name": "Discord",
                "connection_config": {"bot_token": BOT_TOKEN, "guild_id": GUILD_ID, "event_delivery": "own_connection"},
                "channel_creation_enabled": True,
                "set_as_default": False,
            },
        )
        r.raise_for_status()
        body = r.json()
        bridge_id = body.get("bridge_id") or body.get("id")
        print(f"registered Discord bridge: {bridge_id}")

    room = c.post(
        f"{GATEWAY}/rooms",
        json={
            "name": "security-intake",
            "description": "Report a curl vulnerability here. Grounded on arrival.",
            "bridge_id": bridge_id,
            "channel_type": "channel_public",
            "agent_names": ["embargo-intake"],
        },
    )
    if room.status_code < 300:
        print(f"Discord intake room: {room.json()['id']}")
    else:
        print(f"intake room: {room.status_code} {room.text[:200]}")
    print("Post any message in the Discord #security-intake channel to activate the room.")


if __name__ == "__main__":
    main()
