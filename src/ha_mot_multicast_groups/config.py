from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

def _find_root() -> Path:
    starts = [Path.cwd(), Path(__file__).resolve().parent]
    seen: set[Path] = set()
    for start in starts:
        for path in [start, *start.parents]:
            if path in seen:
                continue
            seen.add(path)
            if (path / ".env").is_file() or (
                (path / "pyproject.toml").is_file() and (path / "src" / "ha_mot_multicast_groups").is_dir()
            ):
                return path
    return Path.cwd()


ROOT = _find_root()
load_dotenv(ROOT / ".env")


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, hex(default) if default >= 0x100 else str(default))
    return int(raw, 0)


@dataclass(frozen=True)
class Settings:
    ha_url: str
    ha_token: str
    ha_group_entity: str
    matter_ws_url: str
    group_id: int
    group_keyset_id: int
    group_key_hex: str
    group_name: str

    @property
    def ha_ws_url(self) -> str:
        base = self.ha_url.rstrip("/")
        if base.startswith("https://"):
            return "wss://" + base.removeprefix("https://") + "/api/websocket"
        if base.startswith("http://"):
            return "ws://" + base.removeprefix("http://") + "/api/websocket"
        raise ValueError(f"Unsupported HA_URL: {self.ha_url}")

    @property
    def group_node_id(self) -> int:
        return 0xFFFFFFFFFFFF0000 | (self.group_id & 0xFFFF)


def load_settings() -> Settings:
    token = os.getenv("HA_TOKEN", "").strip()
    if not token:
        raise SystemExit("HA_TOKEN is missing. Copy .env.example to .env and paste your long-lived token.")
    return Settings(
        ha_url=os.getenv("HA_URL", "https://home.dome.haus").rstrip("/"),
        ha_token=token,
        ha_group_entity=os.getenv("HA_GROUP_ENTITY", "light.dining_room_chandelier"),
        matter_ws_url=os.getenv("MATTER_WS_URL", "").strip(),
        group_id=_int_env("MATTER_GROUP_ID", 0x0D01),
        group_keyset_id=_int_env("MATTER_GROUP_KEYSET_ID", 42),
        group_key_hex=os.getenv("MATTER_GROUP_KEY_HEX", "").strip(),
        group_name=os.getenv("MATTER_GROUP_NAME", "DiningChandelier"),
    )
