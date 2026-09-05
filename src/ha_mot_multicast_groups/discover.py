from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ha_mot_multicast_groups.ha_client import HomeAssistantClient

MATTER_ID_RE = re.compile(
    r"(?P<fabric>[0-9A-Fa-f]{16})-(?P<node>[0-9A-Fa-f]{16})"
)


@dataclass
class MappedLight:
    entity_id: str
    friendly_name: str
    state: str
    platform: str | None
    unique_id: str | None
    device_id: str | None
    node_id: int | None
    endpoint_id: int | None
    available: bool


def _parse_matter_ids(unique_id: str | None, identifiers: list[list[str]] | None) -> tuple[int | None, int | None]:
    candidates: list[str] = []
    if unique_id:
        candidates.append(unique_id)
    for ident in identifiers or []:
        if len(ident) >= 2:
            candidates.append(str(ident[1]))
    node_id: int | None = None
    endpoint_id: int | None = None
    for text in candidates:
        match = MATTER_ID_RE.search(text.replace("deviceid_", "").replace("ID_TYPE_DEVICE_ID_", ""))
        if not match:
            continue
        node_id = int(match.group("node"), 16)
        parts = text.split("-")
        for i, part in enumerate(parts):
            if part.lower() == match.group("node").lower() and i + 1 < len(parts) and parts[i + 1].isdigit():
                endpoint_id = int(parts[i + 1])
                break
        if endpoint_id is None:
            # unique_id: fabric-node-<deviceclass?>-endpoint-...
            # Fall back to first small integer after the node hex.
            after = text.split(match.group("node"), 1)[-1].lstrip("-")
            for token in after.split("-"):
                if token.isdigit() and 0 < int(token) < 256:
                    endpoint_id = int(token)
                    break
        break
    if endpoint_id is None and node_id is not None:
        endpoint_id = 1
    return node_id, endpoint_id


async def discover_group(
    ha: HomeAssistantClient,
    group_entity_id: str,
) -> tuple[dict[str, Any], list[MappedLight]]:
    group_state = await ha.get_state(group_entity_id)
    member_ids = list((group_state.get("attributes") or {}).get("entity_id") or [])
    if not member_ids:
        raise RuntimeError(f"{group_entity_id} has no entity_id members (is it a helper group?)")

    devices = {d["id"]: d for d in await ha.device_registry_list()}
    registry = {e["entity_id"]: e for e in await ha.entity_registry_list()}

    mapped: list[MappedLight] = []
    for entity_id in member_ids:
        try:
            state = await ha.get_state(entity_id)
        except Exception:
            state = {"state": "unknown", "attributes": {}}
        entry = registry.get(entity_id) or {}
        device = devices.get(entry.get("device_id") or "") or {}
        identifiers = device.get("identifiers") or []
        node_id, endpoint_id = _parse_matter_ids(entry.get("unique_id"), identifiers)
        mapped.append(
            MappedLight(
                entity_id=entity_id,
                friendly_name=(state.get("attributes") or {}).get("friendly_name") or entity_id,
                state=str(state.get("state")),
                platform=entry.get("platform"),
                unique_id=entry.get("unique_id"),
                device_id=entry.get("device_id"),
                node_id=node_id,
                endpoint_id=endpoint_id,
                available=str(state.get("state")) not in {"unavailable", "unknown"},
            )
        )
    return group_state, mapped


def format_table(lights: list[MappedLight]) -> str:
    header = f"{'entity_id':<42} {'state':<12} {'platform':<10} {'node':<18} {'ep':<4} name"
    lines = [header, "-" * len(header)]
    for light in lights:
        node = hex(light.node_id) if light.node_id is not None else "?"
        ep = str(light.endpoint_id) if light.endpoint_id is not None else "?"
        lines.append(
            f"{light.entity_id:<42} {light.state:<12} {(light.platform or '?'):<10} {node:<18} {ep:<4} {light.friendly_name}"
        )
    return "\n".join(lines)
