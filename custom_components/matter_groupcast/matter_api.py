from __future__ import annotations

import asyncio
import base64
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er

from .const import (
    AUTH_MODE_CASE,
    AUTH_MODE_GROUP,
    CLUSTER_GROUP_KEY_MANAGEMENT,
    CLUSTER_GROUPS,
    CLUSTER_ONOFF,
    CONF_GROUP_ID,
    CONF_GROUP_KEY_HEX,
    CONF_GROUP_KEYSET_ID,
    CONF_GROUP_NAME,
    CONF_SOURCE_ENTITY,
    DEFAULT_GROUP_ID,
    DEFAULT_GROUP_KEYSET_ID,
    DEFAULT_GROUP_NAME,
    PRIVILEGE_ADMINISTER,
    PRIVILEGE_OPERATE,
)

_LOGGER = logging.getLogger(__name__)

MATTER_ID_RE = re.compile(r"(?P<fabric>[0-9A-Fa-f]{16})-(?P<node>[0-9A-Fa-f]{16})")


@dataclass(frozen=True)
class GroupMember:
    entity_id: str
    node_id: int
    endpoint_id: int
    available: bool


def _get_matter_client(hass: HomeAssistant) -> Any:
    """Return the official Matter integration's websocket client."""
    try:
        from homeassistant.components.matter.helpers import get_matter
    except ImportError as err:
        raise HomeAssistantError("The Matter integration is not available") from err
    return get_matter(hass).matter_client


def _parse_node_endpoint(unique_id: str | None) -> tuple[int | None, int | None]:
    if not unique_id:
        return None, None
    match = MATTER_ID_RE.search(unique_id)
    if not match:
        return None, None
    node_id = int(match.group("node"), 16)
    endpoint_id = 1
    after = unique_id.split(match.group("node"), 1)[-1].lstrip("-")
    for token in after.split("-"):
        if token.isdigit() and 0 < int(token) < 256:
            endpoint_id = int(token)
            break
    return node_id, endpoint_id


def _epoch_keys(key_hex: str) -> tuple[str, str, str]:
    k0 = bytes.fromhex(key_hex)
    k1 = k0[:-1] + bytes([k0[-1] ^ 0x01])
    k2 = k0[:-1] + bytes([k0[-1] ^ 0x02])
    encode = lambda key: base64.b64encode(key).decode("ascii")
    return encode(k0), encode(k1), encode(k2)


def _extract_acl(raw: Any) -> list[dict[str, Any]]:
    values: list[Any] = []
    if isinstance(raw, dict):
        for value in raw.values():
            if isinstance(value, list):
                values = value
                break
    elif isinstance(raw, list):
        values = raw
    entries: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        privilege = item.get("privilege", item.get("1"))
        auth_mode = item.get("authMode", item.get("auth_mode", item.get("2")))
        subjects = item.get("subjects", item.get("3"))
        targets = item.get("targets", item.get("4"))
        if privilege is None or auth_mode is None:
            continue
        entries.append(
            {
                "privilege": int(privilege),
                "auth_mode": int(auth_mode),
                "subjects": subjects,
                "targets": targets,
            }
        )
    return entries


def _merge_group_acl(existing: list[dict[str, Any]], group_id: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    saw_group = False
    for item in existing:
        entry = dict(item)
        if entry.get("auth_mode") == AUTH_MODE_GROUP and entry.get("privilege") == PRIVILEGE_OPERATE:
            subjects = list(entry.get("subjects") or [])
            if group_id not in subjects:
                subjects.append(group_id)
            entry["subjects"] = subjects
            saw_group = True
        entries.append(entry)
    if not any(
        e.get("privilege") == PRIVILEGE_ADMINISTER and e.get("auth_mode") == AUTH_MODE_CASE for e in entries
    ):
        raise HomeAssistantError("Refusing to write ACL: no Administer/CASE entry was read back")
    if not saw_group:
        entries.append(
            {
                "privilege": PRIVILEGE_OPERATE,
                "auth_mode": AUTH_MODE_GROUP,
                "subjects": [group_id],
                "targets": None,
            }
        )
    return entries


class MatterGroupController:
    """Talk to HA's Matter Server: provision groups, try groupcast, fall back to concurrent unicast."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.last_send_path: str = "unknown"

    @property
    def source_entity_id(self) -> str:
        return self.entry.data[CONF_SOURCE_ENTITY]

    @property
    def group_id(self) -> int:
        return int(self.entry.data.get(CONF_GROUP_ID, DEFAULT_GROUP_ID))

    @property
    def group_name(self) -> str:
        return str(self.entry.data.get(CONF_GROUP_NAME, DEFAULT_GROUP_NAME))

    @property
    def group_keyset_id(self) -> int:
        return int(self.entry.data.get(CONF_GROUP_KEYSET_ID, DEFAULT_GROUP_KEYSET_ID))

    async def async_setup(self) -> None:
        _get_matter_client(self.hass)
        members = self.async_members()
        if not members:
            raise HomeAssistantError(
                f"{self.source_entity_id} has no Matter members (is Matter set up and is this a light group?)"
            )

    @callback
    def async_member_entity_ids(self) -> list[str]:
        state = self.hass.states.get(self.source_entity_id)
        if state is None:
            return []
        return list(state.attributes.get("entity_id") or [])

    @callback
    def async_members(self) -> list[GroupMember]:
        registry = er.async_get(self.hass)
        members: list[GroupMember] = []
        for entity_id in self.async_member_entity_ids():
            entry = registry.async_get(entity_id)
            node_id, endpoint_id = _parse_node_endpoint(entry.unique_id if entry else None)
            if node_id is None or endpoint_id is None:
                continue
            state = self.hass.states.get(entity_id)
            members.append(
                GroupMember(
                    entity_id=entity_id,
                    node_id=node_id,
                    endpoint_id=endpoint_id,
                    available=state is not None and state.state not in {"unavailable", "unknown"},
                )
            )
        return members

    @callback
    def async_is_on(self) -> bool | None:
        states = [
            self.hass.states.get(entity_id)
            for entity_id in self.async_member_entity_ids()
        ]
        known = [s for s in states if s is not None and s.state in {"on", "off"}]
        if not known:
            return None
        return any(s.state == "on" for s in known)

    async def async_turn(self, on: bool) -> None:
        command = "on" if on else "off"
        if await self._async_try_group_command(command):
            self.last_send_path = "groupcast"
            return
        await self._async_unicast_all(command)
        self.last_send_path = "concurrent_unicast"

    async def _async_try_group_command(self, command: str) -> bool:
        client = _get_matter_client(self.hass)
        try:
            await client.send_command(
                "group_command",
                group_id=self.group_id,
                endpoint_id=1,
                cluster_id=CLUSTER_ONOFF,
                command_name=command,
                payload={},
            )
            return True
        except Exception as err:  # noqa: BLE001 — server has no group_command yet
            _LOGGER.debug("group_command unavailable (%s); using concurrent unicast", err)
            return False

    async def _async_unicast_all(self, command: str) -> None:
        client = _get_matter_client(self.hass)
        members = [m for m in self.async_members() if m.available]
        if not members:
            raise HomeAssistantError("No available Matter members to command")
        results = await asyncio.gather(
            *(
                client.send_command(
                    "device_command",
                    node_id=member.node_id,
                    endpoint_id=member.endpoint_id,
                    cluster_id=CLUSTER_ONOFF,
                    command_name=command,
                    payload={},
                )
                for member in members
            ),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        if errors and len(errors) == len(results):
            raise HomeAssistantError(f"All Matter unicast commands failed: {errors[0]}")
        for err in errors:
            _LOGGER.warning("Matter unicast command failed: %s", err)

    async def async_provision(self) -> None:
        data = dict(self.entry.data)
        key_hex = data.get(CONF_GROUP_KEY_HEX) or secrets.token_bytes(16).hex()
        if not data.get(CONF_GROUP_KEY_HEX):
            data[CONF_GROUP_KEY_HEX] = key_hex
            self.hass.config_entries.async_update_entry(self.entry, data=data)

        client = _get_matter_client(self.hass)
        key0, key1, key2 = _epoch_keys(key_hex)
        keyset_payload = {
            "groupKeySetID": self.group_keyset_id,
            "groupKeySecurityPolicy": 0,
            "epochKey0": key0,
            "epochStartTime0": 2220000,
            "epochKey1": key1,
            "epochStartTime1": 2220001,
            "epochKey2": key2,
            "epochStartTime2": 2220002,
        }
        failures: list[str] = []
        for member in self.async_members():
            if not member.available:
                _LOGGER.info("Skipping unavailable %s", member.entity_id)
                continue
            try:
                await self._async_provision_member(client, member, keyset_payload)
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception("Provisioning %s failed", member.entity_id)
                failures.append(f"{member.entity_id}: {err}")
        if failures:
            raise HomeAssistantError("Provisioning failed for: " + "; ".join(failures[:8]))

    async def _async_provision_member(
        self,
        client: Any,
        member: GroupMember,
        keyset_payload: dict[str, Any],
    ) -> None:
        await client.send_command(
            "device_command",
            node_id=member.node_id,
            endpoint_id=0,
            cluster_id=CLUSTER_GROUP_KEY_MANAGEMENT,
            command_name="keySetWrite",
            payload={"groupKeySet": keyset_payload},
        )
        await client.send_command(
            "write_attribute",
            node_id=member.node_id,
            attribute_path="0/63/0",
            value=[{"groupId": self.group_id, "groupKeySetID": self.group_keyset_id}],
        )
        await client.send_command(
            "device_command",
            node_id=member.node_id,
            endpoint_id=member.endpoint_id,
            cluster_id=CLUSTER_GROUPS,
            command_name="addGroup",
            payload={"groupID": self.group_id, "groupName": self.group_name},
        )
        raw = await client.send_command(
            "read_attribute",
            node_id=member.node_id,
            attribute_path="0/31/0",
        )
        await client.send_command(
            "set_acl_entry",
            node_id=member.node_id,
            entry=_merge_group_acl(_extract_acl(raw), self.group_id),
        )
