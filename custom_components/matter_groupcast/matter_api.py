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
    CONF_GROUP_ID,
    CONF_GROUP_KEY_HEX,
    CONF_GROUP_KEYSET_ID,
    CONF_GROUP_NAME,
    CONF_MSG_COUNTER,
    CONF_SENDER_URL,
    CONF_SOURCE_ENTITY,
    DEFAULT_CONTROLLER_NODE_ID,
    DEFAULT_GROUP_ID,
    DEFAULT_GROUP_KEYSET_ID,
    DEFAULT_GROUP_NAME,
    PRIVILEGE_ADMINISTER,
    PRIVILEGE_OPERATE,
)
from .group_send import (
    ClusterInvoke,
    EncodedGroupMessage,
    GroupSendParams,
    encode_group_invoke,
    epoch_key_bytes,
    groupcast_addresses,
    invoke_onoff,
    invokes_for_turn_on,
    next_message_counter,
    send_udp_multicast,
)
from .sender_client import async_find_sender, async_inject_multicast, hassio_prefers_addon
from .sender_urls import SUPERVISOR_SENDER

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
    encode = lambda key: base64.b64encode(key).decode("ascii")
    return tuple(encode(key) for key in epoch_key_bytes(key_hex))


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
    """Provision Matter groups and send light commands as IPv6 group multicast."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.last_send_path: str = "unknown"
        self._sender_url: str | None = None
        self._overlay_addresses: list[str] | None = None

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

    async def async_turn_off(self) -> None:
        await self.async_apply([invoke_onoff("off")])

    async def async_turn_on(
        self,
        *,
        brightness: int | None = None,
        hs_color: tuple[float, float] | None = None,
        xy_color: tuple[float, float] | None = None,
        kelvin: int | None = None,
        transition_s: float | None = 0,
    ) -> None:
        await self.async_apply(
            invokes_for_turn_on(
                brightness=brightness,
                hs_color=hs_color,
                xy_color=xy_color,
                kelvin=kelvin,
                transition_s=transition_s,
            )
        )

    async def async_apply(self, invokes: list[ClusterInvoke]) -> None:
        if await self._async_try_plugin_groupcast(invokes):
            return
        if hassio_prefers_addon(self.hass):
            if self.last_send_path == "needs_provision":
                raise HomeAssistantError(
                    "Run Developer Tools → Actions → matter_groupcast.provision once. "
                    "This entity will not unicast Thread bulbs (that is popcorn)."
                )
            raise HomeAssistantError(
                "Matter group multicast did not send. Not falling back to unicast."
            )
        self.last_send_path = "concurrent_unicast"
        await self._async_unicast_invokes(invokes)

    async def _async_try_plugin_groupcast(self, invokes: list[ClusterInvoke]) -> bool:
        key_hex = self.entry.data.get(CONF_GROUP_KEY_HEX)
        if not key_hex:
            self.last_send_path = "needs_provision"
            _LOGGER.warning(
                "No Matter group key stored yet; run matter_groupcast.provision, "
                "then light commands will use IPv6 group multicast"
            )
            return False

        fabric = self._fabric_params()
        if fabric is None:
            self.last_send_path = "no_fabric"
            _LOGGER.warning("Matter Server fabric info is missing; cannot groupcast")
            return False

        sender_url = await self._async_sender_url()
        if not sender_url and hassio_prefers_addon(self.hass):
            self.last_send_path = "addon_unreachable"
            _LOGGER.warning(
                "Matter Groupcast add-on is not reachable. Install it from this "
                "GitHub repo (host network) so multicast can reach Thread."
            )
            return False

        counter = next_message_counter(self.entry.data.get(CONF_MSG_COUNTER))
        encoded_packets: list[tuple[ClusterInvoke, EncodedGroupMessage]] = []
        for invoke in invokes:
            # Same counter for every epoch key and privacy variant: only the
            # matching key/header decrypts. Spec wants the P flag; CHIP omits it.
            for epoch_key in epoch_key_bytes(key_hex):
                for privacy in (False, True):
                    encoded = encode_group_invoke(
                        GroupSendParams(
                            fabric_id=fabric["fabric_id"],
                            compressed_fabric_id=fabric["compressed_fabric_id"],
                            source_node_id=fabric["source_node_id"],
                            group_id=self.group_id,
                            epoch_key=epoch_key,
                            endpoint_id=1,
                            message_counter=counter,
                            privacy=privacy,
                        ),
                        invoke,
                    )
                    encoded_packets.append((invoke, encoded))
            counter = next_message_counter(counter)

        destinations = list(groupcast_addresses(fabric["fabric_id"], self.group_id))
        destinations.extend(await self._async_overlay_addresses())
        try:
            for invoke, encoded in encoded_packets:
                if sender_url:
                    await async_inject_multicast(
                        self.hass,
                        sender_url,
                        destinations,
                        encoded.port,
                        encoded.packet,
                    )
                    self.last_send_path = (
                        "groupcast_supervisor" if sender_url == SUPERVISOR_SENDER else "groupcast_addon"
                    )
                else:
                    for address in destinations:
                        await self.hass.async_add_executor_job(
                            send_udp_multicast,
                            encoded.packet,
                            address,
                            encoded.port,
                        )
                    self.last_send_path = "groupcast_local"
                _LOGGER.info(
                    "Sent Matter groupcast %s to %s dests session=%s counter=%s via %s",
                    invoke.command_name,
                    len(destinations),
                    encoded.session_id,
                    encoded.message_counter,
                    self.last_send_path,
                )
        except Exception as err:  # noqa: BLE001
            self.last_send_path = "groupcast_failed"
            _LOGGER.warning("Plugin groupcast send failed (%s)", err)
            return False

        last_counter = encoded_packets[-1][1].message_counter
        data = dict(self.entry.data)
        data[CONF_MSG_COUNTER] = last_counter
        if sender_url and not sender_url.startswith("supervisor:"):
            data[CONF_SENDER_URL] = sender_url
        self.hass.config_entries.async_update_entry(self.entry, data=data)
        return True

    def _fabric_params(self) -> dict[str, int] | None:
        client = _get_matter_client(self.hass)
        info = getattr(client, "server_info", None)
        if info is None:
            return None
        if isinstance(info, dict):
            fabric_id = info.get("fabric_id", info.get("fabricId"))
            compressed = info.get("compressed_fabric_id", info.get("compressedFabricId"))
            node_id = info.get("controller_node_id", info.get("controllerNodeId", info.get("node_id")))
        else:
            fabric_id = getattr(info, "fabric_id", None) or getattr(info, "fabricId", None)
            compressed = getattr(info, "compressed_fabric_id", None) or getattr(
                info, "compressedFabricId", None
            )
            node_id = (
                getattr(info, "controller_node_id", None)
                or getattr(info, "controllerNodeId", None)
                or getattr(info, "node_id", None)
            )
        if fabric_id is None or compressed is None:
            return None
        return {
            "fabric_id": int(fabric_id),
            "compressed_fabric_id": int(compressed),
            "source_node_id": int(node_id) if node_id is not None else DEFAULT_CONTROLLER_NODE_ID,
        }

    async def _async_sender_url(self) -> str | None:
        if self._sender_url:
            return self._sender_url
        configured = self.entry.data.get(CONF_SENDER_URL)
        self._sender_url = await async_find_sender(self.hass, configured)
        if self._sender_url:
            _LOGGER.info("Using Matter Groupcast add-on at %s", self._sender_url)
        return self._sender_url

    async def _async_overlay_addresses(self) -> list[str]:
        """Thread OMR unicasts. Google is the primary BBR, so LAN multicast
        often never enters the mesh; the same group packet still works if it
        arrives on the bulb's operational address (port 5540).
        """
        if self._overlay_addresses is not None:
            return self._overlay_addresses
        client = _get_matter_client(self.hass)
        members = [member for member in self.async_members() if member.available]
        addrs: list[str] = []

        async def _one(member: GroupMember) -> list[str]:
            try:
                result = await client.send_command("get_node_ip_addresses", node_id=member.node_id)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("No overlay IPs for node %s: %s", member.node_id, err)
                return []
            found: list[str] = []
            values = result if isinstance(result, list) else []
            for item in values:
                text = str(item)
                if ":" in text and not text.lower().startswith("fe80:"):
                    found.append(text)
            return found

        results = await asyncio.gather(*[_one(member) for member in members], return_exceptions=True)
        seen: set[str] = set()
        for result in results:
            if isinstance(result, Exception):
                continue
            for address in result:
                if address not in seen:
                    seen.add(address)
                    addrs.append(address)
        self._overlay_addresses = addrs
        _LOGGER.info("Matter groupcast overlay unicast dests: %s", len(addrs))
        return addrs

    async def _async_unicast_invokes(self, invokes: list[ClusterInvoke]) -> None:
        client = _get_matter_client(self.hass)
        members = [m for m in self.async_members() if m.available]
        if not members:
            raise HomeAssistantError("No available Matter members to command")
        tasks = [
            client.send_command(
                "device_command",
                node_id=member.node_id,
                endpoint_id=member.endpoint_id,
                cluster_id=invoke.cluster_id,
                command_name=invoke.command_name,
                payload=invoke.payload,
            )
            for invoke in invokes
            for member in members
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
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
            payload={"groupID": self.group_id, "groupName": self.group_name[:16]},
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
