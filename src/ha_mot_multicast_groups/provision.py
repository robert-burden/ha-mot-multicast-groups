from __future__ import annotations

import base64
import secrets
from typing import Any

from ha_mot_multicast_groups.config import Settings
from ha_mot_multicast_groups.discover import MappedLight
from ha_mot_multicast_groups.matter_client import MatterClient

CLUSTER_GROUPS = 0x0004
CLUSTER_ONOFF = 0x0006
CLUSTER_ACCESS_CONTROL = 0x001F
CLUSTER_GROUP_KEY_MANAGEMENT = 0x003F

AUTH_MODE_CASE = 2
AUTH_MODE_GROUP = 3
PRIVILEGE_OPERATE = 3
PRIVILEGE_ADMINISTER = 5


def generate_group_key() -> str:
    return secrets.token_bytes(16).hex()


def group_key_bytes(key_hex: str) -> str:
    raw = bytes.fromhex(key_hex)
    if len(raw) != 16:
        raise ValueError("MATTER_GROUP_KEY_HEX must be 16 bytes (32 hex chars)")
    return base64.b64encode(raw).decode("ascii")


def epoch_keys(key_hex: str) -> tuple[str, str, str]:
    k0 = bytes.fromhex(key_hex)
    if len(k0) != 16:
        raise ValueError("MATTER_GROUP_KEY_HEX must be 16 bytes (32 hex chars)")
    k1 = k0[:-1] + bytes([k0[-1] ^ 0x01])
    k2 = k0[:-1] + bytes([k0[-1] ^ 0x02])
    encode = lambda k: base64.b64encode(k).decode("ascii")
    return encode(k0), encode(k1), encode(k2)


async def provision_node(
    matter: MatterClient,
    settings: Settings,
    light: MappedLight,
    existing_acl: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if light.node_id is None or light.endpoint_id is None:
        raise RuntimeError(f"Cannot provision {light.entity_id}: missing Matter node/endpoint")

    key_hex = settings.group_key_hex
    if not key_hex:
        raise RuntimeError("MATTER_GROUP_KEY_HEX is empty; generate one before join-group")

    key0, key1, key2 = epoch_keys(key_hex)
    keyset_payload = {
        "groupKeySetID": settings.group_keyset_id,
        "groupKeySecurityPolicy": 0,
        "epochKey0": key0,
        "epochStartTime0": 2220000,
        "epochKey1": key1,
        "epochStartTime1": 2220001,
        "epochKey2": key2,
        "epochStartTime2": 2220002,
    }
    keyset = await matter.device_command(
        light.node_id,
        0,
        CLUSTER_GROUP_KEY_MANAGEMENT,
        "keySetWrite",
        {"groupKeySet": keyset_payload},
    )

    binding = [
        {
            "groupId": settings.group_id,
            "groupKeySetID": settings.group_keyset_id,
        }
    ]
    keymap = await matter.write_attribute(light.node_id, "0/63/0", binding)

    add_group = await matter.device_command(
        light.node_id,
        light.endpoint_id,
        CLUSTER_GROUPS,
        "addGroup",
        {"groupID": settings.group_id, "groupName": settings.group_name},
    )

    acl_source = existing_acl
    if acl_source is None:
        raw = await matter.read_attribute(light.node_id, "0/31/0")
        acl_source = _extract_acl(raw)

    acl_entries = _merge_group_acl(acl_source, settings.group_id)
    acl = await matter.set_acl_entry(light.node_id, acl_entries)
    return {"keyset": keyset, "keymap": keymap, "add_group": add_group, "acl": acl}


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
        privilege = item.get("privilege", item.get("Privilege", item.get("1")))
        auth_mode = item.get("authMode", item.get("auth_mode", item.get("2")))
        subjects = item.get("subjects", item.get("Subjects", item.get("3")))
        targets = item.get("targets", item.get("Targets", item.get("4")))
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
        privilege = int(item.get("privilege") or item.get("Privilege") or 0)
        auth_mode = int(item.get("authMode") or item.get("auth_mode") or 0)
        subjects = item.get("subjects") if "subjects" in item else item.get("Subjects")
        targets = item.get("targets") if "targets" in item else item.get("targets", None)
        if targets is None:
            targets = item.get("Targets")
        entry = {
            "privilege": privilege,
            "auth_mode": auth_mode,
            "subjects": subjects,
            "targets": targets,
        }
        if auth_mode == AUTH_MODE_GROUP and privilege == PRIVILEGE_OPERATE:
            subj = list(subjects or [])
            if group_id not in subj:
                subj.append(group_id)
            entry["subjects"] = subj
            saw_group = True
        entries.append(entry)
    if not any(e["privilege"] == PRIVILEGE_ADMINISTER and e["auth_mode"] == AUTH_MODE_CASE for e in entries):
        raise RuntimeError("Refusing to write ACL: no existing Administer/CASE entry was read back")
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


async def unicast_onoff(matter: MatterClient, light: MappedLight, command: str) -> Any:
    if light.node_id is None or light.endpoint_id is None:
        raise RuntimeError(f"Cannot command {light.entity_id}: missing Matter node/endpoint")
    return await matter.device_command(
        light.node_id,
        light.endpoint_id,
        CLUSTER_ONOFF,
        command,
        {},
    )


def is_group_node_id(node_id: int) -> bool:
    return (node_id & 0xFFFFFFFFFFFF0000) == 0xFFFFFFFFFFFF0000


# matter.js Matter Server treats node IDs >= this as local test nodes and
# device_command returns without sending. Group NodeIds (0xFFFFFFFFFFFFXXXX)
# fall in that range, so multicast cannot go out via device_command.
MATTERJS_TEST_NODE_START = 0xFFFF_FFFE_0000_0000


async def group_onoff(matter: MatterClient, settings: Settings, command: str, endpoint_id: int = 1) -> Any:
    dest = settings.group_node_id
    if dest >= MATTERJS_TEST_NODE_START:
        raise RuntimeError(
            f"Group NodeId {hex(dest)} is in the Matter Server test-node range "
            f"(>= {hex(MATTERJS_TEST_NODE_START)}). device_command will not put a multicast "
            "packet on the wire. Device-side group membership is provisioned; the missing "
            "piece is a real controller group_command API."
        )
    return await matter.device_command(
        dest,
        endpoint_id,
        CLUSTER_ONOFF,
        command,
        {},
    )
