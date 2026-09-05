from __future__ import annotations

import argparse
import asyncio
import os

import aiohttp

from ha_mot_multicast_groups.config import ROOT, load_settings
from ha_mot_multicast_groups.discover import discover_group, format_table
from ha_mot_multicast_groups.ha_client import HomeAssistantClient
from ha_mot_multicast_groups.matter_client import MatterClient, MatterError
from ha_mot_multicast_groups.provision import (
    generate_group_key,
    group_onoff,
    provision_node,
    unicast_onoff,
)


def _write_env_value(key: str, value: str) -> None:
    path = ROOT / ".env"
    lines = path.read_text().splitlines() if path.exists() else []
    found = False
    out: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    path.write_text("\n".join(out) + "\n")
    os.environ[key] = value


async def _ha_session() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))


async def cmd_discover(args: argparse.Namespace) -> int:
    settings = load_settings()
    async with await _ha_session() as session:
        async with HomeAssistantClient(settings, session) as ha:
            group, lights = await discover_group(ha, args.group or settings.ha_group_entity)
            print(f"{group.get('entity_id')}  state={group.get('state')}  members={len(lights)}")
            print(format_table(lights))
            missing = [l.entity_id for l in lights if l.node_id is None]
            if missing:
                print(f"\nCould not parse Matter node_id for {len(missing)} entit(y/ies). Matter Server mapping may still work.")
    return 0


async def cmd_ha_info(_args: argparse.Namespace) -> int:
    settings = load_settings()
    async with await _ha_session() as session:
        async with HomeAssistantClient(settings, session) as ha:
            cfg = await ha.get_config()
            entries = await ha.config_entries("matter")
            print(f"location: {cfg.get('location_name')}")
            print(f"version:  {cfg.get('version')}")
            print(f"internal_url: {cfg.get('internal_url')}")
            print(f"external_url: {cfg.get('external_url')}")
            print(f"matter component: {'matter' in (cfg.get('components') or [])}")
            print(f"matter config entries: {entries}")
    return 0


async def cmd_matter_info(_args: argparse.Namespace) -> int:
    settings = load_settings()
    async with await _ha_session() as session:
        async with MatterClient(settings.matter_ws_url, session) as matter:
            info = matter.server_info
            print(info)
            nodes = await matter.get_nodes()
            print(f"nodes: {len(nodes)}")
            for node in nodes[:20]:
                node_id = node.get("node_id") or node.get("nodeId")
                available = node.get("available")
                print(f"  node {node_id} available={available}")
            if len(nodes) > 20:
                print(f"  ... {len(nodes) - 20} more")
    return 0


async def _load_mapped(settings, session, entity_id: str | None = None):
    async with HomeAssistantClient(settings, session) as ha:
        _, lights = await discover_group(ha, settings.ha_group_entity)
    if entity_id:
        lights = [l for l in lights if l.entity_id == entity_id]
        if not lights:
            raise SystemExit(f"{entity_id} is not in {settings.ha_group_entity}")
    return lights


async def cmd_unicast(args: argparse.Namespace) -> int:
    settings = load_settings()
    async with await _ha_session() as session:
        lights = await _load_mapped(settings, session, args.entity)
        target = next((l for l in lights if l.available), lights[0])
        async with MatterClient(settings.matter_ws_url, session) as matter:
            result = await unicast_onoff(matter, target, args.command)
            print(f"{args.command} -> {target.entity_id} node={target.node_id} ep={target.endpoint_id}")
            print(result)
    return 0


async def cmd_join_group(args: argparse.Namespace) -> int:
    settings = load_settings()
    if not settings.group_key_hex:
        key = generate_group_key()
        _write_env_value("MATTER_GROUP_KEY_HEX", key)
        settings = load_settings()
        print(f"generated MATTER_GROUP_KEY_HEX and saved to .env")
    async with await _ha_session() as session:
        lights = await _load_mapped(settings, session)
        if args.limit:
            lights = lights[: args.limit]
        async with MatterClient(settings.matter_ws_url, session) as matter:
            for light in lights:
                if not light.available:
                    print(f"skip unavailable {light.entity_id}")
                    continue
                print(f"provisioning {light.entity_id} node={light.node_id} ...")
                try:
                    result = await provision_node(matter, settings, light)
                    print(f"  ok: {result}")
                except MatterError as exc:
                    print(f"  failed: {exc}")
                    if not args.continue_on_error:
                        return 1
    return 0


async def cmd_group(args: argparse.Namespace) -> int:
    settings = load_settings()
    async with await _ha_session() as session:
        async with MatterClient(settings.matter_ws_url, session) as matter:
            try:
                result = await group_onoff(matter, settings, args.command)
                print(f"group {hex(settings.group_id)} {args.command} via node {hex(settings.group_node_id)}")
                print(result)
                return 0
            except (MatterError, RuntimeError) as exc:
                print(f"group command failed: {exc}")
                return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="matter-groups")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover", help="Map HA helper group members to Matter node IDs")
    p.add_argument("--group", help="Override HA_GROUP_ENTITY")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("ha-info", help="Show Home Assistant version and Matter integration")
    p.set_defaults(func=cmd_ha_info)

    p = sub.add_parser("matter-info", help="Connect to Matter Server and list nodes")
    p.set_defaults(func=cmd_matter_info)

    p = sub.add_parser("unicast", help="Send On/Off to one chandelier bulb via Matter Server")
    p.add_argument("command", choices=["on", "off", "toggle"])
    p.add_argument("--entity", help="Specific light entity_id")
    p.set_defaults(func=cmd_unicast)

    p = sub.add_parser("join-group", help="Provision Matter group keys/membership/ACL on chandelier bulbs")
    p.add_argument("--limit", type=int, help="Only the first N members (useful for a 1-bulb trial)")
    p.add_argument("--continue-on-error", action="store_true")
    p.set_defaults(func=cmd_join_group)

    p = sub.add_parser("group", help="Send On/Off to the Matter group NodeId")
    p.add_argument("command", choices=["on", "off", "toggle"])
    p.set_defaults(func=cmd_group)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(args.func(args))
