"""HTTP client for the host-network Matter Groupcast add-on."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import aiohttp
from homeassistant.core import HomeAssistant

from .sender_urls import (
    ADDON_PORT,
    ADDON_SLUG_SUFFIX,
    addon_hosts_from_info,
    build_sender_urls,
    hyphenate_slug,
    lan_hosts_from_network_info,
)

_LOGGER = logging.getLogger(__name__)

SEND_TIMEOUT = aiohttp.ClientTimeout(total=2.0, sock_connect=0.6)


def candidate_sender_urls(hass: HomeAssistant, configured: str | None = None) -> list[str]:
    extra: list[str] = []
    extra.extend(_supervisor_addon_hosts(hass))
    extra.extend(_supervisor_lan_hosts(hass))
    return build_sender_urls(
        configured=configured,
        extra_hosts=extra,
        hass_host=_hass_host(hass),
    )


def _supervisor_addon_hosts(hass: HomeAssistant) -> list[str]:
    try:
        from homeassistant.components.hassio import get_addons_info, hostname_from_addon_slug
    except ImportError:
        return []
    try:
        addons = get_addons_info(hass)
    except Exception:  # noqa: BLE001
        return []
    hosts = addon_hosts_from_info(addons if isinstance(addons, dict) else None)
    if isinstance(addons, dict):
        for slug in addons:
            slug_s = str(slug)
            if ADDON_SLUG_SUFFIX in slug_s:
                try:
                    hosts.append(hostname_from_addon_slug(slug_s))
                except Exception:  # noqa: BLE001
                    hosts.append(hyphenate_slug(slug_s))
    return hosts


def _supervisor_lan_hosts(hass: HomeAssistant) -> list[str]:
    try:
        from homeassistant.components.hassio import get_network_info
    except ImportError:
        return []
    try:
        info = get_network_info(hass)
    except Exception:  # noqa: BLE001
        return []
    return lan_hosts_from_network_info(info)


def _hass_host(hass: HomeAssistant) -> str | None:
    internal = getattr(hass.config, "internal_url", None)
    if not internal:
        return None
    host = urlparse(internal).hostname
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return None
    if host.endswith(".local") or host.endswith(".lan"):
        return host
    if host.startswith(("10.", "192.168.", "172.")):
        return host
    return None


async def async_find_sender(hass: HomeAssistant, configured: str | None = None) -> str | None:
    urls = candidate_sender_urls(hass, configured)
    async with aiohttp.ClientSession(timeout=SEND_TIMEOUT) as session:
        for url in urls:
            try:
                async with session.get(f"{url}/health") as resp:
                    if resp.status != 200:
                        continue
                    payload = await resp.json(content_type=None)
                    if payload.get("ok"):
                        _LOGGER.info("Matter Groupcast sender reachable at %s", url)
                        return url
            except Exception as err:  # noqa: BLE001 — probe a list of possible add-on URLs
                _LOGGER.debug("Sender probe failed for %s: %s", url, err)
                continue
    _LOGGER.warning(
        "Matter Groupcast sender not reachable. Probed: %s",
        ", ".join(urls),
    )
    return None


async def async_inject_multicast(
    hass: HomeAssistant,
    sender_url: str,
    address: str,
    port: int,
    packet: bytes,
) -> None:
    del hass  # API keeps hass for call-site compatibility with other HA clients.
    async with aiohttp.ClientSession(timeout=SEND_TIMEOUT) as session:
        async with session.post(
            f"{sender_url.rstrip('/')}/multicast",
            json={"address": address, "port": port, "packet": packet.hex()},
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"Groupcast add-on returned HTTP {resp.status}: {text[:200]}")
            payload: dict[str, Any] = await resp.json(content_type=None)
            if not payload.get("ok"):
                raise RuntimeError(payload.get("error") or "Groupcast add-on send failed")


def hassio_prefers_addon(hass: HomeAssistant) -> bool:
    try:
        from homeassistant.helpers.hassio import is_hassio

        return bool(is_hassio(hass))
    except Exception:  # noqa: BLE001
        return False
