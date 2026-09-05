"""HTTP client for the host-network Matter Groupcast add-on."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from aiohttp import ClientTimeout
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.hassio import is_hassio

_LOGGER = logging.getLogger(__name__)

ADDON_PORT = 5599
SEND_TIMEOUT = ClientTimeout(total=2.0)


def candidate_sender_urls(hass: HomeAssistant, configured: str | None = None) -> list[str]:
    urls: list[str] = []
    if configured:
        urls.append(configured.rstrip("/"))
    urls.extend(
        [
            f"http://127.0.0.1:{ADDON_PORT}",
            f"http://homeassistant.local:{ADDON_PORT}",
            f"http://matter_groupcast_sender:{ADDON_PORT}",
            f"http://supervisor:{ADDON_PORT}",
            f"http://172.30.32.1:{ADDON_PORT}",
        ]
    )
    host = _hass_host(hass)
    if host:
        urls.append(f"http://{host}:{ADDON_PORT}")
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


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
    session = async_get_clientsession(hass)
    for url in candidate_sender_urls(hass, configured):
        try:
            async with session.get(f"{url}/health", timeout=SEND_TIMEOUT) as resp:
                if resp.status == 200:
                    payload = await resp.json(content_type=None)
                    if payload.get("ok"):
                        return url
        except Exception:  # noqa: BLE001 — probe a list of possible add-on URLs
            continue
    return None


async def async_inject_multicast(
    hass: HomeAssistant,
    sender_url: str,
    address: str,
    port: int,
    packet: bytes,
) -> None:
    session = async_get_clientsession(hass)
    async with session.post(
        f"{sender_url.rstrip('/')}/multicast",
        json={"address": address, "port": port, "packet": packet.hex()},
        timeout=SEND_TIMEOUT,
    ) as resp:
        if resp.status != 200:
            text = await resp.text()
            raise RuntimeError(f"Groupcast add-on returned HTTP {resp.status}: {text[:200]}")
        payload: dict[str, Any] = await resp.json(content_type=None)
        if not payload.get("ok"):
            raise RuntimeError(payload.get("error") or "Groupcast add-on send failed")


def hassio_prefers_addon(hass: HomeAssistant) -> bool:
    try:
        return bool(is_hassio(hass))
    except Exception:  # noqa: BLE001
        return False
