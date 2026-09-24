"""HTTP client for the host-network Matter Groupcast add-on."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import aiohttp
from homeassistant.core import HomeAssistant

from .sender_urls import (
    ADDON_SLUG_SUFFIX,
    GITHUB_REPO_SLUG,
    SUPERVISOR_SENDER,
    addon_hosts_from_info,
    build_sender_urls,
    hyphenate_slug,
    lan_hosts_from_network_info,
)

_LOGGER = logging.getLogger(__name__)

SEND_TIMEOUT = aiohttp.ClientTimeout(total=15.0, sock_connect=0.6)


def candidate_sender_urls(hass: HomeAssistant, configured: str | None = None) -> list[str]:
    extra: list[str] = []
    extra.extend(_supervisor_addon_hosts(hass))
    extra.extend(_supervisor_lan_hosts(hass))
    http_configured = None if configured and configured.startswith("supervisor:") else configured
    return build_sender_urls(
        configured=http_configured,
        extra_hosts=extra,
        hass_host=_hass_host(hass),
    )


def sender_addon_slug(hass: HomeAssistant) -> str | None:
    try:
        from homeassistant.components.hassio import get_addons_info
    except ImportError:
        return GITHUB_REPO_SLUG if hassio_prefers_addon(hass) else None
    try:
        addons = get_addons_info(hass)
    except Exception:  # noqa: BLE001
        addons = None
    if isinstance(addons, dict):
        for slug in addons:
            if ADDON_SLUG_SUFFIX in str(slug):
                return str(slug)
    return GITHUB_REPO_SLUG if hassio_prefers_addon(hass) else None


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


def _stdin_service(hass: HomeAssistant) -> tuple[str, str] | None:
    if hass.services.has_service("hassio", "app_stdin"):
        return "app_stdin", "app"
    if hass.services.has_service("hassio", "addon_stdin"):
        return "addon_stdin", "addon"
    return None


async def async_find_sender(hass: HomeAssistant, configured: str | None = None) -> str | None:
    # Home Assistant Core is firewalled off host-network add-on ports. Supervisor
    # stdin can still reach the sender.
    if hassio_prefers_addon(hass) and _stdin_service(hass) and sender_addon_slug(hass):
        _LOGGER.info("Using Supervisor stdin for Matter Groupcast sender")
        return SUPERVISOR_SENDER

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
    address: str | list[str],
    port: int,
    packet: bytes,
) -> None:
    addresses = [address] if isinstance(address, str) else list(address)
    payload = {
        "address": addresses[0],
        "addresses": addresses,
        "port": port,
        "packet": packet.hex(),
    }
    if sender_url == SUPERVISOR_SENDER:
        await _async_inject_stdin(hass, payload)
        return
    async with aiohttp.ClientSession(timeout=SEND_TIMEOUT) as session:
        async with session.post(
            f"{sender_url.rstrip('/')}/multicast",
            json=payload,
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"Groupcast add-on returned HTTP {resp.status}: {text[:200]}")
            body: dict[str, Any] = await resp.json(content_type=None)
            if not body.get("ok"):
                raise RuntimeError(body.get("error") or "Groupcast add-on send failed")


async def _async_inject_stdin(hass: HomeAssistant, payload: dict[str, Any]) -> None:
    service = _stdin_service(hass)
    slug = sender_addon_slug(hass)
    if not service or not slug:
        raise RuntimeError("Supervisor stdin is not available for the Groupcast sender")
    service_name, slug_key = service
    await hass.services.async_call(
        "hassio",
        service_name,
        {slug_key: slug, "input": payload},
        blocking=True,
    )


def hassio_prefers_addon(hass: HomeAssistant) -> bool:
    try:
        from homeassistant.helpers.hassio import is_hassio

        return bool(is_hassio(hass))
    except Exception:  # noqa: BLE001
        return False
