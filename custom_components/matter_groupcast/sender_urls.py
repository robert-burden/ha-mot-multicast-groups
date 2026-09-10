"""HA-import-free URL candidates for the Matter Groupcast sender add-on."""

from __future__ import annotations

from typing import Any

ADDON_PORT = 5599
ADDON_SLUG_SUFFIX = "matter_groupcast_sender"
# Supervisor slug prefix for https://github.com/robert-burden/ha-mot-multicast-groups
GITHUB_REPO_SLUG = "1c2d22dc_matter_groupcast_sender"


def hyphenate_slug(slug: str) -> str:
    return slug.replace("_", "-")


def host_url(host: str, port: int = ADDON_PORT) -> str:
    host = host.strip().rstrip("/")
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    if "://" not in host and host.count(":") == 1:
        return f"http://{host}"
    return f"http://{host}:{port}"


def addon_hosts_from_info(addons: dict[str, Any] | None) -> list[str]:
    """Return hostnames/IPs Supervisor knows for the sender add-on."""
    hosts: list[str] = []
    if not isinstance(addons, dict):
        return hosts
    for slug, info in addons.items():
        slug_s = str(slug)
        if ADDON_SLUG_SUFFIX not in slug_s:
            continue
        hosts.append(hyphenate_slug(slug_s))
        hosts.append(f"{hyphenate_slug(slug_s)}.local.hass.io")
        if isinstance(info, dict):
            hostname = info.get("hostname")
            if hostname:
                hosts.append(str(hostname))
                hosts.append(f"{hostname}.local.hass.io")
            ip = info.get("ip_address")
            if ip:
                hosts.append(str(ip))
    return hosts


def lan_hosts_from_network_info(info: Any) -> list[str]:
    hosts: list[str] = []
    if not isinstance(info, dict):
        return hosts
    interfaces = info.get("interfaces") or info.get("interface") or []
    if isinstance(interfaces, dict):
        interfaces = list(interfaces.values())
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        ipv4 = iface.get("ipv4") or {}
        addresses = ipv4.get("address") or ipv4.get("addresses") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        for addr in addresses:
            ip = str(addr).split("/", 1)[0]
            if ip.startswith(("10.", "192.168.")) or (
                ip.startswith("172.") and not ip.startswith("172.30.32.")
            ):
                hosts.append(ip)
    return hosts


def build_sender_urls(
    *,
    configured: str | None = None,
    extra_hosts: list[str] | None = None,
    hass_host: str | None = None,
    port: int = ADDON_PORT,
) -> list[str]:
    """Ordered URLs to probe. Supervisor DNS names come first; mDNS last."""
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        url = url.rstrip("/")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)

    if configured:
        add(host_url(configured, port) if "://" not in configured else configured.rstrip("/"))
    for host in extra_hosts or []:
        add(host_url(host, port))

    add(host_url(hyphenate_slug(GITHUB_REPO_SLUG), port))
    add(host_url(f"{hyphenate_slug(GITHUB_REPO_SLUG)}.local.hass.io", port))
    add(host_url("172.30.32.1", port))
    add(host_url(ADDON_SLUG_SUFFIX, port))
    add(host_url(hyphenate_slug(ADDON_SLUG_SUFFIX), port))
    add(host_url("127.0.0.1", port))
    add(host_url("supervisor", port))
    if hass_host:
        add(host_url(hass_host, port))
    add(host_url("homeassistant.local", port))
    return urls
