"""Host-network UDP injector for Matter group multicast.

The Home Assistant integration encodes the Matter group message. This add-on
puts that datagram on every host IPv6 multicast interface, including the
Thread wpan device. CHIP does the same: group messages are sent on each
up multicast interface, not only the LAN NIC. Sending solely on eno1 never
reaches Thread bulbs unless the border router already has an MLR listener.
"""

from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv6Address
from pathlib import Path

LISTEN_PORT = 5599
MATTER_UDP_PORT = 5540
MAX_PACKET = 1280
PREFERRED_IFACES = ("eno1", "eth0", "end0", "enp1s0", "enp0s3", "enp0s25")
THREAD_PREFIXES = ("wpan", "otbr", "openthread", "spinel")
SKIP_EXACT = {"lo", "docker0", "hassio", "flannel.1"}
SKIP_PREFIXES = ("veth", "br-", "docker", "hassio", "flannel")


def iface_allowed(name: str) -> bool:
    if name in SKIP_EXACT:
        return False
    return not any(name.startswith(prefix) for prefix in SKIP_PREFIXES)


def is_thread_iface(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in THREAD_PREFIXES)


def _multicast_ifaces() -> list[tuple[int, str | None, str]]:
    """(ifindex, unicast source, name) for each host iface that can groupcast."""
    names = {name: idx for idx, name in socket.if_nameindex() if iface_allowed(name)}
    by_index = {idx: name for name, idx in names.items()}
    sources: dict[int, str] = {}
    thread_linklocal: dict[int, str] = {}

    proc = Path("/proc/net/if_inet6")
    if proc.is_file():
        for line in proc.read_text().splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            raw, idx_hex, _plen, scope_hex, _flags, ifname = parts[:6]
            if not iface_allowed(ifname):
                continue
            idx = int(idx_hex, 16)
            names.setdefault(ifname, idx)
            by_index[idx] = ifname
            try:
                addr = str(IPv6Address(bytes.fromhex(raw)))
            except ValueError:
                continue
            scope = int(scope_hex, 16)
            if scope & 0x20:  # link-local
                if is_thread_iface(ifname):
                    thread_linklocal.setdefault(idx, addr)
                continue
            sources.setdefault(idx, addr)

    targets: list[tuple[int, str | None, str]] = []
    seen: set[int] = set()

    def add(idx: int, src: str | None, name: str) -> None:
        if idx in seen or not name:
            return
        seen.add(idx)
        targets.append((idx, src, name))

    for preferred in PREFERRED_IFACES:
        if preferred in names:
            idx = names[preferred]
            add(idx, sources.get(idx), preferred)
    for idx, name in sorted(by_index.items(), key=lambda item: item[1]):
        if is_thread_iface(name):
            add(idx, sources.get(idx) or thread_linklocal.get(idx), name)
    for idx, src in sources.items():
        add(idx, src, by_index.get(idx, f"if{idx}"))
    return targets


def is_multicast_address(address: str) -> bool:
    try:
        return IPv6Address(address).is_multicast
    except ValueError:
        return True


def _send_one(address: str, port: int, packet: bytes, ifindex: int, src: str | None, name: str, *, multicast: bool) -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        if multicast:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 64)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
            if ifindex:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 64)
        if src:
            sock.bind((src, 0, 0, ifindex))
        if multicast and ifindex:
            try:
                group = socket.inet_pton(socket.AF_INET6, address)
                sock.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_JOIN_GROUP,
                    group + ifindex.to_bytes(4, "little"),
                )
            except OSError as err:
                print(f"matter-groupcast: join {address} on {name} failed: {err}", flush=True)
        scope_id = ifindex if multicast else 0
        sock.sendto(packet, (address, port, 0, scope_id))
        print(
            f"matter-groupcast: sent {len(packet)} bytes to [{address}]:{port} "
            f"iface={name} ifindex={ifindex} src={src}",
            flush=True,
        )
    finally:
        sock.close()


def send_multicast(address: str, port: int, packet: bytes) -> None:
    multicast = is_multicast_address(address)
    targets = _multicast_ifaces()
    if not multicast:
        # Unicast overlay must use the LAN path (Google BBR). Injecting on
        # wpan0 hits ChannelAccessFailure and never reaches the bulbs.
        targets = [(idx, src, name) for idx, src, name in targets if not is_thread_iface(name)] or targets
    if not targets:
        raise OSError("no IPv6 multicast interface")
    errors: list[str] = []
    sent = 0
    for ifindex, src, name in targets:
        try:
            _send_one(address, port, packet, ifindex, src, name, multicast=multicast)
            sent += 1
        except OSError as err:
            errors.append(f"{name}: {err}")
            print(f"matter-groupcast: send failed on {name}: {err}", flush=True)
    if sent == 0:
        raise OSError("; ".join(errors) or "multicast send failed")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        print(f"matter-groupcast: {fmt % args}", flush=True)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/health":
            ifaces = [
                {"ifindex": idx, "src": src, "name": name} for idx, src, name in _multicast_ifaces()
            ]
            self._json(
                200,
                {
                    "ok": True,
                    "role": "matter-groupcast-sender",
                    "ifaces": ifaces,
                    "ifindex": ifaces[0]["ifindex"] if ifaces else 0,
                    "src": ifaces[0]["src"] if ifaces else None,
                },
            )
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/multicast":
            self._json(404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > 16_384:
            self._json(400, {"ok": False, "error": "invalid body"})
            return
        try:
            data = json.loads(self.rfile.read(length))
            handle_command(data)
        except (KeyError, ValueError, json.JSONDecodeError, OSError) as err:
            status = 500 if isinstance(err, OSError) else 400
            self._json(status, {"ok": False, "error": str(err)})
            return
        self._json(200, {"ok": True, "address": data.get("address"), "port": data.get("port")})


def handle_command(data: dict) -> None:
    port = int(data.get("port") or MATTER_UDP_PORT)
    packet = bytes.fromhex(str(data["packet"]))
    if not packet or len(packet) > MAX_PACKET:
        raise ValueError("packet too large or empty")
    addresses = data.get("addresses") or [data["address"]]
    if not isinstance(addresses, list) or not addresses:
        raise ValueError("address or addresses required")
    errors: list[str] = []
    sent = 0
    for raw in addresses:
        address = str(raw)
        try:
            send_multicast(address, port, packet)
            sent += 1
        except OSError as err:
            errors.append(f"{address}: {err}")
            print(f"matter-groupcast: send failed to {address}: {err}", flush=True)
    if sent == 0:
        raise OSError("; ".join(errors) or "send failed")


def _stdin_loop() -> None:
    import sys
    import time

    print("matter-groupcast: reading Supervisor stdin", flush=True)
    buf = ""
    while True:
        chunk = sys.stdin.read(1)
        if chunk == "":
            time.sleep(0.25)
            continue
        buf += chunk
        if chunk != "\n" and len(buf) < 16_384:
            try:
                data = json.loads(buf)
            except json.JSONDecodeError:
                continue
            buf = ""
            try:
                handle_command(data)
            except Exception as err:  # noqa: BLE001
                print(f"matter-groupcast: stdin command failed: {err}", flush=True)
            continue
        if chunk == "\n":
            line = buf.strip()
            buf = ""
            if not line:
                continue
            try:
                handle_command(json.loads(line))
            except Exception as err:  # noqa: BLE001
                print(f"matter-groupcast: stdin command failed: {err}", flush=True)


def main() -> None:
    import threading

    ifaces = _multicast_ifaces()
    threading.Thread(target=_stdin_loop, name="stdin", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    summary = ", ".join(f"{name}({idx}/{src})" for idx, src, name in ifaces) or "none"
    print(
        f"matter-groupcast: listening on 0.0.0.0:{LISTEN_PORT} ifaces=[{summary}]",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
