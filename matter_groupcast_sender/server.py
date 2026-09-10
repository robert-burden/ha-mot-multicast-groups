"""Host-network UDP injector for Matter group multicast.

The Home Assistant integration encodes the Matter group message. This add-on
only puts the datagram on the host's IPv6 stack so the Thread border router
can forward it.
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


def _backbone_iface() -> tuple[int, str | None]:
    """LAN interface index and a global/ULA IPv6 source address, if any."""
    names = {name: idx for idx, name in socket.if_nameindex()}
    by_index: dict[int, str] = {idx: name for name, idx in names.items()}
    preferred_idx = next((names[n] for n in PREFERRED_IFACES if n in names), None)

    best: tuple[int, str | None] | None = None
    proc = Path("/proc/net/if_inet6")
    if proc.is_file():
        for line in proc.read_text().splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            raw, idx_hex, _plen, scope_hex, _flags, ifname = parts[:6]
            if ifname in {"lo", "hassio", "docker0", "flannel.1"}:
                continue
            scope = int(scope_hex, 16)
            if scope & 0x20:  # link-local
                continue
            idx = int(idx_hex, 16)
            try:
                addr = str(IPv6Address(bytes.fromhex(raw)))
            except ValueError:
                continue
            if preferred_idx is not None and idx == preferred_idx:
                return idx, addr
            if best is None:
                best = (idx, addr)
            elif by_index.get(idx) in PREFERRED_IFACES:
                best = (idx, addr)
    if best:
        return best
    if preferred_idx is not None:
        return preferred_idx, None
    return 0, None


def send_multicast(address: str, port: int, packet: bytes) -> None:
    ifindex, src = _backbone_iface()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 64)
        if ifindex:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        if src:
            sock.bind((src, 0, 0, ifindex))
        sock.sendto(packet, (address, port, 0, ifindex))
        print(
            f"matter-groupcast: sent {len(packet)} bytes to [{address}]:{port} "
            f"ifindex={ifindex} src={src}",
            flush=True,
        )
    finally:
        sock.close()


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
            ifindex, src = _backbone_iface()
            self._json(
                200,
                {
                    "ok": True,
                    "role": "matter-groupcast-sender",
                    "ifindex": ifindex,
                    "src": src,
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
            address = str(data["address"])
            port = int(data.get("port") or MATTER_UDP_PORT)
            packet_hex = str(data["packet"])
            packet = bytes.fromhex(packet_hex)
        except (KeyError, ValueError, json.JSONDecodeError) as err:
            self._json(400, {"ok": False, "error": f"invalid json: {err}"})
            return
        if not packet or len(packet) > MAX_PACKET:
            self._json(400, {"ok": False, "error": "packet too large or empty"})
            return
        try:
            send_multicast(address, port, packet)
        except OSError as err:
            self._json(500, {"ok": False, "error": str(err)})
            return
        self._json(
            200,
            {
                "ok": True,
                "bytes": len(packet),
                "address": address,
                "port": port,
            },
        )


def main() -> None:
    ifindex, src = _backbone_iface()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(
        f"matter-groupcast: listening on 0.0.0.0:{LISTEN_PORT} "
        f"backbone ifindex={ifindex} src={src}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
