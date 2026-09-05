"""Host-network UDP injector for Matter group multicast.

The Home Assistant integration encodes the Matter group message. This add-on
only puts the datagram on the host's IPv6 stack so the Thread border router
can forward it.
"""

from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = 5599
MATTER_UDP_PORT = 5540
MAX_PACKET = 1280


def send_multicast(address: str, port: int, packet: bytes) -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 64)
        sock.sendto(packet, (address, port, 0, 0))
    finally:
        sock.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        print(f"matter-groupcast: {fmt % args}")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/health":
            self._json(200, {"ok": True, "role": "matter-groupcast-sender"})
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
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"matter-groupcast: listening on 0.0.0.0:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
