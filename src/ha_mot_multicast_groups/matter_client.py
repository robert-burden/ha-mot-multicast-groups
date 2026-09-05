from __future__ import annotations

from typing import Any
from uuid import uuid4

import aiohttp


class MatterError(RuntimeError):
    def __init__(self, error_code: int | None, details: str) -> None:
        super().__init__(f"Matter server error {error_code}: {details}")
        self.error_code = error_code
        self.details = details


class MatterClient:
    def __init__(self, ws_url: str, session: aiohttp.ClientSession) -> None:
        if not ws_url:
            raise SystemExit(
                "MATTER_WS_URL is empty. Expose the Matter Server WebSocket on LAN port 5580 "
                "and set MATTER_WS_URL=ws://<ha-lan-ip>:5580/ws in .env"
            )
        self._ws_url = ws_url
        self._session = session
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self.server_info: dict[str, Any] = {}

    async def __aenter__(self) -> MatterClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def connect(self) -> dict[str, Any]:
        self._ws = await self._session.ws_connect(self._ws_url, heartbeat=30, max_msg_size=0)
        hello = await self._ws.receive_json()
        self.server_info = hello
        return hello

    async def close(self) -> None:
        if self._ws is not None and not self._ws.closed:
            await self._ws.close()
        self._ws = None

    async def send(self, command: str, args: dict[str, Any] | None = None) -> Any:
        if self._ws is None:
            raise RuntimeError("Matter websocket is not connected")
        message_id = uuid4().hex
        payload: dict[str, Any] = {"message_id": message_id, "command": command}
        if args:
            payload["args"] = args
        await self._ws.send_json(payload)
        while True:
            incoming = await self._ws.receive_json()
            if incoming.get("message_id") != message_id:
                continue
            if "error_code" in incoming:
                raise MatterError(incoming.get("error_code"), str(incoming.get("details") or incoming))
            return incoming.get("result")

    async def get_nodes(self) -> list[dict[str, Any]]:
        result = await self.send("get_nodes")
        if isinstance(result, dict) and "nodes" in result:
            return list(result["nodes"])
        if isinstance(result, list):
            return result
        return []

    async def get_node(self, node_id: int) -> dict[str, Any]:
        return await self.send("get_node", {"node_id": node_id})

    async def read_attribute(self, node_id: int, attribute_path: str | list[str]) -> Any:
        return await self.send(
            "read_attribute",
            {"node_id": node_id, "attribute_path": attribute_path},
        )

    async def write_attribute(self, node_id: int, attribute_path: str, value: Any) -> Any:
        return await self.send(
            "write_attribute",
            {"node_id": node_id, "attribute_path": attribute_path, "value": value},
        )

    async def device_command(
        self,
        node_id: int,
        endpoint_id: int,
        cluster_id: int,
        command_name: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        return await self.send(
            "device_command",
            {
                "node_id": node_id,
                "endpoint_id": endpoint_id,
                "cluster_id": cluster_id,
                "command_name": command_name,
                "payload": payload or {},
            },
        )

    async def set_acl_entry(self, node_id: int, entry: list[dict[str, Any]]) -> Any:
        return await self.send("set_acl_entry", {"node_id": node_id, "entry": entry})
