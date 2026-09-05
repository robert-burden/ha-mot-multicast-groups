from __future__ import annotations

from typing import Any

import aiohttp

from ha_mot_multicast_groups.config import Settings


class HomeAssistantClient:
    def __init__(self, settings: Settings, session: aiohttp.ClientSession) -> None:
        self._settings = settings
        self._session = session
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._msg_id = 0

    async def __aenter__(self) -> HomeAssistantClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def connect(self) -> None:
        self._ws = await self._session.ws_connect(self._settings.ha_ws_url, heartbeat=30)
        hello = await self._ws.receive_json()
        if hello.get("type") != "auth_required":
            raise RuntimeError(f"Unexpected HA hello: {hello}")
        await self._ws.send_json({"type": "auth", "access_token": self._settings.ha_token})
        auth = await self._ws.receive_json()
        if auth.get("type") != "auth_ok":
            raise RuntimeError(f"Home Assistant auth failed: {auth}")

    async def close(self) -> None:
        if self._ws is not None and not self._ws.closed:
            await self._ws.close()
        self._ws = None

    async def send(self, payload: dict[str, Any]) -> Any:
        if self._ws is None:
            raise RuntimeError("Home Assistant websocket is not connected")
        self._msg_id += 1
        msg_id = self._msg_id
        await self._ws.send_json({"id": msg_id, **payload})
        while True:
            incoming = await self._ws.receive_json()
            if incoming.get("id") != msg_id:
                continue
            if not incoming.get("success", False):
                error = incoming.get("error") or incoming
                raise RuntimeError(f"HA command failed: {error}")
            return incoming.get("result")

    async def rest_get(self, path: str) -> Any:
        url = f"{self._settings.ha_url}{path}"
        headers = {"Authorization": f"Bearer {self._settings.ha_token}"}
        async with self._session.get(url, headers=headers) as resp:
            if resp.status == 401:
                raise RuntimeError("Home Assistant rejected HA_TOKEN (401). Create a new long-lived token.")
            resp.raise_for_status()
            return await resp.json()

    async def get_state(self, entity_id: str) -> dict[str, Any]:
        return await self.rest_get(f"/api/states/{entity_id}")

    async def get_config(self) -> dict[str, Any]:
        return await self.rest_get("/api/config")

    async def entity_registry_get(self, entity_id: str) -> dict[str, Any]:
        return await self.send({"type": "config/entity_registry/get", "entity_id": entity_id})

    async def entity_registry_list(self) -> list[dict[str, Any]]:
        return await self.send({"type": "config/entity_registry/list"})

    async def device_registry_list(self) -> list[dict[str, Any]]:
        return await self.send({"type": "config/device_registry/list"})

    async def config_entries(self, domain: str) -> Any:
        return await self.send({"type": "config_entries/get", "domain": domain})
