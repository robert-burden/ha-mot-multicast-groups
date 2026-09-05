from __future__ import annotations

from typing import Any

from homeassistant.components.light import ColorMode, LightEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_state_change_event

from .const import DOMAIN
from .matter_api import MatterGroupController


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    controller: MatterGroupController = entry.runtime_data
    async_add_entities([MatterGroupcastLight(controller)])


class MatterGroupcastLight(LightEntity):
    """Light that tries Matter groupcast, then concurrent unicast."""

    _attr_supported_color_modes = {ColorMode.ONOFF}
    _attr_color_mode = ColorMode.ONOFF
    _attr_should_poll = False

    def __init__(self, controller: MatterGroupController) -> None:
        self._controller = controller
        self._attr_unique_id = f"{DOMAIN}_{controller.entry.entry_id}"
        source = controller.hass.states.get(controller.source_entity_id)
        self._attr_name = f"{(source.name if source else 'Chandelier')} (Matter group)"

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_track_state_change_event(
                self.hass,
                [self._controller.source_entity_id, *self._controller.async_member_entity_ids()],
                self._async_member_changed,
            )
        )

    @callback
    def _async_member_changed(self, _event: Any) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        return self._controller.async_is_on()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        members = self._controller.async_members()
        return {
            "source_entity": self._controller.source_entity_id,
            "matter_group_id": self._controller.group_id,
            "member_count": len(members),
            "send_path": self._controller.last_send_path,
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._controller.async_turn(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._controller.async_turn(False)
