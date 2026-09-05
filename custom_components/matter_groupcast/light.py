from __future__ import annotations

from typing import Any

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_HS_COLOR,
    ATTR_RGB_COLOR,
    ATTR_TRANSITION,
    ATTR_XY_COLOR,
    ColorMode,
    LightEntity,
    LightEntityFeature,
    filter_supported_color_modes,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.util import color as color_util

from .const import DOMAIN
from .matter_api import MatterGroupController


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    controller: MatterGroupController = entry.runtime_data
    async_add_entities([MatterGroupcastLight(controller)])


def _as_color_mode(value: Any) -> ColorMode | None:
    try:
        return ColorMode(value)
    except ValueError:
        return None


class MatterGroupcastLight(LightEntity):
    """Light that groupcasts On/Off, brightness, color, and color temperature."""

    _attr_should_poll = False
    _attr_supported_features = LightEntityFeature.TRANSITION

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

    def _source_attrs(self) -> dict[str, Any]:
        state = self.hass.states.get(self._controller.source_entity_id)
        if state is None:
            return {}
        return dict(state.attributes)

    @property
    def is_on(self) -> bool | None:
        return self._controller.async_is_on()

    @property
    def brightness(self) -> int | None:
        value = self._source_attrs().get("brightness")
        return int(value) if isinstance(value, (int, float)) else None

    @property
    def hs_color(self) -> tuple[float, float] | None:
        value = self._source_attrs().get("hs_color")
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return float(value[0]), float(value[1])
        return None

    @property
    def xy_color(self) -> tuple[float, float] | None:
        value = self._source_attrs().get("xy_color")
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return float(value[0]), float(value[1])
        return None

    @property
    def color_temp_kelvin(self) -> int | None:
        attrs = self._source_attrs()
        kelvin = attrs.get("color_temp_kelvin")
        if isinstance(kelvin, (int, float)):
            return int(kelvin)
        mireds = attrs.get("color_temp")
        if isinstance(mireds, (int, float)) and mireds > 0:
            return int(color_util.color_temperature_mired_to_kelvin(mireds))
        return None

    @property
    def min_color_temp_kelvin(self) -> int:
        value = self._source_attrs().get("min_color_temp_kelvin")
        return int(value) if isinstance(value, (int, float)) else 2000

    @property
    def max_color_temp_kelvin(self) -> int:
        value = self._source_attrs().get("max_color_temp_kelvin")
        return int(value) if isinstance(value, (int, float)) else 6535

    @property
    def color_mode(self) -> ColorMode | None:
        mode = _as_color_mode(self._source_attrs().get("color_mode"))
        if mode:
            return mode
        supported = self.supported_color_modes or set()
        if ColorMode.HS in supported:
            return ColorMode.HS
        if ColorMode.XY in supported:
            return ColorMode.XY
        if ColorMode.COLOR_TEMP in supported:
            return ColorMode.COLOR_TEMP
        if ColorMode.BRIGHTNESS in supported:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    @property
    def supported_color_modes(self) -> set[ColorMode] | None:
        raw = self._source_attrs().get("supported_color_modes")
        parsed: set[ColorMode] = set()
        for item in raw or []:
            mode = _as_color_mode(item)
            if mode is not None:
                parsed.add(mode)
        if not parsed:
            parsed = {ColorMode.HS, ColorMode.COLOR_TEMP}
        return filter_supported_color_modes(parsed)

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
        hs_color = kwargs.get(ATTR_HS_COLOR)
        xy_color = kwargs.get(ATTR_XY_COLOR)
        if hs_color is None and ATTR_RGB_COLOR in kwargs:
            rgb = kwargs[ATTR_RGB_COLOR]
            hs_color = color_util.color_RGB_to_hs(*rgb)
        kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        if kelvin is None and kwargs.get("color_temp"):
            kelvin = color_util.color_temperature_mired_to_kelvin(kwargs["color_temp"])
        await self._controller.async_turn_on(
            brightness=kwargs.get(ATTR_BRIGHTNESS),
            hs_color=hs_color,
            xy_color=xy_color,
            kelvin=int(kelvin) if kelvin is not None else None,
            transition_s=kwargs.get(ATTR_TRANSITION, 0),
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._controller.async_turn_off()
