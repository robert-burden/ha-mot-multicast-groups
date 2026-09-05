from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.selector import EntitySelector, EntitySelectorConfig
import voluptuous as vol

from .const import (
    CONF_GROUP_ID,
    CONF_GROUP_NAME,
    CONF_SOURCE_ENTITY,
    DEFAULT_GROUP_ID,
    DEFAULT_GROUP_NAME,
    DOMAIN,
)

STEP_USER = vol.Schema(
    {
        vol.Required(CONF_SOURCE_ENTITY): EntitySelector(EntitySelectorConfig(domain="light")),
        vol.Optional(CONF_GROUP_NAME, default=DEFAULT_GROUP_NAME): str,
        vol.Optional(CONF_GROUP_ID, default=DEFAULT_GROUP_ID): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=0xFEFF)
        ),
    }
)


class MatterGroupcastConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow for Matter Groupcast."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if not self.hass.config_entries.async_loaded_entries("matter"):
            return self.async_abort(reason="matter_not_setup")

        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=self.add_suggested_values_to_schema(
                    STEP_USER,
                    {
                        CONF_SOURCE_ENTITY: "light.dining_room_chandelier",
                        CONF_GROUP_NAME: DEFAULT_GROUP_NAME,
                        CONF_GROUP_ID: DEFAULT_GROUP_ID,
                    },
                ),
            )

        source = user_input[CONF_SOURCE_ENTITY]
        await self.async_set_unique_id(f"{DOMAIN}:{source}")
        self._abort_if_unique_id_configured()

        state = self.hass.states.get(source)
        members = (state.attributes.get("entity_id") if state else None) or []
        if not members:
            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER,
                errors={"base": "not_a_group"},
            )

        title = (state.attributes.get("friendly_name") if state else None) or source
        return self.async_create_entry(title=title, data=user_input)
