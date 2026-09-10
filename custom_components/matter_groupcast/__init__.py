from __future__ import annotations

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
import voluptuous as vol

from .const import DOMAIN, PLATFORMS, SERVICE_PROVISION
from .matter_api import MatterGroupController

type MatterGroupcastConfigEntry = ConfigEntry[MatterGroupController]


async def async_setup(hass: HomeAssistant, _config: ConfigType) -> bool:
    """Set up the Matter Groupcast component."""

    async def _handle_provision(call: ServiceCall) -> None:
        entry_id = call.data.get("entry_id")
        entries = [
            entry
            for entry in hass.config_entries.async_entries(DOMAIN)
            if entry.state is ConfigEntryState.LOADED and (entry_id is None or entry.entry_id == entry_id)
        ]
        if not entries:
            raise HomeAssistantError("No Matter Groupcast config entry is loaded")
        for entry in entries:
            controller: MatterGroupController = entry.runtime_data
            await controller.async_provision()

    hass.services.async_register(
        DOMAIN,
        SERVICE_PROVISION,
        _handle_provision,
        schema=vol.Schema({vol.Optional("entry_id"): cv.string}),
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: MatterGroupcastConfigEntry) -> bool:
    """Set up a config entry."""
    try:
        controller = MatterGroupController(hass, entry)
        await controller.async_setup()
    except Exception as err:
        raise ConfigEntryNotReady(str(err)) from err

    entry.runtime_data = controller
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: MatterGroupcastConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
