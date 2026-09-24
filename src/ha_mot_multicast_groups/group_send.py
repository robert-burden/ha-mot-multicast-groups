"""Re-export the integration's Matter group-send codec for the laptop CLI."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_GROUP_SEND = (
    Path(__file__).resolve().parents[2]
    / "custom_components"
    / "matter_groupcast"
    / "group_send.py"
)
_spec = importlib.util.spec_from_file_location("matter_groupcast_group_send", _GROUP_SEND)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load group_send from {_GROUP_SEND}")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

ClusterInvoke = _module.ClusterInvoke
EncodedGroupMessage = _module.EncodedGroupMessage
GroupSendParams = _module.GroupSendParams
derive_group_session_id = _module.derive_group_session_id
derive_operational_key = _module.derive_operational_key
encode_group_invoke = _module.encode_group_invoke
encode_group_onoff = _module.encode_group_onoff
epoch_key_bytes = _module.epoch_key_bytes
invoke_onoff = _module.invoke_onoff
invokes_for_turn_on = _module.invokes_for_turn_on
multicast_address_for = _module.multicast_address_for
groupcast_addresses = _module.groupcast_addresses
next_message_counter = _module.next_message_counter
send_udp_multicast = _module.send_udp_multicast

__all__ = [
    "ClusterInvoke",
    "EncodedGroupMessage",
    "GroupSendParams",
    "derive_group_session_id",
    "derive_operational_key",
    "encode_group_invoke",
    "encode_group_onoff",
    "epoch_key_bytes",
    "invoke_onoff",
    "invokes_for_turn_on",
    "multicast_address_for",
    "groupcast_addresses",
    "next_message_counter",
    "send_udp_multicast",
]
