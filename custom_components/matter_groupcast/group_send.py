"""Matter groupcast sender: encode an Invoke and emit IPv6 multicast.

The official Matter Server treats Group NodeIds as test nodes and never puts a
group message on the wire. This module implements the missing send path in the
plugin: HKDF operational keys, a group-session AES-CCM packet, and UDP to the
fabric's site-local multicast address (port 5540).

Supports On/Off, Level Control (brightness), and Color Control (HS, XY, mireds).
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MATTER_UDP_PORT = 5540
INTERACTION_PROTOCOL_ID = 0x0001
INVOKE_COMMAND_REQUEST = 0x08
CLUSTER_ONOFF = 0x0006
CLUSTER_LEVEL_CONTROL = 0x0008
CLUSTER_COLOR_CONTROL = 0x0300
ONOFF_COMMANDS = {"off": 0x00, "on": 0x01, "toggle": 0x02}
CMD_MOVE_TO_LEVEL_WITH_ON_OFF = 0x04
CMD_MOVE_TO_HUE_AND_SATURATION = 0x06
CMD_MOVE_TO_COLOR = 0x07
CMD_MOVE_TO_COLOR_TEMPERATURE = 0x0A

SESSION_TYPE_GROUP = 0x01
SECURITY_FLAG_PRIVACY = 0x80
PACKET_FLAG_DEST_GROUP = 0x02
PACKET_FLAG_SOURCE_NODE = 0x04
EXCHANGE_FLAG_INITIATOR = 0x01
PRIVACY_KEY_INFO = b"PrivacyKey"

GROUP_KEY_INFO = b"GroupKey v1.0"
GROUP_KEY_HASH_INFO = b"GroupKeyHash"
IM_REVISION = 11
MATTER_MAX_MIREDS = 65279

TLV_END = 0x18
TLV_ANON_STRUCT = 0x15
TLV_CTX_STRUCT = 0x35
TLV_CTX_ARRAY = 0x36
TLV_CTX_BOOL_FALSE = 0x28
TLV_CTX_BOOL_TRUE = 0x29
TLV_CTX_UINT8 = 0x24
TLV_CTX_UINT16 = 0x25
TLV_CTX_UINT32 = 0x26


@dataclass(frozen=True)
class TlvUInt:
    tag: int
    value: int
    width: int  # 1, 2, or 4


@dataclass(frozen=True)
class ClusterInvoke:
    cluster_id: int
    command_id: int
    command_name: str
    payload: dict[str, Any]
    fields: tuple[TlvUInt, ...]


@dataclass(frozen=True)
class GroupSendParams:
    fabric_id: int
    compressed_fabric_id: int
    source_node_id: int
    group_id: int
    epoch_key: bytes
    command: str | None = None
    endpoint_id: int = 1
    message_counter: int | None = None
    exchange_id: int | None = None
    privacy: bool = False


@dataclass(frozen=True)
class EncodedGroupMessage:
    packet: bytes
    multicast_address: str
    port: int
    session_id: int
    message_counter: int
    operational_key: bytes


def epoch_key_bytes(key_hex: str) -> tuple[bytes, bytes, bytes]:
    """The three epoch keys written at provision time.

    Epoch 1/2 are the epoch-0 key with the last byte XORed. Devices without a
    trusted clock use the second-newest start time (epoch 1); devices with time
    use the latest start time that is not in the future (epoch 2). Send all three.
    """
    k0 = bytes.fromhex(key_hex)
    if len(k0) != 16:
        raise ValueError("Matter epoch key must be 16 bytes")
    k1 = k0[:-1] + bytes([k0[-1] ^ 0x01])
    k2 = k0[:-1] + bytes([k0[-1] ^ 0x02])
    return k0, k1, k2


def derive_operational_key(epoch_key: bytes, compressed_fabric_id: int) -> bytes:
    if len(epoch_key) != 16:
        raise ValueError("Matter epoch key must be 16 bytes")
    salt = compressed_fabric_id.to_bytes(8, "big")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=GROUP_KEY_INFO,
    ).derive(epoch_key)


def derive_privacy_key(operational_key: bytes) -> bytes:
    """HKDF(operational key, salt=[], info=\"PrivacyKey\", 16)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=PRIVACY_KEY_INFO,
    ).derive(operational_key)


def apply_privacy(header: bytes, ciphertext: bytes, operational_key: bytes, session_id: int) -> bytes:
    """Obfuscate message counter + node/group IDs (header[4:]) with AES-CCM keystream."""
    mic = ciphertext[-16:]
    nonce = struct.pack(">H", session_id & 0xFFFF) + mic[5:]
    privacy_key = derive_privacy_key(operational_key)
    obfuscated = AESCCM(privacy_key, tag_length=16).encrypt(nonce, header[4:], b"")[: len(header) - 4]
    return header[:4] + obfuscated


def derive_group_session_id(operational_key: bytes) -> int:
    hashed = HKDF(
        algorithm=hashes.SHA256(),
        length=2,
        salt=None,
        info=GROUP_KEY_HASH_INFO,
    ).derive(operational_key)
    return int.from_bytes(hashed, "big")


def multicast_address_for(fabric_id: int, group_id: int, scope: int = 5) -> str:
    """CHIP BuildMatterPerGroupMulticastAddress: FF3{scope}:0040:FD + FabricId + 00 + GroupId."""
    packed = (
        bytes((0xFF, 0x30 | (scope & 0x0F), 0x00, 0x40, 0xFD))
        + int(fabric_id).to_bytes(8, "big")
        + b"\x00"
        + int(group_id & 0xFFFF).to_bytes(2, "big")
    )
    return socket.inet_ntop(socket.AF_INET6, packed)


def groupcast_addresses(fabric_id: int, group_id: int) -> tuple[str, ...]:
    """Destinations CHIP and Thread stacks actually subscribe to.

    Per-group is site-local (ff35). Thread only forwards that after MLR, so
    also send the realm-local twin (ff33) and IANA Matter (ff0s::fa).
    """
    return (
        multicast_address_for(fabric_id, group_id, 5),
        multicast_address_for(fabric_id, group_id, 3),
        "ff05::fa",
        "ff03::fa",
    )


def _tlv_ctx_uint(tag: int, value: int, width: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("TLV unsigned integers cannot be negative")
    if width is None:
        if value <= 0xFF:
            width = 1
        elif value <= 0xFFFF:
            width = 2
        elif value <= 0xFFFFFFFF:
            width = 4
        else:
            raise ValueError(f"Integer too large for TLV uint: {value}")
    if width == 1:
        return bytes((TLV_CTX_UINT8, tag, value & 0xFF))
    if width == 2:
        return bytes((TLV_CTX_UINT16, tag)) + struct.pack("<H", value & 0xFFFF)
    if width == 4:
        return bytes((TLV_CTX_UINT32, tag)) + struct.pack("<I", value & 0xFFFFFFFF)
    raise ValueError(f"Unsupported TLV uint width {width}")


def encode_invoke(
    cluster_id: int,
    command_id: int,
    fields: tuple[TlvUInt, ...] = (),
    endpoint_id: int | None = 1,
) -> bytes:
    path = bytearray((TLV_CTX_STRUCT, 0x00))
    if endpoint_id is not None:
        path.extend(_tlv_ctx_uint(0x00, endpoint_id))
    path.extend(_tlv_ctx_uint(0x01, cluster_id))
    path.extend(_tlv_ctx_uint(0x02, command_id))
    path.append(TLV_END)

    command_ib = bytearray((TLV_ANON_STRUCT, *path))
    if fields:
        command_ib.append(TLV_CTX_STRUCT)
        command_ib.append(0x01)
        for field in fields:
            command_ib.extend(_tlv_ctx_uint(field.tag, field.value, field.width))
        command_ib.append(TLV_END)
    command_ib.append(TLV_END)

    invoke_requests = bytes((TLV_CTX_ARRAY, 0x02, *command_ib, TLV_END))
    return bytes(
        (
            TLV_ANON_STRUCT,
            TLV_CTX_BOOL_TRUE,
            0x00,  # suppressResponse
            TLV_CTX_BOOL_FALSE,
            0x01,  # timedRequest
            *invoke_requests,
            # InteractionModelRevision is context tag 0xFF on every IM message.
            # Tag 3 is DelayReportData; putting the revision there makes IKEA
            # (and current CHIP) reject the Invoke.
            *_tlv_ctx_uint(0xFF, IM_REVISION),
            TLV_END,
        )
    )


def encode_onoff_invoke(command: str, endpoint_id: int | None = 1) -> bytes:
    command_id = ONOFF_COMMANDS.get(command.lower())
    if command_id is None:
        raise ValueError(f"Unsupported On/Off command: {command}")
    return encode_invoke(CLUSTER_ONOFF, command_id, (), endpoint_id)


def brightness_to_matter_level(brightness: int) -> int:
    return max(1, min(254, round(int(brightness) * 254 / 255)))


def hs_to_matter(hs_color: tuple[float, float]) -> tuple[int, int]:
    hue = max(0, min(254, round(float(hs_color[0]) / 360 * 254)))
    sat = max(0, min(254, round(float(hs_color[1]) / 100 * 254)))
    return hue, sat


def xy_to_matter(xy_color: tuple[float, float]) -> tuple[int, int]:
    color_x = max(0, min(0xFFFF, round(float(xy_color[0]) * 65536)))
    color_y = max(0, min(0xFFFF, round(float(xy_color[1]) * 65536)))
    return color_x, color_y


def kelvin_to_mireds(kelvin: int) -> int:
    kelvin = max(1, int(kelvin))
    return min(MATTER_MAX_MIREDS, max(1, round(1_000_000 / kelvin)))


def transition_tenths(transition_s: float | None) -> int:
    if not transition_s:
        return 0
    return max(0, min(0xFFFF, round(float(transition_s) * 10)))


def invoke_onoff(command: str) -> ClusterInvoke:
    command_id = ONOFF_COMMANDS.get(command.lower())
    if command_id is None:
        raise ValueError(f"Unsupported On/Off command: {command}")
    return ClusterInvoke(
        cluster_id=CLUSTER_ONOFF,
        command_id=command_id,
        command_name=command.lower(),
        payload={},
        fields=(),
    )


def invoke_move_to_level(brightness: int, transition_s: float | None = 0) -> ClusterInvoke:
    level = brightness_to_matter_level(brightness)
    tenths = transition_tenths(transition_s)
    return ClusterInvoke(
        cluster_id=CLUSTER_LEVEL_CONTROL,
        command_id=CMD_MOVE_TO_LEVEL_WITH_ON_OFF,
        command_name="moveToLevelWithOnOff",
        payload={
            "level": level,
            "transitionTime": tenths,
            "optionsMask": 0,
            "optionsOverride": 0,
        },
        fields=(
            TlvUInt(0, level, 1),
            TlvUInt(1, tenths, 2),
            TlvUInt(2, 0, 1),
            TlvUInt(3, 0, 1),
        ),
    )


def invoke_move_to_hs(
    hs_color: tuple[float, float], transition_s: float | None = 0
) -> ClusterInvoke:
    hue, sat = hs_to_matter(hs_color)
    tenths = transition_tenths(transition_s)
    return ClusterInvoke(
        cluster_id=CLUSTER_COLOR_CONTROL,
        command_id=CMD_MOVE_TO_HUE_AND_SATURATION,
        command_name="moveToHueAndSaturation",
        payload={
            "hue": hue,
            "saturation": sat,
            "transitionTime": tenths,
            "optionsMask": 1,
            "optionsOverride": 1,
        },
        fields=(
            TlvUInt(0, hue, 1),
            TlvUInt(1, sat, 1),
            TlvUInt(2, tenths, 2),
            TlvUInt(3, 1, 1),
            TlvUInt(4, 1, 1),
        ),
    )


def invoke_move_to_xy(
    xy_color: tuple[float, float], transition_s: float | None = 0
) -> ClusterInvoke:
    color_x, color_y = xy_to_matter(xy_color)
    tenths = transition_tenths(transition_s)
    return ClusterInvoke(
        cluster_id=CLUSTER_COLOR_CONTROL,
        command_id=CMD_MOVE_TO_COLOR,
        command_name="moveToColor",
        payload={
            "colorX": color_x,
            "colorY": color_y,
            "transitionTime": tenths,
            "optionsMask": 1,
            "optionsOverride": 1,
        },
        fields=(
            TlvUInt(0, color_x, 2),
            TlvUInt(1, color_y, 2),
            TlvUInt(2, tenths, 2),
            TlvUInt(3, 1, 1),
            TlvUInt(4, 1, 1),
        ),
    )


def invoke_move_to_color_temp(kelvin: int, transition_s: float | None = 0) -> ClusterInvoke:
    mireds = kelvin_to_mireds(kelvin)
    tenths = transition_tenths(transition_s)
    return ClusterInvoke(
        cluster_id=CLUSTER_COLOR_CONTROL,
        command_id=CMD_MOVE_TO_COLOR_TEMPERATURE,
        command_name="moveToColorTemperature",
        payload={
            "colorTemperatureMireds": mireds,
            "transitionTime": tenths,
            "optionsMask": 1,
            "optionsOverride": 1,
        },
        fields=(
            TlvUInt(0, mireds, 2),
            TlvUInt(1, tenths, 2),
            TlvUInt(2, 1, 1),
            TlvUInt(3, 1, 1),
        ),
    )


def invokes_for_turn_on(
    *,
    brightness: int | None = None,
    hs_color: tuple[float, float] | None = None,
    xy_color: tuple[float, float] | None = None,
    kelvin: int | None = None,
    transition_s: float | None = 0,
) -> list[ClusterInvoke]:
    """Match Home Assistant's Matter light: color, then brightness-with-on, else On."""
    invokes: list[ClusterInvoke] = []
    if hs_color is not None:
        invokes.append(invoke_move_to_hs(hs_color, transition_s))
    elif xy_color is not None:
        invokes.append(invoke_move_to_xy(xy_color, transition_s))
    elif kelvin is not None:
        invokes.append(invoke_move_to_color_temp(kelvin, transition_s))
    if brightness is not None:
        invokes.append(invoke_move_to_level(brightness, transition_s))
        return invokes
    invokes.append(invoke_onoff("on"))
    return invokes


def encode_packet_header(
    session_id: int,
    message_counter: int,
    source_node_id: int,
    dest_group_id: int,
    *,
    privacy: bool = False,
) -> bytes:
    flags = PACKET_FLAG_DEST_GROUP | PACKET_FLAG_SOURCE_NODE
    security_flags = SESSION_TYPE_GROUP | (SECURITY_FLAG_PRIVACY if privacy else 0)
    return (
        struct.pack("<BHB", flags, session_id & 0xFFFF, security_flags)
        + struct.pack("<I", message_counter & 0xFFFFFFFF)
        + struct.pack("<Q", source_node_id & 0xFFFFFFFFFFFFFFFF)
        + struct.pack("<H", dest_group_id & 0xFFFF)
    )


def encode_payload_header(exchange_id: int) -> bytes:
    return struct.pack(
        "<BBHH",
        EXCHANGE_FLAG_INITIATOR,
        INVOKE_COMMAND_REQUEST,
        exchange_id & 0xFFFF,
        INTERACTION_PROTOCOL_ID,
    )


def generate_nonce(security_flags: int, message_counter: int, source_node_id: int) -> bytes:
    return (
        struct.pack("<B", security_flags & 0xFF)
        + struct.pack("<I", message_counter & 0xFFFFFFFF)
        + struct.pack("<Q", source_node_id & 0xFFFFFFFFFFFFFFFF)
    )


def encode_group_invoke(params: GroupSendParams, invoke: ClusterInvoke) -> EncodedGroupMessage:
    operational_key = derive_operational_key(params.epoch_key, params.compressed_fabric_id)
    session_id = derive_group_session_id(operational_key)
    message_counter = (
        params.message_counter
        if params.message_counter is not None
        else (time.time_ns() // 1_000) & 0xFFFFFFFF
    )
    exchange_id = params.exchange_id if params.exchange_id is not None else (message_counter ^ session_id) & 0xFFFF
    header = encode_packet_header(
        session_id,
        message_counter,
        params.source_node_id,
        params.group_id,
        privacy=params.privacy,
    )
    # Group Invoke paths omit endpoint; GroupTable maps the dest group to endpoints.
    plaintext = encode_payload_header(exchange_id) + encode_invoke(
        invoke.cluster_id, invoke.command_id, invoke.fields, endpoint_id=None
    )
    nonce = generate_nonce(header[3], message_counter, params.source_node_id)
    ciphertext = AESCCM(operational_key, tag_length=16).encrypt(nonce, plaintext, header)
    if params.privacy:
        header = apply_privacy(header, ciphertext, operational_key, session_id)
    return EncodedGroupMessage(
        packet=header + ciphertext,
        multicast_address=multicast_address_for(params.fabric_id, params.group_id),
        port=MATTER_UDP_PORT,
        session_id=session_id,
        message_counter=message_counter,
        operational_key=operational_key,
    )


def encode_group_onoff(params: GroupSendParams) -> EncodedGroupMessage:
    if not params.command:
        raise ValueError("GroupSendParams.command is required for encode_group_onoff")
    return encode_group_invoke(params, invoke_onoff(params.command))


def send_udp_multicast(packet: bytes, address: str, port: int = MATTER_UDP_PORT) -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 64)
        hop_if = os.environ.get("MATTER_GROUPCAST_IFINDEX")
        if hop_if:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, int(hop_if))
        sock.sendto(packet, (address, port, 0, 0))
    finally:
        sock.close()


def next_message_counter(previous: int | None) -> int:
    """Monotonic 32-bit group message counter.

    Devices reject replayed counters from the same source node, so we never
    go backwards: take the max of the persisted value and a time-based floor.
    """
    floor = (time.time_ns() // 1_000_000) & 0xFFFFFFFF
    if previous is None:
        return floor or 1
    nxt = (int(previous) + 1) & 0xFFFFFFFF
    if nxt == 0:
        nxt = 1
    if _counter_ahead(floor, nxt):
        return floor
    return nxt


def _counter_ahead(candidate: int, current: int) -> bool:
    """True when candidate is forward of current in 32-bit serial space."""
    return ((candidate - current) & 0xFFFFFFFF) < 0x80000000 and candidate != current
