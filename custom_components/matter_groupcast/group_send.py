"""Matter groupcast sender: encode an On/Off Invoke and emit IPv6 multicast.

The official Matter Server treats Group NodeIds as test nodes and never puts a
group message on the wire. This module implements the missing send path in the
plugin: HKDF operational keys, a group-session AES-CCM packet, and UDP to the
fabric's site-local multicast address (port 5540).

On HAOS the Home Assistant Core container usually cannot inject that multicast
onto the Thread backbone; the companion add-on (host network) forwards the
already-encoded datagram.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MATTER_UDP_PORT = 5540
INTERACTION_PROTOCOL_ID = 0x0001
INVOKE_COMMAND_REQUEST = 0x08
CLUSTER_ONOFF = 0x0006
ONOFF_COMMANDS = {"off": 0x00, "on": 0x01, "toggle": 0x02}

SESSION_TYPE_GROUP = 0x01
PACKET_FLAG_DEST_GROUP = 0x02
PACKET_FLAG_SOURCE_NODE = 0x04
EXCHANGE_FLAG_INITIATOR = 0x01

GROUP_KEY_INFO = b"GroupKey v1.0"
GROUP_KEY_HASH_INFO = b"GroupKeyHash"
IM_REVISION = 11

TLV_END = 0x18
TLV_ANON_STRUCT = 0x15
TLV_CTX_STRUCT = 0x35
TLV_CTX_ARRAY = 0x36
TLV_CTX_BOOL_FALSE = 0x28
TLV_CTX_BOOL_TRUE = 0x29
TLV_CTX_UINT8 = 0x24


@dataclass(frozen=True)
class GroupSendParams:
    fabric_id: int
    compressed_fabric_id: int
    source_node_id: int
    group_id: int
    epoch_key: bytes
    command: str
    endpoint_id: int = 1
    message_counter: int | None = None
    exchange_id: int | None = None


@dataclass(frozen=True)
class EncodedGroupMessage:
    packet: bytes
    multicast_address: str
    port: int
    session_id: int
    message_counter: int
    operational_key: bytes


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


def derive_group_session_id(operational_key: bytes) -> int:
    hashed = HKDF(
        algorithm=hashes.SHA256(),
        length=2,
        salt=None,
        info=GROUP_KEY_HASH_INFO,
    ).derive(operational_key)
    return int.from_bytes(hashed, "big")


def multicast_address_for(fabric_id: int, group_id: int) -> str:
    """Per-group IPv6 address: FF35:0040:FD<FabricId>00:<GroupId>."""
    packed = (
        b"\xff\x35\x00\x40\xfd"
        + int(fabric_id).to_bytes(8, "big")
        + b"\x00"
        + int(group_id & 0xFFFF).to_bytes(2, "big")
    )
    return socket.inet_ntop(socket.AF_INET6, packed)


def _tlv_ctx_uint8(tag: int, value: int) -> bytes:
    return bytes((TLV_CTX_UINT8, tag, value & 0xFF))


def encode_onoff_invoke(command: str, endpoint_id: int | None = 1) -> bytes:
    command_id = ONOFF_COMMANDS.get(command.lower())
    if command_id is None:
        raise ValueError(f"Unsupported On/Off command: {command}")

    path = bytearray((TLV_CTX_STRUCT, 0x00))
    if endpoint_id is not None:
        path.extend(_tlv_ctx_uint8(0x00, endpoint_id))
    path.extend(_tlv_ctx_uint8(0x01, CLUSTER_ONOFF))
    path.extend(_tlv_ctx_uint8(0x02, command_id))
    path.append(TLV_END)

    invoke_requests = bytes(
        (
            TLV_CTX_ARRAY,
            0x02,
            TLV_ANON_STRUCT,
            *path,
            TLV_END,
            TLV_END,
        )
    )
    return bytes(
        (
            TLV_ANON_STRUCT,
            TLV_CTX_BOOL_TRUE,
            0x00,  # suppressResponse
            TLV_CTX_BOOL_FALSE,
            0x01,  # timedRequest
            *invoke_requests,
            *_tlv_ctx_uint8(0x03, IM_REVISION),
            TLV_END,
        )
    )


def encode_packet_header(
    session_id: int,
    message_counter: int,
    source_node_id: int,
    dest_group_id: int,
) -> bytes:
    flags = PACKET_FLAG_DEST_GROUP | PACKET_FLAG_SOURCE_NODE
    security_flags = SESSION_TYPE_GROUP
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


def encode_group_onoff(params: GroupSendParams) -> EncodedGroupMessage:
    operational_key = derive_operational_key(params.epoch_key, params.compressed_fabric_id)
    session_id = derive_group_session_id(operational_key)
    message_counter = (
        params.message_counter
        if params.message_counter is not None
        else (time.time_ns() // 1_000) & 0xFFFFFFFF
    )
    exchange_id = params.exchange_id if params.exchange_id is not None else (message_counter ^ session_id) & 0xFFFF

    header = encode_packet_header(
        session_id, message_counter, params.source_node_id, params.group_id
    )
    plaintext = encode_payload_header(exchange_id) + encode_onoff_invoke(
        params.command, params.endpoint_id
    )
    nonce = generate_nonce(header[3], message_counter, params.source_node_id)
    ciphertext = AESCCM(operational_key, tag_length=16).encrypt(nonce, plaintext, header)
    return EncodedGroupMessage(
        packet=header + ciphertext,
        multicast_address=multicast_address_for(params.fabric_id, params.group_id),
        port=MATTER_UDP_PORT,
        session_id=session_id,
        message_counter=message_counter,
        operational_key=operational_key,
    )


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
