from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from tests.conftest import group_send as gs


def test_multicast_address_matches_spec_for_fabric_2() -> None:
    addr = gs.multicast_address_for(2, 0x0D01)
    packed = __import__("socket").inet_pton(__import__("socket").AF_INET6, addr)
    assert packed == bytes.fromhex("ff350040fd0000000000000002000d01")


def test_operational_key_is_16_bytes_and_key_dependent() -> None:
    epoch = bytes.fromhex("00112233445566778899aabbccddeeff")
    a = gs.derive_operational_key(epoch, 0x1122334455667788)
    b = gs.derive_operational_key(epoch, 0x1122334455667789)
    assert len(a) == 16
    assert a != b
    assert gs.derive_operational_key(epoch, 0x1122334455667788) == a


def test_session_id_is_big_endian_hkdf() -> None:
    key = gs.derive_operational_key(bytes(16), 1)
    session_id = gs.derive_group_session_id(key)
    assert 0 <= session_id <= 0xFFFF
    assert gs.derive_group_session_id(key) == session_id


def test_onoff_invoke_tlv_contains_cluster_and_command() -> None:
    payload = gs.encode_onoff_invoke("on", endpoint_id=1)
    assert payload[0] == 0x15
    assert payload[-1] == 0x18
    assert bytes((0x24, 0x01, gs.CLUSTER_ONOFF)) in payload
    assert bytes((0x24, 0x02, 0x01)) in payload  # On
    off = gs.encode_onoff_invoke("off", endpoint_id=1)
    assert bytes((0x24, 0x02, 0x00)) in off


def test_encoded_group_message_roundtrip_decrypt() -> None:
    params = gs.GroupSendParams(
        fabric_id=2,
        compressed_fabric_id=0xAABBCCDDEEFF0011,
        source_node_id=112233,
        group_id=0x0D01,
        epoch_key=bytes.fromhex("0123456789abcdeffedcba9876543210"),
        command="off",
        endpoint_id=1,
        message_counter=0x01020304,
        exchange_id=0x1111,
    )
    encoded = gs.encode_group_onoff(params)
    header_len = 1 + 2 + 1 + 4 + 8 + 2
    header = encoded.packet[:header_len]
    ciphertext = encoded.packet[header_len:]
    flags, session_id, security_flags = struct.unpack_from("<BHB", header, 0)
    assert flags == 0x06
    assert security_flags == 0x01
    assert session_id == encoded.session_id
    nonce = gs.generate_nonce(security_flags, params.message_counter, params.source_node_id)
    plaintext = AESCCM(encoded.operational_key, tag_length=16).decrypt(nonce, ciphertext, header)
    assert plaintext[1] == 0x08  # InvokeCommandRequest
    assert gs.encode_onoff_invoke("off", 1) in plaintext


def test_message_counter_never_goes_backwards() -> None:
    first = gs.next_message_counter(None)
    second = gs.next_message_counter(first)
    assert 0 < second <= 0xFFFFFFFF
    assert second != first
    later = gs.next_message_counter(second)
    assert later != second
