from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from tests.conftest import group_send as gs
from tests.conftest import sender as sender_mod
from tests.conftest import sender_urls as su


def test_groupcast_addresses_include_thread_and_iana() -> None:
    addrs = gs.groupcast_addresses(2, 0x0D01)
    packed = __import__("socket").inet_pton
    af = __import__("socket").AF_INET6
    assert packed(af, addrs[0]) == bytes.fromhex("ff350040fd0000000000000002000d01")
    assert packed(af, addrs[1]) == bytes.fromhex("ff330040fd0000000000000002000d01")
    assert "ff05::fa" in addrs
    assert "ff03::fa" in addrs


def test_sender_skips_docker_and_keeps_thread() -> None:
    assert sender_mod.iface_allowed("eno1")
    assert sender_mod.iface_allowed("wpan0")
    assert sender_mod.is_thread_iface("wpan0")
    assert not sender_mod.iface_allowed("lo")
    assert not sender_mod.iface_allowed("docker0")
    assert not sender_mod.iface_allowed("hassio")
    assert not sender_mod.iface_allowed("veth1a2b3c")


def test_spec_operational_key_and_session_id() -> None:
    epoch = bytes.fromhex("235bf7e62823d358dca4ba50b1535f4b")
    op = gs.derive_operational_key(epoch, 0x87E1B004E235A130)
    assert op.hex() == "a6f5306baf6d050af23ba4bd6b9dd960"
    zero = gs.derive_operational_key(bytes(16), 0x87E1B004E235A130)
    assert zero.hex() == "c5f2690187115150c356ad93b385bb0f"
    assert gs.derive_group_session_id(zero) == 0x479E
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


def test_brightness_and_color_conversions() -> None:
    assert gs.brightness_to_matter_level(255) == 254
    assert gs.brightness_to_matter_level(0) == 1
    assert gs.hs_to_matter((360, 100)) == (254, 254)
    assert gs.hs_to_matter((0, 0)) == (0, 0)
    assert gs.kelvin_to_mireds(2000) == 500
    assert gs.xy_to_matter((0.5, 0.4)) == (32768, 26214)


def test_level_and_color_temp_invokes_encode_fields() -> None:
    level = gs.encode_invoke(
        gs.CLUSTER_LEVEL_CONTROL,
        gs.CMD_MOVE_TO_LEVEL_WITH_ON_OFF,
        gs.invoke_move_to_level(128).fields,
        endpoint_id=1,
    )
    assert bytes((0x24, 0x01, gs.CLUSTER_LEVEL_CONTROL)) in level
    assert gs._tlv_ctx_uint(0, gs.brightness_to_matter_level(128), 1) in level

    ct = gs.encode_invoke(
        gs.CLUSTER_COLOR_CONTROL,
        gs.CMD_MOVE_TO_COLOR_TEMPERATURE,
        gs.invoke_move_to_color_temp(2700).fields,
        endpoint_id=1,
    )
    # Color Control cluster 0x0300 does not fit in a uint8 tag
    assert bytes((0x25, 0x01, 0x00, 0x03)) in ct
    assert gs._tlv_ctx_uint(0, gs.kelvin_to_mireds(2700), 2) in ct


def test_turn_on_invokes_color_then_brightness() -> None:
    invokes = gs.invokes_for_turn_on(brightness=200, kelvin=2700)
    assert [item.command_name for item in invokes] == [
        "moveToColorTemperature",
        "moveToLevelWithOnOff",
    ]
    color_only = gs.invokes_for_turn_on(hs_color=(30.0, 80.0))
    assert [item.command_name for item in color_only] == ["moveToHueAndSaturation", "on"]


def test_color_temp_group_message_roundtrip_decrypt() -> None:
    invoke = gs.invoke_move_to_color_temp(3000)
    params = gs.GroupSendParams(
        fabric_id=2,
        compressed_fabric_id=0xAABBCCDDEEFF0011,
        source_node_id=112233,
        group_id=0x0D01,
        epoch_key=bytes.fromhex("0123456789abcdeffedcba9876543210"),
        endpoint_id=1,
        message_counter=0x01020305,
        exchange_id=0x2222,
    )
    encoded = gs.encode_group_invoke(params, invoke)
    header_len = 1 + 2 + 1 + 4 + 8 + 2
    header = encoded.packet[:header_len]
    ciphertext = encoded.packet[header_len:]
    nonce = gs.generate_nonce(header[3], params.message_counter, params.source_node_id)
    plaintext = AESCCM(encoded.operational_key, tag_length=16).decrypt(nonce, ciphertext, header)
    assert gs.encode_invoke(invoke.cluster_id, invoke.command_id, invoke.fields, 1) in plaintext


def test_sender_urls_prefer_supervisor_hostname() -> None:
    extra = su.addon_hosts_from_info(
        {
            "1c2d22dc_matter_groupcast_sender": {
                "hostname": "1c2d22dc-matter-groupcast-sender",
                "ip_address": "172.30.32.1",
            }
        }
    )
    urls = su.build_sender_urls(extra_hosts=extra)
    assert urls[0] == "http://1c2d22dc-matter-groupcast-sender:5599"
    assert "http://1c2d22dc-matter-groupcast-sender.local.hass.io:5599" in urls
    assert urls.index("http://1c2d22dc-matter-groupcast-sender:5599") < urls.index(
        "http://homeassistant.local:5599"
    )


def test_epoch_keys_are_last_byte_variants() -> None:
    k0, k1, k2 = gs.epoch_key_bytes("00112233445566778899aabbccddeeff")
    assert k0.hex() == "00112233445566778899aabbccddeeff"
    assert k1.hex() == "00112233445566778899aabbccddeefe"
    assert k2.hex() == "00112233445566778899aabbccddeefd"
    assert len({k0, k1, k2}) == 3
