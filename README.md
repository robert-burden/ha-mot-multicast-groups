# Matter over Thread multicast groups

Home Assistant custom integration plus a laptop CLI. The plugin implements the **group-send API that Matter Server is missing**: it encodes a Matter group On/Off invoke and emits one IPv6 multicast packet. A tiny companion add-on (host network) puts that packet on the wire so the Thread border router can forward it.

Official Matter Server still treats Group NodeIds as test nodes, so `device_command` never groupcasts. Helper groups are not Matter groups.

## Home Assistant plugin

[`custom_components/matter_groupcast`](custom_components/matter_groupcast) adds a light entity for a helper group of Matter bulbs.

1. `matter_groupcast.provision` writes group keys, membership, and a fabric-safe ACL on each member (same flow proven on Bulb 1).
2. On/Off encodes one Matter group message in the integration (operational key, AES-CCM, Invoke On/Off).
3. The **Matter Groupcast Sender** add-on (`host_network: true`) injects that UDP datagram to `ff35:0040:fd…` port **5540**.
4. If the add-on is not running, it falls back to concurrent unicast (popcorn).

The light’s `send_path` attribute is `groupcast_addon`, `groupcast_local`, `groupcast_server`, or `concurrent_unicast`.

### Install the integration (HACS)

1. HACS → **⋯ → Custom repositories**.
2. Repository: `https://github.com/robert-burden/ha-mot-multicast-groups`
3. Type: **Integration**.
4. Download **Matter Groupcast**, then restart Home Assistant.
5. **Settings → Devices & services → Add integration → Matter Groupcast**.
6. Pick `light.dining_room_chandelier` (Group ID default `3329` / `0x0D01`).

### Install the sender add-on (required on HAOS)

Home Assistant Core cannot put site-local IPv6 multicast onto the Thread backbone. The add-on can, because it uses host networking (same reason the Matter Server add-on does).

1. **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add `https://github.com/robert-burden/ha-mot-multicast-groups`.
3. Install **Matter Groupcast Sender**, start it. It listens on host port **5599** (LAN only).
4. Restart Home Assistant (or reload Matter Groupcast) so the integration can find the add-on.

### Provision, then toggle

1. Developer Tools → Actions → `matter_groupcast.provision` (do this after the add-on is running).
2. Toggle `light.*_matter_group`. `send_path` should become `groupcast_addon`.
3. All provisioned members should switch together. Unprovisioned members will not hear the multicast.

On/Off only. No brightness or color groupcast in v1.

### Manual integration install

Copy `custom_components/matter_groupcast` to `/config/custom_components/matter_groupcast`, then restart and add the integration as above.

## Laptop CLI

Matter Server port 5580 is published on the HAOS host (`192.168.68.83`). Keep it off the public reverse proxy.

```
MATTER_WS_URL=ws://192.168.68.83:5580/ws
```

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
matter-groups discover
matter-groups unicast toggle --entity light.dining_room_bulb_1
matter-groups join-group --limit 1
matter-groups group on
```

`group on|off|toggle` now sends a real Matter group multicast from this machine (needs IPv6 to the LAN/OTBR). Use the same `MATTER_GROUP_KEY_HEX` you provisioned. Do not mix laptop `join-group` on all 32 bulbs with a different key than the HA config entry.

## Why an add-on

A custom component cannot add APIs inside `core_matter_server`. Group send needs:

- The same epoch key written to the bulbs
- The fabric’s compressed fabric ID (for the operational key) and fabric ID (for the multicast address)
- A sender on a network that the OTBR actually forwards

The plugin does the first two. The add-on is the third.
