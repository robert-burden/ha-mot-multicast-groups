# Matter over Thread multicast groups

Home Assistant custom integration plus a laptop CLI. Both talk to HA’s Matter Server (Path A).

## Home Assistant plugin

[`custom_components/matter_groupcast`](custom_components/matter_groupcast) adds a light entity for a helper group of Matter bulbs.

- Uses the official Matter integration’s client (no second fabric, no extra 5580 from inside HA).
- On/Off first tries a Matter `group_command` (multicast) when the server supports it.
- Today Matter Server has no group-send API, so it **falls back to concurrent unicast** (all members in parallel). That is already snappier than a sequential helper group.
- `matter_groupcast.provision` writes group keys, membership, and a fabric-safe ACL (same flow proven on Bulb 1).

### Install with HACS

1. HACS → **⋯ → Custom repositories**.
2. Repository: `https://github.com/robert-burden/ha-mot-multicast-groups`
3. Type: **Integration**.
4. Download **Matter Groupcast**, then restart Home Assistant.
5. **Settings → Devices & services → Add integration → Matter Groupcast**.
6. Pick `light.dining_room_chandelier` (Group ID default `3329` / `0x0D01`).
7. Optional, when you want device-side Matter groups: Developer Tools → Actions → `matter_groupcast.provision`.

### Manual install

Copy `custom_components/matter_groupcast` to `/config/custom_components/matter_groupcast`, then restart and add the integration as above.

The new light’s `send_path` attribute is `groupcast` or `concurrent_unicast`.

True IPv6 group multicast still needs a Matter Server `group_command`. The plugin will use it automatically once it exists.

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
```

Do not run `join-group` on all 32 bulbs from the laptop unless you are using the same group key the HA config entry will store.
