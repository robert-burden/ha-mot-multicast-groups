"""Load group_send.py without importing the Home Assistant package __init__."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUP_SEND = ROOT / "custom_components" / "matter_groupcast" / "group_send.py"
SENDER_URLS = ROOT / "custom_components" / "matter_groupcast" / "sender_urls.py"
SENDER = ROOT / "matter_groupcast_sender" / "server.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


group_send = _load(GROUP_SEND, "matter_groupcast_group_send")
sender_urls = _load(SENDER_URLS, "matter_groupcast_sender_urls")
sender = _load(SENDER, "matter_groupcast_sender_server")
