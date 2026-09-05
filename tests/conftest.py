"""Load group_send.py without importing the Home Assistant package __init__."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUP_SEND = ROOT / "custom_components" / "matter_groupcast" / "group_send.py"


def _load_group_send():
    spec = importlib.util.spec_from_file_location("matter_groupcast_group_send", GROUP_SEND)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


group_send = _load_group_send()
