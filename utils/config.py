from __future__ import annotations

import json
import os
from typing import Any, Dict


CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "settings.json")


def load_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: Dict[str, Any]) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

