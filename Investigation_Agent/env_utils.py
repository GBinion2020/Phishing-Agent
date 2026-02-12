#!/usr/bin/env python3
"""Environment helpers for loading local .env settings without external deps."""

from __future__ import annotations

import os
from pathlib import Path


def _clean_env_value(val: str) -> str:
    v = val.strip()
    if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
        v = v[1:-1].strip()
    return v


def load_dotenv(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return

    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = _clean_env_value(val)
        if key and key not in os.environ:
            os.environ[key] = val


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)).strip())
    except Exception:
        return default
