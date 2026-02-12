#!/usr/bin/env python3
"""Simple IOC cache for enrichment tooling.

Stores normalized IOC enrichment results in a JSON file with TTL support.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class IOCCache:
    def __init__(self, path: str = "MCP_Adapters/ioc_cache.json") -> None:
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("{}\n", encoding="utf-8")

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _key(tool_id: str, ioc_type: str, value: str) -> str:
        return f"{tool_id}|{ioc_type}|{value.lower().strip()}"

    def get(self, tool_id: str, ioc_type: str, value: str, ttl_seconds: int) -> dict[str, Any] | None:
        store = self._load()
        key = self._key(tool_id, ioc_type, value)
        item = store.get(key)
        if not item:
            return None

        cached_at = float(item.get("cached_at", 0))
        age = time.time() - cached_at
        if age > max(0, ttl_seconds):
            return None

        return {
            "key": key,
            "age_seconds": age,
            "data": item.get("data"),
        }

    def set(self, tool_id: str, ioc_type: str, value: str, data: dict[str, Any]) -> None:
        store = self._load()
        key = self._key(tool_id, ioc_type, value)
        store[key] = {
            "cached_at": time.time(),
            "data": data,
        }
        self._save(store)
