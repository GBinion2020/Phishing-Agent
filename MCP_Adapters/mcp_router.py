#!/usr/bin/env python3
"""MCP-style tool router with strict I/O checks and IOC cache.

This router is API-key and network agnostic for now:
- Reads tool metadata from registry
- Validates input payload against minimal schema
- Returns cached result if available
- Returns deferred stub when live API calls are disabled
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_cache import IOCCache


ALLOWED_STATUS = {"ok", "deferred", "error"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_yaml_like(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            loaded = yaml.safe_load(text)
            if not isinstance(loaded, dict):
                raise ValueError(f"Config at {path} must parse to object")
            return loaded
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                f"Cannot parse {path}. Use JSON-compatible YAML or install PyYAML."
            ) from exc


def _validate_payload(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    if schema.get("type") != "object":
        raise ValueError("Only object schemas are supported")
    required = schema.get("required", [])
    properties = schema.get("properties", {})

    if not isinstance(payload, dict):
        raise ValueError("payload must be object")

    for req in required:
        if req not in payload:
            raise ValueError(f"payload missing required field: {req}")

    for key, prop in properties.items():
        if key not in payload:
            continue
        value = payload[key]

        if "enum" in prop and value not in prop["enum"]:
            raise ValueError(f"{key} must be one of {prop['enum']}")

        ptype = prop.get("type")
        if ptype == "string" and not isinstance(value, str):
            raise ValueError(f"{key} must be string")
        if ptype == "integer" and not isinstance(value, int):
            raise ValueError(f"{key} must be integer")
        if ptype == "number" and not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be number")
        if ptype == "boolean" and not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")

        if isinstance(value, str):
            min_len = int(prop.get("min_length", 0))
            if len(value.strip()) < min_len:
                raise ValueError(f"{key} must have length >= {min_len}")


def _validate_output(output: dict[str, Any], schema: dict[str, Any]) -> None:
    required = schema.get("required", [])
    properties = schema.get("properties", {})

    for req in required:
        if req not in output:
            raise ValueError(f"output missing required field: {req}")

    status = output.get("status")
    if status not in ALLOWED_STATUS:
        raise ValueError(f"invalid output status: {status}")

    for key, prop in properties.items():
        if key not in output:
            continue
        value = output[key]
        ptype = prop.get("type")
        if ptype == "string" and not isinstance(value, str):
            raise ValueError(f"output {key} must be string")
        if ptype == "integer" and not isinstance(value, int):
            raise ValueError(f"output {key} must be integer")
        if ptype == "number" and not isinstance(value, (int, float)):
            raise ValueError(f"output {key} must be number")
        if ptype == "boolean" and not isinstance(value, bool):
            raise ValueError(f"output {key} must be boolean")
        if "enum" in prop and value not in prop["enum"]:
            raise ValueError(f"output {key} must be one of {prop['enum']}")


def _build_deferred_output(schema: dict[str, Any]) -> dict[str, Any]:
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    out: dict[str, Any] = {"status": "deferred", "reason": "Live API call disabled or not yet wired"}
    for field in required:
        if field in out:
            continue
        prop = properties.get(field, {})
        ptype = prop.get("type")
        enum = prop.get("enum")
        if enum:
            out[field] = "deferred" if "deferred" in enum else enum[0]
            continue
        if ptype == "boolean":
            out[field] = False
        elif ptype == "number":
            out[field] = 0.0
        elif ptype == "integer":
            out[field] = 0
        elif ptype == "string":
            out[field] = "unknown"
        else:
            out[field] = None
    return out


def _find_tool(registry: dict[str, Any], tool_id: str) -> dict[str, Any]:
    tools = registry.get("tools", [])
    for tool in tools:
        if tool.get("id") == tool_id:
            return tool
    raise ValueError(f"Unknown tool id: {tool_id}")


def route_tool_call(
    tool_id: str,
    payload: dict[str, Any],
    registry: dict[str, Any],
    cache: IOCCache,
    live_call: bool = False,
) -> dict[str, Any]:
    tool = _find_tool(registry, tool_id)

    _validate_payload(payload, tool.get("input_schema", {}))

    ioc_type = payload["ioc_type"]
    ioc_value = payload["value"]
    if ioc_type not in tool.get("ioc_types", []):
        raise ValueError(f"Tool {tool_id} does not support ioc_type={ioc_type}")

    ttl = int(tool.get("cache_ttl_seconds", 0))
    cached = cache.get(tool_id, ioc_type, ioc_value, ttl_seconds=ttl)
    if cached:
        out = dict(cached["data"])
        out["cache"] = {
            "hit": True,
            "age_seconds": round(cached["age_seconds"], 2),
            "ttl_seconds": ttl,
        }
        return {
            "schema_version": "1.0",
            "generated_at": _now_iso(),
            "tool_id": tool_id,
            "provider": tool.get("provider"),
            "input": payload,
            "output": out,
            "source": "cache",
        }

    if live_call:
        auth_env = tool.get("auth_env_var")
        if auth_env and not os.getenv(auth_env):
            raise RuntimeError(f"Missing required API key env var: {auth_env}")
        raise NotImplementedError(
            f"Live API execution for {tool_id} is intentionally stubbed in this phase"
        )

    deferred_output = _build_deferred_output(tool.get("output_schema", {}))
    _validate_output(deferred_output, tool.get("output_schema", {}))

    return {
        "schema_version": "1.0",
        "generated_at": _now_iso(),
        "tool_id": tool_id,
        "provider": tool.get("provider"),
        "input": payload,
        "output": deferred_output,
        "source": "stub",
        "cache": {"hit": False, "ttl_seconds": ttl},
    }


def seed_cache(
    tool_id: str,
    payload: dict[str, Any],
    output: dict[str, Any],
    registry: dict[str, Any],
    cache: IOCCache,
) -> dict[str, Any]:
    tool = _find_tool(registry, tool_id)
    _validate_payload(payload, tool.get("input_schema", {}))
    _validate_output(output, tool.get("output_schema", {}))

    cache.set(tool_id, payload["ioc_type"], payload["value"], output)
    return {
        "schema_version": "1.0",
        "generated_at": _now_iso(),
        "tool_id": tool_id,
        "seeded": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Route MCP-style tool calls with strict schemas and IOC cache.")
    parser.add_argument("--tool", required=True, help="Tool id from MCP_Adapters/mcp_tool_registry.yaml")
    parser.add_argument("--ioc-type", required=True, help="IOC type (url/domain/ip/hash)")
    parser.add_argument("--value", required=True, help="IOC value")
    parser.add_argument("--registry", default="MCP_Adapters/mcp_tool_registry.yaml", help="Tool registry path")
    parser.add_argument("--cache", default="MCP_Adapters/ioc_cache.json", help="Cache file path")
    parser.add_argument("--live", action="store_true", help="Enable live mode (not implemented in this phase)")
    parser.add_argument("--seed-status", choices=["ok", "deferred", "error"], default=None)
    parser.add_argument("--seed-malicious", choices=["true", "false"], default=None)
    parser.add_argument("--seed-confidence", type=float, default=0.0)
    parser.add_argument("--out", default=None, help="Optional output path")
    args = parser.parse_args()

    registry = _load_yaml_like(Path(args.registry))
    cache = IOCCache(path=args.cache)

    payload = {"ioc_type": args.ioc_type, "value": args.value}

    if args.seed_status is not None and args.seed_malicious is not None:
        seed_output = {
            "status": args.seed_status,
            "malicious": args.seed_malicious == "true",
            "confidence": float(args.seed_confidence),
        }
        result = seed_cache(args.tool, payload, seed_output, registry, cache)
    else:
        result = route_tool_call(args.tool, payload, registry, cache, live_call=args.live)

    output = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
