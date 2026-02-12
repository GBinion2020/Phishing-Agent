#!/usr/bin/env python3
"""MCP-style tool router with strict I/O checks and IOC cache.

Capabilities:
- schema-validated input/output
- cache-first lookups
- live API execution for selected providers
- deferred mode fallback when live is disabled
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_cache import IOCCache


ALLOWED_STATUS = {"ok", "deferred", "error"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_secret(raw: str | None) -> str:
    if raw is None:
        return ""
    v = raw.strip()
    if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
        v = v[1:-1].strip()
    if v.lower().startswith("bearer "):
        v = v.split(" ", 1)[1].strip()
    return v


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


def _build_error_output(schema: dict[str, Any], reason: str) -> dict[str, Any]:
    out = _build_deferred_output(schema)
    out["status"] = "error"
    out["reason"] = reason[:500]
    return out


def _find_tool(registry: dict[str, Any], tool_id: str) -> dict[str, Any]:
    tools = registry.get("tools", [])
    for tool in tools:
        if tool.get("id") == tool_id:
            return tool
    raise ValueError(f"Unknown tool id: {tool_id}")


def _http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> Any:
    req = urllib.request.Request(url=url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def _vt_malicious_from_stats(stats: dict[str, Any]) -> tuple[bool, float]:
    if not isinstance(stats, dict):
        return False, 0.0
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = mal + susp + harmless + undetected
    bad = mal + susp
    if total <= 0:
        return bad > 0, 0.0
    conf = min(1.0, max(0.0, bad / total))
    return bad > 0, conf


def _iso_to_age_days(date_str: str | None) -> int:
    if not date_str:
        return 0
    ds = date_str.strip()
    if ds.endswith("Z"):
        ds = ds[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ds)
    except Exception:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0, (now - dt).days)


def _live_tool_call(tool_id: str, payload: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    ioc_type = payload["ioc_type"]
    value = payload["value"]
    base_url = str(tool.get("base_url") or "").rstrip("/")

    if tool_id == "virustotal_url":
        api_key = _clean_secret(os.getenv("VT_API_KEY", ""))
        if not api_key:
            raise RuntimeError("VT_API_KEY missing")
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").strip("=")
        url = f"{base_url}/urls/{url_id}"
        data = _http_get_json(url, headers={"x-apikey": api_key})
        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious, confidence = _vt_malicious_from_stats(stats)
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "virustotal_ip":
        api_key = _clean_secret(os.getenv("VT_API_KEY", ""))
        if not api_key:
            raise RuntimeError("VT_API_KEY missing")
        url = f"{base_url}/ip_addresses/{urllib.parse.quote(value, safe='')}"
        data = _http_get_json(url, headers={"x-apikey": api_key})
        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious, confidence = _vt_malicious_from_stats(stats)
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "virustotal_hash":
        api_key = _clean_secret(os.getenv("VT_API_KEY", ""))
        if not api_key:
            raise RuntimeError("VT_API_KEY missing")
        url = f"{base_url}/files/{urllib.parse.quote(value, safe='')}"
        data = _http_get_json(url, headers={"x-apikey": api_key})
        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious, confidence = _vt_malicious_from_stats(stats)
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "urlscan_lookup":
        api_key = _clean_secret(os.getenv("URLSCAN_API_KEY", ""))
        if not api_key:
            raise RuntimeError("URLSCAN_API_KEY missing")
        queries: list[str]
        if ioc_type == "url":
            host = urllib.parse.urlparse(value).hostname or value
            queries = [f"domain:{host}", f"page.domain:{host}", f"page.url:\"{value}\""]
        else:
            queries = [f"domain:{value}", f"page.domain:{value}"]

        data = None
        last_error = None
        for query in queries:
            url = f"{base_url}/search/?q={urllib.parse.quote(query, safe='')}"
            try:
                data = _http_get_json(url, headers={"API-Key": api_key, "api-key": api_key})
                break
            except Exception as exc:
                last_error = exc
                continue
        if data is None:
            raise RuntimeError(f"urlscan lookup failed: {last_error}")

        results = data.get("results", []) if isinstance(data, dict) else []
        malicious = False
        confidence = 0.15
        for r in results[:5]:
            verdicts = r.get("verdicts", {}) if isinstance(r, dict) else {}
            overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
            if isinstance(overall, dict) and overall.get("malicious") is True:
                malicious = True
                confidence = max(confidence, 0.9)
                break
            score = overall.get("score") if isinstance(overall, dict) else None
            if isinstance(score, (int, float)):
                confidence = max(confidence, min(1.0, max(0.0, float(score) / 100.0)))
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "icann_rdap_domain":
        domain = urllib.parse.quote(value, safe="")
        candidates = [
            f"https://rdap.org/domain/{domain}",
            f"{base_url}/rdap/domain/{domain}",
            f"https://www.rdap.net/domain/{domain}",
        ]
        data = None
        last_error = None
        for url in candidates:
            try:
                data = _http_get_json(url)
                break
            except urllib.error.HTTPError as exc:
                if exc.code in {400, 404}:
                    continue
                last_error = exc
                continue
            except Exception as exc:
                last_error = exc
                continue
        if data is None:
            return {"status": "ok", "registered": False, "age_days": 0}

        events = data.get("events", []) if isinstance(data, dict) else []
        created = None
        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).lower()
            if action in {"registration", "registered", "creation", "created"}:
                created = ev.get("eventDate")
                break
        age_days = _iso_to_age_days(created)
        registered = bool(data.get("ldhName") or data.get("handle") or events)
        return {"status": "ok", "registered": registered, "age_days": age_days}

    if tool_id == "abuseipdb_check":
        api_key = _clean_secret(os.getenv("ABUSEIPDB_API_KEY", ""))
        if not api_key:
            raise RuntimeError("ABUSEIPDB_API_KEY missing")
        url = f"{base_url}/check?ipAddress={urllib.parse.quote(value, safe='')}&maxAgeInDays=90"
        data = _http_get_json(url, headers={"Key": api_key, "Accept": "application/json"})
        inner = data.get("data", {}) if isinstance(data, dict) else {}
        score = float(inner.get("abuseConfidenceScore", 0) or 0.0)
        malicious = score >= 25.0
        confidence = min(1.0, max(0.0, score / 100.0))
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "alienvault_otx":
        api_key = _clean_secret(os.getenv("OTX_API_KEY", ""))
        if not api_key:
            raise RuntimeError("OTX_API_KEY missing")
        type_map = {
            "url": "url",
            "domain": "domain",
            "ip": "IPv4",
            "hash": "file",
        }
        otx_type = type_map.get(ioc_type)
        if not otx_type:
            raise RuntimeError(f"Unsupported OTX ioc_type: {ioc_type}")
        encoded_value = urllib.parse.quote(value, safe="")
        url = f"{base_url}/indicators/{otx_type}/{encoded_value}/general"
        data = _http_get_json(url, headers={"X-OTX-API-KEY": api_key})
        pulse_info = data.get("pulse_info", {}) if isinstance(data, dict) else {}
        count = int(pulse_info.get("count", 0) or 0)
        malicious = count > 0
        confidence = min(0.95, max(0.1 if malicious else 0.05, count / 20.0))
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    if tool_id == "crtsh_lookup":
        q = urllib.parse.quote(value, safe="")
        url = f"{base_url}/?q={q}&output=json"
        data = _http_get_json(url)
        count = len(data) if isinstance(data, list) else 0
        # crt.sh is context signal; keep low-confidence maliciousness inference.
        malicious = False
        confidence = min(0.4, max(0.05, count / 1000.0))
        return {"status": "ok", "malicious": malicious, "confidence": confidence}

    raise RuntimeError(f"No live handler implemented for tool_id={tool_id}")


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
        schema = tool.get("output_schema", {})
        try:
            output = _live_tool_call(tool_id, payload, tool)
            _validate_output(output, schema)
            cache.set(tool_id, ioc_type, ioc_value, output)
            return {
                "schema_version": "1.0",
                "generated_at": _now_iso(),
                "tool_id": tool_id,
                "provider": tool.get("provider"),
                "input": payload,
                "output": output,
                "source": "live",
                "cache": {"hit": False, "ttl_seconds": ttl},
            }
        except Exception as exc:
            err_output = _build_error_output(schema, f"live_call_failed:{exc}")
            _validate_output(err_output, schema)
            return {
                "schema_version": "1.0",
                "generated_at": _now_iso(),
                "tool_id": tool_id,
                "provider": tool.get("provider"),
                "input": payload,
                "output": err_output,
                "source": "live_error",
                "cache": {"hit": False, "ttl_seconds": ttl},
            }

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
    parser.add_argument("--live", action="store_true", help="Enable live mode")
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
