#!/usr/bin/env python3
"""Playbook selector driven by signal outcomes.

Selects pre-defined playbooks when trigger conditions are satisfied.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALID_SIGNAL_VALUE = {"true", "false", "unknown"}


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


def _validate_signals(signals_doc: dict[str, Any]) -> None:
    signals = signals_doc.get("signals")
    if not isinstance(signals, dict):
        raise ValueError("signals doc missing signals object")
    for signal_id, payload in signals.items():
        if not isinstance(payload, dict):
            raise ValueError(f"signal payload must be object: {signal_id}")
        value = payload.get("value")
        if value not in VALID_SIGNAL_VALUE:
            raise ValueError(f"invalid signal value for {signal_id}: {value}")


def _validate_playbooks(config: dict[str, Any]) -> None:
    pbs = config.get("playbooks")
    if not isinstance(pbs, list):
        raise ValueError("playbook config missing playbooks list")
    for pb in pbs:
        if not isinstance(pb, dict):
            raise ValueError("playbook entry must be object")
        for field in ("id", "name", "description", "priority", "triggers", "steps"):
            if field not in pb:
                raise ValueError(f"playbook missing field: {field}")
        triggers = pb["triggers"]
        for tfield in ("minimum_true", "any_true", "all_true"):
            if tfield not in triggers:
                raise ValueError(f"playbook {pb['id']} missing trigger field: {tfield}")
        if not isinstance(pb["steps"], list) or not pb["steps"]:
            raise ValueError(f"playbook {pb['id']} requires at least one step")


def select_playbooks(signals_doc: dict[str, Any], playbook_config: dict[str, Any]) -> dict[str, Any]:
    _validate_signals(signals_doc)
    _validate_playbooks(playbook_config)

    signals = signals_doc["signals"]
    selected: list[dict[str, Any]] = []

    for pb in playbook_config["playbooks"]:
        trigger = pb["triggers"]
        any_true = trigger.get("any_true", [])
        all_true = trigger.get("all_true", [])
        minimum_true = int(trigger.get("minimum_true", 1))

        true_hits = [sig for sig in any_true if sig in signals and signals[sig].get("value") == "true"]
        all_true_ok = all(sig in signals and signals[sig].get("value") == "true" for sig in all_true)

        if not all_true_ok:
            continue

        if any_true:
            if len(true_hits) < minimum_true:
                continue
        else:
            if minimum_true > 0:
                continue

        confidence_bonus = 0.0
        for sig in true_hits:
            if signals[sig].get("kind") == "non_deterministic":
                confidence_bonus += 2.0
            if signals[sig].get("evidence"):
                confidence_bonus += 0.5

        selected.append(
            {
                "id": pb["id"],
                "name": pb["name"],
                "description": pb["description"],
                "priority": pb["priority"],
                "matched_true_signals": true_hits,
                "required_all_true_signals": all_true,
                "step_count": len(pb["steps"]),
                "steps": pb["steps"],
                "selection_score": round(float(pb["priority"]) + len(true_hits) * 5 + confidence_bonus, 2),
            }
        )

    selected_sorted = sorted(selected, key=lambda x: x["selection_score"], reverse=True)

    return {
        "schema_version": "1.0",
        "case_id": signals_doc.get("case_id"),
        "generated_at": _now_iso(),
        "selected_playbook_count": len(selected_sorted),
        "selected_playbooks": selected_sorted,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Select investigation playbooks from signal outputs.")
    parser.add_argument("--signals", required=True, help="Path to signals JSON")
    parser.add_argument("--playbooks", default="Playbooks/playbook_library.yaml", help="Path to playbook config")
    parser.add_argument("--out", default=None, help="Output path for selected playbooks JSON")
    args = parser.parse_args()

    signals_doc = json.loads(Path(args.signals).read_text(encoding="utf-8"))
    playbook_config = _load_yaml_like(Path(args.playbooks))
    result = select_playbooks(signals_doc, playbook_config)

    output = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
