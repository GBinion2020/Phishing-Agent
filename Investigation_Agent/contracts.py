#!/usr/bin/env python3
"""Prompt contracts and strict validators for the investigation agent."""

from __future__ import annotations

from typing import Any


VALID_SIGNAL_VALUE = {"true", "false", "unknown"}


PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "playbook_order",
        "why",
        "expected_signal_lift",
        "stop_conditions",
    ],
    "properties": {
        "playbook_order": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 8,
        },
        "why": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 8,
        },
        "expected_signal_lift": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 0,
            "maxItems": 20,
        },
        "stop_conditions": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 8,
        },
    },
}


SIGNAL_UPDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["updates", "notes"],
    "properties": {
        "updates": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["signal_id", "value", "evidence", "rationale"],
                "properties": {
                    "signal_id": {"type": "string"},
                    "value": {"type": "string", "enum": ["true", "false", "unknown"]},
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "maxItems": 10,
                    },
                    "rationale": {"type": "string", "minLength": 3, "maxLength": 400},
                },
            },
        },
        "notes": {"type": "string", "minLength": 0, "maxLength": 1200},
    },
}


REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["executive_summary", "key_indicators", "recommended_actions", "unknowns"],
    "properties": {
        "executive_summary": {"type": "string", "minLength": 3, "maxLength": 2000},
        "key_indicators": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 20,
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 20,
        },
        "unknowns": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 0,
            "maxItems": 20,
        },
    },
}


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def validate_plan(plan: dict[str, Any], allowed_playbook_ids: set[str], max_playbooks: int) -> None:
    _assert(isinstance(plan, dict), "plan must be an object")
    for key in PLAN_SCHEMA["required"]:
        _assert(key in plan, f"plan missing field: {key}")
    _assert(isinstance(plan["playbook_order"], list), "playbook_order must be list")
    _assert(1 <= len(plan["playbook_order"]) <= max_playbooks, "playbook_order size out of bounds")
    seen: set[str] = set()
    for pb_id in plan["playbook_order"]:
        _assert(isinstance(pb_id, str), "playbook id must be string")
        _assert(pb_id in allowed_playbook_ids, f"playbook not allowed: {pb_id}")
        _assert(pb_id not in seen, f"duplicate playbook in plan: {pb_id}")
        seen.add(pb_id)
    _assert(isinstance(plan["why"], list), "why must be list")
    _assert(isinstance(plan["expected_signal_lift"], list), "expected_signal_lift must be list")
    _assert(isinstance(plan["stop_conditions"], list), "stop_conditions must be list")



def validate_signal_updates(
    updates_doc: dict[str, Any],
    allowed_signal_ids: set[str],
    non_deterministic_only: set[str],
) -> None:
    _assert(isinstance(updates_doc, dict), "updates doc must be object")
    _assert("updates" in updates_doc and isinstance(updates_doc["updates"], list), "updates missing/invalid")
    _assert("notes" in updates_doc and isinstance(updates_doc["notes"], str), "notes missing/invalid")

    for update in updates_doc["updates"]:
        _assert(isinstance(update, dict), "update item must be object")
        for field in ("signal_id", "value", "evidence", "rationale"):
            _assert(field in update, f"update missing field: {field}")
        signal_id = update["signal_id"]
        _assert(signal_id in allowed_signal_ids, f"unknown signal id: {signal_id}")
        _assert(signal_id in non_deterministic_only, f"deterministic signal update blocked: {signal_id}")
        _assert(update["value"] in VALID_SIGNAL_VALUE, f"invalid signal value: {update['value']}")
        _assert(isinstance(update["evidence"], list) and len(update["evidence"]) > 0, "evidence must be non-empty list")
        for ev in update["evidence"]:
            _assert(isinstance(ev, str) and ev.strip() != "", "evidence entries must be non-empty strings")
        _assert(isinstance(update["rationale"], str) and len(update["rationale"].strip()) >= 3, "rationale too short")



def validate_report(report_doc: dict[str, Any]) -> None:
    _assert(isinstance(report_doc, dict), "report must be object")
    for field in REPORT_SCHEMA["required"]:
        _assert(field in report_doc, f"report missing field: {field}")
    _assert(isinstance(report_doc["executive_summary"], str), "executive_summary must be string")
    _assert(isinstance(report_doc["key_indicators"], list), "key_indicators must be list")
    _assert(isinstance(report_doc["recommended_actions"], list), "recommended_actions must be list")
    _assert(isinstance(report_doc["unknowns"], list), "unknowns must be list")
