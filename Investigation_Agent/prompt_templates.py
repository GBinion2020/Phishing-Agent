#!/usr/bin/env python3
"""Prompt templates for investigation planning, signal updates, and reporting."""

from __future__ import annotations

import json
from typing import Any


PLANNER_SYSTEM_PROMPT = """
You are a phishing investigation planner.
Rules:
- You must output valid JSON following the schema.
- Choose only playbooks provided in candidate list.
- Prioritize resolving high-impact unknown non-deterministic signals.
- Prefer highest expected confidence gain per cost.
- Do not output prose outside JSON.
""".strip()


SIGNAL_UPDATE_SYSTEM_PROMPT = """
You are a strict evidence-to-signal updater.
Rules:
- Update only non-deterministic signals.
- Never change deterministic signals.
- Every update must include evidence references from the provided tool evidence.
- If evidence is insufficient, leave signal as unknown (do not fabricate).
- Output valid JSON only.
""".strip()


REPORT_SYSTEM_PROMPT = """
You are a SOC analyst report generator.
Rules:
- Use only provided evidence and scores.
- If a fact is missing, list it under unknowns.
- Do not speculate.
- Output valid JSON only.
""".strip()



def planner_user_prompt(
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
    candidate_playbooks: list[dict[str, Any]],
    max_playbooks: int,
) -> str:
    unknown_high = [
        sid
        for sid, payload in signals_doc.get("signals", {}).items()
        if payload.get("value") == "unknown"
        and payload.get("kind") == "non_deterministic"
    ]
    compact = {
        "case_id": envelope.get("case_id"),
        "message_metadata": {
            "from": (envelope.get("message_metadata", {}).get("from") or {}).get("address"),
            "subject": envelope.get("message_metadata", {}).get("subject"),
            "date": envelope.get("message_metadata", {}).get("date"),
        },
        "risk": {
            "risk_score": score_doc.get("risk_score"),
            "confidence_score": score_doc.get("confidence_score"),
            "gate": score_doc.get("agent_gate"),
        },
        "unknown_non_deterministic_signals": unknown_high,
        "candidate_playbooks": [
            {
                "id": pb.get("id"),
                "priority": pb.get("priority"),
                "selection_score": pb.get("selection_score"),
                "matched_true_signals": pb.get("matched_true_signals"),
                "step_count": pb.get("step_count"),
            }
            for pb in candidate_playbooks
        ],
        "constraints": {
            "max_playbooks": max_playbooks,
            "objective": "maximize confidence gain with lowest cost",
        },
    }
    return json.dumps(compact, indent=2)



def signal_update_user_prompt(
    current_signals_doc: dict[str, Any],
    playbook: dict[str, Any],
    new_evidence: list[dict[str, Any]],
) -> str:
    snapshot = {
        "playbook": {
            "id": playbook.get("id"),
            "name": playbook.get("name"),
        },
        "current_non_deterministic_signals": {
            sid: payload
            for sid, payload in current_signals_doc.get("signals", {}).items()
            if payload.get("kind") == "non_deterministic"
        },
        "new_evidence": new_evidence,
    }
    return json.dumps(snapshot, indent=2)



def report_user_prompt(
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
    iterations: list[dict[str, Any]],
) -> str:
    compact = {
        "case_id": envelope.get("case_id"),
        "from": (envelope.get("message_metadata", {}).get("from") or {}).get("address"),
        "subject": envelope.get("message_metadata", {}).get("subject"),
        "final_score": {
            "risk_score": score_doc.get("risk_score"),
            "confidence_score": score_doc.get("confidence_score"),
            "verdict": score_doc.get("verdict"),
            "agent_gate": score_doc.get("agent_gate"),
        },
        "top_reasons": score_doc.get("reasons", [])[:8],
        "signal_summary": {
            "true": [sid for sid, p in signals_doc.get("signals", {}).items() if p.get("value") == "true"],
            "unknown": [sid for sid, p in signals_doc.get("signals", {}).items() if p.get("value") == "unknown"],
        },
        "iterations": [
            {
                "index": it.get("index"),
                "playbook_id": it.get("playbook_id"),
                "score_after": it.get("score_after", {}),
                "new_updates": it.get("signal_updates", []),
            }
            for it in iterations
        ],
        "instruction": "Produce concise SOC-ready summary with no unsupported claims",
    }
    return json.dumps(compact, indent=2)
