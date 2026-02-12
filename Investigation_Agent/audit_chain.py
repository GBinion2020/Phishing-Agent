#!/usr/bin/env python3
"""Audit chain builder for end-to-end pipeline traceability."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any



def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")



def _stage_status(error_count: int, warn_count: int = 0) -> str:
    if error_count > 0:
        return "error"
    if warn_count > 0:
        return "warning"
    return "ok"



def _count_signal_values(signals_doc: dict[str, Any]) -> dict[str, int]:
    counts = {"true": 0, "false": 0, "unknown": 0}
    for payload in signals_doc.get("signals", {}).values():
        v = payload.get("value")
        if v in counts:
            counts[v] += 1
    return counts



def build_audit_chain(
    *,
    eml_path: str,
    envelope: dict[str, Any],
    baseline_signals: dict[str, Any],
    semantic_doc: dict[str, Any],
    baseline_score: dict[str, Any],
    candidates_doc: dict[str, Any],
    plan_doc: dict[str, Any] | None,
    result: dict[str, Any],
) -> dict[str, Any]:
    sem_notes = str(semantic_doc.get("notes", ""))
    sem_fallback = "fallback" in sem_notes.lower()

    tool_errors: list[dict[str, Any]] = []
    iteration_rows: list[dict[str, Any]] = []

    for it in result.get("iterations", []):
        src_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for ev in it.get("evidence", []):
            res = ev.get("result") or {}
            src = res.get("source", "unknown")
            src_counts[src] = src_counts.get(src, 0) + 1
            out = res.get("output") or {}
            st = out.get("status", "unknown")
            status_counts[st] = status_counts.get(st, 0) + 1
            if st == "error":
                tool_errors.append(
                    {
                        "playbook_id": it.get("playbook_id"),
                        "tool_id": ev.get("tool_id"),
                        "reason": out.get("reason", ""),
                    }
                )

        iteration_rows.append(
            {
                "index": it.get("index"),
                "playbook_id": it.get("playbook_id"),
                "tool_calls_used": it.get("tool_calls_used"),
                "evidence_count": it.get("evidence_count"),
                "source_counts": src_counts,
                "status_counts": status_counts,
                "score_after": it.get("score_after", {}),
            }
        )

    stages = [
        {
            "name": "ingestion_normalization",
            "status": _stage_status(0, 0),
            "details": {
                "input_eml": eml_path,
                "case_id": envelope.get("case_id"),
                "warnings": envelope.get("warnings", []),
            },
        },
        {
            "name": "baseline_signal_generation",
            "status": _stage_status(0, 0),
            "details": {
                "signal_counts": _count_signal_values(baseline_signals),
                "total_signals": len(baseline_signals.get("signals", {})),
            },
        },
        {
            "name": "semantic_assessment",
            "status": _stage_status(0, 1 if sem_fallback else 0),
            "details": {
                "fallback_used": sem_fallback,
                "prompt_injection_detected": semantic_doc.get("prompt_injection_detected"),
                "prompt_injection_indicators": semantic_doc.get("prompt_injection_indicators", []),
                "assessment_count": len(semantic_doc.get("assessments", [])),
                "notes": semantic_doc.get("notes", ""),
            },
        },
        {
            "name": "baseline_scoring",
            "status": _stage_status(0, 0),
            "details": {
                "risk_score": baseline_score.get("risk_score"),
                "confidence_score": baseline_score.get("confidence_score"),
                "verdict": baseline_score.get("verdict"),
                "agent_gate": baseline_score.get("agent_gate"),
            },
        },
        {
            "name": "playbook_selection",
            "status": _stage_status(0, 0),
            "details": {
                "candidate_count": candidates_doc.get("selected_playbook_count"),
                "candidate_ids": [p.get("id") for p in candidates_doc.get("selected_playbooks", [])],
            },
        },
        {
            "name": "investigation_plan",
            "status": _stage_status(0, 1 if plan_doc and any("fallback" in str(x).lower() for x in plan_doc.get("why", [])) else 0),
            "details": {
                "playbook_order": (plan_doc or {}).get("playbook_order", []),
                "why": (plan_doc or {}).get("why", []),
            },
        },
        {
            "name": "playbook_execution_loop",
            "status": _stage_status(len(tool_errors), 0),
            "details": {
                "iteration_count": len(iteration_rows),
                "iterations": iteration_rows,
                "tool_error_count": len(tool_errors),
            },
        },
        {
            "name": "final_decision",
            "status": _stage_status(0, 0),
            "details": {
                "stop_reason": result.get("stop_reason"),
                "risk_score": (result.get("final_score") or {}).get("risk_score"),
                "confidence_score": (result.get("final_score") or {}).get("confidence_score"),
                "verdict": (result.get("final_score") or {}).get("verdict"),
                "agent_gate": (result.get("final_score") or {}).get("agent_gate"),
            },
        },
    ]

    return {
        "schema_version": "1.0",
        "generated_at": _now_iso(),
        "case_id": envelope.get("case_id"),
        "guardrails": {
            "llm_can_execute_tools": False,
            "llm_final_verdict_control": False,
            "deterministic_verdict_engine": True,
            "prompt_injection_system_guard": True,
        },
        "stages": stages,
        "errors": tool_errors,
    }



def to_markdown(audit: dict[str, Any]) -> str:
    lines = []
    lines.append(f"# Audit Chain: {audit.get('case_id', 'unknown')}")
    lines.append("")
    lines.append("## Guardrails")
    guard = audit.get("guardrails", {})
    for k, v in guard.items():
        lines.append(f"- `{k}`: `{v}`")
    lines.append("")

    lines.append("## Stage Summary")
    for st in audit.get("stages", []):
        lines.append(f"- `{st.get('name')}` -> `{st.get('status')}`")
    lines.append("")

    lines.append("## Tool Errors")
    errs = audit.get("errors", [])
    if not errs:
        lines.append("- none")
    else:
        for e in errs[:30]:
            lines.append(f"- `{e.get('playbook_id')}` `{e.get('tool_id')}`: {e.get('reason')}")

    return "\n".join(lines) + "\n"
