"""Reusable service layer for launching phishing investigation runs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Investigation_Agent.investigation_pipeline import EventHook, run_pipeline


class PipelineService:
    """Small orchestration wrapper used by CLI now and HTTP UI later."""

    def __init__(self, base_output_dir: str | Path = "Sample_Emails") -> None:
        self.base_output_dir = Path(base_output_dir)

    def build_run_output_dir(self, mode: str) -> Path:
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.base_output_dir / f"Case_Run_{mode.upper()}_{stamp}"

    def execute(self, eml_path: str, mode: str = "mock", event_hook: EventHook | None = None) -> dict[str, Any]:
        out_dir = self.build_run_output_dir(mode)
        result = run_pipeline(eml_path=eml_path, out_dir=str(out_dir), mode=mode, event_hook=event_hook)
        result["artifacts_dir"] = str(out_dir)
        return result


def summarize_result(result: dict[str, Any]) -> dict[str, Any]:
    final_score = result.get("final_score", {})
    final_report = result.get("final_report", {})
    return {
        "case_id": result.get("case_id"),
        "mode": result.get("mode"),
        "verdict": final_score.get("verdict"),
        "risk_score": final_score.get("risk_score"),
        "confidence_score": final_score.get("confidence_score"),
        "stop_reason": result.get("stop_reason", "agent_not_invoked"),
        "used_playbooks": (result.get("budgets") or {}).get("used_playbooks", 0),
        "executive_summary": final_report.get("executive_summary", ""),
        "artifacts_dir": result.get("artifacts_dir"),
    }


def scrub_runtime_state(data: Any) -> None:
    """Best-effort memory scrubbing for in-process runtime state between runs."""
    if isinstance(data, dict):
        for value in list(data.values()):
            scrub_runtime_state(value)
        data.clear()
    elif isinstance(data, list):
        for value in data:
            scrub_runtime_state(value)
        data.clear()
