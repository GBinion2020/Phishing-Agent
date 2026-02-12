#!/usr/bin/env python3
"""Interactive CLI for the phishing triage pipeline."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LAUNCH_CWD = Path.cwd()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from Investigation_Agent.pipeline_service import PipelineService, scrub_runtime_state, summarize_result


STAGE_LABELS = {
    "load_configs": "Load configuration",
    "normalize_envelope": "Normalize envelope",
    "baseline_scoring": "Baseline signals and score",
    "select_playbooks": "Playbook selection",
    "build_plan": "Investigation plan",
    "adaptive_investigation": "Adaptive investigation",
    "final_report": "Final report",
}


class CLIView:
    def __init__(self) -> None:
        self._rich = None
        self._console = None
        try:
            from rich.console import Console

            self._rich = True
            self._console = Console()
        except Exception:
            self._rich = False

    def banner(self) -> None:
        line = "=" * 74
        self.print(line)
        self.print("Phishing Triage Agent CLI")
        self.print("Evidence-first investigation for .eml files")
        self.print(line)

    def print(self, message: str) -> None:
        if self._rich:
            self._console.print(message)
        else:
            print(message)

    def event_hook(self, event: str, payload: dict[str, Any]) -> None:
        if event == "pipeline_started":
            self.print("\n[RUN] Starting pipeline")
            self.print(f"      input={payload.get('eml_path')}")
            self.print(f"      mode={payload.get('mode')}")
        elif event == "stage_started":
            stage = payload.get("stage", "")
            label = STAGE_LABELS.get(stage, stage)
            self.print(f"\n[STEP] {label} ...")
        elif event == "stage_completed":
            stage = payload.get("stage", "")
            label = STAGE_LABELS.get(stage, stage)
            self.print(f"[DONE] {label}")
            if stage == "baseline_scoring":
                self.print(
                    "       "
                    f"risk={payload.get('risk_score')} confidence={payload.get('confidence_score')} "
                    f"verdict={payload.get('verdict')} invoke_agent={payload.get('invoke_agent')}"
                )
        elif event == "playbook_started":
            self.print(
                f"[PLAYBOOK] {payload.get('playbook_id')} | {payload.get('playbook_name')} "
                f"(expected_gain={payload.get('expected_gain')})"
            )
        elif event == "playbook_completed":
            self.print(
                "[RESULT] "
                f"risk={payload.get('risk_score')} confidence={payload.get('confidence_score')} "
                f"verdict={payload.get('verdict')} tool_calls={payload.get('tool_calls_used')}"
            )
            notes = payload.get("llm_notes")
            if notes:
                self.print(f"         agent_reasoning={notes}")
        elif event == "pipeline_completed":
            self.print("\n[COMPLETE] Pipeline finished")

    def show_summary(self, summary: dict[str, Any]) -> None:
        self.print("\n--- Investigation Summary ---")
        self.print(f"case_id: {summary.get('case_id')}")
        self.print(f"mode: {summary.get('mode')}")
        self.print(f"verdict: {summary.get('verdict')}")
        self.print(f"risk_score: {summary.get('risk_score')}")
        self.print(f"confidence_score: {summary.get('confidence_score')}")
        self.print(f"stop_reason: {summary.get('stop_reason')}")
        self.print(f"used_playbooks: {summary.get('used_playbooks')}")
        self.print(f"artifacts_dir: {summary.get('artifacts_dir')}")
        executive = summary.get("executive_summary")
        if executive:
            self.print("\nAnalyst Explanation:")
            self.print(executive)


def validate_eml_path(raw_path: str) -> tuple[bool, str]:
    p = Path(raw_path).expanduser()
    if not p.is_absolute():
        p = (LAUNCH_CWD / p).resolve()
    if not p.exists() or not p.is_file():
        return False, f"Path does not exist or is not a file: {p}"
    if p.suffix.lower() != ".eml":
        return False, "Invalid extension. Only .eml files are accepted."
    return True, str(p.resolve())


def ask_eml_path(view: CLIView) -> str | None:
    while True:
        user_input = input("Enter full path to .eml file (or 'q' to quit): ").strip()
        if user_input.lower() in {"q", "quit", "exit"}:
            return None
        ok, msg = validate_eml_path(user_input)
        if ok:
            return msg
        view.print(f"[ERROR] {msg}")


def ask_mode(default_mode: str) -> str:
    while True:
        value = input(f"Mode [mock/live] (default: {default_mode}): ").strip().lower()
        if not value:
            return default_mode
        if value in {"mock", "live"}:
            return value
        print("[ERROR] Mode must be 'mock' or 'live'.")


def ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = "[y/N]" if default_no else "[Y/n]"
    value = input(f"{prompt} {suffix}: ").strip().lower()
    if not value:
        return not default_no
    return value in {"y", "yes"}


def run_once(service: PipelineService, view: CLIView, eml_path: str, mode: str, scrub_artifacts: bool) -> dict[str, Any]:
    result = service.execute(eml_path=eml_path, mode=mode, event_hook=view.event_hook)
    summary = summarize_result(result)
    view.show_summary(summary)

    if scrub_artifacts:
        artifacts_dir = summary.get("artifacts_dir")
        if artifacts_dir:
            shutil.rmtree(artifacts_dir, ignore_errors=True)
            view.print(f"[SCRUB] Removed artifacts directory: {artifacts_dir}")

    # Prevent cross-run bleed of potentially sensitive fields in process memory.
    scrub_runtime_state(result)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive CLI for phishing email investigation")
    parser.add_argument("--eml", help="Optional .eml file path. If omitted, interactive prompt is used.")
    parser.add_argument("--mode", choices=["mock", "live"], default=os.getenv("INVESTIGATION_MODE", "mock"))
    parser.add_argument("--out-base", default="Sample_Emails", help="Base output directory for case artifacts")
    parser.add_argument("--scrub-artifacts", action="store_true", help="Delete run artifacts immediately after each run")
    args = parser.parse_args()

    view = CLIView()
    view.banner()
    service = PipelineService(base_output_dir=args.out_base)

    while True:
        if args.eml:
            ok, msg = validate_eml_path(args.eml)
            if not ok:
                raise SystemExit(f"Invalid --eml value: {msg}")
            eml_path = msg
        else:
            eml_path = ask_eml_path(view)
            if eml_path is None:
                view.print("Exiting.")
                return

        mode = args.mode if args.eml else ask_mode(args.mode)

        try:
            run_once(service, view, eml_path, mode, scrub_artifacts=args.scrub_artifacts)
        except KeyboardInterrupt:
            view.print("\nInterrupted.")
            return
        except Exception as exc:
            view.print(f"[ERROR] Run failed: {exc}")

        if args.eml:
            return

        if not ask_yes_no("Run another email?", default_no=False):
            view.print("Done.")
            return


if __name__ == "__main__":
    main()
