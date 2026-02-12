#!/usr/bin/env python3
"""Deterministic signal weighting and scoring engine.

Input: signals.json
Output: score decision JSON (risk, confidence, verdict, agent gate)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALID_SIGNAL_VALUE = {"true", "false", "unknown"}
VALID_SIGNAL_KIND = {"deterministic", "non_deterministic"}


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
                raise ValueError(f"Config at {path} must parse to a mapping")
            return loaded
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                f"Cannot parse {path}. Use JSON-compatible YAML or install PyYAML."
            ) from exc


def _validate_signals_document(signals_doc: dict[str, Any]) -> None:
    if not isinstance(signals_doc, dict):
        raise ValueError("signals document must be an object")
    if "signals" not in signals_doc:
        raise ValueError("signals document missing 'signals'")
    if not isinstance(signals_doc["signals"], dict):
        raise ValueError("signals field must be an object")

    for signal_id, payload in signals_doc["signals"].items():
        if not isinstance(payload, dict):
            raise ValueError(f"signal payload must be object: {signal_id}")
        value = payload.get("value")
        kind = payload.get("kind")
        evidence = payload.get("evidence")
        rationale = payload.get("rationale")
        if value not in VALID_SIGNAL_VALUE:
            raise ValueError(f"invalid value for {signal_id}: {value}")
        if kind not in VALID_SIGNAL_KIND:
            raise ValueError(f"invalid kind for {signal_id}: {kind}")
        if not isinstance(evidence, list):
            raise ValueError(f"evidence must be list for {signal_id}")
        if not isinstance(rationale, str):
            raise ValueError(f"rationale must be string for {signal_id}")


def _get_signal_weight(signal_id: str, kind: str, config: dict[str, Any]) -> float:
    risk_cfg = config["risk"]
    overrides = risk_cfg.get("signal_overrides", {})
    if signal_id in overrides and "true_weight" in overrides[signal_id]:
        return float(overrides[signal_id]["true_weight"])

    category = signal_id.split(".", 1)[0]
    category_defaults = risk_cfg.get("category_defaults", {}).get(category)
    if not category_defaults:
        return 0.0

    if kind == "deterministic":
        return float(category_defaults.get("deterministic", 0.0))
    return float(category_defaults.get("non_deterministic", 0.0))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def score_signals(signals_doc: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    _validate_signals_document(signals_doc)

    signals = signals_doc["signals"]
    risk_cfg = config["risk"]
    conf_cfg = config["confidence"]
    gate_cfg = config["agent_gate"]

    high_impact = set(risk_cfg.get("high_impact_signals", []))
    risk_score = 0.0

    total = len(signals)
    known = 0
    det_total = 0
    det_known = 0
    nondet_total = 0
    nondet_known = 0
    evidence_present = 0
    true_without_evidence = 0
    high_impact_unknown = 0

    weighted_rows: list[dict[str, Any]] = []
    reasons: list[dict[str, Any]] = []

    for signal_id, payload in signals.items():
        value = payload["value"]
        kind = payload["kind"]
        evidence = payload.get("evidence", [])
        rationale = payload.get("rationale", "")
        weight_applied = 0.0

        if kind == "deterministic":
            det_total += 1
        else:
            nondet_total += 1

        if value in {"true", "false"}:
            known += 1
            if kind == "deterministic":
                det_known += 1
            else:
                nondet_known += 1

        if evidence:
            evidence_present += 1

        if value == "unknown" and signal_id in high_impact:
            high_impact_unknown += 1

        if value == "true":
            weight_applied = _get_signal_weight(signal_id, kind, config)
            risk_score += weight_applied
            if not evidence:
                true_without_evidence += 1
            reasons.append(
                {
                    "signal_id": signal_id,
                    "weight": weight_applied,
                    "kind": kind,
                    "rationale": rationale,
                    "evidence": evidence,
                }
            )

        weighted_rows.append(
            {
                "signal_id": signal_id,
                "kind": kind,
                "value": value,
                "weight_applied": round(weight_applied, 2),
                "high_impact": signal_id in high_impact,
            }
        )

    risk_score = _clamp(
        risk_score,
        float(risk_cfg.get("min_score", 0)),
        float(risk_cfg.get("max_score", 100)),
    )

    coverage = (known / total) if total else 0.0
    det_coverage = (det_known / det_total) if det_total else 0.0
    nondet_coverage = (nondet_known / nondet_total) if nondet_total else 0.0
    evidence_coverage = (evidence_present / total) if total else 0.0

    confidence_score = (
        float(conf_cfg.get("base", 0.2))
        + float(conf_cfg.get("coverage_weight", 0.4)) * coverage
        + float(conf_cfg.get("deterministic_coverage_weight", 0.1)) * det_coverage
        + float(conf_cfg.get("nondeterministic_coverage_weight", 0.1)) * nondet_coverage
        + float(conf_cfg.get("evidence_presence_weight", 0.1)) * evidence_coverage
        - float(conf_cfg.get("high_impact_unknown_penalty", 0.05)) * high_impact_unknown
        - float(conf_cfg.get("true_signal_without_evidence_penalty", 0.02)) * true_without_evidence
    )
    confidence_score = _clamp(
        confidence_score,
        float(conf_cfg.get("min", 0.0)),
        float(conf_cfg.get("max", 1.0)),
    )

    thresholds = risk_cfg.get("verdict_thresholds", {})
    benign_max = float(thresholds.get("benign_max", 20))
    phish_min = float(thresholds.get("phish_min", 75))
    if risk_score >= phish_min:
        verdict = "phish"
    elif risk_score <= benign_max:
        verdict = "benign"
    else:
        verdict = "suspicious"

    invoke_agent = True
    gate_reason = "Default route: invoke investigation agent for additional evidence"

    if high_impact_unknown >= int(gate_cfg.get("force_agent_if_high_impact_unknown_count_at_least", 2)):
        invoke_agent = True
        gate_reason = "High-impact unknown signals require enrichment"
    elif confidence_score < float(gate_cfg.get("force_agent_if_confidence_below", 0.65)):
        invoke_agent = True
        gate_reason = "Confidence below gate threshold"
    elif (
        risk_score >= float(gate_cfg.get("auto_phish_min_risk", 85))
        and confidence_score >= float(gate_cfg.get("auto_phish_min_confidence", 0.8))
    ):
        invoke_agent = False
        gate_reason = "Auto-classified phish with high confidence"
    elif (
        risk_score <= float(gate_cfg.get("auto_benign_max_risk", 20))
        and confidence_score >= float(gate_cfg.get("auto_benign_min_confidence", 0.8))
    ):
        invoke_agent = False
        gate_reason = "Auto-classified benign with high confidence"
    elif (
        float(gate_cfg.get("ambiguous_risk_min", 21))
        <= risk_score
        <= float(gate_cfg.get("ambiguous_risk_max", 84))
    ):
        invoke_agent = True
        gate_reason = "Risk in ambiguous band"

    reasons_sorted = sorted(reasons, key=lambda x: x["weight"], reverse=True)

    return {
        "schema_version": "1.0",
        "case_id": signals_doc.get("case_id"),
        "generated_at": _now_iso(),
        "risk_score": round(risk_score, 2),
        "confidence_score": round(confidence_score, 4),
        "verdict": verdict,
        "agent_gate": {
            "invoke_agent": invoke_agent,
            "reason": gate_reason,
        },
        "metrics": {
            "signal_count": total,
            "known_signal_count": known,
            "deterministic_known": det_known,
            "non_deterministic_known": nondet_known,
            "high_impact_unknown_count": high_impact_unknown,
            "true_without_evidence_count": true_without_evidence,
        },
        "reasons": reasons_sorted[:15],
        "weighted_signals": weighted_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score phishing signals into risk/confidence decisions.")
    parser.add_argument("--signals", required=True, help="Path to signals JSON")
    parser.add_argument("--weights", default="Scoring_Engine/scoring_weights.yaml", help="Path to scoring weights config")
    parser.add_argument("--out", default=None, help="Output path for scoring JSON")
    args = parser.parse_args()

    signals_doc = json.loads(Path(args.signals).read_text(encoding="utf-8"))
    config = _load_yaml_like(Path(args.weights))
    result = score_signals(signals_doc, config)

    output = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
