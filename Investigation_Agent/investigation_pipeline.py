#!/usr/bin/env python3
"""End-to-end phishing investigation pipeline with adaptive playbook execution.

Pipeline:
1) Ingest and normalize envelope
2) Baseline signals and scoring
3) Candidate playbook selection
4) LLM investigation plan (with deterministic fallback)
5) Adaptive playbook loop with confidence gate and pivot
6) Final deterministic score + analyst report
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "MCP_Adapters") not in sys.path:
    sys.path.insert(0, str(ROOT / "MCP_Adapters"))

from src.Ingestion.intake import build_envelope
from Signal_Engine.signal_engine import run_signal_engine
from Signal_Engine.semantic_signal_assessor import (
    assess_semantic_signals,
    build_controlled_evidence_envelope,
    semantic_assessments_to_updates,
)
from Scoring_Engine.scoring_engine import score_signals
from Playbooks.playbook_selector import select_playbooks
from MCP_Adapters.ioc_cache import IOCCache
from MCP_Adapters.mcp_router import route_tool_call, seed_cache
from MCP_Adapters.mock_enrichment import synthesize_mock_output

from Investigation_Agent.contracts import (
    PLAN_SCHEMA,
    REPORT_SCHEMA,
    SIGNAL_UPDATE_SCHEMA,
    validate_plan,
    validate_report,
    validate_signal_updates,
)
from Investigation_Agent.audit_chain import build_audit_chain, to_markdown
from Investigation_Agent.env_utils import env_float, env_int, load_dotenv
from Investigation_Agent.llm_client import LLMClient
from Investigation_Agent.prompt_templates import (
    PLANNER_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    SIGNAL_UPDATE_SYSTEM_PROMPT,
    planner_user_prompt,
    report_user_prompt,
    signal_update_user_prompt,
)


TOOL_ALIAS_TO_MCP: dict[str, list[str]] = {
    "url_reputation": ["virustotal_url", "urlscan_lookup", "urlhaus_lookup"],
    # Cuckoo detonation is intentionally disabled until local sandbox infra is ready.
    "url_detonation": ["urlscan_detonate"],
    "whois_domain_age": ["icann_rdap_domain"],
    "hash_intel_lookup": ["virustotal_hash", "alienvault_otx"],
    "ip_reputation": ["abuseipdb_check", "virustotal_ip"],
    "mx_reputation": ["crtsh_lookup"],
}

INTERNAL_TRUSTED_DOMAINS = {
    "microsoft.com",
    "google.com",
    "amazon.com",
    "apple.com",
    "docusign.net",
    "paypal.com",
    "outlook.com",
    "office.com",
    "valero.com",
}

TOOL_ALIAS_TO_SIGNAL_IDS: dict[str, list[str]] = {
    "org_domain_inventory": ["identity.domain_not_owned_by_org"],
    "whois_domain_age": ["identity.newly_registered_sender_domain", "url.domain_newly_registered"],
    "brand_lookalike_detector": ["identity.lookalike_domain_confirmed"],
    "dns_txt_lookup": ["auth.missing_spf_record", "auth.missing_dmarc_record"],
    "url_reputation": ["url.reputation_malicious"],
    "url_detonation": ["url.reputation_malicious", "url.redirect_chain_detected"],
    "url_redirect_resolver": ["url.redirect_chain_detected"],
    "hosting_provider_intel": ["url.hosting_on_free_provider", "infra.bulletproof_hosting_detected"],
    "campaign_similarity": ["content.similarity_to_known_campaign"],
    "nlp_anomaly_model": ["content.nlp_anomaly_score_high"],
    "hash_intel_lookup": ["attachment.hash_known_malicious"],
    "attachment_sandbox": ["attachment.sandbox_behavior_malicious"],
    "ip_reputation": ["infra.sending_ip_reputation_bad"],
    "dns_mx_lookup": ["infra.malicious_mx_records"],
    "mx_reputation": ["infra.malicious_mx_records", "infra.bulletproof_hosting_detected"],
    "mailbox_history": ["behavior.user_not_previous_correspondent"],
    "campaign_clustering": ["behavior.multiple_similar_messages_detected"],
    "dns_history": ["evasion.domain_fast_flux_behavior"],
    "cdn_fronting_detector": ["evasion.cdn_abuse_detected"],
}


@dataclass
class Budget:
    max_playbooks: int
    max_steps: int
    max_tool_calls: int
    min_expected_gain: float


EventHook = Callable[[str, dict[str, Any]], None]



def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(event_hook: EventHook | None, event: str, payload: dict[str, Any]) -> None:
    if event_hook is None:
        return
    try:
        event_hook(event, payload)
    except Exception:
        # Event handlers are best-effort and should not break the pipeline.
        return



def _load_json_or_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            parsed = yaml.safe_load(text)
        except ModuleNotFoundError as exc:
            raise RuntimeError(f"Cannot parse {path}. Use JSON-compatible YAML or install PyYAML.") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected mapping in {path}")
    return parsed



def _extract_primary_domain(envelope: dict[str, Any]) -> str | None:
    return ((envelope.get("message_metadata", {}).get("from") or {}).get("domain") or None)


def _org_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower().strip(".")
    return ".".join(parts[-2:])


def _configured_org_domains() -> set[str]:
    raw = os.getenv("ORG_TRUSTED_DOMAINS", "")
    values = {v.strip().lower() for v in raw.split(",") if v.strip()}
    return values



def _extract_urls(envelope: dict[str, Any]) -> list[str]:
    return [u.get("normalized") for u in envelope.get("entities", {}).get("urls", []) if u.get("normalized")]



def _extract_domains(envelope: dict[str, Any]) -> list[str]:
    out = [d.get("domain") for d in envelope.get("entities", {}).get("domains", []) if d.get("domain")]
    primary = _extract_primary_domain(envelope)
    if primary and primary not in out:
        out.append(primary)
    return out



def _extract_ips(envelope: dict[str, Any]) -> list[str]:
    return [i.get("ip") for i in envelope.get("entities", {}).get("ips", []) if i.get("ip")]



def _extract_hashes(envelope: dict[str, Any]) -> list[str]:
    hashes = []
    for att in envelope.get("attachments", []) or []:
        sha = (att.get("hashes") or {}).get("sha256")
        if sha:
            hashes.append(sha)
    return hashes



def _non_deterministic_signal_ids(signals_doc: dict[str, Any]) -> set[str]:
    return {
        sid
        for sid, payload in signals_doc.get("signals", {}).items()
        if payload.get("kind") == "non_deterministic"
    }



def _all_signal_ids(signals_doc: dict[str, Any]) -> set[str]:
    return set(signals_doc.get("signals", {}).keys())



def _high_impact_unknown(signals_doc: dict[str, Any], scoring_cfg: dict[str, Any]) -> set[str]:
    high = set(scoring_cfg.get("risk", {}).get("high_impact_signals", []))
    return {
        sid
        for sid, payload in signals_doc.get("signals", {}).items()
        if sid in high and payload.get("value") == "unknown"
    }



def _build_tool_payloads(tool_alias: str, envelope: dict[str, Any]) -> list[dict[str, str]]:
    urls = _extract_urls(envelope)
    domains = _extract_domains(envelope)
    ips = _extract_ips(envelope)
    hashes = _extract_hashes(envelope)

    if tool_alias in {"url_reputation", "url_detonation"}:
        return [{"ioc_type": "url", "value": u} for u in urls[:3]]
    if tool_alias in {"whois_domain_age", "brand_lookalike_detector", "dns_txt_lookup", "dns_mx_lookup", "dns_history", "cdn_fronting_detector", "hosting_provider_intel", "mx_reputation"}:
        return [{"ioc_type": "domain", "value": d} for d in domains[:3]]
    if tool_alias in {"ip_reputation"}:
        return [{"ioc_type": "ip", "value": ip} for ip in ips[:3]]
    if tool_alias in {"hash_intel_lookup", "attachment_sandbox"}:
        return [{"ioc_type": "hash", "value": h} for h in hashes[:2]]

    # Internal text/history tools still return one domain context payload.
    if domains:
        return [{"ioc_type": "domain", "value": domains[0]}]
    return []



def _execute_internal_tool(tool_alias: str, payload: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    value = str(payload.get("value", "")).lower()

    if tool_alias == "org_domain_inventory":
        configured = _configured_org_domains()
        if not configured:
            return {"status": "deferred", "reason": "ORG_TRUSTED_DOMAINS not configured", "confidence": 0.0}
        org_set = INTERNAL_TRUSTED_DOMAINS.union(configured)
        owned = (
            value in org_set
            or _org_domain(value) in org_set
            or value.endswith(".edu")
            or value.endswith(".gov")
        )
        return {"status": "ok", "owned": owned, "confidence": 0.8 if owned else 0.7}

    if tool_alias == "brand_lookalike_detector":
        lookalike = "-" in value and not value.endswith(".edu")
        return {"status": "ok", "is_lookalike": lookalike, "confidence": 0.8 if lookalike else 0.3}

    if tool_alias == "dns_txt_lookup":
        suspicious = "secure" in value or "verify" in value
        return {"status": "ok", "spf_exists": not suspicious, "dmarc_exists": not suspicious, "confidence": 0.7}

    if tool_alias == "dns_mx_lookup":
        malicious = "mail" in value and "secure" in value
        return {"status": "ok", "malicious": malicious, "confidence": 0.6}

    if tool_alias == "url_redirect_resolver":
        redirect_chain = any(tok in value for tok in ("redirect", "target=", "next=", "url="))
        return {"status": "ok", "redirect_chain": redirect_chain, "confidence": 0.7}

    if tool_alias == "campaign_similarity":
        text = (envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_plain", "") or "").lower()
        matched = any(t in text for t in ("verify", "urgent", "password", "invoice"))
        return {"status": "ok", "matched": matched, "confidence": 0.65}

    if tool_alias == "nlp_anomaly_model":
        text = (envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_plain", "") or "")
        anomaly = len(text) > 120 and ("http" in text.lower() or "urgent" in text.lower())
        return {"status": "ok", "score": 0.82 if anomaly else 0.18, "threshold": 0.7, "confidence": 0.6}

    if tool_alias == "attachment_sandbox":
        # Static mock until live sandbox exists.
        hashes = _extract_hashes(envelope)
        malicious = any(h.startswith("deadbeef") for h in hashes)
        return {"status": "ok", "malicious_behavior": malicious, "confidence": 0.75 if malicious else 0.2}

    if tool_alias == "mailbox_history":
        # Do not assert "new correspondent" without real mailbox telemetry.
        return {"status": "deferred", "reason": "mailbox history provider not configured", "confidence": 0.0}

    if tool_alias == "campaign_clustering":
        subject = (envelope.get("message_metadata", {}).get("subject") or "").lower()
        clustered = any(k in subject for k in ("urgent", "invoice", "verify", "password"))
        return {"status": "ok", "clustered": clustered, "cluster_size": 4 if clustered else 1, "confidence": 0.6}

    if tool_alias == "dns_history":
        fast_flux = any(tok in value for tok in ("secure", "verify", "update"))
        return {"status": "ok", "fast_flux": fast_flux, "confidence": 0.65}

    if tool_alias == "cdn_fronting_detector":
        abuse = any(tok in value for tok in ("cdn", "front"))
        return {"status": "ok", "abuse_detected": abuse, "confidence": 0.55}

    if tool_alias == "hosting_provider_intel":
        free = any(tok in value for tok in ("blogspot", "weebly", "wixsite", "000webhost"))
        bulletproof = any(tok in value for tok in ("offshore", "secure")) and free
        return {"status": "ok", "is_free_hosting": free, "is_bulletproof": bulletproof, "confidence": 0.5}

    return {"status": "deferred", "confidence": 0.0}



def _map_tool_result_to_signal_updates(
    tool_alias: str,
    payload: dict[str, Any],
    result: dict[str, Any],
    evidence_id: str,
) -> list[dict[str, Any]]:
    output = result.get("output", result)
    updates: list[dict[str, Any]] = []
    if not isinstance(output, dict):
        return updates
    if str(output.get("status", "ok")).lower() != "ok":
        return updates

    def add(signal_id: str, value: str, rationale: str) -> None:
        updates.append(
            {
                "signal_id": signal_id,
                "value": value,
                "evidence": [evidence_id],
                "rationale": rationale,
            }
        )

    if tool_alias == "org_domain_inventory":
        owned = output.get("owned")
        if isinstance(owned, bool):
            add("identity.domain_not_owned_by_org", "false" if owned else "true", f"domain ownership check owned={owned}")

    elif tool_alias == "whois_domain_age":
        registered = output.get("registered")
        age_days = output.get("age_days")
        if isinstance(age_days, int):
            if registered is False or age_days <= 0:
                value = "unknown"
                rationale = f"domain registration age unavailable (registered={registered}, age_days={age_days})"
            else:
                value = "true" if age_days < 30 else "false"
                rationale = f"domain age days={age_days}"
            add("identity.newly_registered_sender_domain", value, rationale)
            add("url.domain_newly_registered", value, rationale)

    elif tool_alias == "brand_lookalike_detector":
        lookalike = output.get("is_lookalike")
        if isinstance(lookalike, bool):
            add("identity.lookalike_domain_confirmed", "true" if lookalike else "false", f"lookalike result={lookalike}")

    elif tool_alias == "dns_txt_lookup":
        spf_exists = output.get("spf_exists")
        dmarc_exists = output.get("dmarc_exists")
        if isinstance(spf_exists, bool):
            add("auth.missing_spf_record", "false" if spf_exists else "true", f"spf_exists={spf_exists}")
        if isinstance(dmarc_exists, bool):
            add("auth.missing_dmarc_record", "false" if dmarc_exists else "true", f"dmarc_exists={dmarc_exists}")

    elif tool_alias == "url_reputation":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("url.reputation_malicious", "true" if mal else "false", f"url reputation malicious={mal}")

    elif tool_alias == "url_detonation":
        mal = output.get("malicious")
        redirects = output.get("redirects")
        if isinstance(mal, bool):
            add("url.reputation_malicious", "true" if mal else "false", f"url detonation malicious={mal}")
        if isinstance(redirects, int):
            add("url.redirect_chain_detected", "true" if redirects > 1 else "false", f"url detonation redirects={redirects}")

    elif tool_alias == "url_redirect_resolver":
        chain = output.get("redirect_chain")
        if isinstance(chain, bool):
            add("url.redirect_chain_detected", "true" if chain else "false", f"redirect_chain={chain}")

    elif tool_alias == "hosting_provider_intel":
        free = output.get("is_free_hosting")
        bullet = output.get("is_bulletproof")
        if isinstance(free, bool):
            add("url.hosting_on_free_provider", "true" if free else "false", f"is_free_hosting={free}")
        if isinstance(bullet, bool):
            add("infra.bulletproof_hosting_detected", "true" if bullet else "false", f"is_bulletproof={bullet}")

    elif tool_alias == "campaign_similarity":
        matched = output.get("matched")
        if isinstance(matched, bool):
            add("content.similarity_to_known_campaign", "true" if matched else "false", f"campaign matched={matched}")

    elif tool_alias == "nlp_anomaly_model":
        score = output.get("score")
        threshold = output.get("threshold")
        if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
            high = score >= threshold
            add("content.nlp_anomaly_score_high", "true" if high else "false", f"score={score}, threshold={threshold}")

    elif tool_alias == "hash_intel_lookup":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("attachment.hash_known_malicious", "true" if mal else "false", f"hash malicious={mal}")

    elif tool_alias == "attachment_sandbox":
        mal = output.get("malicious_behavior")
        if isinstance(mal, bool):
            add("attachment.sandbox_behavior_malicious", "true" if mal else "false", f"sandbox malicious_behavior={mal}")

    elif tool_alias == "ip_reputation":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("infra.sending_ip_reputation_bad", "true" if mal else "false", f"ip malicious={mal}")

    elif tool_alias in {"dns_mx_lookup", "mx_reputation"}:
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("infra.malicious_mx_records", "true" if mal else "false", f"mx malicious={mal}")

    elif tool_alias == "mailbox_history":
        prev = output.get("previous_contact")
        if isinstance(prev, bool):
            add("behavior.user_not_previous_correspondent", "false" if prev else "true", f"previous_contact={prev}")

    elif tool_alias == "campaign_clustering":
        clustered = output.get("clustered")
        if isinstance(clustered, bool):
            add("behavior.multiple_similar_messages_detected", "true" if clustered else "false", f"clustered={clustered}")

    elif tool_alias == "dns_history":
        ff = output.get("fast_flux")
        if isinstance(ff, bool):
            add("evasion.domain_fast_flux_behavior", "true" if ff else "false", f"fast_flux={ff}")

    elif tool_alias == "cdn_fronting_detector":
        abuse = output.get("abuse_detected")
        if isinstance(abuse, bool):
            add("evasion.cdn_abuse_detected", "true" if abuse else "false", f"abuse_detected={abuse}")

    return updates



def _dedupe_updates(updates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    rank = {"true": 3, "false": 2, "unknown": 1}
    for up in updates:
        sid = up["signal_id"]
        prev = latest.get(sid)
        if prev is None:
            latest[sid] = up
            continue
        prev_rank = rank.get(str(prev.get("value", "unknown")), 0)
        new_rank = rank.get(str(up.get("value", "unknown")), 0)
        if new_rank >= prev_rank:
            latest[sid] = up
    return list(latest.values())



def _apply_signal_updates(signals_doc: dict[str, Any], updates: list[dict[str, Any]]) -> None:
    for up in updates:
        sid = up["signal_id"]
        if sid not in signals_doc.get("signals", {}):
            continue
        payload = signals_doc["signals"][sid]
        if payload.get("kind") != "non_deterministic":
            continue
        payload["value"] = up["value"]
        payload["evidence"] = up["evidence"]
        payload["rationale"] = up["rationale"]



def _fallback_plan(candidate_playbooks: list[dict[str, Any]], max_playbooks: int) -> dict[str, Any]:
    ordered = sorted(candidate_playbooks, key=lambda x: x.get("selection_score", 0), reverse=True)
    picked = ordered[:max_playbooks]
    return {
        "playbook_order": [p.get("id") for p in picked],
        "why": ["Fallback deterministic ranking by selection_score"],
        "expected_signal_lift": [],
        "stop_conditions": [
            "stop when confidence gate passes",
            "stop when expected gain too low",
            "stop on budget exhaustion",
        ],
    }



def _expected_playbook_gain(
    playbook: dict[str, Any],
    signals_doc: dict[str, Any],
    high_impact_unknown: set[str],
    executed_target_signals: set[str],
) -> tuple[float, float, float]:
    target_signals: set[str] = set()
    total_cost = 0.0
    for step in playbook.get("steps", []):
        alias = step.get("tool")
        total_cost += float(step.get("cost", 1.0))
        for sig in TOOL_ALIAS_TO_SIGNAL_IDS.get(alias, []):
            target_signals.add(sig)

    unknown_targets = {
        sig
        for sig in target_signals
        if sig in signals_doc.get("signals", {})
        and signals_doc["signals"][sig].get("value") == "unknown"
    }

    coverage_high = len(high_impact_unknown.intersection(unknown_targets))
    overlap = len(target_signals.intersection(executed_target_signals))
    expected_gain = coverage_high * 0.20 + len(unknown_targets) * 0.05
    score = (expected_gain / (1.0 + total_cost)) + (float(playbook.get("priority", 0)) / 300.0) - (overlap * 0.03)
    return score, expected_gain, total_cost



def _choose_next_playbook(
    remaining: list[dict[str, Any]],
    signals_doc: dict[str, Any],
    scoring_cfg: dict[str, Any],
    executed_target_signals: set[str],
    llm_rank_order: list[str],
) -> tuple[dict[str, Any] | None, float]:
    if not remaining:
        return None, 0.0

    high_unknown = _high_impact_unknown(signals_doc, scoring_cfg)
    rank_bonus = {pb_id: (len(llm_rank_order) - idx) * 0.01 for idx, pb_id in enumerate(llm_rank_order)}

    ranked: list[tuple[float, float, dict[str, Any]]] = []
    for pb in remaining:
        score, gain, _cost = _expected_playbook_gain(pb, signals_doc, high_unknown, executed_target_signals)
        score += rank_bonus.get(pb.get("id"), 0.0)
        ranked.append((score, gain, pb))

    ranked.sort(key=lambda x: x[0], reverse=True)
    best_score, best_gain, best_pb = ranked[0]
    _ = best_score
    return best_pb, best_gain



def _llm_plan(
    llm: LLMClient,
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
    candidates: list[dict[str, Any]],
    max_playbooks: int,
) -> dict[str, Any]:
    if not llm.enabled:
        return _fallback_plan(candidates, max_playbooks)

    user_prompt = planner_user_prompt(envelope, signals_doc, score_doc, candidates, max_playbooks)
    out = llm.call_json(
        system_prompt=PLANNER_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        json_schema=PLAN_SCHEMA,
        schema_name="investigation_plan",
        temperature=0.0,
    )
    validate_plan(out, {p.get("id") for p in candidates}, max_playbooks)
    return out



def _llm_signal_updates(
    llm: LLMClient,
    signals_doc: dict[str, Any],
    playbook: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    if not llm.enabled:
        return {"updates": [], "notes": "LLM disabled; deterministic update path used"}

    user_prompt = signal_update_user_prompt(signals_doc, playbook, evidence)
    out = llm.call_json(
        system_prompt=SIGNAL_UPDATE_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        json_schema=SIGNAL_UPDATE_SCHEMA,
        schema_name="signal_updates",
        temperature=0.0,
    )
    validate_signal_updates(out, _all_signal_ids(signals_doc), _non_deterministic_signal_ids(signals_doc))
    return out



def _llm_report(
    llm: LLMClient,
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
    iterations: list[dict[str, Any]],
) -> dict[str, Any]:
    def _fallback_report(note: str) -> dict[str, Any]:
        return {
            "executive_summary": (
                f"Case {envelope.get('case_id')}: verdict={score_doc.get('verdict')} "
                f"risk={score_doc.get('risk_score')} confidence={score_doc.get('confidence_score')} "
                f"({note})"
            ),
            "key_indicators": [r.get("signal_id") for r in score_doc.get("reasons", [])[:6]],
            "recommended_actions": [
                "Block sender domain if policy allows",
                "Search mailbox for similar IOCs",
                "Escalate to SOC analyst if confidence remains low",
            ],
            "unknowns": [
                sid
                for sid, payload in signals_doc.get("signals", {}).items()
                if payload.get("value") == "unknown"
            ],
        }

    if not llm.enabled:
        return _fallback_report("LLM disabled")

    user_prompt = report_user_prompt(envelope, signals_doc, score_doc, iterations)
    try:
        out = llm.call_json(
            system_prompt=REPORT_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            json_schema=REPORT_SCHEMA,
            schema_name="investigation_report",
            temperature=0.0,
        )
        validate_report(out)
        return out
    except Exception as exc:
        return _fallback_report(f"LLM report fallback due to error: {exc}")



def _execute_playbook(
    playbook: dict[str, Any],
    envelope: dict[str, Any],
    registry: dict[str, Any],
    cache: IOCCache,
    mode: str,
    tool_call_budget_remaining: int,
    evidence_counter_start: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    evidence: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    tool_calls_used = 0
    ev_idx = evidence_counter_start

    for step in playbook.get("steps", []):
        tool_alias = step.get("tool")
        payloads = _build_tool_payloads(tool_alias, envelope)
        if not payloads:
            continue

        # Limit fanout to keep loop bounded.
        payloads = payloads[:2]

        for payload in payloads:
            if tool_calls_used >= tool_call_budget_remaining:
                break

            if tool_alias in TOOL_ALIAS_TO_MCP:
                mcp_tools = TOOL_ALIAS_TO_MCP[tool_alias]
                for mcp_tool in mcp_tools:
                    if tool_calls_used >= tool_call_budget_remaining:
                        break

                    if mode == "mock":
                        mock_output = synthesize_mock_output(mcp_tool, payload)
                        seed_cache(mcp_tool, payload, mock_output, registry, cache)

                    routed = route_tool_call(mcp_tool, payload, registry, cache, live_call=(mode == "live"))
                    ev_idx += 1
                    evidence_id = f"ev_mcp_{ev_idx:04d}"
                    ev = {
                        "evidence_id": evidence_id,
                        "tool_alias": tool_alias,
                        "tool_id": mcp_tool,
                        "payload": payload,
                        "result": routed,
                    }
                    evidence.append(ev)
                    updates.extend(_map_tool_result_to_signal_updates(tool_alias, payload, routed, evidence_id))
                    tool_calls_used += 1
            else:
                internal = _execute_internal_tool(tool_alias, payload, envelope)
                ev_idx += 1
                evidence_id = f"ev_internal_{ev_idx:04d}"
                ev = {
                    "evidence_id": evidence_id,
                    "tool_alias": tool_alias,
                    "tool_id": f"internal.{tool_alias}",
                    "payload": payload,
                    "result": internal,
                }
                evidence.append(ev)
                updates.extend(_map_tool_result_to_signal_updates(tool_alias, payload, internal, evidence_id))
                tool_calls_used += 1

        if tool_calls_used >= tool_call_budget_remaining:
            break

    return evidence, _dedupe_updates(updates), tool_calls_used



def run_pipeline(
    eml_path: str,
    out_dir: str,
    mode: str = "mock",
    event_hook: EventHook | None = None,
) -> dict[str, Any]:
    load_dotenv(str(ROOT / ".env"))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _emit(event_hook, "pipeline_started", {"eml_path": eml_path, "out_dir": str(out), "mode": mode})

    # Core configs
    _emit(event_hook, "stage_started", {"stage": "load_configs"})
    signal_taxonomy = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_taxonomy.yaml")
    signal_det_rules = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_rules_deterministic.yaml")
    signal_nondet_rules = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_rules_nondeterministic.yaml")
    scoring_cfg = _load_json_or_yaml(ROOT / "Scoring_Engine" / "scoring_weights.yaml")
    playbook_cfg = _load_json_or_yaml(ROOT / "Playbooks" / "playbook_library.yaml")
    mcp_registry_path = Path(os.getenv("MCP_TOOL_REGISTRY", "MCP_Adapters/mcp_tool_registry.yaml"))
    if not mcp_registry_path.is_absolute():
        mcp_registry_path = ROOT / mcp_registry_path
    mcp_registry = _load_json_or_yaml(mcp_registry_path)

    cache_path = os.getenv("MCP_CACHE_PATH", "MCP_Adapters/ioc_cache.json")
    cache_abs = Path(cache_path) if Path(cache_path).is_absolute() else ROOT / cache_path
    cache = IOCCache(path=str(cache_abs))

    budget = Budget(
        max_playbooks=env_int("INVESTIGATION_MAX_PLAYBOOKS", 5),
        max_steps=env_int("INVESTIGATION_MAX_STEPS", 20),
        max_tool_calls=env_int("INVESTIGATION_MAX_TOOL_CALLS", 30),
        min_expected_gain=env_float("INVESTIGATION_MIN_EXPECTED_GAIN", 0.04),
    )

    llm = LLMClient(timeout_seconds=env_int("OPENAI_TIMEOUT_SECONDS", 60))
    _emit(event_hook, "stage_completed", {"stage": "load_configs"})

    # 1) Envelope
    _emit(event_hook, "stage_started", {"stage": "normalize_envelope"})
    envelope = build_envelope(eml_path=eml_path, source="local_file")
    (out / "envelope.json").write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "normalize_envelope",
            "case_id": envelope.get("case_id"),
            "sender": (envelope.get("message_metadata", {}).get("from") or {}).get("address"),
            "subject": envelope.get("message_metadata", {}).get("subject"),
        },
    )

    # 2) Baseline signals + scoring
    _emit(event_hook, "stage_started", {"stage": "baseline_scoring"})
    signals_doc = run_signal_engine(
        envelope=envelope,
        taxonomy=signal_taxonomy,
        deterministic_rules=signal_det_rules,
        nondeterministic_rules=signal_nondet_rules,
        tool_results=None,
    )

    controlled_evidence = build_controlled_evidence_envelope(envelope)
    semantic_doc = assess_semantic_signals(controlled_evidence, llm=llm)
    semantic_updates = semantic_assessments_to_updates(semantic_doc)
    _apply_signal_updates(signals_doc, semantic_updates)

    baseline_signals = copy.deepcopy(signals_doc)
    score_doc = score_signals(signals_doc, scoring_cfg)
    baseline_score = copy.deepcopy(score_doc)

    (out / "evidence.controlled.json").write_text(json.dumps(controlled_evidence, indent=2) + "\n", encoding="utf-8")
    (out / "semantic_assessment.json").write_text(json.dumps(semantic_doc, indent=2) + "\n", encoding="utf-8")
    (out / "signals.baseline.json").write_text(json.dumps(signals_doc, indent=2) + "\n", encoding="utf-8")
    (out / "score.baseline.json").write_text(json.dumps(score_doc, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "baseline_scoring",
            "risk_score": score_doc.get("risk_score"),
            "confidence_score": score_doc.get("confidence_score"),
            "verdict": score_doc.get("verdict"),
            "invoke_agent": score_doc.get("agent_gate", {}).get("invoke_agent"),
        },
    )

    # 3) Candidate playbooks
    _emit(event_hook, "stage_started", {"stage": "select_playbooks"})
    candidates_doc = select_playbooks(signals_doc, playbook_cfg)
    candidates = candidates_doc.get("selected_playbooks", [])
    (out / "playbooks.candidates.json").write_text(json.dumps(candidates_doc, indent=2) + "\n", encoding="utf-8")
    _emit(event_hook, "stage_completed", {"stage": "select_playbooks", "candidate_count": len(candidates)})

    if not score_doc.get("agent_gate", {}).get("invoke_agent", True):
        _emit(event_hook, "stage_started", {"stage": "final_report"})
        final_report = _llm_report(llm, envelope, signals_doc, score_doc, [])
        result = {
            "schema_version": "1.0",
            "case_id": envelope.get("case_id"),
            "generated_at": _now_iso(),
            "mode": mode,
            "agent_invoked": False,
            "investigation_plan": None,
            "iterations": [],
            "final_signals": signals_doc,
            "final_score": score_doc,
            "final_report": final_report,
        }
        (out / "investigation_result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        _emit(
            event_hook,
            "stage_completed",
            {
                "stage": "final_report",
                "risk_score": score_doc.get("risk_score"),
                "confidence_score": score_doc.get("confidence_score"),
                "verdict": score_doc.get("verdict"),
            },
        )
        _emit(
            event_hook,
            "pipeline_completed",
            {
                "case_id": result.get("case_id"),
                "agent_invoked": False,
                "risk_score": score_doc.get("risk_score"),
                "confidence_score": score_doc.get("confidence_score"),
                "verdict": score_doc.get("verdict"),
            },
        )
        return result

    # 4) LLM plan with fallback
    _emit(event_hook, "stage_started", {"stage": "build_plan"})
    try:
        plan_doc = _llm_plan(llm, envelope, signals_doc, score_doc, candidates, budget.max_playbooks)
    except Exception as exc:
        plan_doc = _fallback_plan(candidates, budget.max_playbooks)
        plan_doc["why"].append(f"LLM plan fallback due to error: {exc}")

    (out / "investigation_plan.json").write_text(json.dumps(plan_doc, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {"stage": "build_plan", "planned_playbooks": plan_doc.get("playbook_order", [])[: budget.max_playbooks]},
    )

    # 5) Adaptive loop
    _emit(event_hook, "stage_started", {"stage": "adaptive_investigation"})
    llm_rank_order = [pid for pid in plan_doc.get("playbook_order", []) if isinstance(pid, str)]
    remaining = [pb for pb in candidates if pb.get("id") in llm_rank_order] + [pb for pb in candidates if pb.get("id") not in llm_rank_order]

    seen_pb: set[str] = set()
    iterations: list[dict[str, Any]] = []
    executed_target_signals: set[str] = set()
    total_tool_calls = 0
    total_steps = 0
    evidence_counter = 0

    current_signals = copy.deepcopy(signals_doc)
    current_score = copy.deepcopy(score_doc)

    while True:
        if len(seen_pb) >= budget.max_playbooks:
            stop_reason = "max_playbooks_reached"
            break
        if total_steps >= budget.max_steps:
            stop_reason = "max_steps_reached"
            break
        if total_tool_calls >= budget.max_tool_calls:
            stop_reason = "max_tool_calls_reached"
            break

        pool = [pb for pb in remaining if pb.get("id") not in seen_pb]
        if not pool:
            stop_reason = "no_remaining_playbooks"
            break

        next_pb, expected_gain = _choose_next_playbook(pool, current_signals, scoring_cfg, executed_target_signals, llm_rank_order)
        if not next_pb:
            stop_reason = "no_playbook_selected"
            break
        if expected_gain < budget.min_expected_gain:
            stop_reason = "expected_gain_below_threshold"
            break

        _emit(
            event_hook,
            "playbook_started",
            {
                "playbook_id": next_pb.get("id"),
                "playbook_name": next_pb.get("name"),
                "expected_gain": round(expected_gain, 4),
            },
        )
        seen_pb.add(next_pb["id"])
        total_steps += len(next_pb.get("steps", []))

        evidence, deterministic_updates, calls_used = _execute_playbook(
            playbook=next_pb,
            envelope=envelope,
            registry=mcp_registry,
            cache=cache,
            mode=mode,
            tool_call_budget_remaining=(budget.max_tool_calls - total_tool_calls),
            evidence_counter_start=evidence_counter,
        )
        total_tool_calls += calls_used
        evidence_counter += len(evidence)

        # deterministic updates from tool outputs
        updates = list(deterministic_updates)

        # optional LLM updates
        try:
            llm_updates_doc = _llm_signal_updates(llm, current_signals, next_pb, evidence)
            validate_signal_updates(llm_updates_doc, _all_signal_ids(current_signals), _non_deterministic_signal_ids(current_signals))
            updates.extend(llm_updates_doc.get("updates", []))
        except Exception as exc:
            llm_updates_doc = {"updates": [], "notes": f"LLM signal update fallback due to error: {exc}"}

        updates = _dedupe_updates(updates)
        _apply_signal_updates(current_signals, updates)

        # refresh score after this playbook
        current_score = score_signals(current_signals, scoring_cfg)

        for step in next_pb.get("steps", []):
            alias = step.get("tool")
            for sig in TOOL_ALIAS_TO_SIGNAL_IDS.get(alias, []):
                executed_target_signals.add(sig)

        iteration = {
            "index": len(iterations) + 1,
            "playbook_id": next_pb.get("id"),
            "playbook_name": next_pb.get("name"),
            "expected_gain": round(expected_gain, 4),
            "tool_calls_used": calls_used,
            "evidence_count": len(evidence),
            "evidence": evidence,
            "signal_updates": updates,
            "llm_update_notes": llm_updates_doc.get("notes", ""),
            "score_after": {
                "risk_score": current_score.get("risk_score"),
                "confidence_score": current_score.get("confidence_score"),
                "verdict": current_score.get("verdict"),
                "agent_gate": current_score.get("agent_gate"),
            },
        }
        iterations.append(iteration)
        _emit(
            event_hook,
            "playbook_completed",
            {
                "playbook_id": next_pb.get("id"),
                "playbook_name": next_pb.get("name"),
                "tool_calls_used": calls_used,
                "risk_score": current_score.get("risk_score"),
                "confidence_score": current_score.get("confidence_score"),
                "verdict": current_score.get("verdict"),
                "llm_notes": llm_updates_doc.get("notes", ""),
            },
        )

        # confidence gate after each playbook
        if not current_score.get("agent_gate", {}).get("invoke_agent", True):
            stop_reason = "confidence_gate_satisfied"
            break

    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "adaptive_investigation",
            "stop_reason": stop_reason,
            "used_playbooks": len(seen_pb),
            "used_tool_calls": total_tool_calls,
        },
    )
    _emit(event_hook, "stage_started", {"stage": "final_report"})
    final_report = _llm_report(llm, envelope, current_signals, current_score, iterations)

    result = {
        "schema_version": "1.0",
        "case_id": envelope.get("case_id"),
        "generated_at": _now_iso(),
        "mode": mode,
        "agent_invoked": True,
        "stop_reason": stop_reason,
        "budgets": {
            "max_playbooks": budget.max_playbooks,
            "max_steps": budget.max_steps,
            "max_tool_calls": budget.max_tool_calls,
            "used_playbooks": len(seen_pb),
            "used_steps": total_steps,
            "used_tool_calls": total_tool_calls,
        },
        "investigation_plan": plan_doc,
        "iterations": iterations,
        "final_signals": current_signals,
        "final_score": current_score,
        "final_report": final_report,
    }

    (out / "signals.final.json").write_text(json.dumps(current_signals, indent=2) + "\n", encoding="utf-8")
    (out / "score.final.json").write_text(json.dumps(current_score, indent=2) + "\n", encoding="utf-8")
    (out / "report.final.json").write_text(json.dumps(final_report, indent=2) + "\n", encoding="utf-8")
    (out / "investigation_result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    audit = build_audit_chain(
        eml_path=eml_path,
        envelope=envelope,
        baseline_signals=baseline_signals,
        semantic_doc=semantic_doc,
        baseline_score=baseline_score,
        candidates_doc=candidates_doc,
        plan_doc=plan_doc,
        result=result,
    )
    (out / "audit_chain.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    (out / "audit_chain.md").write_text(to_markdown(audit), encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "final_report",
            "risk_score": current_score.get("risk_score"),
            "confidence_score": current_score.get("confidence_score"),
            "verdict": current_score.get("verdict"),
        },
    )
    _emit(
        event_hook,
        "pipeline_completed",
        {
            "case_id": result.get("case_id"),
            "agent_invoked": result.get("agent_invoked"),
            "stop_reason": result.get("stop_reason"),
            "risk_score": current_score.get("risk_score"),
            "confidence_score": current_score.get("confidence_score"),
            "verdict": current_score.get("verdict"),
            "used_playbooks": result.get("budgets", {}).get("used_playbooks"),
        },
    )

    return result



def main() -> None:
    parser = argparse.ArgumentParser(description="Run full phishing investigation pipeline with adaptive playbook loop.")
    parser.add_argument("--eml", required=True, help="Path to .eml input")
    parser.add_argument("--out-dir", required=True, help="Directory for generated artifacts")
    parser.add_argument("--mode", default=os.getenv("INVESTIGATION_MODE", "mock"), choices=["mock", "live"], help="Investigation mode")
    args = parser.parse_args()

    result = run_pipeline(eml_path=args.eml, out_dir=args.out_dir, mode=args.mode)
    print(json.dumps({
        "case_id": result.get("case_id"),
        "agent_invoked": result.get("agent_invoked"),
        "stop_reason": result.get("stop_reason"),
        "risk_score": result.get("final_score", {}).get("risk_score"),
        "confidence_score": result.get("final_score", {}).get("confidence_score"),
        "verdict": result.get("final_score", {}).get("verdict"),
        "used_playbooks": result.get("budgets", {}).get("used_playbooks"),
    }, indent=2))


if __name__ == "__main__":
    main()
