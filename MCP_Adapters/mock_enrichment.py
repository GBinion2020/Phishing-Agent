#!/usr/bin/env python3
"""Mock enrichment output generator for MCP tool registry entries."""

from __future__ import annotations

import ipaddress
from typing import Any


SUSPICIOUS_TOKENS = {
    "login",
    "verify",
    "password",
    "secure",
    "update",
    "invoice",
    "account",
    "auth",
}



def _contains_suspicious_token(value: str) -> bool:
    lv = value.lower()
    return any(tok in lv for tok in SUSPICIOUS_TOKENS)



def _domain_age_days(domain: str) -> int:
    d = domain.lower()
    if d.endswith(".edu") or d.endswith(".gov"):
        return 5000
    if _contains_suspicious_token(d):
        return 15
    if d.count("-") >= 2:
        return 40
    return 700



def synthesize_mock_output(tool_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ioc_type = payload.get("ioc_type", "")
    value = str(payload.get("value", ""))
    lv = value.lower()

    if tool_id == "icann_rdap_domain":
        age_days = _domain_age_days(value)
        return {
            "status": "ok",
            "registered": True,
            "age_days": age_days,
        }

    if tool_id in {"virustotal_url", "urlscan_lookup", "openphish_lookup", "phishtank_lookup"}:
        malicious = _contains_suspicious_token(lv)
        confidence = 0.92 if malicious else 0.15
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": confidence,
        }

    if tool_id == "urlscan_detonate":
        malicious = _contains_suspicious_token(lv)
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": 0.93 if malicious else 0.2,
            "scan_id": "mock-scan-001",
            "result_url": "https://urlscan.io/result/mock-scan-001/",
            "final_url": value,
            "redirects": 2 if malicious else 0,
        }

    if tool_id == "cuckoo_url_detonate":
        malicious = _contains_suspicious_token(lv)
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": 0.9 if malicious else 0.2,
            "task_id": 1001,
            "score": 8.0 if malicious else 1.0,
            "signatures_count": 4 if malicious else 0,
        }

    if tool_id == "urlhaus_lookup":
        malicious = _contains_suspicious_token(lv)
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": 0.95 if malicious else 0.05,
        }

    if tool_id in {"virustotal_ip", "abuseipdb_check"} and ioc_type == "ip":
        malicious = False
        confidence = 0.1
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                malicious = False
                confidence = 0.05
            elif value.startswith("203.0.113.") or value.startswith("198.51.100."):
                malicious = True
                confidence = 0.75
        except ValueError:
            malicious = False
            confidence = 0.0
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": confidence,
        }

    if tool_id in {"virustotal_hash", "alienvault_otx"}:
        malicious = lv.startswith("deadbeef") or lv.endswith("bad")
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": 0.88 if malicious else 0.2,
        }

    if tool_id == "crtsh_lookup":
        malicious = _contains_suspicious_token(lv)
        return {
            "status": "ok",
            "malicious": malicious,
            "confidence": 0.55 if malicious else 0.2,
        }

    return {
        "status": "deferred",
        "malicious": False,
        "confidence": 0.0,
    }
