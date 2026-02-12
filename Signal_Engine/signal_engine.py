#!/usr/bin/env python3
"""Signal engine for phishing triage.

Consumes normalized envelope JSON and emits bounded signal outputs:
- Deterministic signals: evaluated directly from envelope content.
- Non-deterministic signals: require external tool outputs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse


SignalResult = dict[str, Any]
Evaluator = Callable[[dict[str, Any]], SignalResult]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}
SUSPICIOUS_ATTACHMENT_EXTS = {
    ".html", ".htm", ".iso", ".img", ".lnk", ".url", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".xlsm", ".xlam", ".docm", ".pptm", ".exe", ".scr", ".bat",
    ".cmd", ".ps1", ".jar", ".chm",
}
BRAND_DOMAIN_MAP = {
    "microsoft": "microsoft.com",
    "office": "office.com",
    "outlook": "outlook.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "docusign": "docusign.net",
    "adobe": "adobe.com",
    "apple": "apple.com",
    "valero": "valero.com",
}
CREDENTIAL_KWS = {"verify account", "password", "login", "sign in", "credential", "reset your password"}
URGENCY_KWS = {"urgent", "immediately", "action required", "asap", "within 24 hours", "final notice"}
PAYMENT_KWS = {"invoice", "payment", "wire transfer", "bank details", "remittance", "purchase order"}
SUSPENSION_KWS = {"suspended", "suspension", "locked", "deactivated", "disable your account"}
GENERIC_GREETINGS = {"dear user", "dear customer", "dear valued customer", "hello user"}
TYPO_MARKERS = {"passwrod", "verfy", "accunt", "immediatly", "suspenssion", "kindly do the needful"}


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


def _extract_domain_from_email(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip(".")


def _msg(envelope: dict[str, Any]) -> dict[str, Any]:
    return envelope.get("message_metadata", {})


def _headers(envelope: dict[str, Any]) -> dict[str, list[str]]:
    return _msg(envelope).get("headers", {}) or {}


def _body_text(envelope: dict[str, Any]) -> str:
    body = envelope.get("mime_parts", {}).get("body_extraction", {})
    return f"{body.get('text_plain', '')}\n{body.get('text_html', '')}".lower()


def _urls(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    return envelope.get("entities", {}).get("urls", []) or []


def _domains(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    return envelope.get("entities", {}).get("domains", []) or []


def _attachments(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    return envelope.get("attachments", []) or []


def _signal(value: str, rationale: str, evidence: list[str] | None = None, tools: list[str] | None = None) -> SignalResult:
    return {
        "value": value,
        "evidence": evidence or [],
        "rationale": rationale,
        "tool_requirements": tools or [],
    }


def identity_reply_to_mismatch(envelope: dict[str, Any]) -> SignalResult:
    from_domain = ((_msg(envelope).get("from") or {}).get("domain") or "").lower()
    reply_domain = ((_msg(envelope).get("reply_to") or {}).get("domain") or "").lower()
    if not reply_domain:
        return _signal("false", "Reply-To not present", ["message_metadata.reply_to"])
    if not from_domain:
        return _signal("unknown", "Missing From domain", ["message_metadata.from"])
    is_mismatch = from_domain != reply_domain
    rationale = f"From domain '{from_domain}' vs Reply-To domain '{reply_domain}'"
    return _signal("true" if is_mismatch else "false", rationale, ["message_metadata.from", "message_metadata.reply_to"])


def identity_display_name_spoof(envelope: dict[str, Any]) -> SignalResult:
    frm = _msg(envelope).get("from") or {}
    display_name = (frm.get("display_name") or "").lower()
    from_domain = (frm.get("domain") or "").lower()
    if not display_name:
        return _signal("false", "No display name present", ["message_metadata.from.display_name"])
    for token, legit_domain in BRAND_DOMAIN_MAP.items():
        if token in display_name and legit_domain not in from_domain:
            return _signal(
                "true",
                f"Display name references '{token}' but sender domain is '{from_domain}'",
                ["message_metadata.from.display_name", "message_metadata.from.domain"],
            )
    return _signal("false", "No brand/display-name spoof pattern detected", ["message_metadata.from.display_name"])


def identity_return_path_mismatch(envelope: dict[str, Any]) -> SignalResult:
    from_domain = ((_msg(envelope).get("from") or {}).get("domain") or "").lower()
    return_path = (_msg(envelope).get("return_path") or "").lower()
    return_domain = _extract_domain_from_email(return_path)
    if not return_domain:
        return _signal("unknown", "Return-Path missing or unparsable", ["message_metadata.return_path"])
    if not from_domain:
        return _signal("unknown", "From domain missing", ["message_metadata.from"])
    return _signal(
        "true" if return_domain != from_domain else "false",
        f"From domain '{from_domain}' vs Return-Path domain '{return_domain}'",
        ["message_metadata.from", "message_metadata.return_path"],
    )


def identity_from_domain_mismatch_in_headers(envelope: dict[str, Any]) -> SignalResult:
    msg = _msg(envelope)
    from_domain = ((msg.get("from") or {}).get("domain") or "").lower()
    candidates: set[str] = set()
    message_id = msg.get("message_id") or ""
    m = re.search(r"@([^>\s]+)", message_id)
    if m:
        candidates.add(m.group(1).lower().strip("."))
    return_domain = _extract_domain_from_email(msg.get("return_path"))
    if return_domain:
        candidates.add(return_domain)
    if not from_domain or not candidates:
        return _signal("unknown", "Insufficient header domains to compare", ["message_metadata.message_id", "message_metadata.return_path"])
    mismatch = any(dom != from_domain for dom in candidates)
    return _signal(
        "true" if mismatch else "false",
        f"From domain '{from_domain}' vs header domains {sorted(candidates)}",
        ["message_metadata.from", "message_metadata.message_id", "message_metadata.return_path"],
    )


def header_missing_message_id(envelope: dict[str, Any]) -> SignalResult:
    message_id = _msg(envelope).get("message_id")
    if not message_id:
        return _signal("true", "Message-ID header missing", ["message_metadata.message_id"])
    is_malformed = not bool(re.match(r"^<[^<>\s]+@[^<>\s]+>$", message_id.strip()))
    return _signal("true" if is_malformed else "false", "Message-ID malformed" if is_malformed else "Message-ID present and valid", ["message_metadata.message_id"])


def header_received_chain_anomaly(envelope: dict[str, Any]) -> SignalResult:
    chain = _msg(envelope).get("received_chain", [])
    if not chain:
        return _signal("unknown", "No Received chain available", ["message_metadata.received_chain"])

    missing_fields = 0
    parsed_dates = []
    for hop in chain:
        for required in ("from", "by", "date"):
            if not hop.get(required):
                missing_fields += 1
        if hop.get("date"):
            try:
                parsed_dates.append(parsedate_to_datetime(hop["date"]))
            except Exception:
                continue

    chronological_issue = False
    if len(parsed_dates) >= 2:
        chronological_issue = any(parsed_dates[idx] < parsed_dates[idx + 1] for idx in range(len(parsed_dates) - 1))

    anomaly = missing_fields > 0 or chronological_issue
    rationale_parts = []
    if missing_fields:
        rationale_parts.append(f"missing_fields={missing_fields}")
    if chronological_issue:
        rationale_parts.append("non_monotonic_received_dates")
    return _signal("true" if anomaly else "false", ", ".join(rationale_parts) if rationale_parts else "No chain anomalies detected", ["message_metadata.received_chain"])


def header_x_originating_ip_present(envelope: dict[str, Any]) -> SignalResult:
    headers = _headers(envelope)
    present = "x-originating-ip" in headers
    return _signal("true" if present else "false", "X-Originating-IP header present" if present else "X-Originating-IP header absent", ["message_metadata.headers.x-originating-ip"] if present else ["message_metadata.headers"])


def header_priority_flag_set(envelope: dict[str, Any]) -> SignalResult:
    headers = _headers(envelope)
    values = []
    for h in ("x-priority", "priority", "importance"):
        values.extend(headers.get(h, []))
    joined = " ".join(values).lower()
    flagged = any(token in joined for token in ("high", "urgent", "1"))
    return _signal("true" if flagged else "false", "Priority/importance urgency flag set" if flagged else "No urgency priority flags", ["message_metadata.headers"])


def header_suspicious_user_agent(envelope: dict[str, Any]) -> SignalResult:
    headers = _headers(envelope)
    values = headers.get("user-agent", []) + headers.get("x-mailer", [])
    joined = " ".join(values).lower()
    suspicious = any(token in joined for token in ("python", "phpmailer", "powershell", "curl", "wget"))
    if not values:
        return _signal("false", "No user-agent/x-mailer headers present", ["message_metadata.headers"])
    return _signal("true" if suspicious else "false", f"User agent observed: {joined[:120]}", ["message_metadata.headers.user-agent", "message_metadata.headers.x-mailer"])


def auth_spf_fail(envelope: dict[str, Any]) -> SignalResult:
    result = (envelope.get("auth_summary", {}).get("spf", {}).get("result") or "unknown").lower()
    if result == "unknown":
        return _signal("unknown", "SPF result unavailable", ["auth_summary.spf"])
    return _signal("true" if result == "fail" else "false", f"SPF result={result}", ["auth_summary.spf.evidence_id"])


def auth_dkim_fail(envelope: dict[str, Any]) -> SignalResult:
    dkim_records = envelope.get("auth_summary", {}).get("dkim", [])
    if not dkim_records:
        return _signal("unknown", "No DKIM result records", ["auth_summary.dkim"])
    has_fail = any((r.get("result") or "").lower() == "fail" for r in dkim_records)
    return _signal("true" if has_fail else "false", "At least one DKIM signature failed" if has_fail else "No DKIM failures", ["auth_summary.dkim"])


def auth_dmarc_fail(envelope: dict[str, Any]) -> SignalResult:
    result = (envelope.get("auth_summary", {}).get("dmarc", {}).get("result") or "unknown").lower()
    if result == "unknown":
        return _signal("unknown", "DMARC result unavailable", ["auth_summary.dmarc"])
    return _signal("true" if result == "fail" else "false", f"DMARC result={result}", ["auth_summary.dmarc.evidence_id"])


def auth_alignment_fail(envelope: dict[str, Any]) -> SignalResult:
    aligned = envelope.get("auth_summary", {}).get("dmarc", {}).get("aligned")
    if aligned == "unknown" or aligned is None:
        return _signal("unknown", "Alignment status unavailable", ["auth_summary.dmarc.aligned"])
    return _signal("true" if aligned is False else "false", f"Alignment={aligned}", ["auth_summary.dmarc.aligned"])


def url_shortener_used(envelope: dict[str, Any]) -> SignalResult:
    for url in _urls(envelope):
        domain = (url.get("domain") or "").lower()
        if domain in SHORTENER_DOMAINS:
            return _signal("true", f"Shortener domain found: {domain}", [url.get("evidence_id", "entities.urls")])
    return _signal("false", "No known shortener domains found", ["entities.urls"])


def url_ip_literal_used(envelope: dict[str, Any]) -> SignalResult:
    for url in _urls(envelope):
        domain = url.get("domain") or ""
        try:
            ipaddress.ip_address(domain)
            return _signal("true", f"IP literal URL host: {domain}", [url.get("evidence_id", "entities.urls")])
        except ValueError:
            continue
    return _signal("false", "No IP literal URL hosts", ["entities.urls"])


def url_display_text_mismatch(envelope: dict[str, Any]) -> SignalResult:
    html = envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_html", "")
    links = re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html, flags=re.IGNORECASE | re.DOTALL)
    for href, text in links:
        clean_text = re.sub(r"<[^>]+>", "", text).strip().lower()
        if "http" in clean_text or "www." in clean_text:
            href_host = (urlparse(href).hostname or "").lower()
            text_host = (urlparse(clean_text).hostname or "").lower()
            if href_host and text_host and href_host != text_host:
                return _signal("true", f"Anchor text host '{text_host}' differs from href host '{href_host}'", ["mime_parts.body_extraction.text_html"])
    return _signal("false", "No link text/href mismatch detected", ["mime_parts.body_extraction.text_html"])


def url_multiple_redirect_pattern_in_path(envelope: dict[str, Any]) -> SignalResult:
    redirect_keys = {"url", "redirect", "next", "target", "dest", "continue"}
    for u in _urls(envelope):
        parsed = urlparse(u.get("normalized") or u.get("url") or "")
        query = parsed.query.lower()
        hits = sum(1 for k in redirect_keys if f"{k}=" in query)
        if hits >= 1 and ("http%3a" in query or "https%3a" in query or "http://" in query or "https://" in query):
            return _signal("true", f"Redirect-like query pattern found in {u.get('normalized')}", [u.get("evidence_id", "entities.urls")])
    return _signal("false", "No redirect-style URL patterns found", ["entities.urls"])


def url_long_obfuscated_string(envelope: dict[str, Any]) -> SignalResult:
    for u in _urls(envelope):
        candidate = f"{u.get('path', '')}?{urlparse(u.get('normalized') or '').query}"
        if len(candidate) > 120 and re.search(r"[A-Za-z0-9]{30,}", candidate):
            return _signal("true", "Long potentially obfuscated URL segment detected", [u.get("evidence_id", "entities.urls")])
    return _signal("false", "No long obfuscated URL segments detected", ["entities.urls"])


def url_punycode_present(envelope: dict[str, Any]) -> SignalResult:
    for d in _domains(envelope):
        puny = (d.get("punycode") or "").lower()
        if "xn--" in puny:
            return _signal("true", f"Punycode domain detected: {puny}", ["entities.domains"])
    return _signal("false", "No punycode domains detected", ["entities.domains"])


def url_embedded_at_symbol(envelope: dict[str, Any]) -> SignalResult:
    for u in _urls(envelope):
        raw_url = u.get("url") or ""
        parsed = urlparse(raw_url)
        if "@" in parsed.netloc:
            return _signal("true", f"Embedded @ symbol in URL authority: {raw_url}", [u.get("evidence_id", "entities.urls")])
    return _signal("false", "No embedded @ symbols in URL authority", ["entities.urls"])


def url_javascript_in_link(envelope: dict[str, Any]) -> SignalResult:
    for u in _urls(envelope):
        parsed = urlparse(u.get("url") or "")
        if parsed.scheme.lower() in {"javascript", "data"}:
            return _signal("true", f"Dangerous URL scheme: {parsed.scheme}", [u.get("evidence_id", "entities.urls")])
    html = envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_html", "")
    if re.search(r"href=[\"'](?:javascript:|data:)", html, flags=re.IGNORECASE):
        return _signal("true", "javascript:/data: href detected in HTML", ["mime_parts.body_extraction.text_html"])
    return _signal("false", "No javascript:/data: links detected", ["entities.urls", "mime_parts.body_extraction.text_html"])


def content_credential_harvest_language(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    matches = [kw for kw in CREDENTIAL_KWS if kw in body]
    return _signal("true" if matches else "false", f"Credential keywords matched: {matches}" if matches else "No credential-harvest keywords", ["mime_parts.body_extraction"])


def content_urgency_language(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    matches = [kw for kw in URGENCY_KWS if kw in body]
    return _signal("true" if matches else "false", f"Urgency keywords matched: {matches}" if matches else "No urgency-language keywords", ["mime_parts.body_extraction"])


def content_payment_or_invoice_lure(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    matches = [kw for kw in PAYMENT_KWS if kw in body]
    return _signal("true" if matches else "false", f"Payment/invoice keywords matched: {matches}" if matches else "No payment/invoice lure keywords", ["mime_parts.body_extraction"])


def content_account_suspension_threat(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    matches = [kw for kw in SUSPENSION_KWS if kw in body]
    return _signal("true" if matches else "false", f"Suspension keywords matched: {matches}" if matches else "No suspension-threat keywords", ["mime_parts.body_extraction"])


def content_generic_greeting(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    first_200 = body[:200]
    matched = [g for g in GENERIC_GREETINGS if g in first_200]
    return _signal("true" if matched else "false", f"Generic greeting matched: {matched}" if matched else "No generic greeting detected", ["mime_parts.body_extraction.text_plain"])


def content_brand_impersonation(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    from_domain = ((_msg(envelope).get("from") or {}).get("domain") or "").lower()
    for brand, legit_domain in BRAND_DOMAIN_MAP.items():
        if brand in body and legit_domain not in from_domain:
            return _signal("true", f"Body references '{brand}' while sender domain is '{from_domain}'", ["mime_parts.body_extraction", "message_metadata.from.domain"])
    return _signal("false", "No brand impersonation mismatch detected", ["mime_parts.body_extraction", "message_metadata.from.domain"])


def content_grammar_spelling_errors(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    matches = [m for m in TYPO_MARKERS if m in body]
    return _signal("true" if len(matches) >= 1 else "false", f"Typo markers matched: {matches}" if matches else "No typo markers detected", ["mime_parts.body_extraction"])


def content_html_form_embedded(envelope: dict[str, Any]) -> SignalResult:
    html = envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_html", "").lower()
    embedded = "<form" in html or "type=\"password\"" in html or "type='password'" in html
    return _signal("true" if embedded else "false", "Embedded HTML form/password input present" if embedded else "No embedded form/password input", ["mime_parts.body_extraction.text_html"])


def content_hidden_text_or_css(envelope: dict[str, Any]) -> SignalResult:
    html = envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_html", "").lower()
    hidden = any(token in html for token in ("display:none", "visibility:hidden", "font-size:0", "opacity:0"))
    return _signal("true" if hidden else "false", "Hidden CSS/text markers found" if hidden else "No hidden CSS/text markers", ["mime_parts.body_extraction.text_html"])


def attachment_suspicious_file_type(envelope: dict[str, Any]) -> SignalResult:
    for att in _attachments(envelope):
        filename = (att.get("filename") or "").lower()
        for ext in SUSPICIOUS_ATTACHMENT_EXTS:
            if filename.endswith(ext):
                return _signal("true", f"Suspicious attachment extension: {filename}", ["attachments"])
    return _signal("false", "No suspicious attachment file types", ["attachments"])


def attachment_double_extension(envelope: dict[str, Any]) -> SignalResult:
    for att in _attachments(envelope):
        filename = (att.get("filename") or "").lower()
        if re.search(r"\.[a-z0-9]{1,5}\.[a-z0-9]{1,5}$", filename):
            return _signal("true", f"Double extension filename: {filename}", ["attachments"])
    return _signal("false", "No double extension attachment names", ["attachments"])


def attachment_contains_macro_indicator(envelope: dict[str, Any]) -> SignalResult:
    markers = ("vba", "autoopen", "enable content", "macro", "ole")
    for att in _attachments(envelope):
        sample = (att.get("extracted_strings_sample") or "").lower()
        if any(m in sample for m in markers):
            return _signal("true", "Macro-related marker found in attachment strings", ["attachments"])
    return _signal("false", "No macro indicators found in attachment strings", ["attachments"])


def attachment_password_protected_archive(envelope: dict[str, Any]) -> SignalResult:
    archive_exts = (".zip", ".rar", ".7z")
    for att in _attachments(envelope):
        filename = (att.get("filename") or "").lower()
        sample = (att.get("extracted_strings_sample") or "").lower()
        if filename.endswith(archive_exts) and ("password" in sample or "encrypted" in sample):
            return _signal("true", f"Archive appears password-protected: {filename}", ["attachments"])
    return _signal("false", "No password-protected archive indicators", ["attachments"])


def attachment_embedded_urls(envelope: dict[str, Any]) -> SignalResult:
    for att in _attachments(envelope):
        urls = att.get("extracted_urls") or []
        if urls:
            return _signal("true", f"Attachment contains extracted URLs ({len(urls)})", ["attachments"])
    return _signal("false", "No URLs extracted from attachments", ["attachments"])


def infra_private_ip_in_received_chain(envelope: dict[str, Any]) -> SignalResult:
    chain_text = "\n".join((hop.get("raw") or "") for hop in (_msg(envelope).get("received_chain") or []))
    for ip_item in envelope.get("entities", {}).get("ips", []):
        ip_text = ip_item.get("ip")
        if not ip_text:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip_obj.is_private and ip_text in chain_text:
            return _signal("true", f"Private IP appears in Received chain: {ip_text}", ["message_metadata.received_chain", "entities.ips"])
    return _signal("false", "No private IP found in Received chain", ["message_metadata.received_chain", "entities.ips"])


def infra_timezone_mismatch_in_headers(envelope: dict[str, Any]) -> SignalResult:
    offsets = set()
    for hop in (_msg(envelope).get("received_chain") or []):
        date_text = hop.get("date") or ""
        m = re.search(r"([+-]\d{4})", date_text)
        if m:
            offsets.add(m.group(1))
    mismatch = len(offsets) > 1
    if not offsets:
        return _signal("unknown", "No timezone offsets parsed from Received chain", ["message_metadata.received_chain"])
    return _signal("true" if mismatch else "false", f"Received timezone offsets={sorted(offsets)}", ["message_metadata.received_chain"])


def behavior_unusual_time_of_day_pattern(envelope: dict[str, Any]) -> SignalResult:
    date_text = _msg(envelope).get("date") or ""
    if not date_text:
        return _signal("unknown", "Message Date missing", ["message_metadata.date"])
    try:
        dt = parsedate_to_datetime(date_text)
        unusual = dt.hour < 5
        return _signal("true" if unusual else "false", f"Message hour={dt.hour}", ["message_metadata.date"])
    except Exception:
        return _signal("unknown", "Unable to parse message date", ["message_metadata.date"])


def behavior_bulk_recipient_pattern(envelope: dict[str, Any]) -> SignalResult:
    to_count = len(_msg(envelope).get("to") or [])
    cc_count = len(_msg(envelope).get("cc") or [])
    total = to_count + cc_count
    is_bulk = total >= 15
    return _signal("true" if is_bulk else "false", f"Recipient count={total}", ["message_metadata.to", "message_metadata.cc"])


def evasion_base64_encoded_html(envelope: dict[str, Any]) -> SignalResult:
    html = envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_html", "")
    found = bool(re.search(r"[A-Za-z0-9+/]{200,}={0,2}", html))
    return _signal("true" if found else "false", "Long base64-like sequence found in HTML" if found else "No long base64-like sequence found", ["mime_parts.body_extraction.text_html"])


def evasion_zero_width_characters(envelope: dict[str, Any]) -> SignalResult:
    body = _body_text(envelope)
    found = bool(re.search(r"[\u200b\u200c\u200d\ufeff]", body))
    return _signal("true" if found else "false", "Zero-width unicode characters detected" if found else "No zero-width unicode characters detected", ["mime_parts.body_extraction"])


def evasion_homoglyph_substitution(envelope: dict[str, Any]) -> SignalResult:
    for d in _domains(envelope):
        dom = d.get("domain") or ""
        puny = d.get("punycode") or ""
        if puny.startswith("xn--"):
            return _signal("true", f"Punycode/homoglyph candidate domain: {dom}", ["entities.domains"])
        if any(ord(ch) > 127 for ch in dom):
            return _signal("true", f"Non-ASCII characters in domain: {dom}", ["entities.domains"])
    return _signal("false", "No homoglyph substitution indicators in domains", ["entities.domains"])


EVALUATORS: dict[str, Evaluator] = {
    "identity_reply_to_mismatch": identity_reply_to_mismatch,
    "identity_display_name_spoof": identity_display_name_spoof,
    "identity_return_path_mismatch": identity_return_path_mismatch,
    "identity_from_domain_mismatch_in_headers": identity_from_domain_mismatch_in_headers,
    "header_missing_message_id": header_missing_message_id,
    "header_received_chain_anomaly": header_received_chain_anomaly,
    "header_x_originating_ip_present": header_x_originating_ip_present,
    "header_priority_flag_set": header_priority_flag_set,
    "header_suspicious_user_agent": header_suspicious_user_agent,
    "auth_spf_fail": auth_spf_fail,
    "auth_dkim_fail": auth_dkim_fail,
    "auth_dmarc_fail": auth_dmarc_fail,
    "auth_alignment_fail": auth_alignment_fail,
    "url_shortener_used": url_shortener_used,
    "url_ip_literal_used": url_ip_literal_used,
    "url_display_text_mismatch": url_display_text_mismatch,
    "url_multiple_redirect_pattern_in_path": url_multiple_redirect_pattern_in_path,
    "url_long_obfuscated_string": url_long_obfuscated_string,
    "url_punycode_present": url_punycode_present,
    "url_embedded_at_symbol": url_embedded_at_symbol,
    "url_javascript_in_link": url_javascript_in_link,
    "content_credential_harvest_language": content_credential_harvest_language,
    "content_urgency_language": content_urgency_language,
    "content_payment_or_invoice_lure": content_payment_or_invoice_lure,
    "content_account_suspension_threat": content_account_suspension_threat,
    "content_generic_greeting": content_generic_greeting,
    "content_brand_impersonation": content_brand_impersonation,
    "content_grammar_spelling_errors": content_grammar_spelling_errors,
    "content_html_form_embedded": content_html_form_embedded,
    "content_hidden_text_or_css": content_hidden_text_or_css,
    "attachment_suspicious_file_type": attachment_suspicious_file_type,
    "attachment_double_extension": attachment_double_extension,
    "attachment_contains_macro_indicator": attachment_contains_macro_indicator,
    "attachment_password_protected_archive": attachment_password_protected_archive,
    "attachment_embedded_urls": attachment_embedded_urls,
    "infra_private_ip_in_received_chain": infra_private_ip_in_received_chain,
    "infra_timezone_mismatch_in_headers": infra_timezone_mismatch_in_headers,
    "behavior_unusual_time_of_day_pattern": behavior_unusual_time_of_day_pattern,
    "behavior_bulk_recipient_pattern": behavior_bulk_recipient_pattern,
    "evasion_base64_encoded_html": evasion_base64_encoded_html,
    "evasion_zero_width_characters": evasion_zero_width_characters,
    "evasion_homoglyph_substitution": evasion_homoglyph_substitution,
}


def _coerce_tool_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value in {"true", "false", "unknown"}:
        return value
    return "unknown"


def run_signal_engine(
    envelope: dict[str, Any],
    taxonomy: dict[str, Any],
    deterministic_rules: dict[str, Any],
    nondeterministic_rules: dict[str, Any],
    tool_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tool_results = tool_results or {}
    signals: dict[str, Any] = {}

    det_by_id = {r["id"]: r for r in deterministic_rules.get("deterministic_rules", [])}
    nondet_by_id = {r["id"]: r for r in nondeterministic_rules.get("non_deterministic_rules", [])}
    tool_signal_values = tool_results.get("signals", {})

    for signal_def in taxonomy.get("signals", []):
        signal_id = signal_def["id"]
        kind = signal_def["kind"]

        if kind == "deterministic":
            rule = det_by_id.get(signal_id)
            if not rule:
                signals[signal_id] = {
                    "kind": kind,
                    **_signal("unknown", "No deterministic rule mapping configured"),
                }
                continue

            evaluator_name = rule.get("evaluator")
            evaluator = EVALUATORS.get(evaluator_name)
            if not evaluator:
                signals[signal_id] = {
                    "kind": kind,
                    **_signal("unknown", f"Evaluator '{evaluator_name}' not implemented"),
                }
                continue

            result = evaluator(envelope)
            signals[signal_id] = {"kind": kind, **result}
            continue

        rule = nondet_by_id.get(signal_id, {})
        required_tools = rule.get("required_tools", [])
        raw_tool_value = tool_signal_values.get(signal_id)

        if isinstance(raw_tool_value, dict):
            value = _coerce_tool_value(raw_tool_value.get("value"))
            evidence = raw_tool_value.get("evidence", [])
            rationale = raw_tool_value.get("rationale", "Non-deterministic value supplied by external tool results")
        elif raw_tool_value is not None:
            value = _coerce_tool_value(raw_tool_value)
            evidence = ["tool_results.signals"]
            rationale = "Non-deterministic value supplied by external tool results"
        else:
            value = "unknown"
            evidence = []
            rationale = "External enrichment required and no tool result supplied"

        signals[signal_id] = {
            "kind": kind,
            **_signal(value, rationale, evidence=evidence, tools=required_tools),
        }

    return {
        "schema_version": "1.0",
        "case_id": envelope.get("case_id"),
        "generated_at": _now_iso(),
        "signals": signals,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate phishing signals from normalized envelope JSON.")
    parser.add_argument("--envelope", required=True, help="Path to normalized envelope JSON")
    parser.add_argument("--out", default=None, help="Output path for signal JSON")
    parser.add_argument("--tool-results", default=None, help="Optional JSON file with non-deterministic signal values")
    parser.add_argument("--registry-dir", default="Signal_Engine", help="Directory holding YAML registry/rules")
    args = parser.parse_args()

    registry_dir = Path(args.registry_dir)
    taxonomy = _load_yaml_like(registry_dir / "signal_taxonomy.yaml")
    deterministic_rules = _load_yaml_like(registry_dir / "signal_rules_deterministic.yaml")
    nondeterministic_rules = _load_yaml_like(registry_dir / "signal_rules_nondeterministic.yaml")

    envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    tool_results = None
    if args.tool_results:
        tool_results = json.loads(Path(args.tool_results).read_text(encoding="utf-8"))

    result = run_signal_engine(
        envelope=envelope,
        taxonomy=taxonomy,
        deterministic_rules=deterministic_rules,
        nondeterministic_rules=nondeterministic_rules,
        tool_results=tool_results,
    )

    output_text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output_text + "\n", encoding="utf-8")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
