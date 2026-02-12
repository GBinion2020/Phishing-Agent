#!/usr/bin/env python3
"""Ingestion + normalization layer for .eml inputs.

This module parses a raw email, normalizes key metadata, extracts entities,
and emits an Envelope JSON object suitable for downstream signal generation.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse


URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://|www\.)[^\s<>()\"']+",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)
IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b",
    re.IGNORECASE,
)
SPF_RESULT_RE = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DKIM_RESULT_RE = re.compile(r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b", re.IGNORECASE)
DMARC_RESULT_RE = re.compile(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE)
HEADER_FROM_RE = re.compile(r"\bheader\.from=([^\s;]+)", re.IGNORECASE)
SENDER_RE = re.compile(r"\bsender=([^\s;]+)", re.IGNORECASE)
CLIENT_IP_RE = re.compile(r"\bclient-ip=([^\s;]+)", re.IGNORECASE)
DKIM_DOMAIN_RE = re.compile(r"\bheader\.d=([^\s;]+)", re.IGNORECASE)
DKIM_SELECTOR_RE = re.compile(r"\bheader\.s=([^\s;]+)", re.IGNORECASE)
DKIM_CANON_RE = re.compile(r"\bheader\.c=([^\s;]+)", re.IGNORECASE)
DMARC_POLICY_RE = re.compile(r"\bpolicy\.(?:dmarc|p)=([^\s;]+)", re.IGNORECASE)
RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s\(\);]+)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s\(\);]+)", re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r"\bwith\s+([^\s\(\);]+)", re.IGNORECASE)
RECEIVED_ID_RE = re.compile(r"\bid\s+([^\s;]+)", re.IGNORECASE)
RECEIVED_FOR_RE = re.compile(r"\bfor\s+<?([^>;]+)>?", re.IGNORECASE)


@dataclass
class PartRecord:
    part_id: str
    content_type: str
    content_disposition: str | None
    filename: str | None
    size_bytes: int
    is_attachment: bool
    charset: str | None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_decode_header(value: str | None, warnings: list[str]) -> str:
    if not value:
        return ""
    decoded_chunks: list[str] = []
    for chunk, charset in decode_header(value):
        if isinstance(chunk, bytes):
            enc = charset or "utf-8"
            try:
                decoded_chunks.append(chunk.decode(enc, errors="replace"))
            except LookupError:
                warnings.append(f"unknown_header_charset:{enc}")
                decoded_chunks.append(chunk.decode("utf-8", errors="replace"))
        else:
            decoded_chunks.append(chunk)
    return "".join(decoded_chunks).strip()


def _extract_domain(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    domain = value.split("@", 1)[1].strip().lower().strip(".")
    return domain or None


def _parse_address_header(raw: str | None, warnings: list[str]) -> dict[str, Any] | None:
    if not raw:
        return None
    name, address = parseaddr(_safe_decode_header(raw, warnings))
    address = address.strip().lower()
    if not address:
        return None
    return {
        "display_name": name.strip(),
        "address": address,
        "domain": _extract_domain(address),
    }


def _normalize_angle_addr(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if v.startswith("<") and v.endswith(">"):
        v = v[1:-1].strip()
    return v or None


def _parse_address_list(raw_values: list[str], warnings: list[str]) -> list[dict[str, Any]]:
    decoded = [_safe_decode_header(v, warnings) for v in raw_values]
    parsed = getaddresses(decoded)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, address in parsed:
        address = (address or "").strip().lower()
        if not address or address in seen:
            continue
        seen.add(address)
        out.append(
            {
                "display_name": (name or "").strip(),
                "address": address,
                "domain": _extract_domain(address),
            }
        )
    return out


def _clean_url_candidate(raw_url: str) -> str:
    cleaned = raw_url.strip().strip(".,;:!?)(").replace("\u200b", "")
    if cleaned.lower().startswith("hxxp://"):
        cleaned = "http://" + cleaned[7:]
    elif cleaned.lower().startswith("hxxps://"):
        cleaned = "https://" + cleaned[8:]
    elif cleaned.lower().startswith("www."):
        cleaned = "http://" + cleaned
    return cleaned


def _normalize_url(raw_url: str) -> dict[str, Any] | None:
    cleaned = _clean_url_candidate(raw_url)
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return None
    if not parsed.netloc and not parsed.path:
        return None
    if not parsed.netloc and parsed.path:
        # Handles malformed forms like https://domain/path where parser failed.
        reparsed = urlparse("http://" + parsed.path)
        if reparsed.netloc:
            parsed = reparsed
        else:
            return None
    scheme = (parsed.scheme or "http").lower()
    domain = parsed.hostname.lower() if parsed.hostname else ""
    if not domain:
        return None
    path = parsed.path or "/"
    normalized = urlunparse((scheme, domain, path, "", parsed.query, ""))
    params = [{"key": k, "value": v} for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return {
        "url": cleaned,
        "normalized": normalized,
        "domain": domain,
        "path": path,
        "params": params,
    }


def _safe_decode_bytes(data: bytes, charset: str | None, warnings: list[str]) -> str:
    if not data:
        return ""
    if charset:
        try:
            return data.decode(charset, errors="replace")
        except LookupError:
            warnings.append(f"unknown_body_charset:{charset}")
    return data.decode("utf-8", errors="replace")


def _parse_received_header(raw_value: str) -> dict[str, Any]:
    record: dict[str, Any] = {"raw": raw_value}
    m_from = RECEIVED_FROM_RE.search(raw_value)
    m_by = RECEIVED_BY_RE.search(raw_value)
    m_with = RECEIVED_WITH_RE.search(raw_value)
    m_id = RECEIVED_ID_RE.search(raw_value)
    m_for = RECEIVED_FOR_RE.search(raw_value)
    date_part = raw_value.split(";")[-1].strip() if ";" in raw_value else None
    if m_from:
        record["from"] = m_from.group(1)
    if m_by:
        record["by"] = m_by.group(1)
    if m_with:
        record["with"] = m_with.group(1)
    if m_id:
        record["id"] = m_id.group(1)
    if m_for:
        record["for"] = m_for.group(1).strip()
    if date_part:
        record["date"] = date_part
    return record


def _extract_auth_summary(auth_headers: list[str]) -> dict[str, Any]:
    joined = "\n".join(auth_headers)
    spf_result = "unknown"
    spf_domain = None
    spf_ip = None
    dmarc_result = "unknown"
    dmarc_policy = None
    dkim_records: list[dict[str, Any]] = []

    for header in auth_headers:
        if spf_result == "unknown":
            m = SPF_RESULT_RE.search(header)
            if m:
                spf_result = m.group(1).lower()
        if spf_domain is None:
            m = SENDER_RE.search(header) or HEADER_FROM_RE.search(header)
            if m:
                spf_domain = m.group(1).lower().strip(";")
        if spf_ip is None:
            m = CLIENT_IP_RE.search(header)
            if m:
                spf_ip = m.group(1)
        if dmarc_result == "unknown":
            m = DMARC_RESULT_RE.search(header)
            if m:
                dmarc_result = m.group(1).lower()
        if dmarc_policy is None:
            m = DMARC_POLICY_RE.search(header)
            if m:
                dmarc_policy = m.group(1).lower()

        dkim_result_m = DKIM_RESULT_RE.search(header)
        if dkim_result_m:
            domain_m = DKIM_DOMAIN_RE.search(header)
            selector_m = DKIM_SELECTOR_RE.search(header)
            canon_m = DKIM_CANON_RE.search(header)
            dkim_records.append(
                {
                    "result": dkim_result_m.group(1).lower(),
                    "domain": domain_m.group(1).lower().strip(";") if domain_m else None,
                    "selector": selector_m.group(1).strip(";") if selector_m else None,
                    "canonicalization": canon_m.group(1).strip(";") if canon_m else None,
                }
            )

    aligned = "unknown"
    if spf_domain and dkim_records:
        dkim_domains = {r["domain"] for r in dkim_records if r.get("domain")}
        aligned = spf_domain in dkim_domains

    return {
        "spf": {
            "result": spf_result,
            "domain": spf_domain,
            "ip": spf_ip,
            "evidence_id": "ev_auth_spf_001",
        },
        "dkim": [
            {
                **record,
                "evidence_id": f"ev_auth_dkim_{idx:03d}",
            }
            for idx, record in enumerate(dkim_records, start=1)
        ],
        "dmarc": {
            "result": dmarc_result,
            "policy": dmarc_policy,
            "aligned": aligned,
            "evidence_id": "ev_auth_dmarc_001",
        },
        "auth_results_raw": joined,
    }


def _build_entities(
    text_blobs: list[str],
    discovered_attachment_urls: list[str],
) -> dict[str, Any]:
    urls_seen: dict[str, dict[str, Any]] = {}
    emails_seen: set[str] = set()
    ips_seen: set[str] = set()

    for blob in text_blobs:
        for match in URL_RE.findall(blob):
            parsed = _normalize_url(match)
            if parsed:
                urls_seen.setdefault(parsed["normalized"], parsed)
        for match in EMAIL_RE.findall(blob):
            emails_seen.add(match.lower())
        for match in IP_RE.findall(blob):
            candidate = match.strip()
            try:
                ipaddress.ip_address(candidate)
                ips_seen.add(candidate)
            except ValueError:
                continue

    for raw_url in discovered_attachment_urls:
        parsed = _normalize_url(raw_url)
        if parsed:
            urls_seen.setdefault(parsed["normalized"], parsed)

    urls = []
    domains_seen: set[str] = set()
    for idx, item in enumerate(sorted(urls_seen.values(), key=lambda x: x["normalized"]), start=1):
        urls.append(
            {
                **item,
                "evidence_id": f"ev_url_{idx:03d}",
            }
        )
        domains_seen.add(item["domain"])

    emails = []
    for address in sorted(emails_seen):
        domain = _extract_domain(address)
        if domain:
            domains_seen.add(domain)
        emails.append(
            {
                "address": address,
                "domain": domain,
            }
        )

    ips = []
    for ip_text in sorted(ips_seen):
        try:
            version = ipaddress.ip_address(ip_text).version
        except ValueError:
            continue
        ips.append({"ip": ip_text, "version": version})

    domains = []
    for domain in sorted(domains_seen):
        try:
            punycode = domain.encode("idna").decode("ascii")
        except UnicodeError:
            punycode = domain
        domains.append(
            {
                "domain": domain,
                "punycode": punycode,
                "is_lookalike_of": [],
            }
        )

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "ips": ips,
    }


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def build_envelope(eml_path: str, case_id: str | None = None, source: str = "local_file") -> dict[str, Any]:
    warnings: list[str] = []
    case_id = case_id or str(uuid.uuid4())
    raw_bytes = Path(eml_path).read_bytes()
    parsed = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_header = _parse_address_header(parsed.get("From"), warnings)
    reply_to_header = _parse_address_header(parsed.get("Reply-To"), warnings)
    return_path = _normalize_angle_addr(_safe_decode_header(parsed.get("Return-Path"), warnings)) or None
    to_headers = _parse_address_list(parsed.get_all("To", []), warnings)
    cc_headers = _parse_address_list(parsed.get_all("Cc", []), warnings)
    subject = _safe_decode_header(parsed.get("Subject"), warnings)
    date_header = _safe_decode_header(parsed.get("Date"), warnings)
    message_id = _safe_decode_header(parsed.get("Message-ID"), warnings) or None

    if not from_header:
        warnings.append("missing_header:From")
    if not subject:
        warnings.append("missing_header:Subject")
    if not date_header:
        warnings.append("missing_header:Date")

    received_headers = parsed.get_all("Received", [])
    auth_headers = parsed.get_all("Authentication-Results", [])
    headers_map: dict[str, list[str]] = {}
    for k, v in parsed.raw_items():
        k_lower = k.lower()
        headers_map.setdefault(k_lower, []).append(_safe_decode_header(v, warnings))

    text_bodies: list[str] = []
    html_bodies: list[str] = []
    part_records: list[PartRecord] = []
    attachments: list[dict[str, Any]] = []
    attachment_urls: list[str] = []

    part_counter = 0
    for part in parsed.walk():
        if part.is_multipart():
            continue
        part_counter += 1
        payload_bytes = part.get_payload(decode=True) or b""
        content_type = (part.get_content_type() or "application/octet-stream").lower()
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()
        charset = part.get_content_charset()
        is_attachment = content_disposition == "attachment" or bool(filename)

        part_records.append(
            PartRecord(
                part_id=f"part_{part_counter:03d}",
                content_type=content_type,
                content_disposition=content_disposition,
                filename=filename,
                size_bytes=len(payload_bytes),
                is_attachment=is_attachment,
                charset=charset,
            )
        )

        if content_type.startswith("text/") and not is_attachment:
            body_text = _safe_decode_bytes(payload_bytes, charset, warnings)
            if content_type == "text/plain":
                text_bodies.append(body_text)
            elif content_type == "text/html":
                html_bodies.append(body_text)
            else:
                text_bodies.append(body_text)

        if is_attachment:
            att_text = _safe_decode_bytes(payload_bytes, charset, warnings)
            attachment_urls.extend(URL_RE.findall(att_text))
            attachments.append(
                {
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": len(payload_bytes),
                    "hashes": _hashes(payload_bytes),
                    "extracted_strings_sample": att_text[:500],
                    "extracted_urls": sorted({_clean_url_candidate(u) for u in URL_RE.findall(att_text)}),
                }
            )

    header_blobs = []
    for k, v in parsed.items():
        header_blobs.append(f"{k}: {_safe_decode_header(v, warnings)}")
    combined_text_blobs = text_bodies + html_bodies + header_blobs + auth_headers + received_headers
    entities = _build_entities(combined_text_blobs, attachment_urls)

    for addr in [from_header, reply_to_header]:
        if addr and addr.get("address"):
            address = addr["address"].lower()
            if not any(e["address"] == address for e in entities["emails"]):
                entities["emails"].append({"address": address, "domain": _extract_domain(address)})
    entities["emails"] = sorted(entities["emails"], key=lambda x: x["address"])

    known_domains = {d["domain"] for d in entities["domains"]}
    for email in entities["emails"]:
        dom = email.get("domain")
        if dom and dom not in known_domains:
            try:
                punycode = dom.encode("idna").decode("ascii")
            except UnicodeError:
                punycode = dom
            entities["domains"].append(
                {
                    "domain": dom,
                    "punycode": punycode,
                    "is_lookalike_of": [],
                }
            )
            known_domains.add(dom)
    entities["domains"] = sorted(entities["domains"], key=lambda x: x["domain"])

    mime_parts = {
        "summary": {
            "total_parts": len(part_records),
            "text_plain_count": sum(1 for p in part_records if p.content_type == "text/plain" and not p.is_attachment),
            "text_html_count": sum(1 for p in part_records if p.content_type == "text/html" and not p.is_attachment),
            "attachment_count": len(attachments),
        },
        "parts": [
            {
                "part_id": p.part_id,
                "content_type": p.content_type,
                "content_disposition": p.content_disposition,
                "filename": p.filename,
                "size_bytes": p.size_bytes,
                "is_attachment": p.is_attachment,
                "charset": p.charset,
            }
            for p in part_records
        ],
        "body_extraction": {
            "text_plain": "\n".join(text_bodies).strip(),
            "text_html": "\n".join(html_bodies).strip(),
        },
    }

    envelope = {
        "schema_version": "1.0",
        "case_id": case_id,
        "ingest": {
            "source": source,
            "received_at": _now_iso(),
            "hashes": _hashes(raw_bytes),
        },
        "message_metadata": {
            "from": from_header,
            "reply_to": reply_to_header,
            "return_path": return_path,
            "to": to_headers,
            "cc": cc_headers,
            "subject": subject,
            "date": date_header,
            "message_id": message_id,
            "received_chain": [_parse_received_header(v) for v in received_headers],
            "headers": headers_map,
        },
        "auth_summary": _extract_auth_summary(auth_headers),
        "entities": entities,
        "mime_parts": mime_parts,
        "attachments": attachments,
        "warnings": sorted(set(warnings)),
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest and normalize a .eml file into envelope JSON.")
    parser.add_argument("--eml", required=True, help="Path to input .eml file")
    parser.add_argument("--case-id", default=None, help="Optional explicit case_id")
    parser.add_argument("--source", default="local_file", help="Ingest source label")
    parser.add_argument("--out", default=None, help="Optional output path for JSON envelope")
    args = parser.parse_args()

    envelope = build_envelope(eml_path=args.eml, case_id=args.case_id, source=args.source)
    output_json = json.dumps(envelope, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output_json + "\n", encoding="utf-8")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
