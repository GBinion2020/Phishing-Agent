# Normalization Pipeline

## Purpose
Normalization converts a raw `.eml` file into the stable Envelope JSON contract used by the signal engine and later investigation stages.

Implementation file:
- `/Users/gabe/Documents/Phishing_Triage_Agent/src/Ingestion/intake.py`

## Envelope Contract
Top-level fields currently emitted:
- `schema_version`
- `case_id`
- `ingest`
- `message_metadata`
- `auth_summary`
- `entities`
- `mime_parts`
- `attachments`
- `warnings`

## Processing Stages
1. Read raw `.eml` bytes and compute input hashes.
2. Parse MIME structure and decode headers/body safely.
3. Build canonical message metadata (From/To/Reply-To/Return-Path/Date/Message-ID/Received).
4. Capture decoded headers map for signal logic.
5. Extract auth summary from `Authentication-Results` (SPF/DKIM/DMARC).
6. Extract entities (URLs, domains, emails, IPs) from body, headers, and attachment strings.
7. Build MIME part summary and static attachment metadata.
8. Attach warnings for missing headers or decode anomalies.

## Output Characteristics
- deterministic structure for downstream modules
- static analysis only (no attachment execution)
- evidence-friendly fields for signal rationale mapping

## CLI Usage
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/src/Ingestion/intake.py \
  --eml /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.eml \
  --out /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.envelope.json
```

## Known Limits
- Auth parsing depends on available `Authentication-Results` header quality.
- Received chain parsing is best-effort and may not fully normalize malformed hops.
- Some advanced signals still require external connectors in later phases.

## Maintenance Notes
When ingestion fields or parsing logic change:
1. Update this file.
2. Update signal docs if a field affects signal behavior.
3. Re-run the sample `.eml` and verify envelope shape.
