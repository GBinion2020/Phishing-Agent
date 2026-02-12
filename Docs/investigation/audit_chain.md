# Audit Chain

## Purpose
Provide full stage-by-stage traceability for each case run so failures and regressions are diagnosable.

Implementation file:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/audit_chain.py`

## Artifacts
Generated per run:
- `audit_chain.json`
- `audit_chain.md`

## Coverage
Audit chain records:
1. ingestion/normalization stage
2. baseline signal generation
3. semantic assessment stage
4. baseline scoring stage
5. playbook selection
6. investigation planning
7. playbook execution loop with per-iteration source/status counts
8. final decision stage

## Error Mapping
For each tool failure, audit captures:
- playbook id
- tool id
- provider reason

This lets you identify whether failures are:
- credential/auth issues
- endpoint/query issues
- provider availability issues
- schema/normalization mapping issues

## Guardrail Attestation
Audit includes explicit guardrail flags:
- `llm_can_execute_tools=false`
- `llm_final_verdict_control=false`
- `deterministic_verdict_engine=true`
- `prompt_injection_system_guard=true`
