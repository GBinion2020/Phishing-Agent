# Prompt Contracts

## Purpose
Define strict JSON contracts for each LLM phase and enforce validation.

Implementation file:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/contracts.py`

## Planner Contract
Schema key: `PLAN_SCHEMA`

Required fields:
- `playbook_order[]`
- `why[]`
- `expected_signal_lift[]`
- `stop_conditions[]`

Validation rules:
- playbooks must be from candidate allowlist
- no duplicate playbooks
- playbook count must be within configured max

## Signal Update Contract
Schema key: `SIGNAL_UPDATE_SCHEMA`

Required fields:
- `updates[]`
- `notes`

Each update requires:
- `signal_id`
- `value` (`true|false|unknown`)
- `evidence[]` (non-empty)
- `rationale`

Validation rules:
- only known signal ids are allowed
- deterministic signal updates are blocked
- empty evidence is blocked

## Report Contract
Schema key: `REPORT_SCHEMA`

Required fields:
- `executive_summary`
- `key_indicators[]`
- `recommended_actions[]`
- `unknowns[]`

Validation rules:
- structured JSON only
- no freeform unstructured output accepted by pipeline

## Failure Handling
If LLM output fails validation:
- planning falls back to deterministic ranked plan
- signal updates fall back to deterministic tool-to-signal mapping
- report falls back to deterministic summary template
