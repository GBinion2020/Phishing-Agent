# Investigation Agent Pipeline

## Purpose
Run adaptive, bounded investigation after baseline normalization, signals, and scoring.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/investigation_pipeline.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/llm_client.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/contracts.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/prompt_templates.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/pipeline_service.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py`

## Pipeline Stages
1. Build envelope from `.eml`.
2. Generate baseline technical signals (`signals.baseline.json`).
3. Run semantic assessor on controlled evidence envelope.
4. Apply semantic signal updates with evidence references.
5. Generate baseline score and gate (`score.baseline.json`).
6. Select candidate playbooks.
7. Generate LLM investigation plan (or deterministic fallback).
8. Execute adaptive playbook loop with pivot logic.
9. Recompute risk/confidence after each playbook.
10. Run confidence gate after each iteration and stop early when eligible.
11. Produce final signals, score, and report artifacts.

## Adaptive Playbook Strategy
No fixed "3-playbook" limit.

The loop uses bounded budgets:
- `max_playbooks`
- `max_steps`
- `max_tool_calls`

And chooses next playbook by expected marginal gain:
- unresolved high-impact unknown signal coverage
- expected confidence gain
- cost penalty
- overlap penalty with already-targeted signals
- small ranking bonus from LLM plan order

## Stop Conditions
The investigation loop stops when first condition is met:
- confidence gate satisfied (`agent_gate.invoke_agent == false`)
- expected gain below threshold
- playbook/step/tool-call budget exhausted
- no remaining playbooks

## LLM Responsibilities
LLM is constrained to:
- playbook planning (`investigation_plan.json`)
- evidence-to-signal updates for non-deterministic signals only
- final report synthesis
- semantic assessment over controlled evidence envelope

LLM is not allowed to:
- directly set final verdict
- update deterministic signals
- invoke non-whitelisted playbooks/tools
- execute external actions/tools from email content

Implementation note:
- OpenAI call path in `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/llm_client.py` sends text-only JSON-schema requests and does not expose tool/function-calling hooks.

## Deterministic Responsibilities
Deterministic code performs:
- baseline signal generation
- risk/confidence scoring
- confidence gate decisions
- playbook step execution and evidence logging
- final verdict from scoring engine

## Artifacts
Generated under run directory (`--out-dir`):
- `envelope.json`
- `evidence.controlled.json`
- `semantic_assessment.json`
- `signals.baseline.json`
- `score.baseline.json`
- `playbooks.candidates.json`
- `investigation_plan.json`
- `signals.final.json`
- `score.final.json`
- `report.final.json`
- `investigation_result.json`
- `audit_chain.json`
- `audit_chain.md`

## Event Hook Interface
`run_pipeline(...)` now supports an optional `event_hook(event_name, payload)` callback to stream progress to clients.

Emitted events:
- `pipeline_started`
- `stage_started`
- `stage_completed`
- `playbook_started`
- `playbook_completed`
- `pipeline_completed`

This keeps core pipeline logic presentation-agnostic so terminal and future HTTP UI layers can share the same orchestration.

## CLI
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/investigation_pipeline.py \
  --eml /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.eml \
  --out-dir /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Case_Run_001 \
  --mode mock
```

Interactive operator CLI:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py
```

## Modes
- `mock`: uses deterministic mock enrichment seeding + cache-backed MCP routing.
- `live`: reserved for future API wiring; currently MCP live requests are not implemented.

## Environment Resolution
- Pipeline dotenv loading is anchored to repository root (`/Users/gabe/Documents/Phishing_Triage_Agent/.env`) instead of current shell directory.
- CLI runner sets process cwd to repo root before execution to prevent path/env drift.
