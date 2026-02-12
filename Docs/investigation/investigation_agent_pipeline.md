# Investigation Agent Pipeline

## Purpose
Run adaptive, bounded investigation after baseline normalization, signals, and scoring.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/investigation_pipeline.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/llm_client.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/contracts.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/prompt_templates.py`

## Pipeline Stages
1. Build envelope from `.eml`.
2. Generate baseline signals (`signals.baseline.json`).
3. Generate baseline score and gate (`score.baseline.json`).
4. Select candidate playbooks.
5. Generate LLM investigation plan (or deterministic fallback).
6. Execute adaptive playbook loop with pivot logic.
7. Recompute risk/confidence after each playbook.
8. Run confidence gate after each iteration and stop early when eligible.
9. Produce final signals, score, and report artifacts.

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

LLM is not allowed to:
- directly set final verdict
- update deterministic signals
- invoke non-whitelisted playbooks/tools

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
- `signals.baseline.json`
- `score.baseline.json`
- `playbooks.candidates.json`
- `investigation_plan.json`
- `signals.final.json`
- `score.final.json`
- `report.final.json`
- `investigation_result.json`

## CLI
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/investigation_pipeline.py \
  --eml /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.eml \
  --out-dir /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Case_Run_001 \
  --mode mock
```

## Modes
- `mock`: uses deterministic mock enrichment seeding + cache-backed MCP routing.
- `live`: reserved for future API wiring; currently MCP live requests are not implemented.
