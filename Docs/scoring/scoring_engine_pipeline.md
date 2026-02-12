# Scoring Engine Pipeline

## Purpose
Convert bounded `signals.json` output into deterministic:
- `risk_score` (0-100)
- `confidence_score` (0-1)
- `verdict` (`benign|suspicious|phish`)
- `agent_gate` decision (`invoke_agent` true/false)

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Scoring_Engine/scoring_engine.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Scoring_Engine/scoring_weights.yaml`

## Input Contract
Input file must match signal engine output shape:
- top-level `signals` object
- each signal must include:
  - `value`: `true|false|unknown`
  - `kind`: `deterministic|non_deterministic`
  - `evidence`: list
  - `rationale`: string

Invalid payloads fail fast with validation errors.

## Risk Scoring Model
For each signal with `value=true`:
1. Resolve weight from config.
2. Apply signal override if present.
3. Else use category+kind default weight.
4. Add to running risk total.
5. Clamp final risk to `[0,100]`.

Verdict thresholds:
- `risk <= benign_max` -> `benign`
- `risk >= phish_min` -> `phish`
- otherwise -> `suspicious`

## Confidence Model
Confidence combines:
- known signal coverage
- deterministic coverage
- non-deterministic coverage
- evidence presence ratio

Penalties:
- unknown high-impact signals
- true signals without evidence

Output confidence is clamped to `[0,1]`.

## Agent Gate Model
The scoring engine decides whether to invoke investigation agent:

Force invoke when:
- high-impact unknown signal count exceeds threshold
- confidence below threshold
- risk falls in ambiguous band

Skip invoke when:
- high risk and high confidence (auto-phish path)
- low risk and high confidence (auto-benign path)

The gate is designed to run repeatedly during investigation:
- baseline gate before playbook execution
- post-playbook gate after every iteration
- final gate at investigation completion

## Outputs
Generated fields:
- `risk_score`
- `confidence_score`
- `verdict`
- `agent_gate`
- `metrics`
- `reasons` (top weighted true signals)
- `weighted_signals` (full breakdown)

## CLI Usage
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Scoring_Engine/scoring_engine.py \
  --signals /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.signals.json \
  --weights /Users/gabe/Documents/Phishing_Triage_Agent/Scoring_Engine/scoring_weights.yaml \
  --out /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.score.json
```

## Tuning Guidance
- Raise `true_weight` for signals with low false-positive rate.
- Keep high-impact list small and stable.
- Treat confidence penalties as safety controls, not risk controls.
- Re-tune only against labeled corpora.

Current anti-false-positive weight tuning:
- reduced weight for wrapper-prone URL heuristics (`display_text_mismatch`, redirect-pattern, long-obfuscated-string)
- reduced weight for relay-prone header/infrastructure heuristics (`from_domain_mismatch_in_headers`, `private_ip_in_received_chain`)
- reduced standalone weight for `content.brand_impersonation` unless supported by other social-engineering indicators
