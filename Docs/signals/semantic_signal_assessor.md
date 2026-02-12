# Semantic Signal Assessor

## Purpose
Add LLM-based semantic triage over a controlled evidence envelope while preserving deterministic decision control.

Implementation file:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/semantic_signal_assessor.py`

## What It Does
1. Builds a controlled, structured evidence envelope from normalized data.
2. Sanitizes untrusted email text and prechecks for prompt-injection indicators.
3. Calls LLM with strict JSON schema for semantic signal assessments.
4. Falls back to deterministic semantic heuristics if LLM is unavailable.
5. Produces bounded signal updates with evidence references.

## Controlled Evidence Envelope
Included fields are bounded and structured:
- message metadata subset
- auth summary
- body excerpts (plain/html)
- extracted links and URL table
- attachment metadata subset
- prompt-injection precheck indicators

This prevents unconstrained raw email ingestion into the model prompt.

## Prompt Injection Defense
Defenses used:
- explicit system instruction to treat email content as hostile data
- rule to ignore in-email instruction attempts
- pre-sanitization/masking of common injection phrases
- explicit prompt-injection signal output (`semantic.prompt_injection_attempt`)

## No-Action Guarantee
This semantic stage cannot execute tools:
- it only uses the OpenAI text response call
- it has no function/tool-calling interface
- tool execution is deterministic pipeline code outside this module

## Output Signals
Current semantic signals:
- `semantic.credential_theft_intent`
- `semantic.coercive_language`
- `semantic.payment_diversion_intent`
- `semantic.impersonation_narrative`
- `semantic.body_url_intent_mismatch`
- `semantic.social_engineering_intent`
- `semantic.prompt_injection_attempt`

## Integration Point
Investigation pipeline baseline now performs:
- baseline technical signals
- semantic assessment
- semantic updates applied to non-deterministic semantic signals
- deterministic scoring/verdict from combined signal set

Artifacts written:
- `evidence.controlled.json`
- `semantic_assessment.json`
