# Confidence Gate and Pivot Logic

## Purpose
Control investigation depth adaptively rather than using a fixed playbook count.

## Gate Inputs
From scoring engine output:
- `risk_score`
- `confidence_score`
- `agent_gate.invoke_agent`
- high-impact unknown metrics

## Gate Timing
Gate is evaluated:
1. once at baseline (before agent invocation)
2. after each playbook execution

## Early Stop
Investigation stops early when:
- scoring gate indicates no further agent action needed
- expected next playbook gain is below threshold

## Pivot Strategy
After each playbook, next playbook is re-ranked by:
- high-impact unknown coverage
- expected confidence gain
- estimated cost
- overlap with previously targeted signal sets
- optional LLM ordering bonus

This provides adaptive depth:
- simple cases terminate quickly
- ambiguous cases continue under budget

## Budget Controls
Configured limits:
- max playbooks
- max steps
- max tool calls

Hard stop triggers on any budget exhaustion.

## Practical Behavior
In mock-mode sample runs, confidence increased across iterations while risk remained stable.
This is expected when enrichment resolves unknowns without adding new confirmed malicious signals.
