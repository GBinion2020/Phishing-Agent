# Repository Working Instructions

## Documentation Sync Rule
Whenever code is added or changed, update the associated documentation in the same change set.

Required behavior:
- If ingestion/normalization changes, update `/Users/gabe/Documents/Phishing_Triage_Agent/Docs/normalization/normalization_pipeline.md`.
- If signal engine logic, taxonomy, or tool requirements change, update `/Users/gabe/Documents/Phishing_Triage_Agent/Docs/signals/signal_engine_pipeline.md`.
- If new major components are introduced, create a new component doc in `/Users/gabe/Documents/Phishing_Triage_Agent/Docs` and link it from README.
- Keep docs concrete: inputs, outputs, execution steps, and operational limits.

## Implementation Preference
- Use configuration-driven design where possible (YAML/JSON configs for taxonomy/rules).
- Keep outputs schema-stable and deterministic for downstream scoring and investigation.
