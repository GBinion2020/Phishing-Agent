# Command-Line Tool

## Purpose
Provide an operator-friendly CLI wrapper for the investigation pipeline with:
- strict `.eml` input validation,
- real-time stage/playbook progress,
- repeat-run workflow in one session,
- runtime memory scrubbing between runs,
- compatibility with future HTTP UI reuse.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/pipeline_service.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Investigation_Agent/investigation_pipeline.py`

## Runtime Flow
1. Prompt operator for file path (or accept `--eml` in one-shot mode).
2. Validate path exists and extension is exactly `.eml`.
3. Launch pipeline via `PipelineService.execute(...)`.
4. Stream pipeline events to CLI display:
   - stage started/completed,
   - playbook started/completed,
   - intermediate score/confidence updates.
5. Print final structured summary including analyst explanation.
6. Scrub in-process runtime state before next run.
7. Optionally delete artifacts with `--scrub-artifacts`.

## Event Model for Reuse
`run_pipeline(...)` now accepts `event_hook(event_name, payload)`.

Current event names:
- `pipeline_started`
- `stage_started`
- `stage_completed`
- `playbook_started`
- `playbook_completed`
- `pipeline_completed`

This keeps the orchestration decoupled from presentation so the same pipeline can back:
- terminal UX,
- HTTP streaming status endpoints,
- future GUI/websocket updates.

## Commands
Interactive mode:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py
```

One-shot mode:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py \
  --eml /absolute/path/to/email.eml \
  --mode live
```

Scrub generated run artifacts from disk after each run:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/cli/phishscan.py --scrub-artifacts
```

## Notes
- `--mode mock` and `--mode live` are both supported by the CLI and passed through to the pipeline.
- Runtime scrubbing clears Python in-memory objects between runs; `--scrub-artifacts` controls whether output files are retained.
- The CLI now forces process working directory to repo root, so `.env` and relative paths resolve consistently even when invoked from `/cli`.
- Optional org ownership behavior can be configured via `ORG_TRUSTED_DOMAINS=example.com,subsidiary.org`; if not set, domain-ownership enrichment is deferred instead of defaulting to suspicious.
