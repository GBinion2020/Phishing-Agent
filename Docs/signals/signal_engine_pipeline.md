# Signal Engine Pipeline

## Purpose
The signal engine converts a normalized envelope into a bounded `signals.json` object.

The output is designed for:
- deterministic scoring
- playbook selection
- downstream investigation routing

## Inputs
- Envelope JSON from normalization:
  - `schema_version`, `case_id`, `message_metadata`, `auth_summary`, `entities`, `mime_parts`, `attachments`, `warnings`
- Signal registry and rule files in `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine`
- Optional external tool results for non-deterministic signals

## Configuration Files
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_taxonomy.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_rules_deterministic.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_rules_nondeterministic.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/tool_requirements.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_output_schema.yaml`

Note: these files are JSON-compatible YAML so parsing does not require PyYAML.

## Execution Stages
1. Load taxonomy and rule mappings.
2. Evaluate deterministic signals using envelope-only logic.
3. Evaluate non-deterministic signals using external tool results when available.
4. Default non-deterministic signals to `unknown` if tool data is missing.
5. Emit strict bounded values: `true`, `false`, or `unknown`.
6. Pass output to scoring engine and playbook selector for deterministic decisioning.

## Deterministic Evaluation
Deterministic evaluators inspect these envelope areas:
- `message_metadata` for identity/header checks
- `auth_summary` for SPF/DKIM/DMARC and alignment checks
- `entities.urls/domains/emails/ips` for URL and infrastructure signals
- `mime_parts.body_extraction` for content/evasion checks
- `attachments` for static attachment indicators

## Non-Deterministic Evaluation
Non-deterministic signals require connectors such as:
- DNS TXT/MX lookups
- WHOIS domain age
- URL/IP reputation providers
- attachment hash intel
- sandboxing
- campaign clustering/mailbox history

If a connector is unavailable, the signal remains `unknown` with a rationale.

## Output Contract
Output includes:
- `schema_version`
- `case_id`
- `generated_at`
- `signals` map keyed by signal id

During investigation there are two snapshots:
- baseline signal output before enrichment
- final signal output after adaptive playbook loop updates

Each signal entry includes:
- `value` (`true|false|unknown`)
- `kind` (`deterministic|non_deterministic`)
- `evidence` (field paths and/or evidence ids)
- `rationale`
- `tool_requirements`

## CLI Usage
Generate signals from envelope:

```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_engine.py \
  --envelope /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.envelope.json \
  --out /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.signals.json
```

Include non-deterministic tool results:

```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Signal_Engine/signal_engine.py \
  --envelope /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.envelope.json \
  --tool-results /path/to/tool_results.json \
  --out /path/to/signals.json
```

## Tool Results Shape
Expected minimal structure:

```json
{
  "signals": {
    "url.reputation_malicious": {
      "value": "true",
      "evidence": ["ev_url_rep_001"],
      "rationale": "Provider marked URL as malicious"
    },
    "infra.sending_ip_reputation_bad": false
  }
}
```

## Maintenance Notes
When adding or changing a signal:
1. Update taxonomy file.
2. Update deterministic or non-deterministic rule mapping.
3. Update this documentation file.
4. Re-run sample output checks.
5. Re-check scoring weights and playbook triggers for the changed signals.
