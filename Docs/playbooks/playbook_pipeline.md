# Playbook Pipeline

## Purpose
Select deterministic investigation playbooks from signal outputs.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/Playbooks/playbook_selector.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/Playbooks/playbook_library.yaml`

## Trigger Model
Each playbook has trigger rules:
- `any_true`: signal list where one or more must be true
- `all_true`: signal list where all must be true
- `minimum_true`: minimum count of true signals from `any_true`

Selection requires:
1. all `all_true` conditions pass
2. `minimum_true` satisfied for `any_true`

Selected playbooks are ranked by:
- base `priority`
- number of matched true signals
- evidence/confidence bonus

Execution policy:
- playbooks are not capped to a fixed count of 3
- adaptive loop continues until confidence gate passes or budgets are exhausted

## Playbook Catalog (12)
1. `identity_spoof_investigation`
2. `auth_failure_validation`
3. `malicious_url_reputation`
4. `content_credential_harvest`
5. `invoice_fraud_flow`
6. `attachment_static_triage`
7. `infrastructure_reputation`
8. `evasion_pattern_analysis`
9. `campaign_correlation`
10. `benign_confirmation_minimal`
11. `high_risk_fast_path`
12. `brand_impersonation_deep_dive`

Each playbook includes:
- purpose
- priority
- signal triggers
- step list (tool, args template, cost)

## Output
Selector output includes:
- `selected_playbook_count`
- ranked `selected_playbooks`
- matched signal list per playbook
- expanded step metadata

## CLI Usage
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/Playbooks/playbook_selector.py \
  --signals /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.signals.json \
  --playbooks /Users/gabe/Documents/Phishing_Triage_Agent/Playbooks/playbook_library.yaml \
  --out /Users/gabe/Documents/Phishing_Triage_Agent/Sample_Emails/Sample_Email.playbooks.json
```

## Governance Rules
- Keep playbooks bounded and tool-whitelisted.
- Every step should have explicit cost estimate.
- Never allow arbitrary URL fetching from LLM-generated input.
- Keep trigger logic deterministic and testable.
