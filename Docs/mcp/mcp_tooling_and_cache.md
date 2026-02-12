# MCP Tooling and IOC Cache

## Purpose
Provide MCP-style tool contracts for enrichment APIs with:
- strict input/output schema checks
- local IOC caching
- live API routing with deferred/error fallbacks

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/mcp_tool_registry.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/mcp_router.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/ioc_cache.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/mock_enrichment.py`

## Why this layer
- decouples signal engine from specific providers
- enables cache-first enrichment
- enforces strict tool contracts before LLM or planner can consume outputs

## API Candidates (open/free tier)
Configured in registry for staged integration:
1. VirusTotal (URL/IP/hash)
2. urlscan.io (URL/domain + detonation)
3. ICANN RDAP (domain registration)
4. AbuseIPDB (IP reputation)
5. AlienVault OTX (multi-IOC intel)
6. crt.sh (certificate transparency/domain context)
7. URLhaus (malware URL/host reputation)
8. CAPE/Cuckoo (self-hosted URL detonation)

Deprecated from active registry:
- PhishTank
- OpenPhish

Loss from deprecating these two feeds:
- less cross-feed URL phishing confirmation coverage
- fewer direct feed matches for known phishing URLs
- slightly lower recall on newly listed phish URLs that appear in those feeds first

## Tool Registry Contract
Each tool definition includes:
- `id`
- `mcp_tool`
- `provider`
- `auth_env_var`
- `ioc_types`
- `cache_ttl_seconds`
- `input_schema`
- `output_schema`

## Router Behavior
Request flow:
1. Validate input payload against tool schema.
2. Check IOC cache by `(tool_id, ioc_type, value)`.
3. Return cached result if fresh.
4. If no cache and live mode disabled, return deferred stub.
5. If live mode enabled, execute provider adapter and normalize output.
6. If live call fails (missing key, timeout, provider error), return schema-valid `error` output.

urlscan-specific hardening:
- lookup now retries transient failures (`timeout`, `429`, `503`, etc.) with bounded backoff.
- transient lookup exhaustion returns `status=deferred` (not hard error), preserving deterministic behavior.
- detonation follows urlscan guidance with configurable initial wait before polling results.
- detonation poll timeout returns `status=deferred` with explicit reason (`result not ready within polling window`).

## Cache Behavior
Cache store:
- file-backed JSON key-value store
- timestamped entries
- TTL-based freshness check

Cache key format:
- `tool_id|ioc_type|normalized_value`

## CLI Examples
Deferred tool call:

```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/mcp_router.py \
  --tool virustotal_url \
  --ioc-type url \
  --value "https://example.com/login"
```

Seed cache for local simulation:

```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent/MCP_Adapters/mcp_router.py \
  --tool virustotal_url \
  --ioc-type url \
  --value "https://example.com/login" \
  --seed-status ok \
  --seed-malicious true \
  --seed-confidence 0.92
```

Then call again to verify cache hit.

## Environment
Keys and mode defaults are configured in:
- `/Users/gabe/Documents/Phishing_Triage_Agent/.env`

Suggested variables:
- `URLSCAN_API_KEY`
- `URLSCAN_VISIBILITY` (default: `unlisted`)
- `URLSCAN_LOOKUP_TIMEOUT_SECONDS` (default: `20`)
- `URLSCAN_LOOKUP_RETRIES` (default: `2`)
- `URLSCAN_SUBMIT_TIMEOUT_SECONDS` (default: `20`)
- `URLSCAN_INITIAL_WAIT_SECONDS` (default: `10`)
- `URLSCAN_POLL_MAX_SECONDS` (default: `45`)
- `URLSCAN_POLL_INTERVAL_SECONDS` (default: `2`)
- `URLHAUS_AUTH_KEY` (optional but recommended)
- `CUCKOO_BASE_URL` (default from registry)
- `CUCKOO_API_TOKEN` (optional, if your Cuckoo/CAPE API is authenticated)
- `CUCKOO_POLL_MAX_SECONDS` (default: `90`)
- `CUCKOO_POLL_INTERVAL_SECONDS` (default: `5`)

Current runtime note:
- `cuckoo_url_detonate` adapter exists but is intentionally not invoked by default playbook execution until local sandbox infrastructure is enabled.
