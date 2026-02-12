# MCP Tooling and IOC Cache

## Purpose
Provide MCP-style tool contracts for enrichment APIs with:
- strict input/output schema checks
- local IOC caching
- deferred mode (no live API calls yet)

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
2. urlscan.io (URL/domain)
3. ICANN RDAP (domain registration)
4. AbuseIPDB (IP reputation)
5. AlienVault OTX (multi-IOC intel)
6. crt.sh (certificate transparency/domain context)

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
5. If live mode enabled, enforce API key presence and fail (not wired in this phase).

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

## Next Integration Step
When API keys are available:
1. implement provider-specific request adapters behind current router
2. normalize provider outputs into shared contract
3. map normalized outputs back to non-deterministic signal updates

## Environment
Keys and mode defaults are configured in:
- `/Users/gabe/Documents/Phishing_Triage_Agent/.env`
