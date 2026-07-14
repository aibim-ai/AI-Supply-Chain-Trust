# API Reference

## Regression watchlist

```text
GET  /api/v1/repos/{owner}/{repo}/regression-contracts
GET  /api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}
POST /api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}/transitions
POST /api/v1/repos/{owner}/{repo}/regression-assessments
GET  /api/v1/repos/{owner}/{repo}/regression-assessments/{head_sha}
```

Transition and assessment writes require the configured worker bearer token.
Transitions require `expected_version`, `to_state`, `actor`, and `reason`;
suppression also requires `expires_at`. Assessment writes require `base_sha`,
`head_sha`, and `changed_files`. Optional `codeowners`, `verified_guards`,
`guard_results`, and `removed_fix_primitives` add evidence dimensions. Set
`publish_check=true` to create or update the single GitHub Check Run associated
with the repository and head SHA.

Base URL: `https://ai-supply-chain-trust.aibim.ai`

Public endpoints are protected by edge request limits. Direct context/scan
creation also has an in-process limit per normalized repository. Queue enqueue
requests are idempotent while a job for the same repository and lane is pending.
Operational mutation endpoints require the worker bearer token.

## Endpoints

### Health

```
GET /health
→ 200 "healthy\n"
```

```
GET /healthz
→ 200 {"status":"ok","db":"connected","scans_total":42}
```

### API Index

```
GET /api
→ 200 {
    "service": "ai-supply-chain-trust",
    "version": "2.0.0-rust",
    "description": "...",
    "endpoints": [...],
    "tools": [...]
  }
```

### OpenAPI Schema

```
GET /api/v1/openapi.json
→ 200 OpenAPI 3.1.0 schema with all paths, parameters, and responses
```

### Leaderboard

```
GET /api/v1/leaderboard?q={query}&limit={n}
→ 200 {
    "count": 42,
    "rows": [
      {"repo": "owner/name", "trust_score": 85.0, "grade": "A", ...}
    ],
    "metrics": {"tracked_repos": 42, "critical_blocks": 0}
  }
```

### Recent Scans

```
GET /api/v1/recent-scans?limit={n}
→ 200 {"count": 10, "rows": [...]}
```

### Get Result

```
GET /api/v1/result?repo=owner/name
→ 200 EvaluationResult (trust_score, grade, verdict, 8 pillar_scores, ...)
→ 404 {"error": "not found"}
```

### Report History

```
GET /api/v1/history?repo=owner/name
→ 200 [EvaluationResult, ...]
```

### Intelligence Hits

```
GET /api/v1/intel/hits?repo=owner/name
→ 200 {"repo": "owner/name", "hits": {...security_intel...}}
```

### Publisher Identity Graph

```
GET /api/v1/pig?account=name
→ 200 {"account": "name", "repos_owned": 12, "average_score": 78.5, "risk_level": "low"}
```

### Suggestions

```
GET /api/v1/suggest?q=search
→ 200 {"candidates": [{"repo": "owner/name", "score": 85.0}, ...]}
```

### Scoring Versions

```
GET /api/v1/scoring/versions
→ 200 {"versions": [...], "default": "2026-07-05-scap-8pillar-v1"}
```

### Metrics

```
GET /api/v1/metrics
→ 200 {"scans_total": 500, "unique_repos": 120}
```

```
GET /api/v1/metrics/prometheus
→ 200 text/plain Prometheus format
```

### SSE Events

```
GET /api/v1/events
→ 200 text/event-stream
  id: 1842
  data: {"id":1842,"repo":"owner/name","event_type":"scan_fast_ready","payload":{...},"created_at":"..."}
```

Events are persisted in `trust_events`. A fresh connection begins after the
latest event; EventSource reconnection sends `Last-Event-ID` and resumes from
that cursor. The payload is structured JSON rather than a JSON-encoded string.

### Queue Operations

```
GET /api/v1/queue/stats
→ 200 {"pending":3,"active":1,"paused":false,"github_foreground_reserve":500,"github_rate_limit":{"limit":5000,"remaining":4200,"reset_at":1780000000},"evidence":{"github_history_page":{"completed":8,"queued":1},"nvd":{"running":1}}}

GET /api/v1/jobs?limit={n}
→ 200 {"count":1,"jobs":[{"id":42,"repo":"owner/name","lane":"foreground","status":"queued"|"running"|"completed"|"failed","created_at":"...","started_at":"...","completed_at":"..."}]}

POST /api/v1/queue/pause  {"seconds": 3600}
→ 200 {"status": "paused", "seconds": 3600}

POST /api/v1/queue/resume
→ 200 {"status": "resumed"}

POST /api/v1/queue/rescan  {"repo": "owner/name", "priority": 1}
→ 200 {"status": "queued", "job_id": 42}
```

`last_error` and provider diagnostics are deliberately absent from public job
responses. Failed-job details are available only through private operations
alerts.

## Run Scan

```
POST /api/v1/scan
Content-Type: application/json

{"repo": "owner/name"}

→ 200 {
    "repo": "owner/name",
    "job_id": 42,
    "status": "enriching",
    "report": { ... EvaluationResult ... }
  }

The foreground call has a total metadata deadline and excludes unbounded commit
history and NVD work. Its report
contains `observed_metrics.scan_state="fast_ready"`. Durable background workers
resume history page-by-page, merge completed evidence into a new report version,
then publish `scan_complete` with `scan_state="complete"`.

→ 429 {"error": "rate_limited", "code": "post_rate_limit"}
→ 502 {"error": "Scan could not be completed", "code": "scan_failed"}
```

## Security Context

```
GET /api/v1/context/{owner}/{repo}?wait={seconds}
→ 200 SecurityContextEnvelope:
  {
    "repo": "owner/name",
    "status": "ready" | "enriching" | "error" | "none",
    "summary": {
      "fixes": 73,
      "cves": 51,
      "top_severity": "critical",
      "remediation_coverage": 70.6
    },
    "artifacts": {
      "security_context_json": "/r/owner/name.json",
      "security_context_md": "/r/owner/name.md",
      "vulnerability_leads_json": "/r/owner/name.leads.json",
      "vulnerability_leads_md": "/r/owner/name.leads.md"
    },
    "context": { ... SecurityContext ... },
    "leads": { ... VulnerabilityLeads ... }
  }
```

```
POST /api/v1/context
{"repo": "owner/name"}

→ 200 (same as GET, with "created": true|false)
```

## Artifacts

```
GET /r/{owner}/{repo}.json
→ 200 SecurityContext JSON

GET /r/{owner}/{repo}.md
→ 200 text/markdown

GET /r/{owner}/{repo}.leads.json
→ 200 VulnerabilityLeads JSON

GET /r/{owner}/{repo}.leads.md
→ 200 text/markdown

GET /free-tools/r/{owner}/{repo}
→ 200 text/html (SPA page)
```

## MCP Protocol

```
POST /mcp
Content-Type: application/json

{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
→ {"jsonrpc": "2.0", "id": 1, "result": {"tools": [...]}}

{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "get_security_context", "arguments": {"repo": "owner/name"}}}
→ {"jsonrpc": "2.0", "id": 2, "result": {
    "content": [{"type": "text", "text": "..."}],
    "structuredContent": {...}
  }}

Available tools:
- get_security_context    — Get generated security context
- get_vulnerability_leads — Get variant-analysis leads
- create_security_context — Create or refresh context
```

## Error Responses

| Code | HTTP | Meaning |
|------|------|---------|
| `bad_request` | 400 | Invalid or missing public parameter |
| `not_found` | 404 | Requested stored result does not exist |
| `auth_required` | 401 | Operational bearer token missing/invalid |
| `post_rate_limit` | 429 | Repository POST limit exceeded |
| `scan_failed` | 502 | Scan failed; private provider detail is withheld |
| `internal` | 500 | Unexpected internal failure |
