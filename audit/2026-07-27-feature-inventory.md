# Feature and Route Inventory — 2026-07-27

Evidence labels: **V** verified by test/runtime; **PV** partially verified; **U** unverified usage/production value.

| System area / location | Intended outcome | Actual observed behavior | Target user | Status | Risk / recommendation |
|---|---|---|---|---|---|
| `HomePage.jsx`, `/` | Start a public repository review | Strict GitHub identity handling, suggestions, queue navigation | Developer | V | Medium — keep; browser accessibility follow-up |
| `ContextPage.jsx`, `/r/:owner/:repository` | Read security context / request rescan | Client polls context and supports rescan | Developer/reviewer | PV | High — browser E2E required |
| `ResultPage.jsx`, `/result` | Read decision, history, intelligence | Report is required; optional APIs settle independently | Developer/reviewer | V | Medium — keep |
| `ContextsPage.jsx`, `/contexts` | Browse recent work and queue | Uses recent/jobs/stats plus SSE/cache fallback | Reviewer/operator | PV | Medium — restart/SSE E2E required |
| `LeaderboardPage.jsx`, `/leaderboard` | Compare reports | Fetches leaderboard table | Reviewer | PV | Low — validate audience/value |
| Legal pages | Explain product/privacy/editorial stance | Static content | Public user | PV | Low — review claims during release |
| `Service`, `Storage`, worker | Persist, scan, finalize, retry | Workspace tests cover jobs, idempotency, failures, queues | System | V | High — live token tests remain skipped |
| GitHub/OSV/NVD/OpenRouter adapters | Collect external evidence | One public live CLI evaluation; adapter tests | System | PV | High — dependency outage / token coverage missing |
| `/mcp` | Provide machine context | Browser/config tests pass; context creation shares repository throttle | Coding agent | PV | High — requester-level admission needs production decision |

## Backend HTTP routes

Source: `backend/crates/server/src/lib.rs:288-359`. Status is endpoint wiring status, not proof of user adoption.

| Route family | Routes | Status / recommendation |
|---|---|---|
| Health and API discovery | `GET /health`, `/healthz`, `/api`, `/api/v1/openapi.json`, `/api/v1/health`, `/api/v1/healthz` | V — health and OpenAPI tests; keep |
| Context and scan | `GET /api/v1/context/:owner/:repo`, `POST /api/v1/context`, `POST /api/v1/scan`, `GET /api/v1/result`, `/history`, `/intel/hits`, `/suggest` | PV — core CLI and selected local API paths verified; full browser E2E missing |
| Context artifacts | `GET /r/*path`, `/sitemap.xml` | V — route/render tests; content semantics need UX review |
| Review / regression APIs | `GET /api/v1/repos/:owner/:repo/regression-contracts`, `GET /…/:contract_id`, `POST /…/transitions`, `POST /…/regression-assessments`, `GET /…/:head_sha` | PV — storage/service tests; no end-user adoption proof |
| Discovery / lists | `GET /api/v1/leaderboard`, `/recent-scans`, `/pig`, `/scoring/versions` | PV — client and service tests; investigate value of `/pig` |
| Queue and operations | `GET /api/v1/jobs`, `/queue/stats`, `POST /queue/pause`, `/queue/resume`, `/queue/rescan`, `/ops/failures/:id/retry`, `/ops/failures/:id/ack` | V/PV — queue capacity manually verified; authenticated ops paths require production integration test |
| Metrics/admin | `GET /api/v1/metrics`, `/metrics/prometheus`, `/admin/discrepancy`, `/admin/consistency` | PV — route exists; production alerts/dashboards unverified |
| Feedback | `POST /api/v1/feedback` | PV — origin/rate unit tests; user workflow unverified |
| MCP | `GET,POST /mcp` | PV — config response tests; context creation uses repository throttle; client interoperability and requester-level controls unverified |
| Static SPA fallback | fallback `serve_static` | V — root, route shell, traversal tests; local Quick Start runtime verified |

## Background and command inventory

| Item | Location | Actual behavior / status | Decision |
|---|---|---|---|
| CLI `eval`, `serve`, `discover`, stats | `backend/bin/ai-supply-chain-trust` | CLI tests; real public evaluation; fixed static-dir default | KEEP |
| Queue workers | `maybe_start_queue_worker` in server | Controlled by `AI_SUPPLY_CHAIN_TRUST_DAEMON`; worker-disabled local tests | PV — require restart/outage tests |
| NVD/detail/finalize/notification/recovery workers | server worker functions | Unit/service coverage | PV — no production evidence |
| Scanner runner | `backend/crates/scanner_runner` | Registry and command execution tests | V — scanner availability still environment-dependent |
| LLM guardrail | `backend/crates/llm` | Grounding tests, severity and response-cap regressions | V — only bounded supplemental output |

## Integrations and configuration

| Integration/config | Actual behavior | Status / action |
|---|---|---|
| GitHub, OSV, NVD | Public data sources; token-dependent flows | PV — keep, verify with a non-secret test account in staging |
| OpenRouter | Structured LLM classification with deterministic guardrails | PV — model output is supplemental, not primary evidence |
| SQLite / Postgres | Storage abstraction and tests | V/PV — Postgres live path unverified |
| `AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS` | Explicit canonical HTTP(S) CORS allowlist; empty = same-origin only; wildcard, `null`, paths, and userinfo rejected | V — keep |
| `AI_SUPPLY_CHAIN_TRUST_MAX_QUEUED_SCANS` | Bounds queued rescans; default 100 | V — keep and monitor |
