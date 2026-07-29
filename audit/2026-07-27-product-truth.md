# Product Truth — 2026-07-27

## Purpose statement

**VERIFIED.** AI Repo Trust helps a developer, security reviewer, or coding agent decide how cautiously to use a public GitHub repository by collecting provenance, dependency, scanner, and vulnerability evidence into an explicitly coverage-limited trust report.

Evidence: `README.md`; `frontend/src/pages/HomePage.jsx`; `backend/crates/service/src/lib.rs`; live command `cargo run -p ai-supply-chain-trust -- eval octocat/Hello-World --json` produced a low-confidence D-grade result with four named evidence gaps.

## Access and evidence limits

| Area | Available evidence | Limitation |
|---|---|---|
| Source, tests, local database, local server | Full workspace access; 4,856 indexed code nodes | Not production data |
| External GitHub/OSV/NVD/OpenRouter | One live public-repo evaluation completed | No GitHub-token live-test coverage |
| Browser | Source-level UI tests and build | No isolated browser surface was available; existing user Chrome session was not touched; no visual/mobile proof |
| Production | No deployment config, users, analytics, logs, SLOs, or incident history | Production readiness cannot be proved |

## User and job map

| User | Context / goal | Critical task | Expected outcome | Likely confusion / cost of failure |
|---|---|---|---|---|
| Developer evaluating a dependency | Needs a fast risk screen before adopting public code | Submit `owner/repository`; understand verdict and gaps | Concrete next action: use, review, or collect missing evidence | Mistaking unavailable evidence for a clean result can introduce unsafe code |
| Security reviewer | Triages supply-chain risk | Inspect flags, scanner status, intelligence, context artifacts | Traceable evidence leads and explicit uncertainty | False LLM-backed severity or hidden scan gaps wastes review time |
| Coding agent / automation client | Needs a machine-readable context | Call `/mcp` or context JSON routes | Structured, bounded evidence | Public endpoint abuse or incomplete context must not look authoritative |
| Operator | Runs workers and handles failures | Queue, resume, alert, retry operations | Bounded backlog and actionable failure state | Missing deployment/observability evidence prevents confident response |

## Core journeys and acceptance criteria

| Journey | Preconditions | User actions | Success criterion | Verified state |
|---|---|---|---|---|
| Public-repository screening | Server, GitHub/OSV/NVD connectivity | Enter supported GitHub identity; evaluate | Report includes decision, evidence coverage, and gaps; no invented certainty | **PARTIALLY VERIFIED** — real CLI run passed; browser journey unverified |
| Queue a rescan | Local server, SQLite, worker disabled for deterministic check | POST a valid repository to `/api/v1/queue/rescan` | Job persists as queued; atomic bounded backlog gives a recoverable `503` | **VERIFIED** — 10 accepts, 11th `503 queue_full`; concurrent storage regression |
| Read an existing result | Persisted report | Open `/result?repo=…` | Decision remains visible if optional history/intel fails | **VERIFIED** — `ResultPage.test.jsx` regression |
| Invalid or unsupported input | Web app | Paste GitLab/Bitbucket/malformed URL | Clear GitHub-only rejection before queue navigation | **VERIFIED** — repository unit/UI tests |
| Cross-origin browser API use | Explicit origin configuration | Browser sends `Origin` request | Only canonical configured HTTP(S) origin receives CORS grant | **VERIFIED** — local allowed-origin, attacker-origin, and `null`-origin check |

## Minimum viable value

The product is useful only when it makes uncertainty concrete: a public repository identity leads to an evidence-labelled decision, not a synthetic score. It must not be represented as a source of complete security assurance.

## Features with no current usage evidence

`/leaderboard`, `/pig`, feedback, analytics, regression-contract operations, failure-ops actions, and MCP use have implementation/test evidence but no user, analytics, or production-operation evidence. Their actual user value is **UNVERIFIED**; keep only while their owner can define and validate a user job.
