# Completion Plan — 2026-07-30

## Scope and definition of done

This plan closes every source-controlled OPEN/UNVERIFIED item in `2026-07-27-final-product-audit.md` and every product gap in `2026-07-30-depx-discovery-analysis.md`. Deployment-only proof is a separate release gate: it cannot be truthfully claimed until a production/staging environment, credentials, and operator ownership exist.

| Workstream | Deliverables | Acceptance proof |
|---|---|---|
| Discovery truth | Durable discovery cycles/candidates, source metadata, eligibility/rejection reasons, dedupe, rate/budget counters | Deterministic HTTP mock plus live GitHub run; API/Prometheus metrics include every counter |
| Package intelligence | GitHub Dependency Graph SBOM client, package normalization, malicious-package advisory matcher, report/context display | Mock SBOM and advisory fixtures; one public repo result with explicit available/unavailable state |
| Admission control | Trusted-proxy configuration, requester-key rate limit, spoofed-forwarded-header rejection, concurrency/load test | Direct/API/MCP tests prove one requester cannot exhaust permits by rotating repositories |
| Worker reliability | Queue restart, outage, retry/backoff and PostgreSQL mirror integration proof | SQLite tests cover queued/running/retry/failed state; PostgreSQL proof covers connection/readiness/report mirroring. Multi-host queue mutation remains a separate migration gate. |
| UX/a11y | Explicit unavailable/retry panels, keyboard combobox, semantic labels, responsive and axe E2E | Playwright runs Home, Context, Result under desktop/mobile and failure fixtures; axe has no serious violations |
| Operations | Dashboards/alerts, runbook, deployment topology, migration/rollback and readiness checks | Documented drill script; health/readiness reports token/dependency/worker state |
| Security/SCA | Dependency vulnerability scan and tracked exceptions | Reproducible scan command in CI; no untriaged critical finding |

## Sequence

1. Add discovery persistence and metrics first; it makes later live proof diagnosable.
2. Add SBOM/package-malware evidence, with strict unavailable semantics.
3. Replace repository-only admission with trusted requester-level admission.
4. Add worker/reliability and Postgres tests.
5. Add browser accessibility/responsive E2E and UI unavailable states.
6. Add operations/runbooks/SCA automation, then rerun full release audit.

## Non-negotiable constraints

- No scanner, SBOM, GitHub, OSV, NVD, or package-feed failure may appear as a clean result.
- Discovery only admits canonical public GitHub `owner/repo` identities.
- Only one worker-capable deployment instance runs SQLite queue mutation; multi-worker production requires Postgres.
- Every fix needs unit/regression coverage; every cross-system claim needs runtime proof.
