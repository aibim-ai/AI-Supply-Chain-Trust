# Testing and Performance Evidence

## Quality contract

No test suite can prove that every possible execution is correct. This project
therefore requires evidence at each observable boundary: pure rules, data
contracts, persistence transitions, queue concurrency, HTTP/MCP behavior,
browser behavior, external-source integration, and production latency.

Every change must answer four questions:

1. Which behavior changed?
2. Which deterministic test proves the expected result and failure mode?
3. Which coverage or contract report shows the code was executed?
4. Which benchmark proves that correctness did not make the interactive path
   slower than its service-level objective?

## Required evidence layers

| Layer | Proof | Command / artifact |
| --- | --- | --- |
| Rust formatting | Stable source formatting | `cargo fmt --all -- --check` |
| Rust static analysis | Warnings and unsafe patterns rejected | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust behavior | Unit, property, integration, and persistence tests | `cargo test --workspace --all-targets` |
| Rust coverage | Executed lines and functions, including missing regions | `cargo llvm-cov --workspace --all-targets` and CI `rust-coverage-lcov` |
| Python guard boundary | Legacy/reference LLM checks | `python3 backend/tests/test_llm_hallucination_guard.py` |
| Frontend behavior | Data normalization, API retry, report interaction | `npm test -- --run` |
| Frontend quality | Formatting, lint, production bundling | `npm run format:check`, `npm run lint`, `npm run build` |
| Evidence independence | Forbidden runtime dependency scan | `scripts/security_independence_guard.sh` |
| Local fast path | Cached scan deadline and concurrency tests | `fast_scan_from_cache_meets_local_latency_budget`, `foreground_jobs_can_complete_concurrently` |
| Production fast path | Real enqueue-to-terminal latency | `scripts/benchmark_scan_pipeline.sh` |
| Deployment | Container health, routing, GitHub connectivity, real scan | `Deploy Production` workflow log and benchmark CSV |

Run all deterministic checks and save logs with:

```bash
scripts/test_evidence.sh
```

Output is written under `.cache/test-evidence/` and is intentionally not
committed. CI artifacts are the durable evidence for a commit.

## Current measured baseline

Measured on 2026-07-12 by `scripts/test_evidence.sh`:

| Metric | Result |
| --- | ---: |
| Rust tests passed | 212 |
| Live tests skipped without credentials | 6 |
| Rust line coverage | 66.73% |
| Rust function coverage | 60.35% |
| Frontend statement coverage after full-source inclusion | 80.21% |
| Frontend branch coverage after full-source inclusion | 60.88% |
| Frontend line coverage after full-source inclusion | 83.95% |
| Frontend function coverage after full-source inclusion | 79.32% |

CI rejects Rust line coverage below 60% or function coverage below 55%. These are
regression floors, not completion targets. New code is expected to exceed the
repository baseline, and critical paths require direct behavior tests even when
aggregate coverage passes.

Frontend CI measures every source module (not only files imported by tests) and
rejects statements below 75%, branches below 60%, functions below 75%, or lines
below 80%.

The initial production observation that motivated the foreground fix was:

| Stage | Job #63 (`octocat/Spoon-Knife`) |
| --- | ---: |
| Queue API acceptance | 0.338 s |
| Queue wait | 188 s |
| Foreground execution | 1,411 s |
| Result | failed |

This failure proved two defects: batch workers waited for the slowest member
before polling again, and foreground GitHub transport retries had no total
deadline. The corrected architecture uses independent worker loops and a 5 s
foreground deadline with stale metadata fallback when available. The deployment
benchmark must produce the post-fix measurement before release succeeds.

The production gate after the worker/runtime fixes measured:

| Stage | `octocat/Hello-World` |
| --- | ---: |
| Queue API acceptance | 0.146 s |
| Queue wait | 2 s |
| Foreground execution | 2 s |
| Enqueue-to-fast-result | 4 s |
| Result | completed |

The post-fix local integration measurement used a fresh SQLite database, six
real worker loops, and the live GitHub API:

| Stage | `octocat/Hello-World` |
| --- | ---: |
| Queue API acceptance | 0.003 s |
| Queue wait | 0 s |
| Foreground execution | 1 s |
| Enqueue-to-fast-result | 1 s |
| GitHub metadata stage from worker log | 606 ms |
| Result | completed |

The same database was reopened after worker restart. `github_history_page`,
`commit_detail_manifest`, `nvd`, and `finalize` all reached `completed`, with
zero pending tasks. This proves checkpoint continuation for this run. The
repository has no qualifying security evidence, so the context evidence gate
correctly returned `error` instead of inventing an empty ready context.

That run also exposed a second bottleneck: a fixed reserve of 500 requests
blocked an anonymous 60-request GitHub quota forever. The effective reserve now
scales to the smaller of the configured reserve and 10% of the observed quota;
tests cover both authenticated 5,000-request and anonymous 60-request budgets.

Production rollout then exposed a third bottleneck: synchronous final report
classification could monopolize the async runtime while processing large commit
histories. Classification now runs in the blocking pool, and credentialed GitHub
requests are attempted before the anonymous fallback.

## Requirement-to-proof matrix

| Requirement | Deterministic proof | Production proof |
| --- | --- | --- |
| Queue accepts valid scans quickly | Handler/service tests | `accept_seconds <= 1` |
| One slow repo does not block other claims | Three concurrent cached jobs complete | `queue_wait_seconds <= 3` |
| Foreground work is bounded | Pending metadata future times out at configured deadline | `foreground_seconds <= 6` |
| Cache can preserve a partial result during upstream failure | Stale fallback timeout test | Report exposes `fast_ready/enriching` |
| Deploy does not erase jobs or reports | Reopen/recovery storage tests | Host-mounted DB survives container recreation |
| Duplicate enqueue is idempotent | Storage dedupe tests | Stable job ID for a pending repo/lane |
| Completed evidence is resumable | Lease/checkpoint/reopen tests | Queue stats retain completed partitions |
| Foreground and research work are separated | Lane-priority and evidence-task tests | Independent scan/evidence worker logs |
| Public errors contain no private upstream details | Sanitization tests | Public jobs omit `last_error`; Slack receives detail |
| Context cannot claim evidence that was not collected | Evidence-gate tests | Partial report remains `enriching/degraded` |
| Browser updates without page reload | SSE hook tests/manual browser trace | Event stream updates list and detail state |
| Artifacts and MCP follow their schemas | Golden envelope, route, and MCP tests | Smoke requests after deploy |

## Performance SLOs

The foreground SLO measures enqueue creation through terminal `scan_job`
completion. Background history and NVD completion are measured separately and
must never extend foreground duration.

| Metric | Gate | Target |
| --- | ---: | ---: |
| Queue API acceptance | <= 1 s | p95 <= 0.5 s |
| Queue wait with available capacity | <= 3 s | p95 <= 1 s |
| Foreground scan | <= 6 s | p95 < 5 s |
| Enqueue-to-fast-result total | <= 8 s | p95 < 5 s |
| Cached local fast path | < 500 ms | p95 < 100 ms |

Run a local or production benchmark:

```bash
BASE_URL=http://127.0.0.1:8000 \
CORPUS=octocat/Hello-World \
RUNS=3 \
scripts/benchmark_scan_pipeline.sh
```

The script writes a CSV and exits non-zero on a latency violation or failed
job. Production deployment runs one real benchmark after the worker and GitHub
connectivity checks. A deploy is not successful if this gate fails.

## Coverage policy

Coverage is a navigation tool, not a substitute for assertions. Priorities are:

1. Foreground scan deadlines, retries, cache and worker concurrency.
2. Storage claims, leases, dedupe, restart recovery and finalization.
3. Public route validation, sanitization, SSE and MCP contracts.
4. Evidence classification and context generation.
5. External-client status, timeout and rate-limit behavior through local mock
   servers; live tests are supplemental and credential-gated.
6. CLI and rendering paths.

Any module at 0% function coverage must either receive tests or be explicitly
removed as unreachable/dead functionality. Aggregate coverage may not be raised
by excluding production modules.

## Test result interpretation

- `passed` means the assertions executed and held for that commit.
- `ignored` live tests are not evidence; the main verification job must run the
  credentialed verification harness.
- A green unit suite without a successful production performance gate is not a
  release signal.
- A fast result with missing historical evidence is not a complete context. The
  state and missing evidence must remain visible in the API payload.
