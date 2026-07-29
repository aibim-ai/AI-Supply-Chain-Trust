# AI Repo Trust — Evidence-Based Product Audit

Audit date: 2026-07-27. Scope: current local worktree, local runtime, source, tests, one live public-repository evaluation. Production is out of scope: no production deployment, users, analytics, logs, or credentials were provided.

## 1. Executive Truth Report

| Item | Conclusion | Evidence |
|---|---|---|
| Product purpose | **VERIFIED.** Evidence-labelled trust context for public GitHub repositories. | `audit/2026-07-27-product-truth.md`; live `octocat/Hello-World` CLI evaluation |
| Intended users | Developers, security reviewers, coding agents, and operators. | UI/API/CLI entry points; product-truth map |
| Value delivered today | **PARTIALLY VERIFIED.** A real public repository yields a decision, score, coverage, and named evidence gaps. | `cargo run -p ai-supply-chain-trust -- eval octocat/Hello-World --json` |
| Main abandonment risks | Unsupported input previously looked queueable; optional result APIs could hide a good report; browser verification is missing; requester-level scan abuse controls need operational confirmation. | Regression tests; source trace; local runtime |
| Readiness | **USABLE FOR A LIMITED AUDIENCE.** Suitable for controlled evaluators who understand evidence limits, not unrestricted public reliance. | All evidence below |

Top blockers before a stronger verdict:

1. No deployed browser/mobile/accessibility end-to-end proof.
2. No production observability, rollout, rollback, or dependency-outage evidence.
3. `/api/v1/scan` rate policy is repository-keyed; deployment must enforce trusted requester-level limits.

## 2. Evidence-Based Feature Matrix

The detailed inventory is [2026-07-27-feature-inventory.md](2026-07-27-feature-inventory.md). This matrix covers the value-critical paths.

| Feature / route / area | Intended user outcome | Actual verified behavior | Evidence | Status | Severity | Decision / required action |
|---|---|---|---|---|---|---|
| GitHub identity intake | Submit an eligible public repo | GitHub `owner/repo` and GitHub URLs accepted; GitLab, Bitbucket, extra paths, malformed URLs rejected | `frontend/src/lib/repository.test.js`; `repository-search.test.js`; `HomePage.test.jsx` | VERIFIED | High, fixed | KEEP |
| CLI evaluation | Produce useful trust decision | Real `octocat/Hello-World` run returned D/low confidence and four evidence gaps | live CLI execution | VERIFIED | High | KEEP |
| Local SPA startup | Follow README Quick Start | `cargo run … serve` from `backend/` returns SPA shell | local `GET /` runtime check; CLI tests | VERIFIED | High, fixed | KEEP |
| Rescan queue | Persist safe background work | Valid jobs queue; capacity is atomically bounded; overflow returns `503 queue_full` | server/storage regressions; 10/11 live request check | VERIFIED | High, fixed | KEEP |
| Result view | Preserve decision under partial failure | Required report renders while history/intel failures degrade to empty optional panels | `ResultPage.test.jsx` | VERIFIED | High, fixed | KEEP |
| LLM classification | Add bounded supplemental review | Higher LLM severity is rejected; error body is capped at 1 MiB | LLM unit/integration tests | VERIFIED | Critical, fixed | KEEP as supplemental only |
| CORS configuration | Restrict cross-origin browser clients | Explicit canonical HTTPS origin receives grant; `null`, attacker, path/userinfo, and wildcard origins are rejected | `allowed_origins_parser_accepts_csv_and_rejects_invalid_headers`; local curl test | VERIFIED | High, fixed | KEEP |
| Context/scan browser path | Obtain and read security context | Source/tests cover route; real browser interaction not safely executed | `ContextPage.test.jsx`; browser limitation | PARTIALLY VERIFIED | High | E2E required |
| Operators/metrics/alerts | Diagnose and recover | APIs and worker tests exist; no deployed telemetry/alert evidence | server/service tests | UNVERIFIED | High | Stage operational drill |

## 3. Core Journey Test Report

| Journey | Preconditions | Steps executed | Expected / actual result | Evidence | Usability / recovery | Status |
|---|---|---|---|---|---|---|
| Screen a real public repository | Local CLI plus external public sources | `eval octocat/Hello-World --json` | Expected evidence-based decision. Actual: completed in ~5.5s, D/low confidence, action to complete missing evidence; four gaps surfaced. | CLI output captured during audit | Outcome is truthful because missing data lowers confidence; browser comprehension unverified. | VERIFIED |
| Reject wrong provider | Built frontend | Run repository and HomePage tests with GitLab/Bitbucket/malformed inputs | Expected no queue/navigation. Actual strict rejection and GitHub-only copy. | Frontend test suite | Clear recovery: provide GitHub owner/repo or GitHub URL. | VERIFIED |
| Queue bounded rescan | Local server, worker disabled, cap=10 | POST 11 distinct valid repos | Expected first ten queue, eleventh gets actionable capacity response. Actual `200` ×10, `503 {"code":"queue_full"…}` ×1, with atomic storage admission under concurrent regression. | Local runtime command; server/storage regression tests | Recovery is retry later; no cancellation UI proof. | VERIFIED |
| Read result during ancillary failure | Frontend test mocks | Report success; history and intelligence reject | Expected report stays visible. Actual report heading and `0 hits` render. | `ResultPage.test.jsx` | Avoids all-or-nothing failure. | VERIFIED |
| Cross-origin API access | Local server with allowlist | Request allowed, attacker, and `null` origins | Expected only canonical configured origin receives CORS header. Actual matched. | Local curl header check | Misconfiguration fails closed; operator must set explicit origin. | VERIFIED |
| Browser security context | Real browser / representative device | Not executed | Needed: queue → progress → ready context → refresh/retry/failure response. | No isolated browser surface was available; existing user Chrome session was deliberately not touched. | Browser proof remains absent. | UNVERIFIED |

## 4. Defect Backlog

| ID | Severity | Affected components | Reproduction / root cause | Impact | Minimal fix / regression | Status |
|---|---|---|---|---|---|---|
| AUD-001 | HIGH | CLI, static server | Start from `backend/`; prior CLI injected relative `frontend/web`, overriding server fallback. | Quick Start served `404`; product inaccessible locally. | Empty default lets server resolve bundled static dir; CLI tests and local `GET /`. | FIXED / VERIFIED |
| AUD-002 | HIGH | Home input, repository normalizer | Enter GitLab/Bitbucket or malformed URL; loose normalizer could form invalid path. | False expectation of a queued scan. | Strict GitHub-only parser plus tests. | FIXED / VERIFIED |
| AUD-003 | HIGH | Queue admission | Queue many distinct repos; a separate count-then-enqueue check could race. | Queue capacity could be exceeded under concurrent submitters. | SQLite `BEGIN IMMEDIATE` atomic admission; concurrent storage regression and 10/11 live test. | FIXED / VERIFIED |
| AUD-004 | HIGH | ResultPage | Make history/intel fail after report succeeds; `Promise.all` rejected whole page. | User loses valid decision. | Required report first; `Promise.allSettled` for ancillary data; UI regression. | FIXED / VERIFIED |
| AUD-005 | CRITICAL | LLM fact checker | Cite a commit ID while escalating severity. | Attacker-controlled commit text could be presented as `llm_verified` severity. | Reject all LLM upward severity changes; regression test. | FIXED / VERIFIED |
| AUD-006 | HIGH | LLM HTTP client | Upstream returns oversized non-2xx body; `resp.text()` was unbounded. | Memory pressure / service degradation. | Stream/cap non-success bodies; 1 MiB regression. | FIXED / VERIFIED |
| AUD-007 | HIGH | CORS config | Set `AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS`; old server always used `CorsLayer::permissive()`, and the first parser accepted `null`. | Documented origin policy was false; sandboxed opaque origins could receive a grant. | Strict canonical HTTP(S) parser/layer rejects `*`, `null`, paths, userinfo, query, and fragments; CLI flag is propagated; local origin test. | FIXED / VERIFIED |
| AUD-008 | HIGH | `/api/v1/scan`, `/api/v1/context`, `/mcp` | Rotate repository names to evade repository-keyed rate limit. MCP context creation now shares that limiter, but it is still repository—not requester—keyed. | Four foreground permits can be held; proxy/client attribution policy is incomplete. | Enforce requester-level limits at trusted edge or add trusted-proxy-aware application limiter; load test must prove attacker cannot monopolize permits. | OPEN |
| AUD-009 | MEDIUM | Context/results UI | Missing scanner/evidence sometimes maps to empty or neutral presentation. | User may read absence as clean evidence. | Add explicit unavailable/retry labels and test every unavailable panel. | OPEN |
| AUD-010 | MEDIUM | Home combobox | Keyboard/focus/ARIA needs real browser audit. | Assistive-tech and keyboard friction. | Add Playwright + axe tests and manual screen-reader pass. | OPEN |
| AUD-011 | MEDIUM | `/api` discovery document | `api_index` stated “rate-limited per IP” and hardcoded the production base URL. | Local/custom-domain API consumers receive false policy and URL information. | Correct wording, derive URL from server base URL, assert both in a server test. | FIXED / VERIFIED |

## 5. Code Health Report

| Category | Finding | Evidence / decision |
|---|---|---|
| Architecture | 4,856 indexed nodes, 53 route nodes, Rust service/storage/evaluator split plus React frontend. | `codebase-memory` architecture; understandable but server is a large concentration point. |
| Dead/unwired candidates | Usage value for leaderboard, `/pig`, feedback, analytics, regression/ops surfaces is unproven. | No production/user analytics supplied. **INVESTIGATE**, do not claim dead code. |
| Fake/placeholder risk | Live evaluation was real and explicitly reported gaps; no fake success found in audited core path. | CLI output and evidence tests. |
| Contradictions fixed | Static web-dir default, provider support, atomic queue capacity, LLM severity, LLM error cap, strict CORS configuration, API discovery claims. | AUD-001…007, AUD-011. |
| Dead code removed | The standalone Rust `render` crate had no production caller; every exported renderer was reached only from its own tests while the server serves the built SPA. | Graph inbound traces plus `rg ai_supply_chain_trust_render`; crate and unused dependencies removed; full workspace regression passed. |
| High-risk debt | `server/src/lib.rs` owns routing, auth checks, worker startup, CORS, rate logic, and handlers. | Complexity/ownership review. Split only when behavior tests protect boundaries. |
| Recommended simplification | Deprecate any unowned `/pig`/leaderboard/analytics surface after usage study; avoid expanding worker/API surface before E2E coverage. | Product-value rule. |

## 6. UX Review

| Area | Evidence-based observation | Recommendation |
|---|---|---|
| Immediate comprehension | Home path is a public-GitHub repository screen; result exposes action, grade, coverage, flags. | Keep this decision-first hierarchy. |
| Misunderstanding risk | Evidence unavailable can resemble no findings; trust scores can be over-read. | Put coverage/unavailable state beside every consequential score and recommendation. |
| Error/recovery | Unsupported provider and queue capacity now give concrete recovery. | Add retry timing and queue-position/next-step copy where feasible. |
| Partial failure | Result report survives optional request failure. | Mark affected panels “unavailable,” not merely empty. |
| Accessibility | Source tests exist, but no browser keyboard/focus/screen-reader proof. | Block general release on keyboard + axe + manual accessibility pass. |
| Responsive/slow network | Not runtime-tested. | Add representative mobile and network-throttle E2E tests. |

## 7. Security and Privacy Review

Threat-focused checks used OWASP ASVS as a reference, tailored to public-repository analysis. Official reference: <https://owasp.org/www-project-application-security-verification-standard/> (accessed 2026-07-27).

| Threat / control | Result | Evidence / limitation |
|---|---|---|
| Repository input, path traversal | VERIFIED for audited handlers | Repository validation and static traversal tests |
| Public error leakage | VERIFIED for scan failure | `public_scan_failure_hides_upstream_diagnostics` |
| LLM prompt/grounding influence | FIXED | AUD-005; guardrail regression and red-team tests |
| Upstream response resource exhaustion | FIXED | AUD-006 oversized error-body test |
| CORS | FIXED | AUD-007 local allowed/rejected-origin test |
| Queue resource exhaustion | FIXED for queued rescans | AUD-003 atomic admission; direct foreground work still needs client limits |
| Independent challenge review | Three high-risk objections found; two fixed, one narrowed but remains open | Strict CORS parser, atomic queue admission, MCP context creation now shares repository throttle; AUD-008 remains open |
| Auth/object authorization | PARTIALLY VERIFIED | Worker-token and auth unit tests; no multi-user/tenant/product deployment model supplied |
| Client privacy/analytics | UNVERIFIED | No production consent/retention/processor evidence |
| Dependency health / SCA | UNVERIFIED | No lockfile vulnerability scan performed in this audit |

## 8. Test Coverage Plan

| Missing test | Risk | Required acceptance criterion |
|---|---|---|
| Browser core E2E: home → scan → context → result | Critical usability | A first-time keyboard user completes a public-repo decision, sees truthful progress/gaps, refreshes safely, and recovers from error. |
| Requester-rate load test | High abuse | A single unauthenticated actor cannot monopolize all foreground permits by rotating repos; honest traffic remains serviceable. |
| Trusted-proxy deployment test | High | With configured proxy, real client identity—not spoofable headers—is rate-limited. |
| Worker restart / Postgres integration | High reliability | Pending, running, retryable, and failed work preserves correct state across restart and concurrent workers. |
| External-adapter outage tests | High correctness | GitHub/OSV/NVD/OpenRouter timeout/rate-limit causes explicit coverage degradation, not false clean evidence. |
| Accessibility suite | Medium | Keyboard, focus, labels, contrast, and axe have no serious violations on Home/Context/Result pages. |
| Security dependency scan | Medium | Lockfiles have no untriaged critical dependency vulnerability. |

## 9. Change Log

| Files | Why / behavior | Validation | Remaining risk |
|---|---|---|---|
| `backend/bin/ai-supply-chain-trust/src/main.rs`, `backend/crates/cli/src/lib.rs` | Correct bundled web-dir resolution. | CLI tests; local SPA `200`. | Production packaging unverified. |
| `frontend/src/lib/repository*.js`, `HomePage.jsx` | Reject unsupported providers/malformed identity early. | Targeted + full frontend tests. | Browser accessibility unverified. |
| `backend/crates/server/src/lib.rs`, `backend/crates/storage/src/lib.rs`, `backend/crates/service/src/lib.rs`, `env.example` | Atomically bound queue; make CORS strict/fail closed; apply repository throttle to MCP context creation. | 22 server + 34 storage tests; local queue/CORS requests. | Direct foreground requester controls open. |
| `backend/crates/server/src/lib.rs`, CLI main | Make API admission-control and base-URL claims truthful; propagate explicit CORS CLI configuration. | `api_index_describes_actual_admission_controls`; CLI tests. | Requester-level limit still open. |
| `backend/crates/llm/src/fact_checker.rs`, `llm_client.rs` | Prevent LLM severity elevation; cap error bodies. | 24 unit + 6 integration LLM tests. | Model/service policy needs production monitoring. |
| `frontend/src/pages/ResultPage.*`, `frontend/web/assets/js/app.js` | Preserve report under ancillary failure; rebuild deployed asset. | Result test, lint, build, full frontend suite. | Unavailable-state wording still needs work. |
| `backend/crates/render/**`, workspace/dependent `Cargo.toml` files | Remove confirmed duplicate, unused SSR renderer. | `cargo test --workspace --all-targets` passed after removal. | If SSR becomes a product requirement, design one owned renderer rather than restoring this parallel path. |

## 10. Final Verdict

### Classification: **USABLE FOR A LIMITED AUDIENCE**

Proven: strict repository intake; local static startup; live public repository evaluation; bounded rescan queue; result resilience; LLM boundary controls; configured CORS behavior; runnable Rust and frontend suites.

Not proven: deployed browser/mobile UX, screen-reader behavior, production operation/alerting, Postgres live behavior, GitHub-token integration tests, multi-user authorization model, dependency-health scan, and trusted requester-level rate limiting.

Before real users should rely on it broadly:

1. Implement and load-test trusted requester-level scan admission at the deployment edge.
2. Run browser accessibility/responsive E2E against a staging deployment.
3. Run an operational drill: external dependency outage, queue restart, alerts, rollback, and Postgres persistence.
