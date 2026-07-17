# Product Marketing Context

*Last updated: 2026-07-16*

> Research status: repository evidence, live production metrics, current competitor pages, proxy reviews, community discussions, and an OpenRouter/Perplexity discovery pass were reviewed on 2026-07-16. Facts are distinguished from hypotheses. Proxy customer language must be replaced with first-party interviews and feedback as it becomes available.

## Product Overview

**One-liner:** Evidence-backed security context for open-source repositories and coding agents.

**What it does:** AI Supply Chain Trust evaluates public GitHub repositories across eight trust and security pillars using live, traceable evidence. It produces an explainable 0–100 trust score, A–F grade, evidence coverage, missing-evidence warnings, known CVEs and security-fix history, and prioritized regression-review leads. Results are available as hosted public pages, REST, MCP, CLI, JSON, and Markdown.

**Product category:** Repository trust assessment and software supply-chain security. The sharper subcategory is **pre-adoption repository due diligence for humans and coding agents**.

**Product type:** Free hosted web utility plus MIT-licensed, self-hostable open-source software.

**Business model:** The hosted scan and source code are currently free. No paid tier or commercial pricing is documented. Future sponsorship, private-repository, managed hosting, or enterprise-policy offerings are possibilities—not current commitments.

**Current stage:** Very early public launch. The GitHub repository was created 2026-07-14 and had 0 stars, 0 forks, and one public contributor when checked on 2026-07-16. Production usage predates or exceeds repository adoption signals.

## Target Audience

**Primary wedge:** Security-conscious developers, coding-agent builders, AppSec engineers, and DevSecOps/platform engineers who must decide whether a public GitHub repository is suitable to inspect, install, fork, or introduce into a workflow.

**Target companies:** Software and AI product companies from startup through mid-market, especially organizations adopting coding agents or formalizing third-party/open-source review. Enterprise security teams are a secondary expansion segment until private-repository scanning, organization policy, identity, and compliance workflows mature.

**Decision-makers:** AppSec or Product Security lead, Head/VP of Engineering, Platform Engineering lead, DevSecOps lead, or CISO for higher-risk adoption.

**Primary use case:** Run a bounded, reproducible pre-adoption review of a public repository and obtain the evidence, uncertainty, and next review steps needed for a human or coding agent to proceed safely.

**Jobs to be done:**

- Decide whether a public repository deserves further review before it enters a workflow.
- Give a coding agent repository-specific security context without letting an LLM invent evidence.
- Replace fragmented GitHub, OSV, NVD, advisory, and history research with one reusable artifact.
- Identify the small set of security fixes, CVEs, components, and recurring risk classes that deserve attention first.
- Share an auditable public context through a URL, JSON, Markdown, REST, MCP, or CLI.

**Use cases:**

- Pre-install or pre-fork public repository review.
- Third-party OSS intake and open-source review board triage.
- Coding-agent/MCP security context before an agent acts on unfamiliar code.
- Security-history and regression-risk review before modifying sensitive components.
- Maintainer-facing public security posture and evidence-gap review.
- Batch or automated review through REST, MCP, and CLI.

## Personas

| Persona | Role in journey | Cares about | Challenge | Value we promise |
|---|---|---|---|---|
| Security-conscious developer / agent builder | Primary user | Fast, concrete pre-install guidance | Cannot manually inspect every unfamiliar repo or transitive dependency | Paste a repo and receive a bounded decision, evidence gaps, and review leads |
| AppSec / Product Security engineer | User and champion | Signal quality, provenance, prioritization, auditability | Scanners create noise and repository research is fragmented | Evidence-linked findings, explicit uncertainty, deterministic rules, and reusable artifacts |
| Platform / DevSecOps engineer | Champion and technical influencer | Automation, policy integration, agent guardrails | Security review does not fit naturally into delivery or agent workflows | REST, MCP, CLI, JSON/Markdown, public contexts, and versioned scoring |
| Engineering or Security leader | Decision maker / future buyer | Consistency, risk ownership, adoption speed | Approval decisions vary between teams and are hard to defend | A common review language with grades, confidence, evidence coverage, and recommended action |
| Open-source maintainer | Secondary user | Credibility and actionable project hardening | Popularity does not prove trust and gaps are hard to communicate | A shareable evidence-backed profile and prioritized missing signals |

**Persona confidence:** Medium. Roles and jobs recur across official guidance, competitor positioning, G2 reviews, and community discussions, but AI Supply Chain Trust has no first-party interview corpus yet.

## Problems & Pain Points

**Core problem:** Public repositories are increasingly selected or acted upon faster than people can investigate them, while the evidence needed for a trustworthy decision is fragmented, incomplete, and difficult to pass into coding-agent workflows.

**Why alternatives fall short:**

- Popularity signals such as stars are not security or trust evidence.
- OpenSSF Scorecard measures security-health heuristics, not the full adoption decision.
- SCA and package-security products concentrate on dependencies, malware, reachability, and policy enforcement rather than a shareable public repository security context.
- Local static analyzers can be deep but require installation, cloning, and operator time.
- Generic LLM summaries may blur observed evidence and inference.
- Point tools rarely combine hosted public pages, progressive history enrichment, regression leads, REST, MCP, CLI, and portable artifacts.
- Missing data is often easy to misread as “nothing found.”

**What it costs them:** Manual research time, duplicated review work, slow approvals, alert fatigue, inconsistent decisions, weak audit trails, and increased exposure to compromised, abandoned, misleading, or poorly governed repositories.

**Emotional tension:** “I need to move quickly, but I cannot defend a decision based on stars, a clean-looking README, or an opaque score.”

## Competitive Landscape

### Direct competitors

- **Repository Trust Doctor** — the closest functional open-source competitor. It offers broad local static analysis, risk profiles, CLI/API/local React workbench, CI gates, JSON/Markdown/SARIF, report diffs, and explicit missing evidence. It is stronger for deep local repository analysis and CI policy; AI Supply Chain Trust is differentiated by zero-install hosted public contexts, live historical enrichment, REST/MCP delivery, public shareability, and regression leads.
- **Repo Trust** — free Apache-2.0 Rust CLI/local viewer with a five-dimensional explainable score covering star authenticity, activity, maintainers, adoption, and security. It is stronger on fake-star, adoption, and maintainer concentration signals; AI Supply Chain Trust is stronger on hosted service delivery, vulnerability/security history, public contexts, MCP/REST, AI/MCP and model-specific pillars, and durable background enrichment.
- **Codebase Archaeologist and similar emerging repo-dossier tools** — bounded pre-install trust reads for public repositories, especially agent surfaces. They validate the category but currently show narrower delivery and proof depth.

### Secondary competitors

- **OpenSSF Scorecard** — established open-source security-health scoring with a CLI, GitHub Action, JSON, API-backed public data, and web viewer. It is a trusted input and ecosystem standard rather than a product to attack; AI Supply Chain Trust should position as an evidence-context layer that incorporates and extends Scorecard.
- **Socket** — developer-first commercial supply-chain platform with behavioral malware analysis, package blocking, reachability, GitHub/IDE/MCP integrations, threat intelligence, and a free tier. Stronger at proactive package enforcement, commercial maturity, and threat coverage; not focused on free public repository decision artifacts and historical regression context.
- **Endor Labs** — enterprise AppSec platform spanning reachability-based SCA, SAST, secrets, malware, agent governance, SBOM/VEX, policies, and remediation. Stronger for enterprise application security and private code workflows; heavier and sales-led relative to a free public-repo review utility.

### Indirect competitors

- Manual GitHub/advisory/OSV/NVD research and security checklists.
- GitHub stars, last-commit date, maintainer reputation, and README quality used as shortcuts.
- Generic SCA/SAST tools, SBOM platforms, vulnerability databases, and GitHub-native security features.
- “Do nothing” or allow coding agents to select/install repositories without a dedicated trust gate.

See [`competitor-profiles/_summary.md`](../competitor-profiles/_summary.md) for the dated comparison.

## Differentiation

**Defensible differentiators:**

- Hosted, public, cacheable repository security contexts with no account required for the core scan.
- Evidence-gated architecture: missing evidence lowers confidence and cannot become a clean bill of health.
- LLM output cannot create security evidence or directly change a score.
- Historical security-fix and CVE context plus prioritized regression-review leads.
- One product surface across web, REST, MCP, CLI, JSON, and Markdown.
- Eight-pillar framework includes publisher credibility, repository health, OpenSSF, code/dependency safety, model/artifact integrity, supply-chain attack prediction, publisher identity, and AI/MCP risk.
- Fast initial result separated from durable, checkpointed evidence enrichment.
- MIT-licensed Rust implementation that can be self-hosted.

**How we do it differently:** We treat a repository as an evidence object for an adoption or agent decision—not only as a dependency manifest, static-code target, or set of best-practice checks. Observed evidence, coverage, uncertainty, decision policy, and review leads remain separate and inspectable.

**Why that's better:** A user can start in seconds, understand what is known and missing, share the result with a teammate or agent, and begin manual review at the most relevant historical risk rather than assembling context from multiple tools.

**Why users choose us:** Zero-install public scans; explicit uncertainty; agent-ready delivery; historical regression context; shareable artifacts; and open-source transparency.

**Claims not to make:** “Only product with MCP,” “complete supply-chain coverage,” “replaces SCA/SAST,” “certified safe,” “vulnerability free,” or “enterprise-ready” without further product proof.

## Objections

| Objection | Response |
|---|---|
| “A single score oversimplifies security.” | The score is only a navigation aid. Every decision includes pillar results, reasons, evidence coverage, missing evidence, confidence, and a recommended next step. |
| “A public metadata scan cannot prove a repo is safe.” | Correct. The product makes no safety guarantee; it identifies evidence, gaps, known history, and where review should begin. |
| “We already use Scorecard, Snyk, Socket, or Endor Labs.” | Keep them. AI Supply Chain Trust is the lightweight repository-context and agent-delivery layer; it complements specialist scanners and explicitly consumes OpenSSF evidence. |
| “The results may be stale or incomplete.” | Reports expose evaluation time, coverage, state, missing sources, and progressive enrichment. Stale or unavailable evidence is labeled rather than silently reused as proof. |
| “We cannot expose private code.” | The hosted product is intentionally scoped to public repositories. Self-hosting is available, but private-repository support is not currently promised. |
| “Why trust the scoring model?” | The rules, weights, evidence sources, versioning, tests, and source code are inspectable. LLM output cannot directly set scores. |

**Anti-persona:** Buyers needing an immediate enterprise SCA replacement, private monorepo coverage, compliance certification, malware sandboxing, binary analysis, exploit generation, real-time package blocking, or a guarantee that software is secure.

## Switching Dynamics

**Push:** Alert fatigue; fragmented repository research; recent supply-chain incidents; an unfamiliar repo selected by a coding agent; inconsistent OSS approval; inability to explain why a repository was allowed.

**Pull:** Free instant scan, public URL, explicit missing evidence, evidence-linked context, ranked review leads, MCP/REST delivery, no invented evidence, and self-hostability.

**Habit:** Existing scanner dashboards, manual checklists, GitHub-native alerts, star-count heuristics, and security reviews performed only after adoption.

**Anxiety:** False confidence, false positives, public visibility of scans, GitHub/API rate limits, incomplete sources, another dashboard to maintain, and uncertainty about whether the score maps to internal policy.

**Likely trigger events:**

- A developer or agent proposes a new public repository or package.
- A supply-chain compromise makes leadership revisit intake controls.
- An AppSec team needs to reduce manual triage or scanner noise.
- A customer, auditor, or open-source review board asks for evidence behind an adoption decision.
- A team introduces coding agents, MCP servers, plugins, or skills with repository access.

## Customer Language

**First-party status:** No public AI Supply Chain Trust reviews or customer interviews were found. The following are proxy phrases from adjacent users and should be treated as hypotheses.

**How the market describes the problem:**

- “No one has the time to review every single line of code” — developer community discussion.
- “Reducing false positives and noise” — Endor Labs reviewer describing the desired outcome.
- “Better decisions, faster” — Socket reviewer describing repository/dependency risk value.
- “Can we use this in production?” — direct-competitor framing.
- “What should we fix first?” — direct-competitor framing.
- “Where do you draw the line between agent can suggest and agent can execute?” — platform-engineering community concern.

**How to describe us:**

- Evidence-backed security context for open-source repositories and coding agents.
- Know what supports a repository before you let a person or agent use it.
- Paste a public repo. See the evidence, the gaps, and where review should start.
- A trust score that shows its work.

**Words to use:** evidence-backed, traceable, bounded, explainable, security context, review lead, live evidence, evidence coverage, missing evidence, public repository, agent-ready, reusable, review aid, regression risk.

**Words to avoid:** certified safe, guaranteed secure, vulnerability-free, complete coverage, autonomous approval, AI-powered proof, perfect accuracy, zero false positives.

**Glossary:**

| Term | Meaning |
|---|---|
| Security context | Structured repository history, risks, evidence, uncertainty, and review guidance for a person or coding agent |
| Trust score | Weighted 0–100 assessment across eight evidence pillars |
| Trust grade | A–F classification derived from the score and policy signals |
| Evidence coverage | Portion of expected evidence that was available and evaluated |
| Review lead | Evidence-backed starting point for deeper manual or agent-assisted investigation |
| Regression contract | Versioned review constraint derived from prior fixes or risks to prevent recurrence |
| Policy block | Critical signal that forces grade F regardless of the numeric score |
| Fast result | Initial evaluation published before deeper evidence enrichment completes |
| Evidence enrichment | Durable background collection and analysis of history, advisories, and vulnerability data |
| Provenance Channel | Brand concept showing live evidence passing through verification stages into an evaluated artifact |

## Brand Voice

**Tone:** Calm, rigorous, candid, professional, and security-conscious.

**Style:** Direct and technical but readable. Lead with the decision, immediately show evidence and uncertainty, and avoid fear-based marketing or absolute claims.

**Personality:** Trustworthy, pragmatic, transparent, restrained, and agent-aware.

**Voice examples:**

- Prefer: “Four evidence gaps lower confidence; review these two historical risk areas first.”
- Avoid: “AI confirms this repository is safe.”
- Prefer: “Eligible for standard review.”
- Avoid: “Approved and secure.”

## Proof Points

**Live product metrics captured 2026-07-16:**

- 1,387 scans across 319 unique repositories.
- 4,183 generated regression contracts.
- 18,602 recorded decisions: 18,510 rule-based, 9 LLM-verified, and 83 deterministic fallbacks when LLM service was unavailable.
- Latest 100 ready reports contained 503 security fixes and 2,403 CVE references across the sample; 27 had at least one CVE and 70 had at least one historical fix.
- Latest 100 grade mix: 7 A, 52 B, 36 C, 4 D, and 1 F/policy block.
- Latest 100 reports averaged 47% evidence coverage, which is a product limitation and proof that the UI currently exposes incomplete evidence rather than hiding it.

**Technical proof:**

- Eight versioned scoring pillars.
- Production evidence states enforced in Rust types and builders.
- Web, REST, MCP, CLI, JSON, and Markdown surfaces.
- A 15-crate Rust workspace with deterministic scoring and guardrail tests.
- Checkpointed evidence workers, durable events, explicit partial/degraded states, bounded public errors, and rate limiting.
- Project entry points in 23 languages.

**Customers:** No verified customer logos.

**Testimonials:** No first-party testimonials. Do not reuse competitor or community quotations as product testimonials.

**Value themes:**

| Theme | Proof |
|---|---|
| Evidence integrity | LLM output cannot create evidence or directly change scores; 99%+ of recorded decisions are deterministic rules |
| Honest uncertainty | Missing evidence is labeled; the current 47% sample coverage is not presented as complete |
| Agent readiness | Native MCP plus JSON/Markdown/REST artifacts |
| Historical context | Security fixes, CVEs, affected components, review leads, and regression contracts |
| Reusability | Hosted public URLs and portable machine/human-readable outputs |
| Open deployment | MIT-licensed source, CLI, Docker, and self-hosting path |

## Goals

**Primary business goal:** Establish AI Supply Chain Trust as the default public-repository evidence and security-context layer used before a developer or coding agent adopts unfamiliar open-source code.

**Key conversion action:** Scan a public repository for free.

**Activation event:** User reaches a ready repository context and inspects at least one evidence gap, historical fix/CVE, or review lead.

**Secondary conversions:** Copy/use MCP endpoint, download or consume JSON/Markdown, share a public context URL, return for another repository, self-host, provide feedback, or contribute on GitHub.

**Current metrics:** 1,387 scans and 319 unique repositories as of 2026-07-16. Google Analytics and PostHog are installed, but unique visitors, scan-submit conversion, result-view completion, repeat usage, MCP calls, artifact downloads, feedback volume, and retention are not available in the repository.

**Recommended next measurement set:**

- Visitor → valid repository selected → scan queued → ready context viewed.
- Time to fast result and time to complete evidence.
- Evidence-section and review-lead engagement.
- Public context shares, JSON/Markdown downloads, API/MCP calls.
- Repeat repositories per user/session and 7/30-day return rate.
- Feedback themes and “decision changed because of this context” rate.

## Research Sources and Confidence

**High-confidence sources:** repository architecture and tests; live production metrics/API; GitHub API; official OpenSSF, Socket, and Endor Labs product/pricing documentation.

**Medium-confidence sources:** G2 proxy reviews, current developer community discussions, adjacent regulatory/industry guidance, and direct-competitor documentation.

**Low-confidence / hypotheses:** willingness to pay, exact company-size sweet spot, primary buyer, future monetization, and first-party emotional language. Validate these with 8–12 interviews split between developers/agent builders and AppSec/platform engineers.

**Research links:**

- Product: https://ai-supply-chain-trust.aibim.ai/
- Source: https://github.com/aibim-ai/AI-Supply-Chain-Trust
- OpenSSF Scorecard: https://openssf.org/scorecard/
- Repo Trust: https://github.com/Dmitrze/repo-trust
- Repository Trust Doctor: https://github.com/Wezylnia/repo-trust-doctor
- Socket: https://socket.dev/ and https://socket.dev/pricing
- Endor Labs: https://www.endorlabs.com/pricing
- NSA MCP guidance: https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/
- Stack Overflow 2025 AI survey: https://survey.stackoverflow.co/2025/ai
