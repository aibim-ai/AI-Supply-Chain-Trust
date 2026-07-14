# Product Positioning

AI Supply Chain Trust evaluates public GitHub repositories using live,
traceable evidence. It produces an explainable trust score, an A–F grade,
evidence coverage, known security history, and prioritized review leads for
people and coding agents.

## Value proposition

See how much evidence supports a repository before you add it to a workflow,
and learn where a security review should start. Results are available through
the web interface, JSON and Markdown artifacts, REST, MCP, and the CLI.

## Intended users

- Application-security teams screening third-party repositories.
- Platform and DevSecOps teams integrating repository review into delivery.
- AI-agent developers that need structured, repository-specific context.
- Maintainers sharing an evidence-backed public security profile.

## Product principles

1. Missing evidence is never presented as absence of risk.
2. LLM output cannot create security evidence or directly change a score.
3. Every published claim is tied to source data, a commit, an advisory, a CVE,
   or a versioned deterministic rule.
4. Fast initial results and durable background enrichment are separate stages.
5. Public errors do not expose provider responses, credentials, or internals.

## Current boundaries

The production pipeline uses GitHub metadata and history plus advisory, OSV,
and NVD data. CLI scanner adapters exist for several third-party tools, but a
scanner is not claimed as production evidence unless its result is connected
to the web/API evaluation. AI/MCP and model-integrity pillars are reported as
unavailable when live detection evidence is absent.

## Messaging

Primary description:

> Evidence-backed security context for open-source repositories.

Primary call to action: **Scan a repository for free.**

Avoid claims such as “certified safe,” “vulnerability free,” or “complete
coverage.” A trust score is a review aid, not a security guarantee.

## Public launch checklist

- Keep the product name, repository URL, and domain consistent.
- Publish reproducible examples without embedding credentials.
- Clearly label partial, unavailable, degraded, and inconclusive outcomes.
- Link security reporting, contribution, license, and data-policy documents.
- Demonstrate API and MCP integrations with bounded, non-destructive examples.
