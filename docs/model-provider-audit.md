# Model Provider and Guardrail Audit

This document records the maintained contract for optional LLM reasoning.
Models enrich explanations only after deterministic evidence collection; they
do not create CVEs, package identities, paths, commits, or score inputs.

## Required controls

- Structured JSON schemas reject unknown fields and invalid decision shapes.
- Evidence references must resolve to IDs supplied in the request.
- Claimed CVEs, paths, SHAs, and security identifiers must occur in input.
- Ecosystem and package identity must exactly match the deterministic result.
- Unsupported severity upgrades are rejected.
- Provider 429, timeout, quota, and availability failures produce an explicit
  unavailable/inconclusive result, never a synthetic quality score.
- A circuit breaker, retry budget, latency budget, and local daily budget bound
  provider usage.
- Production rejects free-only routes unless explicitly permitted.

## Model selection policy

The default model is selected by a reproducible labeled benchmark. Correctness
and unsupported-claim rate rank ahead of latency and cost. A model is promoted
only when it passes the grounding checks, beats or matches the deterministic
baseline on enough cases, and completes without systematic provider errors.

The July 2026 `model-quality-v2` run selected `openai/gpt-4.1-mini` as primary.
It tied `google/gemini-2.5-flash` on 12 labeled cases (83.3% classification,
66.7% severity agreement, zero unsupported claims), while being slightly
faster and materially cheaper. Gemini is the provider-diverse secondary.
GPT-4o mini scored 50% classification in the four-case screening round and was
not promoted. Any 429 or malformed response makes a run inconclusive.

`OPENROUTER_MODEL_PRIMARY` selects the primary route and
`OPENROUTER_MODEL_SECONDARY` selects a bounded fallback. Feature flags can
disable commit classification and ecosystem resolution independently.

## Production posture

Package/ecosystem resolution remains constrained to deterministic identity;
the model cannot substitute another package. Provider responses and keys are
never written to public errors. Telemetry records task, selected model,
outcome, latency, and rejection categories without recording credentials.

## Verification

Run the offline and live opt-in suites:

```bash
cd backend
cargo test -p ai-supply-chain-trust-llm
RUN_OPENROUTER_LIVE_TESTS=1 cargo run -p ai-supply-chain-trust-llm \
  --example quality_benchmark
```

Live tests require a locally supplied `OPENROUTER_API_KEY`. Never commit the
key, webhook URLs, raw provider failures, or benchmark output containing
request headers.
