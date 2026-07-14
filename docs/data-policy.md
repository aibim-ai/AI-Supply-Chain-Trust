# Data and Evidence Policy

## Provenance

Trust reports and security contexts may use only evidence fetched from the
repository, GitHub REST, OSV, NVD, configured scanners, and deterministic local
derivations. The service must not copy or fill gaps from another security-context
product.

Every published fact must be traceable to stored source payloads, a commit SHA,
an advisory/CVE identifier, scanner output, or a deterministic rule version.
LLM output is optional annotation and cannot create evidence.

## Partial results

The foreground result intentionally contains repository metadata and a
deterministic evaluation before historical evidence is complete. It must use:

- `observed_metrics.scan_state = "fast_ready"` while background work is pending;
- `verification_status = "enriching"` for incomplete evidence;
- explicit `missing_evidence`, `confidence`, and evidence coverage;
- zero/empty evidence collections only as "not collected yet" or "not found in
  completed sources", never as proof that no vulnerability exists.

The security context becomes `ready` only after its evidence gate and required
progressive tasks are terminal. Exhausted sources produce a degraded/error state,
not a silently complete report.

## Cache policy

`source_cache` stores payload, source, ETag, Last-Modified, and expiry. Cache use
has two modes:

1. Fresh cache: canonical input for the fast result.
2. Stale repository metadata: allowed only when the foreground GitHub call fails
   or reaches its total deadline. The result remains partial and background work
   must refresh it.

Stale metadata may not create fix commits, advisories, CVEs, or scanner results.
Immutable commit-detail payloads may be reused by SHA.

## Evidence gate

`VerifiedEvidenceBuilder` requires at least one concrete evidence class before a
ready context can be constructed:

- a valid commit SHA;
- advisory or OSV/CVE evidence; or
- an available scanner run.

Version mismatch and empty evidence are errors. Tests cover each accepted and
rejected state. The gate is necessary but not sufficient for completeness;
progressive task state also controls whether the public context is ready.

## Failure policy

External failures are classified internally (for example rate limit, timeout,
unauthorized, or not found), checkpointed where applicable, and sent to the
operations webhook after retry exhaustion.

Public APIs expose stable state and error codes but remove upstream URLs,
credentials, raw provider messages, and retry controls. The browser must not show
private diagnostic text. Logs and Slack payloads must never contain token values.

## LLM policy

LLM tasks receive only supplied evidence and a versioned task contract. Output is
accepted only after deterministic fact checking of CVE IDs, SHAs, paths, severity
changes, and evidence references. Rejected output cannot affect the score,
context, or leads. Runtime source-boundary checks prohibit ad hoc model calls
outside `backend/crates/llm`, and hallucination guard tests run in CI.

## Retention and deployment

Reports, jobs, evidence checkpoints, cache entries, events, and operational
alerts are stored in the persistent database. Production deployment sync excludes
the host data directory and container recreation mounts the same path. Retention
or deletion must be an explicit operational action; deployment is never a data
reset mechanism.
