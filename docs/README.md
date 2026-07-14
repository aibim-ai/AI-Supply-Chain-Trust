# Technical Documentation

This directory contains maintained system contracts. Historical audits and
implementation plans do not belong here; decisions that became code are
documented as current architecture, while unfinished work remains in issues.

| Document | Contract |
| --- | --- |
| [Architecture](architecture.md) | Scope, components, scan state machine, queues, data model, and failure boundaries |
| [API](api.md) | Public HTTP, artifact, SSE, and MCP interfaces |
| [Deployment](deployment.md) | Production topology, persistence, configuration, rollout, and recovery |
| [Data policy](data-policy.md) | Evidence provenance, partial results, cache rules, and public error policy |
| [Testing and performance](testing-and-performance.md) | Required test layers, proof matrix, coverage, benchmarks, and release gates |
| [Product positioning](marketing.md) | Audiences, messaging, launch content, and communication boundaries |
| [Model provider audit](model-provider-audit.md) | Model selection, grounding, reliability, and live-usage requirements |

## Sources of truth

- Routes and OpenAPI: `backend/crates/server/src/lib.rs`
- Scan orchestration: `backend/crates/service/src/lib.rs`
- Queue and persistent schema: `backend/crates/storage/src/lib.rs`
- Public report types: `backend/crates/models/src/`
- Production topology: `.github/deploy/production/`
- Browser routes and API calls: `frontend/src/`

Documentation changes must be verified against these sources in the same pull
request. Examples must not contain real credentials, production error details,
or claims that cannot be reproduced by a test or benchmark.
