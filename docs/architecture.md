# Architecture

## Product scope

AI Supply Chain Trust evaluates public source repositories and publishes two
related outputs:

1. A trust decision with score, grade, evidence coverage, missing evidence, and
   recommended action.
2. A security context for coding agents: prior security fixes, disclosed CVEs,
   recurring risk classes, affected components, and regression-review leads.

The service is not a source-code hosting proxy, malware sandbox, exploit
generator, or guarantee that a repository is safe. A fast result is explicitly
partial until historical and vulnerability evidence completes.

## System context

```mermaid
flowchart LR
    User[Developer or coding agent]
    Edge[Edge Nginx]
    Web[React SPA]
    API[Rust API]
    Worker[Foreground and evidence workers]
    DB[(Persistent SQLite / PostgreSQL)]
    GH[GitHub REST]
    OSV[OSV]
    NVD[NVD]
    Slack[Slack alert webhook]

    User -->|HTTPS UI, REST, MCP| Edge
    Edge --> Web
    Edge --> API
    API --> DB
    Worker --> DB
    DB -->|durable trust events| API
    API -->|SSE resume stream| User
    Worker --> GH
    Worker --> OSV
    Worker --> NVD
    Worker --> Slack
```

## Production containers

```mermaid
flowchart TB
    Internet --> Nginx[nginx: TLS and routing]
    Nginx --> Frontend[frontend: static SPA]
    Nginx --> Backend[backend: API only]
    Backend --> Volume[(legacy host path /opt/ai-repo-trust/data)]
    Worker[worker: queue and evidence loops] --> Volume
    Worker --> Upstream[GitHub / OSV / NVD]

    subgraph Private Docker networks
      Frontend
      Backend
      Worker
    end
```

Only Nginx publishes host ports. The API container has background workers
disabled. The worker container shares the persistent database volume and runs
independent foreground workers plus source-specific evidence workers.

## Backend modules

| Crate | Responsibility | May perform network I/O |
| --- | --- | --- |
| `models` | Serializable domain contracts | No |
| `scoring` | Grade and weighted score rules | No |
| `evaluator` | Eight-pillar deterministic evaluation | No |
| `github_metadata` | Canonical repository and owner metadata | GitHub |
| `intelligence` | Advisories, history, OSV, and NVD evidence | GitHub, OSV, NVD |
| `security_context` | Evidence gate, fingerprints, risks, leads, artifacts | No |
| `storage` | Reports, queues, leases, cache, events, alerts | Database |
| `service` | Scan orchestration and progressive finalization | Through clients |
| `server` | HTTP, SSE, MCP, validation, public error boundary | No direct evidence calls |
| `scanner_runner` | Optional external scanners | Local processes |
| `render` | Server-rendered artifact helpers | No |
| `auth` | Worker/admin bearer verification | No |
| `discovery` | Repository discovery | GitHub and registries |
| `cli` | Command-line parsing | No |

```mermaid
flowchart LR
    server --> service
    server --> auth
    server --> render
    service --> github_metadata
    service --> intelligence
    service --> evaluator
    service --> security_context
    service --> scanner_runner
    service --> storage
    evaluator --> scoring
    evaluator --> models
    intelligence --> models
    security_context --> models
```

## Interactive scan lifecycle

The interactive queue and research/evidence work are separate. Foreground
workers only claim `scan_jobs`; source-specific workers claim `evidence_tasks`.
A slow history or NVD task cannot occupy a foreground worker.

```mermaid
sequenceDiagram
    participant UI as Browser / API client
    participant API
    participant DB
    participant FW as Foreground worker
    participant GH as GitHub metadata
    participant EW as Evidence workers

    UI->>API: POST /api/v1/queue/rescan
    API->>DB: enqueue foreground scan_job
    API-->>UI: job_id, queued
    FW->>DB: atomic claim
    FW->>GH: repository metadata (5 s foreground deadline)
    alt fresh or stale cache is usable
      FW->>DB: persist fast_ready report
      FW->>DB: complete job and enqueue evidence DAG
      FW->>DB: publish durable scan_fast_ready event
      DB-->>API: poll events after cursor
      API-->>UI: SSE scan_fast_ready
      EW->>DB: claim durable evidence partitions
      EW->>DB: checkpoint pages/items
      EW->>DB: merge and publish complete report
      EW->>DB: publish durable scan_complete event
      DB-->>API: poll events after cursor
      API-->>UI: SSE scan_complete
    else no metadata before deadline
      FW->>DB: fail job with private diagnostic
      FW-->>UI: public failed state
      FW->>DB: enqueue Slack notification
    end
```

## State machine

```mermaid
stateDiagram-v2
    [*] --> queued
    queued --> running: foreground worker claims
    running --> fast_ready: metadata + evaluation persisted
    running --> failed: deadline / invalid repo / storage failure
    fast_ready --> enriching: evidence tasks scheduled
    enriching --> enriching: page or item checkpoint completed
    enriching --> complete: required evidence terminal + finalize
    enriching --> degraded: retry budget exhausted
    failed --> queued: private operator retry
    degraded --> queued: private operator retry
```

Public UI states are `queued`, `running`, `enriching`, `ready`, and `failed`.
Detailed upstream errors and retry controls are private and delivered to the
configured operations webhook.

## Evidence DAG

```mermaid
flowchart LR
    Core[repository metadata] --> Fast[fast evaluation]
    Fast --> PublishFast[publish fast_ready]
    PublishFast --> History[GitHub history pages]
    PublishFast --> NVD[NVD enrichment]
    History --> Manifest[commit detail manifest]
    Manifest --> Details[bounded commit details]
    History --> Finalize{required sources terminal?}
    NVD --> Finalize
    Details --> Finalize
    Finalize -->|yes| Complete[re-evaluate and publish complete]
    Finalize -->|no| Wait[retain durable checkpoints]
```

Every evidence task is unique by `(job_id, source, partition_key)`, leased,
checkpointed, retryable, and re-queued after an expired lease. Deploys reopen
`running` scan jobs as `queued`; completed evidence pages are not repeated.

GitHub background work preserves foreground capacity. The effective reserve is
`min(configured reserve, 10% of observed quota)`, so a 500-request production
reserve does not deadlock anonymous 60-request quotas.

Configured GitHub credentials are attempted before the anonymous fallback.
Finalize classification runs on Tokio's blocking pool so large histories cannot
starve HTTP health checks, SSE delivery, or foreground queue claims.

## Persistent data schema

SQLite is the production source today. PostgreSQL definitions exist for
multi-instance migration; code paths must not assume identical column names
without an adapter.

```mermaid
erDiagram
    SCAN_JOBS ||--o{ EVIDENCE_TASKS : schedules
    SCAN_JOBS ||--o{ SCANNER_TASKS : schedules
    SCAN_JOBS ||--o| FAILURE_ALERTS : may_raise
    SCANNER_TASKS ||--o{ SCANNER_RESULTS : produces
    EVALUATIONS ||--o{ TRUST_EVENTS : publishes
    EVALUATIONS ||--o{ REGRESSION_CONTRACTS : derives
    REGRESSION_CONTRACTS ||--o{ REGRESSION_EVENTS : audits
    REGRESSION_CONTRACTS ||--o{ REGRESSION_ASSESSMENTS : evaluates

    SCAN_JOBS {
      integer id PK
      text repo
      text lane
      text status
      integer priority
      datetime created_at
      datetime started_at
      datetime completed_at
      text last_error_private
    }
    EVIDENCE_TASKS {
      integer id PK
      integer job_id FK
      text source
      text partition_key
      text status
      text cursor
      json checkpoint_json
      integer attempts
      datetime lease_expires_at
    }
    EVALUATIONS {
      integer id PK
      text repo
      real trust_score
      text grade
      json report_json
      json metrics_json
      datetime created_at
    }
    SOURCE_CACHE {
      text cache_key PK
      text source
      text etag
      text last_modified
      json payload_json
      datetime expires_at
    }
    TRUST_EVENTS {
      integer id PK
      text repo
      text event_type
      json payload_json
      datetime created_at
    }
    FAILURE_ALERTS {
      integer id PK
      text source_kind
      integer source_id
      text repo
      text status
      text error_private
      text notification_status
    }
    REGRESSION_CONTRACTS {
      text contract_id PK
      text repo
      text state
      integer version
      json evidence_json
      json guard_json
      datetime expires_at
    }
    REGRESSION_EVENTS {
      integer id PK
      text contract_id FK
      text from_state
      text to_state
      text actor
      text reason
      datetime created_at
    }
    REGRESSION_ASSESSMENTS {
      integer id PK
      text contract_id FK
      text base_sha
      text head_sha
      text disposition
      json reason_vector_json
      datetime created_at
    }
```

Regression contracts are evidence-backed, versioned review constraints rather
than editable vulnerability claims. Assessments are immutable for a
`(contract_id, base_sha, head_sha)` tuple; lifecycle changes append audit events
and use optimistic version checks. Missing analysis is represented explicitly
and never converted into a passing result.

## Public data contracts

```mermaid
classDiagram
    class EvaluationResult {
      repo: String
      trust_score: f64
      grade: A..F
      verdict: String
      evidence_coverage: f64
      confidence: String
      missing_evidence: String[]
      pillar_scores: Map
      observed_metrics: JSON
    }
    class SecurityContextEnvelope {
      repo: String
      status: none|building|ready|error
      summary: ContextSummary
      artifacts: ContextArtifacts
      context: SecurityContext
      leads: VulnerabilityLeads
    }
    class SecurityContext {
      fingerprints: Fingerprint[]
      known_cves: JSON[]
      top_risks: TopRisk[]
      remediation: Remediation
      trust: TrustMetrics
    }
    class VulnerabilityLeads {
      findings: JSON[]
      leads: JSON[]
      fingerprints: JSON[]
    }
    EvaluationResult --> SecurityContextEnvelope : transformed after evidence gate
    SecurityContextEnvelope *-- SecurityContext
    SecurityContextEnvelope *-- VulnerabilityLeads
```

## Reliability invariants

- Foreground metadata has a total deadline; retries cannot extend user-visible
  work indefinitely.
- A stale cached metadata object may support a clearly partial fast result; it
  never creates historical fixes or CVEs.
- Foreground worker loops are independent. One slow repository cannot stop
  other workers from claiming queued jobs.
- Evidence retries are durable and source-specific. A GitHub or NVD failure
  does not reset completed work from another source.
- Database files live on a host-mounted persistent path and are never replaced
  by deployment sync.
- Public responses remove upstream error details. Operations receive detailed
  alerts through the configured webhook.
- Browser updates use SSE/background requests; page navigation is not driven by
  timed full-page refreshes.
- SSE is backed by `trust_events`, not an in-process channel. New connections
  start at the latest event; reconnects resume from `Last-Event-ID`. Worker and
  API containers therefore do not need shared process memory.
