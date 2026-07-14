# AI Supply Chain Trust

English | [简体中文](README.zh.md) | [繁體中文](README.zht.md) | [한국어](README.ko.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md) | [Italiano](README.it.md) | [Dansk](README.da.md) | [日本語](README.ja.md) | [Polski](README.pl.md) | [Русский](README.ru.md) | [Bosanski](README.bs.md) | [العربية](README.ar.md) | [Norsk](README.no.md) | [Português (Brasil)](README.br.md) | [ไทย](README.th.md) | [Türkçe](README.tr.md) | [Українська](README.uk.md) | [বাংলা](README.bn.md) | [Ελληνικά](README.el.md) | [Tiếng Việt](README.vi.md) | [हिन्दी](README.hi.md)

**Free, open-source repository trust and supply-chain security scanner.**

Evaluates public GitHub repositories across an eight-pillar framework, producing
trust scores, security contexts, and vulnerability leads from live evidence only —
no mock data, no fallback heuristics.

Built in Rust. Previously Python; fully ported to a 15-crate workspace.

## Quick Start

```bash
# Build
cd backend && cargo build --release -p ai-supply-chain-trust

# Run server
cd backend && GITHUB_TOKEN=ghp_xxx cargo run -p ai-supply-chain-trust serve

# Scan a repo
cd backend && GITHUB_TOKEN=ghp_xxx cargo run -p ai-supply-chain-trust eval owner/repo

# Run all tests
cd backend && cargo test --workspace
```

## Architecture And Evidence

```
backend/
├── bin/ai-supply-chain-trust          CLI entrypoint (serve, eval, discover, scan, daemon)
├── crates/                    Rust workspace crates
├── migrations/                Database migrations
└── tests/                     Backend integration and guardrail tests

frontend/
├── web/                       Static browser app and assets
├── Dockerfile                 Frontend Nginx image
└── nginx.conf                 SPA/static asset serving

.github/deploy/production/
└── docker-compose.prod.yml    GitHub Actions production deploy config
```

Maintained technical contracts:

- [Architecture and schemas](docs/architecture.md)
- [API reference](docs/api.md)
- [Deployment and recovery](docs/deployment.md)
- [Data and evidence policy](docs/data-policy.md)
- [Testing and performance evidence](docs/testing-and-performance.md)

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api` | API index |
| GET | `/api/v1/openapi.json` | OpenAPI 3.1.0 schema |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/healthz` | Health with DB ping |
| GET | `/api/v1/context/{owner}/{repo}` | Get security context envelope |
| POST | `/api/v1/context` | Create/refresh security context |
| POST | `/api/v1/scan` | Run trust scan |
| GET | `/api/v1/leaderboard` | Leaderboard |
| GET | `/api/v1/recent-scans` | Recent scans |
| GET | `/api/v1/result` | Get evaluation result |
| GET | `/api/v1/history` | Report history |
| GET | `/api/v1/intel/hits` | Intelligence hits |
| GET | `/api/v1/pig` | Publisher identity graph |
| GET | `/api/v1/suggest` | Repo suggestions |
| GET | `/api/v1/scoring/versions` | Scoring versions |
| GET | `/api/v1/metrics` | JSON metrics |
| GET | `/api/v1/metrics/prometheus` | Prometheus metrics |
| GET | `/api/v1/events` | SSE event stream |
| GET | `/api/v1/queue/stats` | Queue statistics |
| POST | `/api/v1/queue/pause` | Pause scan queue |
| POST | `/api/v1/queue/resume` | Resume scan queue |
| POST | `/api/v1/queue/rescan` | Enqueue rescan |
| GET | `/r/{owner}/{repo}` | Security context HTML page |
| GET | `/r/{owner}/{repo}.json` | Security context JSON artifact |
| GET | `/r/{owner}/{repo}.md` | Security context Markdown artifact |
| GET | `/r/{owner}/{repo}.leads.json` | Vulnerability leads JSON artifact |
| POST | `/mcp` | MCP JSON-RPC 2.0 endpoint |

## Eight Pillars

| # | Pillar | Max Score | Weight |
|---|--------|-----------|--------|
| 1 | Publisher Credibility | 20 | 20 |
| 2 | Repository Health & Activity | 15 | 15 |
| 3 | OpenSSF Scorecard | 25 | 25 |
| 4 | Code & Dependency Safety | 15 | 15 |
| 5 | Model / Artifact Integrity | 10 | 10 |
| 6 | Supply Chain Attack Prediction | 8 | 8 |
| 7 | Publisher Identity Graph | 4 | 4 |
| 8 | AI / MCP-Specific Risk | 3 | 3 |

### Grade Table

| Grade | Score ≥ | Verdict |
|-------|---------|---------|
| A | 85 | Eligible for standard review |
| B | 70 | Review with known gaps |
| C | 50 | Manual security review required |
| D | 30 | Do not approve without security owner |
| F | < 30 | Manual security review required |

**Policy block**: Any critical flag forces grade F with `Blocked by policy signal`
regardless of score. Missing evidence lowers confidence and can downgrade the
decision label until the evidence is complete.

## Data Policy

AI Supply Chain Trust enforces a strict **no invented security evidence** policy:

- `ContextStatus::Ready` requires `VerifiedEvidence` — at least one real evidence
  source (commit SHA from live API, advisory/OSV data, or scanner run)
- `VerifiedEvidence` can only be constructed through a fallible builder that rejects
  empty evidence at compile time
- Every external API failure produces an explicit `DataSourceError` variant
- `#![deny(unreachable_patterns)]` on all evidence-state enums
- Seed data is behind `#[cfg(feature = "seed-data")]` — never compiled into production
- A stale repository-metadata cache may produce an explicitly marked partial
  fast result; it cannot create fixes, CVEs, or a ready security context.

## CLI Usage

```
ai-supply-chain-trust serve --port 8000
ai-supply-chain-trust eval owner/repo --json
ai-supply-chain-trust discover --limit-per-source 10
ai-supply-chain-trust scan --path /local/repo
ai-supply-chain-trust leaderboard --query tensorflow
ai-supply-chain-trust security-context owner/repo --format markdown
ai-supply-chain-trust daemon --discovery-interval 3600
ai-supply-chain-trust db stats
ai-supply-chain-trust doctor
```

## Docker

```bash
docker build -f backend/Dockerfile -t ai-supply-chain-trust backend
docker run -p 8000:8000 -e GITHUB_TOKEN=xxx ai-supply-chain-trust
```

## Development

```bash
scripts/test_evidence.sh
BASE_URL=http://127.0.0.1:8000 scripts/benchmark_scan_pipeline.sh
```

## License

MIT
