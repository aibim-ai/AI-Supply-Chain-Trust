# Security Policy

## Supported Versions

This repository is in early implementation. Security fixes target the latest
main branch until versioned releases begin.

## Reporting a Vulnerability

Do not open public issues for suspected vulnerabilities. Use
[GitHub private vulnerability reporting](https://github.com/aibim-ai/AI-Supply-Chain-Trust/security/advisories/new)
and include:

- affected command or module
- reproduction steps
- expected impact
- scanner output, if available

The maintainer aims to acknowledge reports within 3 business days, provide an
initial assessment within 7 days, and publish a fix or status update within 30
days when the issue is confirmed. Do not include production credentials or
personal data in a report; use synthetic proof-of-concept inputs.

## Scope and safe research

The public web application, API, MCP endpoint, CLI, and source code are in
scope. Denial-of-service testing, automated high-volume scanning, social
engineering, accessing other users' data, or testing third-party providers is
not authorized. Use a local deployment and bounded synthetic data whenever
possible.

## Secret Rotation

Production secrets should live in Secret Manager or an equivalent managed
secret store, with metadata labels for `owner`, `purpose`, `created_at`,
`rotation_interval_days`, `next_rotation_due`, and `environment`.

Rotation intervals:

| Secret | Rotation interval |
|---|---:|
| GitHub token | 90 days |
| Hugging Face token | 90 days |
| JWT signing secret | 180 days |
| Webhook secret | 180 days |
| DB storage token | 90 days |
| Database password | 180 days |

CI can enforce rotation metadata from an exported JSON manifest:

```bash
python3 scripts/check_secret_expiry.py --metadata secrets-metadata.json
```

The command exits non-zero for overdue secrets and reports `due_soon` for
secrets inside the warning window.
