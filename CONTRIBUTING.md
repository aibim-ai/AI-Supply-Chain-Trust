# Contributing

Thanks for considering a contribution to AI Supply Chain Trust.

## Development Setup

```bash
git clone https://github.com/aibim-ai/AI-Supply-Chain-Trust.git
cd AI-Supply-Chain-Trust
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run the full verification gate:

```bash
make verify
```

## Contribution Areas

Useful contributions include:

- scoring improvements with tests
- scanner parser improvements
- self-hosting documentation
- language/i18n improvements
- SEO/GEO metadata improvements
- accessibility fixes
- Cloud Run, Docker, and Kubernetes deployment examples

## Pull Request Expectations

- Keep changes scoped.
- Add or update tests for behavior changes.
- Update docs when changing CLI flags, API responses, deployment settings, or
  user-facing copy.
- Do not commit generated cache files, local databases, secrets, or private scan
  outputs.
- Run `make verify` before opening a PR.

## Security

Do not open public issues for sensitive vulnerabilities. Follow
[SECURITY.md](SECURITY.md).
