# Backend

Rust API source and deployment boundary for AI Supply Chain Trust.

This directory is the Cargo workspace root. Run Cargo commands from here:

```bash
cargo check --workspace
cargo test --workspace
cargo build --release -p ai-supply-chain-trust
```

This directory also owns the backend container definition:

- `Dockerfile`: builds the `ai-supply-chain-trust` Rust binary and runs API/MCP/security-context routes.

Production backend responsibilities:

- `/api` and `/api/*`
- `/mcp`
- `/r/*`
- `/health` and `/healthz`

The backend does not serve the production frontend and does not publish a host
port in `.github/deploy/production/docker-compose.prod.yml`.
