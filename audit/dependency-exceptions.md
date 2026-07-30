# Dependency Security Exceptions

## RustSec SQLx optional MySQL dependency — 2026-07-30

- Advisory: `RUSTSEC-2023-0071`, `rsa` `0.9.10`, Marvin timing side channel.
- Source: Cargo audit scans every package retained in `Cargo.lock`, including
  SQLx's optional MySQL package closure.
- Scope assessment: workspace sets `sqlx.default-features = false` and enables
  only `runtime-tokio-rustls`, `postgres`, `chrono`, and `uuid`. `cargo tree
  --target all -i rsa` returns no active dependency path; application JWT code
  uses HS256 rather than RSA.
- Control: `backend/.cargo/audit.toml` records the no-fixed-release exception. Keep
  SQLx MySQL disabled, rerun `cargo audit` in CI, and remove this exception when
  a fixed RSA release exists or Cargo stops retaining the optional closure.
- Owner: application security
- Review by: 2026-08-30

## React Router advisory feed conflict — 2026-07-30

- Package: `react-router-dom` / `react-router` `7.18.2` (exactly pinned)
- Severity: high, npm advisory `GHSA-qwww-vcr4-c8h2`
- Current evidence: `npm audit --omit=dev --audit-level=high` still reports this RSC-mode CSRF advisory at `7.18.2`; its own remediation suggests `7.11.0`. That downgrade instead produces two high findings covering older React Router releases.
- Scope assessment: this project is a client-only Vite SPA using `createBrowserRouter`; it does not expose React Router loaders, actions, RSC, or server rendering routes. The affected RSC action path is not reachable in the deployed architecture.
- Control: pin `react-router-dom` to `7.18.2`, rerun the production-only audit in CI, and remove this exception as soon as a release resolves both advisory ranges.
- Owner: application security
- Review by: 2026-08-30
