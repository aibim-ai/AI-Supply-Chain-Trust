# Rust multi-stage build for AI Supply Chain Trust
# Produces a minimal runtime image (~20 MB binary + debian-slim base)

FROM rust:1.88-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/ bin/

RUN cargo build --release -p ai-supply-chain-trust && \
    strip /app/target/release/ai-supply-chain-trust

# Scanner binaries. Only self-contained, single-binary Go tools are built here:
# they add tens of megabytes and no runtime dependencies. Deliberately NOT
# installed (see the notes at the bottom of this file): semgrep, bandit,
# pip-audit (a full Python toolchain), npm audit (a full Node toolchain), and
# trivy (needs a multi-hundred-megabyte vulnerability DB downloaded into a
# writable cache at runtime, which this read-only, nobody-owned image has no
# place for).
FROM golang:1.25-bookworm AS scanner-builder
# gitleaks moved GitHub organisations but its go.mod still declares the module
# as github.com/zricethezav/gitleaks/v8 (verified through v8.30.1), so the
# install path must use the declared module path, not the current repo URL.
RUN GOBIN=/out go install github.com/ossf/scorecard/v5@v5.3.0 && \
    GOBIN=/out go install github.com/zricethezav/gitleaks/v8@v8.21.2

# --- Runtime stage ---
FROM debian:bookworm-slim
# git is required only by the opt-in scanner source checkout below; without it
# that feature reports an explicit deployment gap rather than silently failing.
RUN apt-get update && apt-get install -y ca-certificates curl git libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ai-supply-chain-trust /usr/local/bin/ai-supply-chain-trust
COPY --from=scanner-builder /out/scorecard /usr/local/bin/scorecard
COPY --from=scanner-builder /out/gitleaks /usr/local/bin/gitleaks

RUN mkdir -p /data && chown nobody:nogroup /data && chmod 700 /data

EXPOSE 8080
ENV PORT=8080
ENV AI_SUPPLY_CHAIN_TRUST_DB_PATH=/data/trust.db
# Production image owns its queue: discover new GitHub repositories and process scans.
ENV AI_SUPPLY_CHAIN_TRUST_DAEMON=1
# Scanners that need a working tree (gitleaks here) shallow-clone the scanned
# repository into a temporary directory. Enabled deliberately: it is what makes
# the Code & Dependency Safety pillar (15 of 100 weight) scoreable at all.
# While off, those scanners report `no_source` and say why, instead of claiming
# the repository had nothing to find.
#
# The clone is depth-1, single-branch, HTTPS-only, and always removed. The size
# cap is enforced *after* the clone completes, so it bounds what is retained,
# not the peak written — the timeout is what bounds the peak. Both are tunable
# here and via .env.prod without rebuilding.
ENV AI_SUPPLY_CHAIN_TRUST_SCANNER_SOURCE_CHECKOUT=1
ENV AI_SUPPLY_CHAIN_TRUST_SCANNER_CHECKOUT_MAX_BYTES=268435456
ENV AI_SUPPLY_CHAIN_TRUST_SCANNER_CHECKOUT_TIMEOUT_SECONDS=120

USER nobody
ENTRYPOINT ["/usr/local/bin/ai-supply-chain-trust", "serve"]
