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

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ai-supply-chain-trust /usr/local/bin/ai-supply-chain-trust

RUN mkdir -p /data && chmod 777 /data

EXPOSE 8080
ENV PORT=8080
ENV AI_SUPPLY_CHAIN_TRUST_DB_PATH=/data/trust.db

USER nobody
ENTRYPOINT ["/usr/local/bin/ai-supply-chain-trust", "serve"]
