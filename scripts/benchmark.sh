#!/bin/bash
# Performance benchmark: Python vs Rust implementations
# Requires both servers running. Compares response times and memory.

set -euo pipefail

RUST_URL="${RUST_URL:-http://localhost:8000}"
PYTHON_URL="${PYTHON_URL:-https://ai-supply-chain-trust.aibim.ai}"
REPO="${REPO:-vercel/next.js}"
WARMUP="${WARMUP:-3}"
RUNS="${RUNS:-10}"

echo "=== AI Supply Chain Trust Performance Benchmark ==="
echo "Rust:    $RUST_URL"
echo "Python:  $PYTHON_URL"
echo "Repo:    $REPO"
echo "Warmup:  $WARMUP, Runs: $RUNS"
echo ""

bench_endpoint() {
    local name="$1"; local path="$2"
    echo "--- $name ---"

    # Warmup (both)
    for _ in $(seq 1 $WARMUP); do
        curl -s -o /dev/null "$RUST_URL$path" 2>/dev/null || true
        curl -s -o /dev/null "$PYTHON_URL$path" 2>/dev/null || true
    done

    # Rust bench
    local rust_total=0
    for _ in $(seq 1 $RUNS); do
        local t=$(curl -s -o /dev/null -w '%{time_total}' "$RUST_URL$path" 2>/dev/null || echo 0)
        rust_total=$(echo "$rust_total + $t" | bc)
    done
    local rust_avg=$(echo "scale=3; $rust_total / $RUNS" | bc)

    # Python bench
    local python_total=0
    for _ in $(seq 1 $RUNS); do
        local t=$(curl -s -o /dev/null -w '%{time_total}' "$PYTHON_URL$path" 2>/dev/null || echo 0)
        python_total=$(echo "$python_total + $t" | bc)
    done
    local python_avg=$(echo "scale=3; $python_total / $RUNS" | bc)

    local speedup=$(echo "scale=1; $python_avg / $rust_avg" | bc 2>/dev/null || echo "N/A")
    printf "  Rust:    %ss avg\n  Python:  %ss avg\n  Speedup: %sx\n\n" "$rust_avg" "$python_avg" "$speedup"
}

# --- Benchmarks ---
bench_endpoint "Health check" "/health"
bench_endpoint "API index" "/api"
bench_endpoint "Leaderboard" "/api/v1/leaderboard?limit=10"
bench_endpoint "Metrics" "/api/v1/metrics"
bench_endpoint "OpenAPI" "/api/v1/openapi.json"
bench_endpoint "Context (${REPO})" "/api/v1/context/${REPO//\//\/}"

echo "=== Memory comparison ==="
echo "Rust binary size: $(du -h backend/target/release/ai-supply-chain-trust 2>/dev/null | cut -f1 || echo 'N/A (not built)')"
echo "Python image:     $(docker images python:3.12-slim --format '{{.Size}}' 2>/dev/null || echo 'N/A')"
