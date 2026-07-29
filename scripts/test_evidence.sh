#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/.cache/test-evidence}"
mkdir -p "$EVIDENCE_DIR"

run_and_record() {
  local name="$1"
  shift
  echo "=== ${name} ==="
  "$@" 2>&1 | tee "$EVIDENCE_DIR/${name}.log"
}

run_and_record security-independence "$ROOT/scripts/security_independence_guard.sh"
run_and_record deploy-contract "$ROOT/scripts/test_deploy_contract.sh"
run_and_record rust-format bash -lc "cd '$ROOT/backend' && cargo fmt --all -- --check"
run_and_record rust-clippy bash -lc "cd '$ROOT/backend' && cargo clippy --workspace --all-targets -- -D warnings"
run_and_record rust-tests bash -lc "cd '$ROOT/backend' && cargo test --workspace --all-targets"
run_and_record python-guardrails python3 "$ROOT/backend/tests/test_llm_hallucination_guard.py"
run_and_record frontend-format bash -lc "cd '$ROOT/frontend' && npm run format:check"
run_and_record frontend-lint bash -lc "cd '$ROOT/frontend' && npm run lint"
run_and_record frontend-tests bash -lc "cd '$ROOT/frontend' && npm test -- --run"
run_and_record frontend-coverage bash -lc "cd '$ROOT/frontend' && npm run test:coverage"
run_and_record frontend-build bash -lc "cd '$ROOT/frontend' && npm run build"
run_and_record frontend-audit bash -lc "cd '$ROOT/frontend' && npm audit --omit=dev --audit-level=critical"
run_and_record frontend-e2e bash -lc "cd '$ROOT/frontend' && npm run test:e2e"

if command -v cargo-llvm-cov >/dev/null; then
  llvm_cov="${LLVM_COV:-}"
  llvm_profdata="${LLVM_PROFDATA:-}"
  if [[ -z "$llvm_cov" ]] && command -v xcrun >/dev/null; then
    llvm_cov="$(xcrun --find llvm-cov 2>/dev/null || true)"
    llvm_profdata="$(xcrun --find llvm-profdata 2>/dev/null || true)"
  fi
  run_and_record rust-coverage bash -lc \
    "cd '$ROOT/backend' && LLVM_COV='$llvm_cov' LLVM_PROFDATA='$llvm_profdata' cargo llvm-cov --workspace --all-targets --summary-only --fail-under-lines 60 --fail-under-functions 55"
else
  echo "cargo-llvm-cov is not installed; coverage evidence was skipped" >&2
  exit 2
fi

date -u '+verified_at=%Y-%m-%dT%H:%M:%SZ' > "$EVIDENCE_DIR/summary.txt"
git -C "$ROOT" rev-parse HEAD | sed 's/^/commit=/' >> "$EVIDENCE_DIR/summary.txt"
if [[ -n "$(git -C "$ROOT" status --porcelain=v1)" ]]; then
  echo "worktree_state=dirty" >> "$EVIDENCE_DIR/summary.txt"
  git -C "$ROOT" status --porcelain=v1 -z | shasum -a 256 | awk '{print "worktree_status_sha256=" $1}' >> "$EVIDENCE_DIR/summary.txt"
else
  echo "worktree_state=clean" >> "$EVIDENCE_DIR/summary.txt"
fi
echo "status=passed" >> "$EVIDENCE_DIR/summary.txt"
echo "Evidence written to $EVIDENCE_DIR"
