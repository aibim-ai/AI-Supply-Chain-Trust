#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ai-repo-trust-deploy-test.XXXXXX")"
ENV_FILE="$DEPLOY_DIR/.env.prod"
trap 'rm -rf "$DEPLOY_DIR"' EXIT

# Source only the helpers; production deployment runs exclusively through main.
# shellcheck source=/dev/null
source "$ROOT/.github/deploy/production/deploy-prod.sh" "$DEPLOY_DIR" "$ENV_FILE"

timeout() {
  shift
  "$@"
}

docker() {
  local command="${1:-}"
  shift || true
  if [[ "$command" == "exec" && " $* " == *" --github-token-from-env "* ]]; then
    return 1
  fi
  return 0
}

if check_github_connectivity "fixture-container"; then
  echo "authenticated GitHub netcheck failure was accepted" >&2
  exit 1
fi

docker() { return 0; }
check_github_connectivity "fixture-container"

docker() {
  if [[ "${1:-}" == "ps" ]]; then
    printf '%s\n' 'ai-supply-chain-trust-backend-prod'
    return 0
  fi
  if [[ "${1:-}" == "cp" ]]; then
    [[ "${2:-}" == 'ai-supply-chain-trust-backend-prod:/data/trust.db' ]] || return 1
    : > "${3:?database copy target missing}"
    return 0
  fi
  return 0
}
prepare_data_dir
[[ -f "$DEPLOY_DIR/data/trust.db" ]] || {
  echo "existing runtime SQLite database was not copied from /data" >&2
  exit 1
}

for required_gate in '/api/v1/healthz' '/assets/js/app.js'; do
  if ! grep -Fq "$required_gate" "$ROOT/.github/deploy/production/deploy-prod.sh"; then
    echo "deployment must enforce ${required_gate}" >&2
    exit 1
  fi
done

if grep -Fq '/free-tools/assets/js/HomePage.js' "$ROOT/.github/deploy/production/deploy-prod.sh"; then
  echo "deployment must not probe the legacy HomePage asset" >&2
  exit 1
fi

if ! grep -Fq 'npm run test:public-release' "$ROOT/.github/workflows/deploy-production.yml"; then
  echo "production workflow must run the public browser release gate" >&2
  exit 1
fi

echo "deploy contract checks passed"
