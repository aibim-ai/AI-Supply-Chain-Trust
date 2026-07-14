#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="${1:-/opt/ai-repo-trust}"
ENV_FILE="${2:-$DEPLOY_DIR/.env.prod}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
COMPOSE_FILE=".github/deploy/production/docker-compose.prod.yml"

select_writable_env_file() {
  if [ ! -e "$ENV_FILE" ] || [ -w "$ENV_FILE" ]; then
    export AI_SUPPLY_CHAIN_TRUST_ENV_FILE="$ENV_FILE"
    return
  fi

  local fallback="${RUNNER_TEMP:-/tmp}/ai-supply-chain-trust-env-${GITHUB_RUN_ID:-$$}"
  if [ -r "$ENV_FILE" ]; then
    cp "$ENV_FILE" "$fallback"
  else
    : > "$fallback"
  fi
  chmod 0600 "$fallback"
  ENV_FILE="$fallback"
  export AI_SUPPLY_CHAIN_TRUST_ENV_FILE="$ENV_FILE"
}

ensure_env_file() {
  mkdir -p "$DEPLOY_DIR"
  if [ -f "$ENV_FILE" ]; then
    return
  fi

  cat > "$ENV_FILE" <<'EOF'
AI_SUPPLY_CHAIN_TRUST_BASE_URL=https://ai-supply-chain-trust.aibim.ai
AI_SUPPLY_CHAIN_TRUST_LOG_FORMAT=json
AI_SUPPLY_CHAIN_TRUST_DAEMON=1
AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_COMMIT_CLASSIFICATION=1
AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_ECOSYSTEM_RESOLUTION=1
TRUST_DOMAIN=ai-supply-chain-trust.aibim.ai
TRUST_HTTP_PORT=8050
TRUST_HTTPS_PORT=8051
RUST_LOG=ai_supply_chain_trust_server=info,tower_http=info
EOF
}

upsert_secret_env() {
  local key="$1"
  local value="${2:-}"
  if [ -z "$value" ]; then
    return
  fi
  mkdir -p "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  if grep -q "^${key}=" "$ENV_FILE"; then
    awk -v key="$key" -v value="$value" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print key "=" value; next } { print }' "$ENV_FILE" > "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

delete_secret_env() {
  local key="$1"
  if [ ! -f "$ENV_FILE" ] || ! grep -q "^${key}=" "$ENV_FILE"; then
    return
  fi
  awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) != 1 { print }' "$ENV_FILE" > "$ENV_FILE.tmp"
  mv "$ENV_FILE.tmp" "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
}

sync_secret_env() {
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_DAEMON" "${AI_SUPPLY_CHAIN_TRUST_DAEMON:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_DAEMON_QUEUE_INTERVAL" "${AI_SUPPLY_CHAIN_TRUST_DAEMON_QUEUE_INTERVAL:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_DAEMON_MAX_CONCURRENT" "${AI_SUPPLY_CHAIN_TRUST_DAEMON_MAX_CONCURRENT:-4}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_WORKER_START_DELAY_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_WORKER_START_DELAY_SECONDS:-0}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_INTERVAL_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_INTERVAL_SECONDS:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_BATCH" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_BATCH:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_CONCURRENCY" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_CONCURRENCY:-2}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_DETAIL_BATCH" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_DETAIL_BATCH:-2}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_CONCURRENCY" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_CONCURRENCY:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_ENABLED" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_ENABLED:-0}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_MODE" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_MODE:-off}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_EVIDENCE_FINALIZE_CONCURRENCY" "${AI_SUPPLY_CHAIN_TRUST_EVIDENCE_FINALIZE_CONCURRENCY:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_NVD_TASK_TIMEOUT_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_NVD_TASK_TIMEOUT_SECONDS:-90}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_ALERT_INTERVAL_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_ALERT_INTERVAL_SECONDS:-60}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_FAILURE_RECOVERY_INTERVAL_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_FAILURE_RECOVERY_INTERVAL_SECONDS:-600}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_COMMIT_DETAIL_LIMIT" "${AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_COMMIT_DETAIL_LIMIT:-25}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_HISTORY_MAX_PAGES" "${AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_HISTORY_MAX_PAGES:-10}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS:-20}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_FOREGROUND_TIMEOUT_SECONDS" "${AI_SUPPLY_CHAIN_TRUST_FOREGROUND_TIMEOUT_SECONDS:-5}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_COMMIT_CLASSIFICATION" "${AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_COMMIT_CLASSIFICATION:-1}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_ECOSYSTEM_RESOLUTION" "${AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_ECOSYSTEM_RESOLUTION:-1}"
  if [ -n "${AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS+x}" ]; then
    upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS" "${AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS}"
  else
    delete_secret_env "AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS"
  fi
  delete_secret_env "AI_SUPPLY_CHAIN_TRUST_GITHUB_TOKEN"
  upsert_secret_env "GITHUB_TOKEN" "${GITHUB_TOKEN:-}"
  upsert_secret_env "GITHUB_TOKENS" "${GITHUB_TOKENS:-}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN" "${AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN:-}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_ALERT_WEBHOOK_URL" "${AI_SUPPLY_CHAIN_TRUST_ALERT_WEBHOOK_URL:-}"
  upsert_secret_env "AI_SUPPLY_CHAIN_TRUST_FEEDBACK_WEBHOOK_URL" "${AI_SUPPLY_CHAIN_TRUST_FEEDBACK_WEBHOOK_URL:-${AI_SUPPLY_CHAIN_TRUST_ALERT_WEBHOOK_URL:-}}"
  upsert_secret_env "NVD_API_KEY" "${NVD_API_KEY:-}"
  upsert_secret_env "OPENROUTER_API_KEY" "${OPENROUTER_API_KEY:-}"
  upsert_secret_env "OPENROUTER_MODEL_PRIMARY" "${OPENROUTER_MODEL_PRIMARY:-openai/gpt-4.1-mini}"
  upsert_secret_env "OPENROUTER_MODEL_SECONDARY" "${OPENROUTER_MODEL_SECONDARY:-google/gemini-2.5-flash}"
  upsert_secret_env "OPENROUTER_TIMEOUT" "${OPENROUTER_TIMEOUT:-20}"
  upsert_secret_env "OPENROUTER_MAX_RETRIES" "${OPENROUTER_MAX_RETRIES:-2}"
  upsert_secret_env "OPENROUTER_REQUESTS_PER_MINUTE" "${OPENROUTER_REQUESTS_PER_MINUTE:-20}"
  upsert_secret_env "OPENROUTER_REQUESTS_PER_DAY" "${OPENROUTER_REQUESTS_PER_DAY:-200}"
  upsert_secret_env "OPENROUTER_RETRY_BASE_DELAY_MS" "${OPENROUTER_RETRY_BASE_DELAY_MS:-250}"
  upsert_secret_env "OPENROUTER_RETRY_MAX_DELAY_MS" "${OPENROUTER_RETRY_MAX_DELAY_MS:-10000}"
  upsert_secret_env "OPENROUTER_CIRCUIT_FAILURE_THRESHOLD" "${OPENROUTER_CIRCUIT_FAILURE_THRESHOLD:-3}"
  upsert_secret_env "OPENROUTER_CIRCUIT_COOLDOWN_SECONDS" "${OPENROUTER_CIRCUIT_COOLDOWN_SECONDS:-60}"
  upsert_secret_env "OPENROUTER_MAX_INPUT_BYTES" "${OPENROUTER_MAX_INPUT_BYTES:-65536}"
  upsert_secret_env "OPENROUTER_FALLBACK_MAX_TOTAL_ATTEMPTS" "${OPENROUTER_FALLBACK_MAX_TOTAL_ATTEMPTS:-4}"
  upsert_secret_env "OPENROUTER_FALLBACK_MAX_TOTAL_LATENCY_MS" "${OPENROUTER_FALLBACK_MAX_TOTAL_LATENCY_MS:-30000}"
  upsert_secret_env "OPENROUTER_REQUIRE_NON_FREE_MODEL" "${OPENROUTER_REQUIRE_NON_FREE_MODEL:-1}"
}

prepare_release_permissions() {
  mkdir -p "$DEPLOY_DIR"
  docker run --rm \
    -v "$DEPLOY_DIR:/target" \
    nginx:alpine \
    sh -c "chown $(id -u):$(id -g) /target && find /target -mindepth 1 -maxdepth 1 ! -name data ! -name .env.prod -exec chown -R $(id -u):$(id -g) {} +"
}

sync_release() {
  rsync -a --delete \
    --exclude .git \
    --exclude .cache \
    --exclude .langgraph_api \
    --exclude .understand-anything \
    --exclude __pycache__ \
    --exclude .env \
    --exclude .env.prod \
    --exclude node_modules \
    --exclude coverage \
    --exclude data \
    --exclude runs \
    --exclude target \
    --exclude backend/target \
    "$REPO_ROOT"/ "$DEPLOY_DIR"/
}

prepare_data_dir() {
  mkdir -p "$DEPLOY_DIR/data"
  chmod 0777 "$DEPLOY_DIR/data"
  if [ -f "$DEPLOY_DIR/data/trust.db" ]; then
    return
  fi
  if docker ps --format '{{.Names}}' | grep -qx 'ai-supply-chain-trust-backend-prod'; then
    docker cp ai-supply-chain-trust-backend-prod:/tmp/trust.db "$DEPLOY_DIR/data/trust.db" 2>/dev/null || true
    chmod 0666 "$DEPLOY_DIR/data/trust.db" 2>/dev/null || true
  fi
}

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

remove_legacy_containers() {
  local container
  for container in \
    ai-repo-trust-nginx-prod \
    ai-repo-trust-certbot-prod \
    ai-repo-trust-frontend-prod \
    ai-repo-trust-backend-prod \
    ai-repo-trust-worker-prod \
    ai-repo-trust-nvd-worker-prod; do
    if docker container inspect "$container" >/dev/null 2>&1; then
      echo "Removing legacy product container: $container"
      docker rm -f "$container"
    fi
  done
}

show_logs() {
  echo "=== Container logs ==="
  echo "=== Container state ==="
  docker inspect ai-supply-chain-trust-backend-prod --format '{{json .State}}' 2>&1 || true
  docker inspect ai-supply-chain-trust-worker-prod --format '{{json .State}} restart={{.RestartCount}}' 2>&1 || true
  docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{json .State}} restart={{.RestartCount}}' 2>&1 || true
  docker logs ai-supply-chain-trust-backend-prod --tail 150 2>&1 || true
  docker logs ai-supply-chain-trust-worker-prod --tail 150 2>&1 || true
  docker logs ai-supply-chain-trust-nvd-worker-prod --tail 100 2>&1 || true
  docker logs ai-supply-chain-trust-frontend-prod --tail 50 2>&1 || true
  docker logs ai-supply-chain-trust-nginx-prod --tail 50 2>&1 || true
}

verify_worker_stability() {
  local initial_id initial_restarts final_id final_restarts
  local nvd_initial_id nvd_initial_restarts nvd_final_id nvd_final_restarts
  initial_id="$(docker inspect ai-supply-chain-trust-worker-prod --format '{{.Id}}')"
  initial_restarts="$(docker inspect ai-supply-chain-trust-worker-prod --format '{{.RestartCount}}')"
  nvd_initial_id="$(docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{.Id}}')"
  nvd_initial_restarts="$(docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{.RestartCount}}')"
  echo "=== Worker stability gate (65s; general=${initial_restarts}, nvd=${nvd_initial_restarts}) ==="
  sleep 65
  final_id="$(docker inspect ai-supply-chain-trust-worker-prod --format '{{.Id}}')"
  final_restarts="$(docker inspect ai-supply-chain-trust-worker-prod --format '{{.RestartCount}}')"
  nvd_final_id="$(docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{.Id}}')"
  nvd_final_restarts="$(docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{.RestartCount}}')"
  docker inspect ai-supply-chain-trust-worker-prod --format '{{json .State}} restart={{.RestartCount}}'
  docker inspect ai-supply-chain-trust-nvd-worker-prod --format '{{json .State}} restart={{.RestartCount}}'
  if [ "$initial_id" != "$final_id" ] || [ "$initial_restarts" != "$final_restarts" ] || \
     [ "$nvd_initial_id" != "$nvd_final_id" ] || [ "$nvd_initial_restarts" != "$nvd_final_restarts" ]; then
    echo "Worker restarted during stability gate: general ${initial_restarts}->${final_restarts}; nvd ${nvd_initial_restarts}->${nvd_final_restarts}" >&2
    docker events --since 2m --until "$(date --iso-8601=seconds)" --filter container=ai-supply-chain-trust-worker-prod 2>&1 || true
    docker events --since 2m --until "$(date --iso-8601=seconds)" --filter container=ai-supply-chain-trust-nvd-worker-prod 2>&1 || true
    return 1
  fi
  run_or_show_logs docker exec ai-supply-chain-trust-worker-prod sh -c 'kill -0 1'
  run_or_show_logs docker exec ai-supply-chain-trust-nvd-worker-prod sh -c 'kill -0 1'
}

run_or_show_logs() {
  "$@" || {
    show_logs
    return 1
  }
}

wait_for_backend_health() {
  local attempts=30
  local delay=3
  for attempt in $(seq 1 "$attempts"); do
    if timeout 8s docker exec ai-supply-chain-trust-backend-prod curl -fsS --max-time 5 http://127.0.0.1:8080/health; then
      return 0
    fi
    echo "Backend health not ready (${attempt}/${attempts}); waiting ${delay}s"
    sleep "$delay"
  done
  show_logs
  return 1
}

verify_backend_frontend() {
  compose ps
  sleep 5
  show_logs

  echo "=== Backend health check ==="
  wait_for_backend_health
  run_or_show_logs timeout 8s docker exec ai-supply-chain-trust-backend-prod curl -fsS --max-time 5 http://127.0.0.1:8080/api/v1/health

  echo "=== Frontend health check ==="
  run_or_show_logs timeout 8s docker exec ai-supply-chain-trust-frontend-prod wget -q -O - http://127.0.0.1/frontend-health
  run_or_show_logs timeout 8s docker exec ai-supply-chain-trust-frontend-prod wget -q -O - http://127.0.0.1/ | grep -q '/assets/css/design-system.css'
  run_or_show_logs timeout 8s docker exec ai-supply-chain-trust-frontend-prod wget -q -O /dev/null http://127.0.0.1/free-tools/assets/js/HomePage.js
}

verify_deploy() {
  compose ps
  sleep 5

  show_logs

  echo "=== Edge routing check ==="
  run_or_show_logs curl -fsS "http://127.0.0.1:${TRUST_HTTP_PORT:-8050}/nginx-health"
}

verify_public_edge() {
  local base_url="https://${TRUST_DOMAIN:-ai-supply-chain-trust.aibim.ai}"
  local attempts=20
  local delay=3
  local attempt
  echo "=== Public edge routing check ==="
  for attempt in $(seq 1 "$attempts"); do
    if curl -fsS --connect-timeout 5 --max-time 15 "${base_url}/api/v1/health" >/dev/null \
      && curl -fsS --connect-timeout 5 --max-time 15 "${base_url}/free-tools/assets/js/HomePage.js" >/dev/null; then
      echo "Public API and frontend asset are reachable"
      return 0
    fi
    echo "Public edge not ready (${attempt}/${attempts}); waiting ${delay}s"
    sleep "$delay"
  done
  show_logs
  return 1
}

check_github_connectivity() {
  local container="$1"
  echo "=== GitHub connectivity check: ${container} ==="
  timeout 20s docker exec "$container" sh -lc \
    'curl -4 -fsS --connect-timeout 5 --max-time 15 -D - https://api.github.com/rate_limit -o /tmp/github-rate.json | sed -n "1,20p"; printf "\n--- body ---\n"; sed -n "1,12p" /tmp/github-rate.json' \
    || echo "GitHub connectivity check failed for ${container}"
  echo "=== Rust netcheck: ${container} ==="
  timeout 45s docker exec "$container" ai-supply-chain-trust netcheck https://api.github.com/rate_limit \
    || echo "Rust netcheck failed for ${container}"
  echo "=== Rust token netcheck: ${container} ==="
  timeout 45s docker exec "$container" ai-supply-chain-trust netcheck \
    https://api.github.com/repos/octocat/hello-world \
    --github-token-from-env \
    || echo "Rust token netcheck failed for ${container}"
}

select_writable_env_file
ensure_env_file
sync_secret_env
prepare_release_permissions
sync_release
prepare_data_dir
cd "$DEPLOY_DIR"
trap show_logs ERR
compose build backend frontend
remove_legacy_containers
compose up -d --force-recreate --remove-orphans backend frontend
verify_backend_frontend
run_or_show_logs compose up -d --force-recreate nginx
verify_deploy
run_or_show_logs compose up -d --force-recreate worker nvd-worker
run_or_show_logs verify_worker_stability
run_or_show_logs verify_public_edge
check_github_connectivity ai-supply-chain-trust-backend-prod
check_github_connectivity ai-supply-chain-trust-worker-prod

echo "=== Foreground scan performance gate ==="
BASE_URL="https://${TRUST_DOMAIN:-ai-supply-chain-trust.aibim.ai}" \
  CORPUS="octocat/Hello-World" \
  RUNS=1 \
  OUTPUT="$DEPLOY_DIR/data/deploy-scan-performance.csv" \
  "$DEPLOY_DIR/scripts/benchmark_scan_pipeline.sh"
