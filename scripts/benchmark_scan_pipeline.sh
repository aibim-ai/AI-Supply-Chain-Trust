#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
RUNS="${RUNS:-1}"
OUTPUT="${OUTPUT:-.cache/benchmarks/scan-pipeline.csv}"
CORPUS="${CORPUS:-octocat/Hello-World}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-0.25}"
JOB_TIMEOUT_SECONDS="${JOB_TIMEOUT_SECONDS:-20}"
MAX_ACCEPT_SECONDS="${MAX_ACCEPT_SECONDS:-1}"
MAX_QUEUE_WAIT_SECONDS="${MAX_QUEUE_WAIT_SECONDS:-3}"
MAX_FOREGROUND_SECONDS="${MAX_FOREGROUND_SECONDS:-6}"
MAX_TOTAL_SECONDS="${MAX_TOTAL_SECONDS:-8}"

for command in curl jq awk date; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done

mkdir -p "$(dirname "$OUTPUT")"
echo "timestamp,repo,run,job_id,status,accept_seconds,queue_wait_seconds,foreground_seconds,total_seconds" > "$OUTPUT"

epoch_from_db_time() {
  jq -nr --arg value "$1" \
    '$value + "Z" | strptime("%Y-%m-%d %H:%M:%SZ") | mktime'
}

assert_at_most() {
  local label="$1" value="$2" maximum="$3"
  awk -v value="$value" -v maximum="$maximum" 'BEGIN { exit !(value <= maximum) }' || {
    echo "Performance gate failed: ${label}=${value}s, maximum=${maximum}s" >&2
    return 1
  }
}

wait_for_job() {
  local job_id="$1" deadline=$(( $(date +%s) + JOB_TIMEOUT_SECONDS )) payload job
  while (( $(date +%s) <= deadline )); do
    payload="$(curl --fail --silent --show-error "${BASE_URL}/api/v1/jobs?limit=100")"
    job="$(jq -c --argjson id "$job_id" \
      '(.jobs // .rows // .) | map(select((.id // .job_id) == $id))[0] // empty' \
      <<<"$payload")"
    if [[ -n "$job" ]] && jq -e '.status == "completed" or .status == "failed"' <<<"$job" >/dev/null; then
      printf '%s\n' "$job"
      return 0
    fi
    sleep "$POLL_INTERVAL_SECONDS"
  done
  echo "Timed out waiting ${JOB_TIMEOUT_SECONDS}s for job ${job_id}" >&2
  return 1
}

failures=0
IFS=',' read -r -a repos <<< "$CORPUS"
for repo in "${repos[@]}"; do
  for run in $(seq 1 "$RUNS"); do
    started_epoch="$(date +%s)"
    response="$(curl --fail --silent --show-error \
      --write-out $'\n%{time_total}' \
      --header 'Content-Type: application/json' \
      --data "{\"repo\":\"${repo}\",\"priority\":100}" \
      "${BASE_URL}/api/v1/queue/rescan")"
    accept_seconds="${response##*$'\n'}"
    body="${response%$'\n'*}"
    job_id="$(jq -er '.job_id' <<<"$body")"
    job="$(wait_for_job "$job_id")" || {
      failures=$((failures + 1))
      continue
    }

    status="$(jq -r '.status' <<<"$job")"
    created_at="$(jq -r '.created_at' <<<"$job")"
    started_at="$(jq -r '.started_at' <<<"$job")"
    completed_at="$(jq -r '.completed_at' <<<"$job")"
    created="$(epoch_from_db_time "$created_at")"
    job_started="$(epoch_from_db_time "$started_at")"
    completed="$(epoch_from_db_time "$completed_at")"
    queue_wait_seconds=$((job_started - created))
    foreground_seconds=$((completed - job_started))
    total_seconds=$((completed - created))
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    echo "${timestamp},${repo},${run},${job_id},${status},${accept_seconds},${queue_wait_seconds},${foreground_seconds},${total_seconds}" \
      | tee -a "$OUTPUT"

    assert_at_most accept "$accept_seconds" "$MAX_ACCEPT_SECONDS" || failures=$((failures + 1))
    assert_at_most queue_wait "$queue_wait_seconds" "$MAX_QUEUE_WAIT_SECONDS" || failures=$((failures + 1))
    assert_at_most foreground "$foreground_seconds" "$MAX_FOREGROUND_SECONDS" || failures=$((failures + 1))
    assert_at_most total "$total_seconds" "$MAX_TOTAL_SECONDS" || failures=$((failures + 1))
    if [[ "$status" != "completed" ]]; then
      echo "Performance gate failed: job ${job_id} ended with ${status}" >&2
      failures=$((failures + 1))
    fi
    if (( $(date +%s) - started_epoch > JOB_TIMEOUT_SECONDS + 2 )); then
      echo "Performance gate warning: wall-clock polling overhead exceeded expected budget" >&2
    fi
  done
done

echo "Benchmark evidence written to ${OUTPUT}"
if (( failures > 0 )); then
  echo "Scan performance gate failed with ${failures} violation(s)" >&2
  exit 1
fi
