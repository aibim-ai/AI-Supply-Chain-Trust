#!/usr/bin/env bash
#
# Re-scan every repository already in the public inventory, gradually.
#
# WHY THIS EXISTS
# ---------------
# Scored fields (trust_score, grade, evidence_coverage, confidence,
# missing_evidence, critical_flags) are frozen into each stored report at scan
# time. A scoring or pipeline fix therefore does not change any existing
# report -- every repository has to be scanned again to pick it up.
#
# Two levers were rejected before this one:
#
#   * Bumping LIVE_SECURITY_CONTEXT_VERSION is the built-in staleness trigger,
#     but it doubles as rule 2 of the evidence gate in `ready_evidence_summary`.
#     Bumping it puts every stored report into `security_context_evidence_missing`
#     at once, so every /r/<owner>/<repo> page renders "Context needs evidence"
#     until that repository has been scanned again.
#
#   * POSTing to /api/v1/queue/rescan per repository hits the public rate limit
#     (10 requests per requester per 24h), which exists to stop an anonymous
#     visitor flooding the queue. It cannot drive a fleet-wide sweep.
#
# So this calls the worker-token protected /api/v1/ops/requeue-all, which
# enqueues the inventory into the background lane at the lowest priority:
# nothing is invalidated, pages keep serving their current context, visitors'
# own scans stay ahead in the queue, and each repository flips to corrected data
# as its own scan lands.
#
# RUN THIS ONLY AFTER THE FIX IS DEPLOYED. Against an older build it just
# reproduces the values it is meant to correct.
#
# Usage:
#   AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN=... scripts/requeue_all_repositories.sh [BASE_URL]
#
# Environment:
#   AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN  required; the raw token, not its digest
#   LIMIT        maximum repositories to enqueue (default: all)
#   DRY_RUN=1    report the inventory size and exit without enqueueing

set -euo pipefail

BASE_URL="${1:-${BASE_URL:-https://ai-supply-chain-trust.aibim.ai}}"
TOKEN="${AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN:-}"
LIMIT="${LIMIT:-50000}"
DRY_RUN="${DRY_RUN:-0}"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
require curl
require python3

echo "Target: $BASE_URL"

inventory_size() {
  curl -fsS "$BASE_URL/api/v1/metrics" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("unique_repos", 0))'
}

echo "Inventory: $(inventory_size) repositories"

if [ "$DRY_RUN" = "1" ]; then
  echo "DRY_RUN=1 -- nothing enqueued."
  exit 0
fi

if [ -z "$TOKEN" ]; then
  cat >&2 <<'MSG'
AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN is not set.

This sweep needs the worker token because the public rescan endpoint is rate
limited to 10 requests per requester per day. The token lives in the production
env file (/opt/ai-repo-trust/.env.prod) and in the deployment secrets.
MSG
  exit 1
fi

response="$(curl -fsS -X POST "$BASE_URL/api/v1/ops/requeue-all" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"limit\": $LIMIT}")" || {
  echo "requeue request failed" >&2
  exit 1
}

echo "$response" | python3 -c '
import json,sys
d = json.load(sys.stdin)
print(f"examined={d.get(\"examined\")} queued={d.get(\"queued\")} failed={d.get(\"failed\")}")
for err in (d.get("errors") or [])[:10]:
    print("  error:", err)
'

echo
echo "Scans run in the background lane at the lowest priority."
echo "Watch progress with: curl -s $BASE_URL/api/v1/queue/stats"
