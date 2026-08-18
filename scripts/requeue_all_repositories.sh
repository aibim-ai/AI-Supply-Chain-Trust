#!/usr/bin/env bash
#
# Gradually re-scan every repository already in the public inventory.
#
# WHY THIS EXISTS
# ---------------
# Scored fields (trust_score, grade, evidence_coverage, confidence,
# missing_evidence, critical_flags) are frozen into each stored report at scan
# time. A scoring or pipeline fix therefore does not change any existing
# report — every repository has to be scanned again to pick it up.
#
# The obvious lever, bumping LIVE_SECURITY_CONTEXT_VERSION, is deliberately NOT
# used here. That constant does double duty: besides marking reports stale it is
# also rule 2 of the evidence gate in `ready_evidence_summary`, so bumping it
# puts every stored report into `security_context_evidence_missing` at once and
# every /r/<owner>/<repo> page renders "Context needs evidence" until that repo
# has been re-scanned. This script instead enqueues repositories in bounded
# batches: nothing is invalidated, pages keep serving their current context, and
# each repository flips to corrected data as its own scan lands.
#
# RUN THIS ONLY AFTER THE FIX IS DEPLOYED. Against an older build it just
# reproduces the same values it is meant to correct.
#
# Usage:
#   scripts/requeue_all_repositories.sh [BASE_URL]
#
# Environment:
#   BATCH_SIZE   repositories enqueued per drain cycle (default 50)
#   POLL_SECONDS seconds between queue-depth checks   (default 20)
#   DRY_RUN=1    list what would be enqueued, send nothing

set -euo pipefail

BASE_URL="${1:-${BASE_URL:-https://ai-supply-chain-trust.aibim.ai}}"
BATCH_SIZE="${BATCH_SIZE:-50}"
POLL_SECONDS="${POLL_SECONDS:-20}"
DRY_RUN="${DRY_RUN:-0}"

# The server rejects enqueues past AI_SUPPLY_CHAIN_TRUST_MAX_QUEUED_SCANS
# (default 100), so stay well under it and wait for the queue to drain.
QUEUE_HEADROOM="${QUEUE_HEADROOM:-60}"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
require curl
require python3

echo "Target: $BASE_URL"

repositories() {
  # recent-scans now returns one row per distinct repository, so a single call
  # with a high limit enumerates the whole inventory.
  curl -fsS "$BASE_URL/api/v1/recent-scans?limit=50000" \
    | python3 -c 'import json,sys
rows = json.load(sys.stdin).get("rows", [])
for row in rows:
    repo = (row.get("repo") or "").strip("/")
    if repo.count("/") == 1:
        print(repo)'
}

queue_depth() {
  curl -fsS "$BASE_URL/api/v1/queue/stats" \
    | python3 -c 'import json,sys
stats = json.load(sys.stdin)
print(int(stats.get("queued", 0) or 0) + int(stats.get("active", 0) or 0))' 2>/dev/null || echo 0
}

# Buffered to a file rather than `mapfile`, which macOS's bash 3.2 does not have.
REPO_LIST="$(mktemp)"
trap 'rm -f "$REPO_LIST"' EXIT
repositories > "$REPO_LIST"

TOTAL="$(wc -l < "$REPO_LIST" | tr -d ' ')"
if [ "${TOTAL:-0}" -eq 0 ]; then
  echo "No repositories returned; nothing to do." >&2
  exit 1
fi
echo "Inventory: $TOTAL repositories"

if [ "$DRY_RUN" = "1" ]; then
  cat "$REPO_LIST"
  echo "DRY_RUN=1 — nothing enqueued."
  exit 0
fi

enqueued=0
failed=0
while IFS= read -r repo; do
  [ -n "$repo" ] || continue
  # Wait for the queue to drop below the headroom before adding more, so this
  # never competes with live user-initiated scans for queue capacity.
  while [ "$(queue_depth)" -ge "$QUEUE_HEADROOM" ]; do
    echo "  queue at capacity, waiting ${POLL_SECONDS}s ..."
    sleep "$POLL_SECONDS"
  done

  # Negative priority keeps these behind anything a real visitor requests.
  if curl -fsS -X POST "$BASE_URL/api/v1/queue/rescan" \
      -H 'Content-Type: application/json' \
      -d "{\"repo\":\"$repo\",\"priority\":-100}" >/dev/null 2>&1; then
    enqueued=$((enqueued + 1))
  else
    failed=$((failed + 1))
    echo "  enqueue failed: $repo" >&2
  fi

  if [ $(((enqueued + failed) % BATCH_SIZE)) -eq 0 ]; then
    echo "  progress: $((enqueued + failed))/$TOTAL (enqueued=$enqueued failed=$failed)"
    sleep "$POLL_SECONDS"
  fi
done < "$REPO_LIST"

echo "Done. enqueued=$enqueued failed=$failed total=$TOTAL"
echo "Watch progress with: curl -s $BASE_URL/api/v1/queue/stats"
