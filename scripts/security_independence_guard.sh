#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

scan_paths=(
  backend
  frontend
  .github
  scripts
)

exclude_globs=(
  --glob '!backend/target/**'
  --glob '!target/**'
  --glob '!frontend/web/**'
  --glob '!frontend/coverage/**'
  --glob '!**/*.png'
  --glob '!**/*.jpg'
  --glob '!**/*.jpeg'
  --glob '!**/*.gif'
  --glob '!docs/**'
  --glob '!scripts/security_independence_guard.sh'
)

fail=0

echo "Checking for forbidden third-party security-context endpoints..."
if rg -n 'https?://[^[:space:]"'"'"']*securitycontext[^[:space:]"'"'"']*|[A-Za-z0-9.-]*securitycontext[.][A-Za-z0-9.-]*|imported-securitycontext|security_context_override|imported_context' "${scan_paths[@]}" "${exclude_globs[@]}"; then
  echo "ERROR: forbidden third-party security-context dependency or imported-data marker found."
  fail=1
fi

echo "Checking for suspicious repo-specific hardcoded metric shortcuts..."
if rg -n 'wolfssl[^[:cntrl:]]*(456|50|21314|922299)|(456|50|21314|922299)[^[:cntrl:]]*wolfssl' "${scan_paths[@]}" "${exclude_globs[@]}"; then
  echo "ERROR: suspicious wolfssl-specific metric shortcut found."
  fail=1
fi

if rg -n '(owner|repo|slug|name)[^[:cntrl:]]*(==|!=|eq|contains|starts_with)[^[:cntrl:]]*(wolfssl|vercel|next[.]js)[^[:cntrl:]]*(return|json!|Some|Ok)[^[:cntrl:]]*[0-9]{2,}' backend frontend scripts "${exclude_globs[@]}"; then
  echo "ERROR: suspicious repo-name branch returning numeric data found."
  fail=1
fi

if rg -n '"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"[^[:cntrl:]]*(fixes|cves|commits|commit_count|commits_scanned|known_cves|fingerprints)[^[:cntrl:]]*[0-9]{2,}|(fixes|cves|commits|commit_count|commits_scanned|known_cves|fingerprints)[^[:cntrl:]]*[0-9]{2,}[^[:cntrl:]]*"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"' "${scan_paths[@]}" "${exclude_globs[@]}"; then
  echo "ERROR: suspicious repo slug plus hardcoded security metric found."
  fail=1
fi

echo "Checking production deploy does not cap security-fix history..."
if rg -n 'AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS=(500|[1-9][0-9]{0,2})' .github/deploy/production scripts; then
  echo "ERROR: production security history fix-commit cap would undercount benchmark repositories."
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "Security data independence guard passed."
