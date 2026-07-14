#!/usr/bin/env python3
"""Shadow mode comparison tool.
Compares Rust server output against Python reference for parity validation.

Usage:
    GITHUB_TOKEN=xxx python3 scripts/shadow_compare.py --repo vercel/next.js
    GITHUB_TOKEN=xxx python3 scripts/shadow_compare.py --sample 10
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from typing import Any

RUST_BINARY = os.environ.get("RUST_BINARY", "./backend/target/release/ai-supply-chain-trust")
RUST_PORT = int(os.environ.get("RUST_PORT", "8001"))
PYTHON_URL = os.environ.get("PYTHON_URL", "https://ai-supply-chain-trust.aibim.ai")
BASE_URL = f"http://localhost:{RUST_PORT}"

DIFF_IGNORE_KEYS = {
    "generated_at", "updated_at", "evaluated_at", "created_at",
    "head_sha", "evaluated_at", "last_analyzed", "commits_scanned",
}


def normalize(obj: Any) -> Any:
    """Recursively remove timestamp fields for comparison."""
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items() if k not in DIFF_IGNORE_KEYS}
    if isinstance(obj, list):
        return [normalize(item) for item in obj]
    return obj


def fetch_json(url: str) -> dict:
    """Fetch JSON from a URL."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def start_rust_server() -> subprocess.Popen:
    """Start the Rust server in the background."""
    env = os.environ.copy()
    env["PORT"] = str(RUST_PORT)
    proc = subprocess.Popen(
        [RUST_BINARY, "serve"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    # Wait for server to be ready
    for _ in range(10):
        try:
            urllib.request.urlopen(f"http://localhost:{RUST_PORT}/health", timeout=1)
            print(f"Rust server ready on port {RUST_PORT}")
            return proc
        except Exception:
            time.sleep(0.5)
    proc.kill()
    raise RuntimeError("Rust server did not start")


def compare_endpoint(ep_name: str, rust_url: str, python_url: str) -> dict:
    """Compare Rust vs Python output for a single endpoint."""
    try:
        rust_data = fetch_json(rust_url)
    except Exception as e:
        return {"endpoint": ep_name, "status": "rust_error", "error": str(e)}

    try:
        python_data = fetch_json(python_url)
    except Exception as e:
        return {"endpoint": ep_name, "status": "python_error", "error": str(e)}

    rust_norm = normalize(rust_data)
    python_norm = normalize(python_data)

    if rust_norm == python_norm:
        return {"endpoint": ep_name, "status": "match"}

    # Find differing paths
    diffs = find_diff_paths(rust_norm, python_norm, "$")
    return {
        "endpoint": ep_name,
        "status": "mismatch",
        "diff_paths": diffs[:20],
        "rust_keys": len(str(rust_norm)),
        "python_keys": len(str(python_norm)),
    }


def find_diff_paths(a: Any, b: Any, path: str) -> list[str]:
    """Find JSON paths where values differ."""
    diffs = []
    if type(a) != type(b):
        diffs.append(path)
    elif isinstance(a, dict):
        all_keys = set(a.keys()) | set(b.keys())
        for key in sorted(all_keys):
            sub_path = f"{path}.{key}"
            if key not in a:
                diffs.append(f"{sub_path} (missing in rust)")
            elif key not in b:
                diffs.append(f"{sub_path} (missing in python)")
            else:
                diffs.extend(find_diff_paths(a[key], b[key], sub_path))
    elif isinstance(a, list):
        for i in range(max(len(a), len(b))):
            sub_path = f"{path}[{i}]"
            if i >= len(a):
                diffs.append(f"{sub_path} (missing in rust)")
            elif i >= len(b):
                diffs.append(f"{sub_path} (missing in python)")
            else:
                diffs.extend(find_diff_paths(a[i], b[i], sub_path))
    elif a != b:
        diffs.append(f"{path}: rust={a!r} python={b!r}")
    return diffs


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Shadow mode comparison")
    parser.add_argument("--repo", help="Single repo to compare")
    parser.add_argument("--sample", type=int, default=0, help="Compare N random repos")
    parser.add_argument("--endpoints", nargs="+", default=["api", "context", "leaderboard"])
    parser.add_argument("--skip-rust", action="store_true", help="Don't start Rust server")
    args = parser.parse_args()

    proc = None
    if not args.skip_rust:
        proc = start_rust_server()

    try:
        repos = []
        if args.repo:
            repos.append(args.repo)
        elif args.sample > 0:
            # Fetch top repos from Python leaderboard
            lb = fetch_json(f"{PYTHON_URL}/api/v1/leaderboard?limit={args.sample}")
            repos = [r["repo"] for r in lb.get("rows", []) if "github.com/" not in r.get("repo", "")]

        results = []
        for repo in repos:
            owner, name = repo.split("/", 1) if "/" in repo else (repo, "")
            print(f"\n--- {repo} ---")

            if "api" in args.endpoints:
                r = compare_endpoint(f"{repo}/api", f"{BASE_URL}/api", f"{PYTHON_URL}/api")
                results.append(r)
                print(f"  API: {r['status']}")

            if "context" in args.endpoints:
                r = compare_endpoint(
                    f"{repo}/context",
                    f"{BASE_URL}/api/v1/context/{owner}/{name}",
                    f"{PYTHON_URL}/api/v1/context/{owner}/{name}",
                )
                results.append(r)
                label = r['status']
                if label == "mismatch" and "diff_paths" in r:
                    diff_count = len(r["diff_paths"])
                    print(f"  Context: MISMATCH ({diff_count} diffs)")
                    for d in r["diff_paths"][:5]:
                        print(f"    {d}")
                else:
                    print(f"  Context: {label}")

        matches = sum(1 for r in results if r["status"] == "match")
        mismatches = sum(1 for r in results if r["status"] == "mismatch")
        errors = sum(1 for r in results if "error" in r["status"])
        total = len(results)

        print(f"\n{'='*50}")
        print(f"Shadow Mode Results: {matches}/{total} match, {mismatches} mismatch, {errors} errors")
        if mismatches > 0:
            print("DISCREPANCY DETECTED — Rust output does not match Python.")
            sys.exit(1)
        elif total == 0:
            print("No repos compared.")
        else:
            print("ALL MATCH — Rust output identical to Python.")

    finally:
        if proc:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    main()
