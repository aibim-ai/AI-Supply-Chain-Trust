#!/usr/bin/env python3
"""Check secret expiry dates from a JSON metadata manifest.

Usage:
    python3 scripts/check_secret_expiry.py --metadata secrets-metadata.json

Exit codes:
    0 — all secrets within rotation window
    1 — overdue secrets found
    2 — secrets due soon (within warning window)

Metadata manifest schema (JSON array):
[
  {
    "name": "github-token",
    "owner": "sec-team",
    "purpose": "Repository read access",
    "created_at": "2026-01-15",
    "rotation_interval_days": 90,
    "next_rotation_due": "2026-04-15",
    "environment": "production"
  }
]
"""

import argparse
import json
import sys
from datetime import date, datetime

WARNING_DAYS = 7  # Warn when a secret is within this many days of expiry


def parse_date(raw: str) -> date:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Unparseable date: {raw}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check secret expiry dates")
    parser.add_argument(
        "--metadata", required=True, help="Path to secrets metadata JSON file"
    )
    args = parser.parse_args()

    with open(args.metadata, encoding="utf-8") as f:
        secrets = json.load(f)

    if not isinstance(secrets, list):
        print("ERROR: metadata must be a JSON array of secret objects")
        return 1

    today = date.today()
    overdue = []
    due_soon = []
    invalid = []

    for index, secret in enumerate(secrets):
        if not isinstance(secret, dict):
            invalid.append(f"entry {index + 1} is not an object")
            continue
        name = secret.get("name", "unnamed")
        env = secret.get("environment", "unknown")
        due_str = secret.get("next_rotation_due")

        if not due_str:
            invalid.append(f"{name} ({env}) has no next_rotation_due field")
            continue

        try:
            due_date = parse_date(due_str)
        except ValueError as e:
            invalid.append(f"{name} ({env}) — {e}")
            continue

        delta = (due_date - today).days

        if delta < 0:
            overdue.append((name, env, abs(delta)))
        elif delta <= WARNING_DAYS:
            due_soon.append((name, env, delta))

    if invalid:
        print(f"INVALID SECRET METADATA ({len(invalid)}):")
        for error in invalid:
            print(f"  - {error}")
        print()
    if overdue:
        print(f"OVERDUE SECRETS ({len(overdue)}):")
        for name, env, days in overdue:
            print(f"  - {name} ({env}): {days} days past rotation deadline")
        print()
    if due_soon:
        print(f"SECRETS DUE SOON ({len(due_soon)}):")
        for name, env, days in due_soon:
            print(f"  - {name} ({env}): {days} days until rotation deadline")
        print()

    if invalid or overdue:
        print("FAIL: invalid metadata or overdue secrets require immediate action.")
        return 1
    if due_soon:
        print("PASS with warnings: some secrets are within the warning window.")
        return 2

    print(f"OK: all {len(secrets)} secrets are within rotation window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
