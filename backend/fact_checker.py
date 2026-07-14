#!/usr/bin/env python3
"""Deterministic post-response checks for LLM outputs.

This mirrors the Rust guardrail policy for CI/source-boundary tests. Runtime
Rust decisions remain authoritative; this module exists so the documented
Python-named guardrail deliverable is executable and adversarially tested.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


CLAIM_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|CWE-\d+|[0-9a-fA-F]{7,40}|[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+\.(?:rs|py|js|ts|tsx|c|cpp|h|hpp|go|java))\b"
)

SEVERITIES = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "unknown": 0}


@dataclass(frozen=True)
class FactCheckResult:
    checked_claims: int


class FactCheckError(ValueError):
    pass


def input_hash(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def verify_llm_output(input_payload: Any, output_payload: Any) -> FactCheckResult:
    allowed_refs = set(_collect_field_values(input_payload, {"id", "evidence_ref"}))
    for ref in _collect_evidence_refs(output_payload):
        if ref not in allowed_refs:
            raise FactCheckError(f"invalid evidence reference: {ref}")

    haystack = json.dumps(input_payload, sort_keys=True)
    claims = _extract_claims(output_payload)
    for claim in claims:
        if claim not in haystack:
            raise FactCheckError(f"claimed fact absent from LLM input: {claim}")

    _verify_severity_upgrade(input_payload, output_payload)
    return FactCheckResult(checked_claims=len(claims))


def rejected_output(input_payload: Any, output_payload: Any, reason: str) -> dict[str, Any]:
    return {
        "status": "rejected_hallucination",
        "decision_source": "rejected_hallucination",
        "reason": reason,
        "input_hash": input_hash(input_payload),
        "rejected_output": output_payload,
    }


def _extract_claims(value: Any) -> list[str]:
    text = " ".join(_walk_strings(value))
    claims: list[str] = []
    for match in CLAIM_RE.finditer(text):
        claim = match.group(0).rstrip(".")
        if claim not in claims:
            claims.append(claim)
    return claims


def _collect_evidence_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "evidence_ref" and isinstance(child, str):
                refs.append(child)
            elif key == "evidence_refs" and isinstance(child, list):
                refs.extend(item for item in child if isinstance(item, str))
            else:
                refs.extend(_collect_evidence_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_collect_evidence_refs(child))
    return refs


def _collect_field_values(value: Any, names: set[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names and isinstance(child, str):
                found.append(child)
            found.extend(_collect_field_values(child, names))
    elif isinstance(value, list):
        for child in value:
            found.extend(_collect_field_values(child, names))
    return found


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for child in value.values():
            out.extend(_walk_strings(child))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for child in value:
            out.extend(_walk_strings(child))
        return out
    return []


def _severity_rank(value: str) -> int:
    return SEVERITIES.get(value.lower(), 0)


def _first_string(value: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        return ""
    for key in keys:
        child = value.get(key)
        if isinstance(child, str):
            return child
    return ""


def _verify_severity_upgrade(input_payload: Any, output_payload: Any) -> None:
    rule = input_payload.get("rule_based_result", {}) if isinstance(input_payload, dict) else {}
    rule_severity = _first_string(rule, ("severity", "risk_level"))
    output_severity = _first_string(output_payload, ("severity", "risk_level"))
    if _severity_rank(output_severity) > _severity_rank(rule_severity) and not _collect_evidence_refs(output_payload):
        raise FactCheckError("severity upgrade lacks cited input evidence")
