#!/usr/bin/env python3
"""Shared Python guardrail wrapper for OpenRouter JSON-schema calls.

The production service uses the Rust `ai_supply_chain_trust_llm` crate. This module is
kept as the executable Python-named contract required by the audit: every
Python-side LLM integration must use this wrapper and its deterministic
`fact_checker.verify_llm_output` gate before a response can be cached,
persisted, or rendered.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any

from fact_checker import input_hash, verify_llm_output


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4.1-mini"

SYSTEM_PROMPT = """You are a bounded security reasoning layer.
You may only use evidence provided in the input JSON.
You have no knowledge of this repository beyond what is provided below. Do not use any prior knowledge about this project, its maintainers, or its vulnerability history.
Never invent CVEs, commit SHAs, file paths, vulnerability claims, package names, severity numbers, or facts not present in the input.
If evidence is insufficient, output {"status":"insufficient_evidence"} rather than guessing.
Justifications must cite evidence_refs by ID and must not restate uncited facts in prose."""


class LlmUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class LlmGuardrail:
    api_key: str
    model: str = DEFAULT_MODEL
    timeout: int = 20

    @classmethod
    def from_env(cls) -> "LlmGuardrail":
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise LlmUnavailable("OPENROUTER_API_KEY is required for LLM decisions")
        return cls(
            api_key=api_key,
            model=os.environ.get("OPENROUTER_MODEL_PRIMARY", DEFAULT_MODEL),
            timeout=int(os.environ.get("OPENROUTER_TIMEOUT", "20")),
        )

    def decide(self, task: str, input_payload: Any, output_schema: dict[str, Any]) -> dict[str, Any]:
        raw = self._chat_json_schema(task, input_payload, output_schema)
        result = verify_llm_output(input_payload, raw)
        raw["decision_source"] = "llm_verified"
        raw["model"] = self.model
        raw["checked_claims"] = result.checked_claims
        raw["input_hash"] = input_hash(input_payload)
        return raw

    def _chat_json_schema(self, task: str, input_payload: Any, output_schema: dict[str, Any]) -> dict[str, Any]:
        body = {
            "model": self.model,
            "temperature": 0,
            "top_p": 1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(input_payload, sort_keys=True)},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": task, "strict": True, "schema": output_schema},
            },
        }
        req = urllib.request.Request(
            OPENROUTER_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "authorization": f"Bearer {self.api_key}",
                "content-type": "application/json",
                "user-agent": "ai-supply-chain-trust/0.2.0 OpenRouter",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read())
        content = payload["choices"][0]["message"]["content"]
        return json.loads(content)


def unavailable_decision(reason: str, rule_based_result: Any) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "decision_source": "rule_fallback_llm_unavailable",
        "reason": reason,
        "rule_based_result": rule_based_result,
    }
