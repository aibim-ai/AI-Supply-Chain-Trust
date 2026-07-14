#!/usr/bin/env python3
"""CI source-boundary checks for the LLM hallucination guard."""

from __future__ import annotations

import pathlib
import sys
import unittest

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from fact_checker import FactCheckError, rejected_output, verify_llm_output  # noqa: E402

OPENROUTER_ENDPOINT = "openrouter.ai/api/v1/" + "chat/completions"


class LlmGuardrailBoundaryTests(unittest.TestCase):
    def test_openrouter_calls_are_confined_to_llm_crate(self) -> None:
        offenders: list[str] = []
        for path in BACKEND_ROOT.rglob("*.rs"):
            rel = path.relative_to(BACKEND_ROOT).as_posix()
            if rel.startswith("target/"):
                continue
            text = path.read_text(encoding="utf-8")
            if OPENROUTER_ENDPOINT in text and not rel.startswith("crates/llm/"):
                offenders.append(rel)
        self.assertEqual(offenders, [], "OpenRouter API calls must pass through crates/llm")

    def test_python_openrouter_calls_are_confined_to_guardrail_wrapper(self) -> None:
        offenders: list[str] = []
        for path in BACKEND_ROOT.rglob("*.py"):
            rel = path.relative_to(BACKEND_ROOT).as_posix()
            if rel.startswith(("target/", ".venv/")):
                continue
            text = path.read_text(encoding="utf-8")
            if OPENROUTER_ENDPOINT in text and rel != "llm_guardrail.py":
                offenders.append(rel)
        self.assertEqual(offenders, [], "Python OpenRouter calls must pass through llm_guardrail.py")

    def test_only_llm_client_contains_openrouter_endpoint(self) -> None:
        offenders: list[str] = []
        for path in (BACKEND_ROOT / "crates/llm/src").rglob("*.rs"):
            rel = path.relative_to(BACKEND_ROOT).as_posix()
            text = path.read_text(encoding="utf-8")
            if OPENROUTER_ENDPOINT in text and rel != "crates/llm/src/llm_client.rs":
                offenders.append(rel)
        self.assertEqual(offenders, [], "OpenRouter endpoint must stay centralized in llm_client.rs")

    def test_every_pipeline_llm_reference_uses_guarded_crate(self) -> None:
        offenders: list[str] = []
        for path in BACKEND_ROOT.rglob("*.rs"):
            rel = path.relative_to(BACKEND_ROOT).as_posix()
            if rel.startswith(("target/", "crates/llm/")):
                continue
            text = path.read_text(encoding="utf-8")
            if "reqwest" in text and "OPENROUTER" in text:
                offenders.append(rel)
        self.assertEqual(offenders, [], "Non-LLM crates must not build ad hoc OpenRouter clients")

    def test_openrouter_request_is_deterministic_strict_json_schema(self) -> None:
        text = (BACKEND_ROOT / "crates/llm/src/llm_client.rs").read_text(encoding="utf-8")
        self.assertIn('"temperature": 0', text)
        self.assertIn('"top_p": 1', text)
        self.assertIn('"response_format"', text)
        self.assertIn('"type": "json_schema"', text)
        self.assertIn('"strict": true', text)

    def test_task_prompt_forbids_model_knowledge_and_prefers_insufficient_evidence(self) -> None:
        text = (BACKEND_ROOT / "crates/llm/src/tasks.rs").read_text(encoding="utf-8")
        self.assertIn("only use evidence provided in the input JSON", text)
        self.assertIn("no knowledge of this repository beyond what is provided", text)
        self.assertIn("Never invent CVEs", text)
        self.assertIn("insufficient_evidence", text)
        self.assertIn('"decision_source": "rule_fallback_llm_unavailable"', text)

    def test_guardrail_tests_are_ci_executed(self) -> None:
        workflow = REPO_ROOT / ".github/workflows/rust-ci.yml"
        text = workflow.read_text(encoding="utf-8")
        self.assertIn("cargo test --workspace", text)
        self.assertIn("backend/tests/test_llm_hallucination_guard.py", text)

    def test_python_fact_checker_rejects_invented_cve(self) -> None:
        input_payload = {"evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]}
        output_payload = {
            "status": "classified",
            "evidence_refs": ["commit_1"],
            "rationale": "Confirmed CVE-2024-99999",
        }
        with self.assertRaises(FactCheckError):
            verify_llm_output(input_payload, output_payload)

    def test_python_fact_checker_rejects_bad_evidence_ref(self) -> None:
        input_payload = {"evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]}
        output_payload = {"status": "classified", "evidence_refs": ["commit_2"], "rationale": "bounds"}
        with self.assertRaises(FactCheckError):
            verify_llm_output(input_payload, output_payload)

    def test_python_fact_checker_rejects_unsupported_severity_upgrade(self) -> None:
        input_payload = {"rule_based_result": {"severity": "low"}, "evidence": [{"id": "commit_1"}]}
        output_payload = {
            "status": "classified",
            "severity": "critical",
            "evidence_refs": [],
            "rationale": "bounds",
        }
        with self.assertRaises(FactCheckError):
            verify_llm_output(input_payload, output_payload)

    def test_python_fact_checker_rejects_prior_knowledge_on_fake_repo(self) -> None:
        input_payload = {
            "repo": "fakewolf/fakewolfssl",
            "rule_based_result": {"severity": "low"},
            "evidence": [{"id": "commit_1", "sha": "9704c8e9fcc5", "subject": "tighten parser bounds"}],
        }
        output_payload = {
            "status": "classified",
            "severity": "high",
            "evidence_refs": ["commit_1"],
            "rationale": "wolfSSL CVE-2022-42961 proves this parser path is exploitable",
        }
        with self.assertRaises(FactCheckError):
            verify_llm_output(input_payload, output_payload)

    def test_python_rejected_output_is_not_llm_verified(self) -> None:
        value = rejected_output({"evidence": []}, {"status": "classified"}, "bad")
        self.assertEqual(value["decision_source"], "rejected_hallucination")
        self.assertIn("input_hash", value)


if __name__ == "__main__":
    unittest.main()
