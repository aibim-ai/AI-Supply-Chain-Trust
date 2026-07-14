use serde_json::{json, Value};

use crate::guardrail::{GuardrailError, LlmGuardrail};
use crate::llm_client::LlmUnavailableError;

pub const SYSTEM_PROMPT: &str = r#"You are a bounded security reasoning layer.
You may only use evidence provided in the input JSON.
You have no knowledge of this repository beyond what is provided below. Do not use any prior knowledge about this project, its maintainers, or its vulnerability history.
Never invent CVEs, commit SHAs, file paths, vulnerability claims, package names, severity numbers, or facts not present in the input.
If evidence is insufficient, output {"status":"insufficient_evidence"} rather than guessing.
Justifications must cite evidence_refs by ID and must not restate uncited facts in prose."#;

pub fn vuln_classifier_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "vuln_class", "severity", "confidence", "evidence_refs", "rationale"],
        "properties": {
            "status": {"type": "string", "enum": ["classified", "insufficient_evidence"]},
            "vuln_class": {"type": "string", "enum": [
                "Auth Bypass", "Cross-Site Scripting", "CSRF", "Server-Side Request Forgery",
                "Denial of Service", "Path Traversal", "Injection", "Use After Free",
                "Double Free", "Buffer Overflow", "Integer Overflow", "Out-of-Bounds Access",
                "NULL Pointer Dereference", "Race Condition", "Information Disclosure",
                "Remote Code Execution", "Privilege Escalation", "Timing/Side-Channel",
                "Format String", "Type Confusion", "Insecure Deserialization", "Security Fix",
                "unknown"
            ]},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "unknown"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"}
        }
    })
}

pub fn lead_severity_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "severity", "confidence", "evidence_refs", "rationale"],
        "properties": {
            "status": {"type": "string", "enum": ["ranked", "insufficient_evidence"]},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "unknown"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"}
        }
    })
}

pub fn ecosystem_resolver_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "ecosystem", "package_name", "aliases", "evidence_refs", "rationale"],
        "properties": {
            "status": {"type": "string", "enum": ["resolved", "insufficient_evidence"]},
            "ecosystem": {"type": "string"},
            "package_name": {"type": "string"},
            "aliases": {"type": "array", "items": {"type": "string"}},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"}
        }
    })
}

pub fn trust_note_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "risk_level", "evidence_refs", "rationale"],
        "properties": {
            "status": {"type": "string", "enum": ["noted", "insufficient_evidence"]},
            "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low", "unknown"]},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"}
        }
    })
}

pub fn summary_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "summary", "evidence_refs"],
        "properties": {
            "status": {"type": "string", "enum": ["summarized", "insufficient_evidence"]},
            "summary": {"type": "string"},
            "evidence_refs": {"type": "array", "items": {"type": "string"}}
        }
    })
}

pub async fn classify_vulnerability(input: &Value) -> Result<Value, GuardrailError> {
    LlmGuardrail::from_env()?
        .decide(
            "vulnerability_classification",
            SYSTEM_PROMPT,
            input,
            &vuln_classifier_schema(),
        )
        .await
}

pub async fn resolve_ecosystem(input: &Value) -> Result<Value, GuardrailError> {
    LlmGuardrail::from_env()?
        .decide(
            "ecosystem_resolution",
            SYSTEM_PROMPT,
            input,
            &ecosystem_resolver_schema(),
        )
        .await
}

pub async fn score_lead(input: &Value) -> Result<Value, GuardrailError> {
    LlmGuardrail::from_env()?
        .decide(
            "lead_severity",
            SYSTEM_PROMPT,
            input,
            &lead_severity_schema(),
        )
        .await
}

pub async fn write_summary(input: &Value) -> Result<Value, GuardrailError> {
    LlmGuardrail::from_env()?
        .decide("trust_summary", SYSTEM_PROMPT, input, &summary_schema())
        .await
}

pub fn unavailable_decision(reason: impl ToString, rule_based_result: Value) -> Value {
    json!({
        "status": "unavailable",
        "decision_source": "rule_fallback_llm_unavailable",
        "reason": reason.to_string(),
        "rule_based_result": rule_based_result
    })
}

pub fn unavailable_decision_for(
    task: &str,
    error: &LlmUnavailableError,
    rule_based_result: Value,
) -> Value {
    let mut value = unavailable_decision(error, rule_based_result);
    if let Some(object) = value.as_object_mut() {
        object.insert("task".into(), Value::String(task.to_string()));
        object.insert(
            "error_type".into(),
            Value::String(error.category().to_string()),
        );
        if let Some(status) = error.http_status() {
            object.insert(
                "http_status".into(),
                Value::Number(serde_json::Number::from(status)),
            );
        }
    }
    value
}

pub fn rejected_hallucination_decision(reason: impl ToString, rule_based_result: Value) -> Value {
    json!({
        "status": "rejected_hallucination",
        "decision_source": "rejected_hallucination",
        "reason": reason.to_string(),
        "rule_based_result": rule_based_result
    })
}

pub fn rejected_hallucination_decision_for(
    task: &str,
    reason: impl ToString,
    rule_based_result: Value,
) -> Value {
    let mut value = rejected_hallucination_decision(reason, rule_based_result);
    if let Some(object) = value.as_object_mut() {
        object.insert("task".into(), Value::String(task.to_string()));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_schemas_are_closed_and_require_grounding_fields() {
        let schemas = [
            vuln_classifier_schema(),
            lead_severity_schema(),
            ecosystem_resolver_schema(),
            trust_note_schema(),
            summary_schema(),
        ];

        for schema in schemas {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            let required = schema["required"].as_array().unwrap();
            assert!(required.iter().any(|field| field == "status"));
            assert!(required.iter().any(|field| field == "evidence_refs"));
            assert_eq!(
                schema["properties"]["evidence_refs"]["items"]["type"],
                "string"
            );
        }
        assert!(SYSTEM_PROMPT.contains("insufficient_evidence"));
        assert!(SYSTEM_PROMPT.contains("Never invent CVEs"));
    }

    #[test]
    fn fallback_decisions_preserve_reason_and_rule_result() {
        let rule_result = json!({"severity": "medium"});
        let unavailable = unavailable_decision("quota", rule_result.clone());
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["reason"], "quota");
        assert_eq!(unavailable["rule_based_result"], rule_result);

        let rejected = rejected_hallucination_decision("invented CVE", rule_result.clone());
        assert_eq!(rejected["status"], "rejected_hallucination");
        assert_eq!(rejected["decision_source"], "rejected_hallucination");
        assert_eq!(rejected["reason"], "invented CVE");
        assert_eq!(rejected["rule_based_result"], rule_result);

        let rate_limited = LlmUnavailableError::HttpStatus {
            status: 429,
            message: "busy".into(),
            retry_after_seconds: Some(2),
        };
        let unavailable = unavailable_decision_for(
            "ecosystem_resolution",
            &rate_limited,
            json!({"ecosystem": "npm"}),
        );
        assert_eq!(unavailable["task"], "ecosystem_resolution");
        assert_eq!(unavailable["error_type"], "rate_limited");
        assert_eq!(unavailable["http_status"], 429);
    }
}
