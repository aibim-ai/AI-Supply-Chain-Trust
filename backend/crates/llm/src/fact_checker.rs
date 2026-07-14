use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum FactCheckError {
    #[error("claimed fact absent from LLM input: {0}")]
    MissingFact(String),
    #[error("invalid evidence reference: {0}")]
    InvalidEvidenceRef(String),
    #[error("severity upgrade lacks cited input evidence")]
    UnsupportedSeverityUpgrade,
    #[error("package identity is not grounded in deterministic input")]
    UnboundPackageIdentity,
}

#[derive(Debug, Clone)]
pub struct FactCheckResult {
    pub checked_claims: usize,
}

pub fn verify_llm_output(input: &Value, output: &Value) -> Result<FactCheckResult, FactCheckError> {
    verify_evidence_refs(input, output)?;
    verify_package_identity(input, output)?;
    verify_claimed_facts(input, output)?;
    verify_severity_upgrade(input, output)?;
    Ok(FactCheckResult {
        checked_claims: extract_claims(output).len(),
    })
}

fn verify_package_identity(input: &Value, output: &Value) -> Result<(), FactCheckError> {
    if output.get("status").and_then(Value::as_str) != Some("resolved") {
        return Ok(());
    }
    let expected_ecosystem = input
        .pointer("/rule_based_result/ecosystem")
        .and_then(Value::as_str);
    let expected_package = input
        .pointer("/rule_based_result/package_name")
        .and_then(Value::as_str);
    let actual_ecosystem = output.get("ecosystem").and_then(Value::as_str);
    let actual_package = output.get("package_name").and_then(Value::as_str);
    if expected_ecosystem.is_none()
        || expected_package.is_none()
        || actual_ecosystem != expected_ecosystem
        || actual_package != expected_package
    {
        return Err(FactCheckError::UnboundPackageIdentity);
    }
    Ok(())
}

pub fn rejected_output(input: &Value, output: &Value, reason: &str) -> Value {
    json!({
        "status": "rejected_hallucination",
        "decision_source": "rejected_hallucination",
        "reason": reason,
        "input_hash": crate::llm_client::input_hash(input),
        "rejected_output": output
    })
}

fn verify_evidence_refs(input: &Value, output: &Value) -> Result<(), FactCheckError> {
    let allowed = collect_evidence_refs(input);
    for reference in collect_string_field_values(output, "evidence_ref")
        .into_iter()
        .chain(collect_array_string_field_values(output, "evidence_refs"))
    {
        if !allowed.contains(&reference) {
            return Err(FactCheckError::InvalidEvidenceRef(reference));
        }
    }
    Ok(())
}

fn verify_claimed_facts(input: &Value, output: &Value) -> Result<(), FactCheckError> {
    let haystack = serde_json::to_string(input).unwrap_or_default();
    for claim in extract_claims(output) {
        if !haystack.contains(&claim) {
            return Err(FactCheckError::MissingFact(claim));
        }
    }
    Ok(())
}

fn verify_severity_upgrade(input: &Value, output: &Value) -> Result<(), FactCheckError> {
    let rule_sev = input
        .pointer("/rule_based_result/severity")
        .or_else(|| input.pointer("/rule_based_result/risk_level"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let llm_sev = output
        .get("severity")
        .or_else(|| output.get("risk_level"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if severity_rank(llm_sev) > severity_rank(rule_sev)
        && !collect_array_string_field_values(output, "evidence_refs").is_empty()
    {
        return Ok(());
    }
    if severity_rank(llm_sev) > severity_rank(rule_sev) {
        return Err(FactCheckError::UnsupportedSeverityUpgrade);
    }
    Ok(())
}

fn severity_rank(value: &str) -> i32 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn collect_evidence_refs(input: &Value) -> Vec<String> {
    let mut refs = Vec::new();
    collect_field_values(input, &["id", "evidence_ref"], &mut refs);
    refs
}

fn collect_string_field_values(value: &Value, field: &str) -> Vec<String> {
    let mut found = Vec::new();
    collect_field_values(value, &[field], &mut found);
    found
}

fn collect_array_string_field_values(value: &Value, field: &str) -> Vec<String> {
    let mut found = Vec::new();
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get(field) {
                found.extend(items.iter().filter_map(Value::as_str).map(String::from));
            }
            for child in map.values() {
                found.extend(collect_array_string_field_values(child, field));
            }
        }
        Value::Array(items) => {
            for child in items {
                found.extend(collect_array_string_field_values(child, field));
            }
        }
        _ => {}
    }
    found
}

fn collect_field_values(value: &Value, fields: &[&str], found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for field in fields {
                if let Some(text) = map.get(*field).and_then(Value::as_str) {
                    found.push(text.to_string());
                }
            }
            for child in map.values() {
                collect_field_values(child, fields, found);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_field_values(child, fields, found);
            }
        }
        _ => {}
    }
}

fn extract_claims(output: &Value) -> Vec<String> {
    let mut text = String::new();
    collect_strings(output, &mut text);
    let mut claims = Vec::new();
    for token in text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
    }) {
        let t = token.trim_matches('.');
        if is_claim_token(t) && !claims.iter().any(|existing| existing == t) {
            claims.push(t.to_string());
        }
    }
    claims
}

fn collect_strings(value: &Value, out: &mut String) {
    match value {
        Value::String(s) => {
            out.push(' ');
            out.push_str(s);
        }
        Value::Array(items) => {
            for child in items {
                collect_strings(child, out);
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                collect_strings(child, out);
            }
        }
        _ => {}
    }
}

fn is_claim_token(token: &str) -> bool {
    is_cve(token)
        || is_ghsa(token)
        || is_cwe(token)
        || looks_like_sha(token)
        || looks_like_path(token)
}

fn is_cve(token: &str) -> bool {
    let parts: Vec<&str> = token.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

fn is_ghsa(token: &str) -> bool {
    token.starts_with("GHSA-")
}

fn is_cwe(token: &str) -> bool {
    token.starts_with("CWE-") && token[4..].chars().all(|c| c.is_ascii_digit())
}

fn looks_like_sha(token: &str) -> bool {
    (7..=40).contains(&token.len()) && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_path(token: &str) -> bool {
    token.contains('/')
        && (token.ends_with(".rs")
            || token.ends_with(".py")
            || token.ends_with(".js")
            || token.ends_with(".ts")
            || token.ends_with(".tsx")
            || token.ends_with(".c")
            || token.ends_with(".cpp")
            || token.ends_with(".h")
            || token.ends_with(".hpp")
            || token.ends_with(".go")
            || token.ends_with(".java"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_invented_cve() {
        let input = json!({"evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]});
        let output = json!({"status": "classified", "evidence_refs": ["commit_1"], "rationale": "CVE-2024-99999"});
        assert!(matches!(
            verify_llm_output(&input, &output),
            Err(FactCheckError::MissingFact(_))
        ));
    }

    #[test]
    fn rejects_invented_path() {
        let input = json!({"evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]});
        let output = json!({"status": "classified", "evidence_refs": ["commit_1"], "rationale": "src/auth.rs"});
        assert!(matches!(
            verify_llm_output(&input, &output),
            Err(FactCheckError::MissingFact(_))
        ));
    }

    #[test]
    fn rejects_bad_evidence_ref() {
        let input = json!({"evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]});
        let output =
            json!({"status": "classified", "evidence_refs": ["commit_2"], "rationale": "bounds"});
        assert!(matches!(
            verify_llm_output(&input, &output),
            Err(FactCheckError::InvalidEvidenceRef(_))
        ));
    }

    #[test]
    fn rejects_unsupported_severity_upgrade() {
        let input = json!({"rule_based_result": {"severity": "low"}, "evidence": [{"id": "commit_1", "subject": "fix parser bounds"}]});
        let output = json!({"status": "classified", "severity": "critical", "evidence_refs": [], "rationale": "bounds"});
        assert!(matches!(
            verify_llm_output(&input, &output),
            Err(FactCheckError::UnsupportedSeverityUpgrade)
        ));
    }

    #[test]
    fn accepts_grounded_claims() {
        let input = json!({"evidence": [{"id": "commit_1", "sha": "9704c8e9fcc5", "path": "src/auth.rs", "subject": "fix CVE-2025-0001 CWE-287"}]});
        let output = json!({"status": "classified", "evidence_refs": ["commit_1"], "rationale": "CVE-2025-0001 CWE-287 src/auth.rs 9704c8e9fcc5"});
        assert!(verify_llm_output(&input, &output).is_ok());
    }

    #[test]
    fn rejects_llm_substitution_of_package_identity() {
        let input = json!({
            "rule_based_result": {"ecosystem": "npm", "package_name": "harmless-repo"},
            "evidence": [{"id": "repo_1", "ecosystem": "npm", "package_name": "harmless-repo"}]
        });
        let output = json!({
            "status": "resolved",
            "ecosystem": "PyPI",
            "package_name": "django",
            "aliases": [],
            "evidence_refs": ["repo_1"],
            "rationale": "resolved"
        });
        assert!(matches!(
            verify_llm_output(&input, &output),
            Err(FactCheckError::UnboundPackageIdentity)
        ));
    }

    #[test]
    fn accepts_exact_deterministic_package_identity() {
        let input = json!({
            "rule_based_result": {"ecosystem": "npm", "package_name": "harmless-repo"},
            "evidence": [{"id": "repo_1", "ecosystem": "npm", "package_name": "harmless-repo"}]
        });
        let output = json!({
            "status": "resolved",
            "ecosystem": "npm",
            "package_name": "harmless-repo",
            "aliases": [],
            "evidence_refs": ["repo_1"],
            "rationale": "resolved"
        });
        assert!(verify_llm_output(&input, &output).is_ok());
    }
}
