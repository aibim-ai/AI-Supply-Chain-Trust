use super::fingerprints::fingerprints_from_report;
use serde_json::{json, Value};

pub fn top_risks(report: &Value) -> Value {
    let fingerprints = fingerprints_from_report(report);
    if let Some(items) = fingerprints.as_array().filter(|items| !items.is_empty()) {
        let mut risks: Vec<Value> = Vec::new();
        for fingerprint in items {
            let class = fingerprint
                .get("vuln_class")
                .and_then(Value::as_str)
                .unwrap_or("Security Fix");
            let component = fingerprint
                .get("components")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                .unwrap_or("repository");
            if let Some(existing) = risks.iter_mut().find(|risk| {
                risk.get("vuln_class").and_then(Value::as_str) == Some(class)
                    && risk.get("component").and_then(Value::as_str) == Some(component)
            }) {
                let count = existing
                    .get("fix_count")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + 1;
                existing["fix_count"] = json!(count);
                if let Some(evidence) = existing.get_mut("evidence").and_then(Value::as_array_mut) {
                    if evidence.len() < 5 {
                        evidence.push(
                            fingerprint
                                .get("commit_sha")
                                .filter(|v| !v.is_null())
                                .cloned()
                                .unwrap_or_else(|| {
                                    fingerprint.get("id").cloned().unwrap_or(Value::Null)
                                }),
                        );
                    }
                }
                if severity_rank(
                    fingerprint
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ) > severity_rank(
                    existing
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ) {
                    existing["severity"] = fingerprint
                        .get("severity")
                        .cloned()
                        .unwrap_or(json!("medium"));
                }
            } else {
                risks.push(json!({
                    "vuln_class": class, "severity": fingerprint.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                    "component": component, "fix_count": 1,
                    "rationale": fingerprint.get("summary").and_then(Value::as_str).unwrap_or("Security intelligence indicates recurring risk in this area."),
                    "summary": fingerprint.get("summary").and_then(Value::as_str).unwrap_or("Security intelligence indicates recurring risk in this area."),
                    "evidence": [fingerprint.get("commit_sha").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| fingerprint.get("id").cloned().unwrap_or(Value::Null))],
                    "decision_source": fingerprint.get("decision_source").and_then(Value::as_str).unwrap_or("rule_based"),
                    "rule_based_result": {
                        "vuln_class": class,
                        "severity": fingerprint.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                        "component": component
                    },
                    "llm_assisted_result": fingerprint.get("llm_assisted_result").cloned().unwrap_or(Value::Null)
                }));
            }
        }
        risks.sort_by(|a, b| {
            severity_rank(b.get("severity").and_then(Value::as_str).unwrap_or(""))
                .cmp(&severity_rank(
                    a.get("severity").and_then(Value::as_str).unwrap_or(""),
                ))
                .then_with(|| {
                    b.get("fix_count")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                        .cmp(&a.get("fix_count").and_then(Value::as_i64).unwrap_or(0))
                })
        });
        risks.truncate(5);
        return json!(risks);
    }
    let risks: Vec<Value> = report.get("critical_flags").and_then(Value::as_array).unwrap_or(&Vec::new()).iter().map(|flag| {
        json!({
            "vuln_class": flag.get("code").and_then(Value::as_str).unwrap_or("security_flag"),
            "severity": flag.get("severity").and_then(Value::as_str).unwrap_or("medium"),
            "component": "repository", "fix_count": 1,
            "rationale": flag.get("message").and_then(Value::as_str).unwrap_or("Critical trust flag."),
            "summary": flag.get("message").and_then(Value::as_str).unwrap_or("Critical trust flag."),
            "evidence": [flag.get("evidence").and_then(Value::as_str).unwrap_or("")],
            "decision_source": "rule_based",
            "rule_based_result": {"code": flag.get("code").and_then(Value::as_str).unwrap_or("security_flag"), "severity": flag.get("severity").and_then(Value::as_str).unwrap_or("medium")},
            "llm_assisted_result": Value::Null
        })
    }).collect();
    if risks.is_empty() {
        json!([{"vuln_class": "review_focus", "severity": "low", "component": "repository", "fix_count": 0, "rationale": report.get("action").and_then(Value::as_str).unwrap_or("No critical flags in the latest report."), "summary": report.get("action").and_then(Value::as_str).unwrap_or("No critical flags in the latest report."), "evidence": []}])
    } else {
        json!(risks)
    }
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

pub fn top_severity_from(fingerprints: &Value) -> String {
    fingerprints
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|fp| fp.get("severity").and_then(Value::as_str))
        .max_by_key(|s| severity_rank(s))
        .unwrap_or("none")
        .to_string()
}
