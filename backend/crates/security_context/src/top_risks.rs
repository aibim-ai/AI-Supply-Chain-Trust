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

pub fn severity_rank(value: &str) -> i32 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Canonical label for a rank produced by [`severity_rank`].
fn severity_label(rank: i32) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "none",
    }
}

/// Standard CVSS v3 severity bands. This is the one shared place where a
/// numeric CVSS score is turned into a severity word.
pub fn severity_from_cvss(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

/// Severity rank of a single `known_cves` row: the explicit severity word wins,
/// and a numeric CVSS score is the fallback for rows that only carry a score.
fn known_cve_rank(cve: &Value) -> i32 {
    let named = cve
        .get("severity")
        .and_then(Value::as_str)
        .map_or(0, severity_rank);
    if named > 0 {
        return named;
    }
    cve.get("cvss")
        .and_then(Value::as_f64)
        .map_or(0, |score| severity_rank(severity_from_cvss(score)))
}

/// Legacy fingerprint-only severity. Kept for callers that genuinely only have
/// fingerprints; prefer [`top_severity_for_report`] for the headline severity.
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

/// Headline severity: the maximum severity across BOTH fix-commit fingerprints
/// and known CVEs.
///
/// Returns a canonical label (`critical` / `high` / `medium` / `low`).
/// `unknown` means evidence exists but none of it carries a usable severity,
/// and `none` means there is genuinely no fingerprint and no known CVE.
pub fn top_severity_from_parts(fingerprints: &Value, known_cves: &Value) -> String {
    let fingerprints = fingerprints.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let known_cves = known_cves.as_array().map(Vec::as_slice).unwrap_or(&[]);

    let mut rank = fingerprints
        .iter()
        .filter_map(|fp| fp.get("severity").and_then(Value::as_str))
        .map(severity_rank)
        .max()
        .unwrap_or(0);
    for cve in known_cves {
        rank = rank.max(known_cve_rank(cve));
    }

    if rank == 0 && !(fingerprints.is_empty() && known_cves.is_empty()) {
        return "unknown".to_string();
    }
    severity_label(rank).to_string()
}

/// Convenience wrapper over [`top_severity_from_parts`] that derives both inputs
/// from a raw trust report.
pub fn top_severity_for_report(report: &Value) -> String {
    top_severity_from_parts(
        &fingerprints_from_report(report),
        &super::context::known_cves(report),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_bands_follow_cvss_v3() {
        assert_eq!(severity_from_cvss(10.0), "critical");
        assert_eq!(severity_from_cvss(9.0), "critical");
        assert_eq!(severity_from_cvss(8.9), "high");
        assert_eq!(severity_from_cvss(7.0), "high");
        assert_eq!(severity_from_cvss(6.9), "medium");
        assert_eq!(severity_from_cvss(4.0), "medium");
        assert_eq!(severity_from_cvss(3.9), "low");
        assert_eq!(severity_from_cvss(0.1), "low");
        assert_eq!(severity_from_cvss(0.0), "none");
    }

    #[test]
    fn severity_rank_ordering_is_preserved() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert_eq!(severity_rank("moderate"), severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("unknown"));
    }

    #[test]
    fn top_severity_uses_cve_severity_word_and_cvss_fallback() {
        let fingerprints = json!([]);
        let cves = json!([
            {"id": "CVE-2026-0001", "severity": "unknown", "cvss": Value::Null},
            {"id": "CVE-2026-0002", "severity": "medium", "cvss": 5.0},
            {"id": "CVE-2026-0003", "severity": "unknown", "cvss": 9.4}
        ]);

        assert_eq!(top_severity_from_parts(&fingerprints, &cves), "critical");
    }

    #[test]
    fn top_severity_falls_back_to_fingerprints_when_cves_are_unrated() {
        let fingerprints = json!([{"severity": "high"}, {"severity": "low"}]);
        let cves = json!([{"id": "CVE-2026-0001", "severity": "unknown", "cvss": Value::Null}]);

        assert_eq!(top_severity_from_parts(&fingerprints, &cves), "high");
    }

    #[test]
    fn top_severity_normalizes_moderate_to_medium() {
        let fingerprints = json!([{"severity": "moderate"}]);
        assert_eq!(top_severity_from_parts(&fingerprints, &json!([])), "medium");
    }

    #[test]
    fn top_severity_is_none_for_empty_inputs_and_unknown_for_unrated_evidence() {
        assert_eq!(top_severity_from_parts(&json!([]), &json!([])), "none");
        assert_eq!(
            top_severity_from_parts(&json!([{"severity": "unrecognised"}]), &json!([])),
            "unknown"
        );
    }
}
