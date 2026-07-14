use super::fingerprints::fingerprints_from_report;
use super::top_risks::top_risks;
use serde_json::{json, Value};

pub const LEADS_RUBRIC_VERSION: &str = "2026-07-09-live-github-v1";

pub fn leads_from_report(report: &Value, repo: &str) -> Value {
    let mut findings = Vec::new();
    let risks = top_risks(report);
    if let Some(risk_rows) = risks.as_array().filter(|rows| {
        rows.iter()
            .any(|row| row.get("fix_count").and_then(Value::as_i64).unwrap_or(0) > 0)
    }) {
        for (idx, risk) in risk_rows.iter().take(10).enumerate() {
            findings.push(json!({
                "rank": idx + 1,
                "severity": risk.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                "vulnerability_class": risk.get("vuln_class").and_then(Value::as_str).unwrap_or("security_intelligence"),
                "vuln_class": risk.get("vuln_class").and_then(Value::as_str).unwrap_or("security_intelligence"),
                "component": risk.get("component").and_then(Value::as_str).unwrap_or("repository"),
                "sink": risk.get("component").and_then(Value::as_str).unwrap_or("repository"),
                "evidence": risk.get("evidence").cloned().unwrap_or(json!([])),
                "why": "Ranked from public fix commits, GitHub advisories, and OSV vulnerability intelligence.",
                "rationale": risk.get("rationale").and_then(Value::as_str).unwrap_or("Security intelligence indicates recurring risk in this area."),
                "decision_source": risk.get("decision_source").and_then(Value::as_str).unwrap_or("rule_based"),
                "rule_based_result": risk.get("rule_based_result").cloned().unwrap_or_else(|| json!({
                    "severity": risk.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                    "vuln_class": risk.get("vuln_class").and_then(Value::as_str).unwrap_or("security_intelligence"),
                    "component": risk.get("component").and_then(Value::as_str).unwrap_or("repository")
                })),
                "llm_assisted_result": risk.get("llm_assisted_result").cloned().unwrap_or(Value::Null)
            }));
        }
    }
    if findings.is_empty() {
        if let Some(flags) = report.get("critical_flags").and_then(Value::as_array) {
            for flag in flags {
                if findings.len() >= 10 {
                    break;
                }
                findings.push(json!({
                    "rank": findings.len() + 1,
                    "severity": flag.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                    "vulnerability_class": flag.get("code").and_then(Value::as_str).unwrap_or("security_flag"),
                    "vuln_class": flag.get("code").and_then(Value::as_str).unwrap_or("security_flag"),
                    "component": "repository",
                    "sink": flag.get("message").and_then(Value::as_str).unwrap_or("security-sensitive path"),
                    "evidence": flag.get("evidence").and_then(Value::as_str).unwrap_or(""),
                    "why": "Trust evaluation flag from the latest scan.",
                    "rationale": flag.get("message").and_then(Value::as_str).unwrap_or("Trust evidence requires review."),
                    "decision_source": "rule_based",
                    "rule_based_result": {"severity": flag.get("severity").and_then(Value::as_str).unwrap_or("medium"), "code": flag.get("code").and_then(Value::as_str).unwrap_or("security_flag")},
                    "llm_assisted_result": Value::Null
                }));
            }
        }
    }
    if findings.is_empty() {
        findings.push(json!({
            "rank": 1, "severity": "low",
            "vulnerability_class": "review_focus", "vuln_class": "review_focus",
            "component": repo,
            "sink": report.get("action").and_then(Value::as_str).unwrap_or("maintain current trust guardrails"),
            "evidence": report.get("verdict").and_then(Value::as_str).unwrap_or(""),
            "why": "No critical flags found; focus on changed dependency paths.",
            "rationale": report.get("verdict").and_then(Value::as_str).unwrap_or("No critical flags."),
            "decision_source": "rule_based",
            "rule_based_result": {"severity": "low", "vuln_class": "review_focus", "component": repo},
            "llm_assisted_result": Value::Null
        }));
    }

    let fingerprints = fingerprints_from_report(report)
        .as_array()
        .map_or(0, |a| a.len()) as i64;
    let coverage = super::context::coverage_percent(report);

    json!({
        "repo": repo,
        "tool": "AI Supply Chain Trust",
        "rubric_version": LEADS_RUBRIC_VERSION,
        "generated_at": report.get("evaluated_at").and_then(Value::as_str).unwrap_or(""),
        "head_ref": report.get("observed_metrics").and_then(|m| m.get("metadata")).and_then(|m| m.get("default_branch")).and_then(Value::as_str).unwrap_or("default"),
        "head_sha": report.get("observed_metrics").and_then(|m| m.get("metadata")).and_then(|m| m.get("head_sha")).and_then(Value::as_str).unwrap_or("unknown"),
        "agent_brief": format!("Review {repo} from latest trust evidence."),
        "remediation_coverage": coverage,
        "measurable_fixes": fingerprints,
        "remediated_fixes": ((coverage / 100.0) * fingerprints as f64).round() as i64,
        "open_leads": top_risks(report).as_array().map_or(0, |a| a.len()) as i64,
        "guarded_sites": json!([]),
        "fingerprints_scanned": 0,
        "fingerprints": json!([]),
        "findings": findings,
        "leads": findings
    })
}
