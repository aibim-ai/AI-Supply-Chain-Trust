//! Port of `security_context.py:context_from_report()`.
//! Builds the full SecurityContext JSON from a trust evaluation report.

use serde_json::{json, Map, Value};

use super::fingerprints::fingerprints_from_report;
use super::top_risks::top_risks;

pub fn context_from_report(report: &Value, repo: &str) -> Value {
    let (owner, name) = split_repo(repo);
    let regression_contracts =
        super::regression_contracts::regression_contracts_from_report(report, repo);
    json!({
        "repo": {
            "owner": owner,
            "name": name,
            "url": format!("https://github.com/{repo}.git"),
            "ref": metadata(report).get("default_branch").and_then(Value::as_str).unwrap_or("default"),
            "head_sha": metadata(report).get("head_sha").and_then(Value::as_str).unwrap_or("unknown")
        },
        "generated_at": report.get("evaluated_at").and_then(Value::as_str).unwrap_or(""),
        "commits_scanned": security_intel(report)
            .get("commit_count")
            .and_then(Value::as_i64)
            .or_else(|| metadata(report).get("commit_count").and_then(Value::as_i64))
            .unwrap_or(0),
        "commits_flagged": report.get("critical_flags").and_then(Value::as_array).map_or(0, Vec::len),
        "archetype": if has_ai_signal(report) { "ai" } else { "repository" },
        "excluded_availability": unavailable_count(report),
        "summary": report.get("verdict").and_then(Value::as_str).unwrap_or("Evidence-backed repository trust context."),
        "llm_summary": llm_summary(report),
        "agent_brief": agent_brief(report, repo),
        "tool": "AI Supply Chain Trust",
        "known_cves": known_cves(report),
        "component_counts": component_counts(report),
        "vuln_class_counts": vuln_class_counts(report),
        "remediation": remediation(report),
        "top_risks": top_risks(report),
        "shared_surfaces": shared_surfaces(report),
        "fingerprints": fingerprints_from_report(report),
        "watchlist": regression_contracts,
        "scanner_runs": report.get("scanner_runs").cloned().unwrap_or(json!([])),
        "themes": themes(report),
        "trust": {
            "score": report.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0).round(),
            "grade": report.get("grade").and_then(Value::as_str).unwrap_or("-"),
            "label": report.get("verdict").and_then(Value::as_str).unwrap_or(""),
            "action": report.get("action").and_then(Value::as_str).unwrap_or(""),
            "coverage": report.get("coverage").and_then(Value::as_str).unwrap_or(""),
            "confidence": report.get("confidence").and_then(Value::as_str).unwrap_or("unknown"),
            "evidence_coverage": report.get("evidence_coverage").and_then(Value::as_f64).unwrap_or(0.0),
            "missing_evidence": report.get("missing_evidence").cloned().unwrap_or_else(|| json!([])),
            "reasons": report.get("decision_reasons").cloned().unwrap_or_else(|| json!([])),
            "decision_source": "rule_based",
            "rule_based_result": {
                "score": report.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0).round(),
                "grade": report.get("grade").and_then(Value::as_str).unwrap_or("-"),
                "label": report.get("verdict").and_then(Value::as_str).unwrap_or(""),
                "action": report.get("action").and_then(Value::as_str).unwrap_or("")
            },
            "llm_assisted_result": llm_trust_note(report)
        },
        "metrics": report.get("observed_metrics").cloned().unwrap_or(json!({}))
    })
}

fn llm_summary(report: &Value) -> Value {
    let rule = json!({
        "fixes": fingerprints_from_report(report).as_array().map_or(0, Vec::len),
        "cves": security_intel(report).get("cves").and_then(Value::as_array).map_or(0, Vec::len),
        "top_severity": super::top_risks::top_severity_from(&fingerprints_from_report(report)),
        "remediation_coverage": coverage_percent(report)
    });
    ai_supply_chain_trust_llm::tasks::unavailable_decision("synchronous_context_generation", rule)
}

fn llm_trust_note(report: &Value) -> Value {
    let rule = json!({
        "score": report.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0).round(),
        "grade": report.get("grade").and_then(Value::as_str).unwrap_or("-"),
        "action": report.get("action").and_then(Value::as_str).unwrap_or("")
    });
    ai_supply_chain_trust_llm::tasks::unavailable_decision("synchronous_context_generation", rule)
}

fn split_repo(repo: &str) -> (&str, &str) {
    repo.split_once('/').unwrap_or((repo, ""))
}

fn metadata(report: &Value) -> Map<String, Value> {
    let metrics = report.get("observed_metrics");
    metrics
        .and_then(|m| m.get("metadata"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_else(|| {
            metrics
                .and_then(|m| m.as_object())
                .cloned()
                .unwrap_or_default()
        })
}

fn security_intel(report: &Value) -> Map<String, Value> {
    report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

fn has_ai_signal(report: &Value) -> bool {
    let metrics = report.get("observed_metrics").and_then(|v| v.as_object());
    metrics
        .and_then(|m| m.get("has_model_artifacts"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || metrics
            .and_then(|m| m.get("has_mcp_indicators"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
}

fn unavailable_count(report: &Value) -> usize {
    let mut count = 0;
    if let Some(scores) = report.get("pillar_scores").and_then(|v| v.as_object()) {
        for value in scores.values() {
            count += value
                .get("unavailable")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
        }
    }
    count
}

fn agent_brief(report: &Value, repo: &str) -> String {
    let verdict = report
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("unknown verdict");
    let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
    format!("Review {repo} from latest trust evidence ({verdict}, grade {grade}).")
}

fn known_cves(report: &Value) -> Value {
    let intel = security_intel(report);
    let mut rows = Vec::new();
    for advisory in intel
        .get("github_advisories")
        .or_else(|| intel.get("advisories"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let id = advisory.get("cve_id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        rows.push(json!({
            "id": id,
            "severity": advisory.get("severity").and_then(Value::as_str).unwrap_or("unknown"),
            "cvss": advisory.get("cvss").and_then(|c| c.get("score")).cloned().unwrap_or(Value::Null),
            "summary": advisory.get("summary").and_then(Value::as_str).unwrap_or("GitHub security advisory."),
            "published": advisory.get("published_at").cloned().unwrap_or(Value::Null),
            "source": advisory.get("ghsa_id").and_then(Value::as_str).unwrap_or("github_advisory")
        }));
        if rows.len() >= 500 {
            break;
        }
    }
    for cve in intel
        .get("nvd_cves")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let id = cve.get("cve_id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty()
            || rows.iter().any(|row| {
                row.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|existing| existing == id)
            })
        {
            continue;
        }
        rows.push(json!({
            "id": id,
            "severity": cve.get("severity").and_then(Value::as_str).unwrap_or("unknown").to_ascii_lowercase(),
            "cvss": cve.get("cvss_score").cloned().unwrap_or(Value::Null),
            "summary": cve.get("description").and_then(Value::as_str).unwrap_or("NVD CVE record."),
            "published": cve.get("published").cloned().unwrap_or(Value::Null),
            "source": cve.get("source").and_then(Value::as_str).unwrap_or("nvd"),
            "attribution_terms": cve.get("attribution_terms").cloned().unwrap_or_else(|| json!([])),
            "source_url": cve.get("source_url").cloned().unwrap_or(Value::Null)
        }));
        if rows.len() >= 500 {
            break;
        }
    }
    for cve in intel
        .get("cves")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if rows.iter().any(|row| {
            row.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id == cve)
        }) {
            continue;
        }
        rows.push(json!({
            "id": cve,
            "severity": "unknown",
            "cvss": Value::Null,
            "summary": "Known CVE associated with this repository or owner.",
            "published": Value::Null,
            "source": "security_intel"
        }));
        if rows.len() >= 500 {
            break;
        }
    }
    json!(rows)
}

fn component_counts(report: &Value) -> Value {
    let mut counts = Map::new();
    let fingerprints = fingerprints_from_report(report);
    if let Some(rows) = fingerprints.as_array() {
        for fingerprint in rows {
            let mut counted_component = false;
            if let Some(components) = fingerprint.get("components").and_then(Value::as_array) {
                for component in components.iter().filter_map(Value::as_str) {
                    if component.trim().is_empty() {
                        continue;
                    }
                    let current = counts.get(component).and_then(Value::as_i64).unwrap_or(0);
                    counts.insert(component.to_string(), json!(current + 1));
                    counted_component = true;
                }
            }
            if !counted_component {
                let component = fingerprint
                    .get("sink")
                    .and_then(Value::as_str)
                    .unwrap_or("repository");
                let current = counts.get(component).and_then(Value::as_i64).unwrap_or(0);
                counts.insert(component.to_string(), json!(current + 1));
            }
        }
    }
    Value::Object(counts)
}

fn vuln_class_counts(report: &Value) -> Value {
    let mut counts = Map::new();
    if let Some(fingerprints) = fingerprints_from_report(report).as_array() {
        for fingerprint in fingerprints {
            let class = fingerprint
                .get("vuln_class")
                .and_then(Value::as_str)
                .filter(|class| !class.trim().is_empty())
                .unwrap_or("Security Fix");
            let current = counts.get(class).and_then(Value::as_i64).unwrap_or(0);
            counts.insert(class.to_string(), json!(current + 1));
        }
    }
    Value::Object(counts)
}

fn remediation(report: &Value) -> Value {
    let fingerprints = fingerprints_from_report(report)
        .as_array()
        .map_or(0, Vec::len) as i64;
    let scanners = scanner_run_count(report);
    let coverage = coverage_percent(report);
    json!({
        "coverage": coverage,
        "measurable_fixes": fingerprints,
        "remediated_fixes": ((coverage / 100.0) * fingerprints as f64).round() as i64,
        "guarded_sites": scanners,
        "open_leads": top_risks(report).as_array().map_or(0, Vec::len) as i64
    })
}

pub fn coverage_percent(report: &Value) -> f64 {
    if scanner_run_count(report) == 0 {
        return 0.0;
    }

    let intel = security_intel(report);
    let cves = intel
        .get("cves")
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as f64;
    let fingerprints = fingerprints_from_report(report)
        .as_array()
        .map_or(0, Vec::len) as f64;
    if fingerprints == 0.0 && cves == 0.0 {
        return 0.0;
    }
    if cves > 0.0 && fingerprints > 0.0 {
        return (fingerprints.min(cves) / cves * 1000.0).round() / 10.0;
    }
    if fingerprints > 0.0 {
        100.0
    } else {
        0.0
    }
}

fn scanner_run_count(report: &Value) -> i64 {
    report
        .get("scanner_runs")
        .and_then(Value::as_array)
        .map(|runs| {
            runs.iter()
                .filter(|run| run.get("status").and_then(Value::as_str) == Some("ok"))
                .count()
        })
        .unwrap_or(0) as i64
}

fn shared_surfaces(report: &Value) -> Value {
    let mut surfaces = Vec::new();
    if let Some(scores) = report.get("pillar_scores").and_then(|v| v.as_object()) {
        for (key, value) in scores {
            let concerns = value
                .get("concerns")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if concerns.is_empty() {
                continue;
            }
            surfaces.push(json!({
                "surface": value.get("name").and_then(Value::as_str).unwrap_or(key),
                "guard": key,
                "entry_points": value.get("evidence").cloned().unwrap_or(json!([])),
                "check_hint": concerns.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
                "evidence": value.get("unavailable").cloned().unwrap_or(json!([]))
            }));
        }
    }
    json!(surfaces)
}

fn themes(report: &Value) -> Value {
    let mut themes = Vec::new();
    if let Some(scores) = report.get("pillar_scores").and_then(|v| v.as_object()) {
        for (key, value) in scores {
            themes.push(json!({
                "pillar": key,
                "name": value.get("name").and_then(Value::as_str).unwrap_or(key),
                "normalized": value.get("normalized").cloned().unwrap_or(json!(0.0))
            }));
        }
    }
    json!(themes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_counts_use_all_fingerprint_components() {
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": [
                        {
                            "sha": "1111111111",
                            "subject": "fix tls validation",
                            "component": "src/tls.c",
                            "vuln_class": "Security Fix",
                            "cwe": [],
                            "severity": "medium",
                            "date": "2026-01-01T00:00:00Z",
                            "html_url": "https://github.com/wolfssl/wolfssl/commit/1111111111"
                        },
                        {
                            "sha": "2222222222",
                            "subject": "fix asn bounds",
                            "component": "wolfcrypt/src/asn.c",
                            "vuln_class": "Security Fix",
                            "cwe": [],
                            "severity": "medium",
                            "date": "2026-01-02T00:00:00Z",
                            "html_url": "https://github.com/wolfssl/wolfssl/commit/2222222222"
                        }
                    ]
                }
            }
        });

        let counts = component_counts(&report);

        assert_eq!(counts["src/tls.c"], json!(1));
        assert_eq!(counts["wolfcrypt/src/asn.c"], json!(1));
        assert_eq!(counts.get("repository"), None);
    }

    #[test]
    fn vuln_class_counts_use_all_fingerprints_not_truncated_top_risks() {
        let classes = [
            "Security Fix",
            "Buffer Overflow",
            "Integer Overflow",
            "Use After Free",
            "Double Free",
            "Timing/Side-Channel",
        ];
        let fix_commits = classes
            .iter()
            .enumerate()
            .map(|(index, class)| {
                json!({
                    "sha": format!("sha{index:02}"),
                    "subject": format!("fix {}", class),
                    "component": format!("src/component_{index}.c"),
                    "vuln_class": class,
                    "cwe": [],
                    "severity": "medium",
                    "date": "2026-01-01T00:00:00Z",
                    "html_url": format!("https://github.com/wolfssl/wolfssl/commit/sha{index:02}")
                })
            })
            .collect::<Vec<_>>();
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": fix_commits
                }
            }
        });

        let counts = vuln_class_counts(&report);

        assert_eq!(counts.as_object().map_or(0, Map::len), 6);
        for class in classes {
            assert_eq!(counts[class], json!(1));
        }
    }

    #[test]
    fn remediation_coverage_requires_scanner_evidence() {
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "cves": [{ "id": "CVE-2026-0001" }],
                    "fix_commits": [
                        {
                            "sha": "1111111111",
                            "subject": "fix certificate validation",
                            "component": "src/tls.c",
                            "vuln_class": "Improper Certificate Validation",
                            "cwe": [],
                            "severity": "high",
                            "date": "2026-01-01T00:00:00Z",
                            "html_url": "https://github.com/wolfssl/wolfssl/commit/1111111111"
                        }
                    ]
                }
            }
        });

        let remediation = remediation(&report);

        assert_eq!(coverage_percent(&report), 0.0);
        assert_eq!(remediation["coverage"], json!(0.0));
        assert_eq!(remediation["guarded_sites"], json!(0));
        assert_eq!(remediation["remediated_fixes"], json!(0));
        assert_eq!(remediation["measurable_fixes"], json!(1));
    }

    #[test]
    fn unavailable_scanners_do_not_create_false_coverage() {
        let report = json!({
            "scanner_runs": [{"tool": "scorecard", "status": "unavailable"}],
            "observed_metrics": {"security_intel": {"fix_commits": [{
                "sha": "1111111111", "subject": "security fix", "component": "src/lib.rs",
                "vuln_class": "Security Fix", "severity": "medium"
            }]}}
        });

        assert_eq!(coverage_percent(&report), 0.0);
    }

    #[test]
    fn remediation_coverage_uses_cve_ratio_when_guarded() {
        let report = json!({
            "scanner_runs": [
                { "tool": "scanner-a", "status": "ok" }
            ],
            "observed_metrics": {
                "security_intel": {
                    "cves": [
                        { "id": "CVE-2026-0001" },
                        { "id": "CVE-2026-0002" },
                        { "id": "CVE-2026-0003" },
                        { "id": "CVE-2026-0004" }
                    ],
                    "fix_commits": [
                        {
                            "sha": "1111111111",
                            "subject": "fix certificate validation",
                            "component": "src/tls.c",
                            "vuln_class": "Improper Certificate Validation",
                            "cwe": [],
                            "severity": "high",
                            "date": "2026-01-01T00:00:00Z",
                            "html_url": "https://github.com/wolfssl/wolfssl/commit/1111111111"
                        },
                        {
                            "sha": "2222222222",
                            "subject": "fix buffer overflow",
                            "component": "src/ssl.c",
                            "vuln_class": "Buffer Overflow",
                            "cwe": [],
                            "severity": "high",
                            "date": "2026-01-02T00:00:00Z",
                            "html_url": "https://github.com/wolfssl/wolfssl/commit/2222222222"
                        }
                    ]
                }
            }
        });

        let remediation = remediation(&report);

        assert_eq!(coverage_percent(&report), 50.0);
        assert_eq!(remediation["coverage"], json!(50.0));
        assert_eq!(remediation["guarded_sites"], json!(1));
        assert_eq!(remediation["remediated_fixes"], json!(1));
        assert_eq!(remediation["measurable_fixes"], json!(2));
    }

    #[test]
    fn known_cves_preserve_nvd_details() {
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "cves": ["CVE-2026-0001"],
                    "nvd_cves": [
                        {
                            "cve_id": "CVE-2026-0001",
                            "description": "A certificate validation flaw in the TLS parser.",
                            "severity": "HIGH",
                            "cvss_score": 8.1,
                            "published": "2026-01-02T00:00:00.000",
                            "source": "nvd",
                            "attribution_terms": ["wolfssl"],
                            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
                        }
                    ]
                }
            }
        });

        let cves = known_cves(&report);
        let first = cves.as_array().unwrap().first().unwrap();

        assert_eq!(first["id"], json!("CVE-2026-0001"));
        assert_eq!(first["severity"], json!("high"));
        assert_eq!(first["cvss"], json!(8.1));
        assert_eq!(
            first["summary"],
            json!("A certificate validation flaw in the TLS parser.")
        );
        assert_eq!(first["source"], json!("nvd"));
        assert_eq!(first["attribution_terms"], json!(["wolfssl"]));
        assert_eq!(
            first["source_url"],
            json!("https://nvd.nist.gov/vuln/detail/CVE-2026-0001")
        );
    }
}
