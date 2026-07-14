//! Port of `security_context.py:context_from_report` fingerprint pipeline.
//! Extracts fingerprints from security intel data in the trust report.
//!
//! IMPORTANT (post-fix): `critical_flags` from the trust report are NOT included
//! as fingerprints. Trust evidence like "missing_license" is not a security fix.

use serde_json::{json, Value};

pub fn fingerprints_from_report(report: &Value) -> Value {
    let mut fingerprints = Vec::new();
    let intel = security_intel(report);

    // 1. Security fix commits from GitHub search
    if let Some(commits) = intel.get("fix_commits").and_then(Value::as_array) {
        for commit in commits {
            let sha = commit.get("sha").and_then(Value::as_str).unwrap_or("");
            let short_sha = sha.chars().take(10).collect::<String>();
            let subject = commit
                .get("subject")
                .and_then(Value::as_str)
                .unwrap_or("Security fix commit");
            let component = commit
                .get("component")
                .and_then(Value::as_str)
                .unwrap_or("repository");
            let changed_files = commit
                .get("changed_files")
                .cloned()
                .unwrap_or_else(|| json!([]));
            let sink_symbols = sink_symbols_from_commit(commit, component);
            fingerprints.push(json!({
                "id": if short_sha.is_empty() { format!("fp_commit_{:02}", fingerprints.len() + 1) } else { format!("fp_{short_sha}") },
                "commit_sha": if sha.is_empty() { Value::Null } else { json!(sha) },
                "commit_date": commit.get("date").cloned().unwrap_or(Value::Null),
                "commit_subject": subject,
                "vuln_class": commit.get("vuln_class").and_then(Value::as_str).unwrap_or("Security Fix"),
                "cwe": commit.get("cwe").cloned().unwrap_or(json!([])),
                "components": [component],
                "sink": component,
                "sink_symbols": sink_symbols,
                "changed_files": changed_files,
                "file_evidence_source": commit.get("file_evidence_source").cloned().unwrap_or(Value::Null),
                "file_evidence_status": commit.get("file_evidence_status").cloned().unwrap_or(Value::Null),
                "fix_shape": "security-relevant commit from GitHub history",
                "severity": commit.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                "poc": Value::Null,
                "summary": subject,
                "evidence": commit.get("html_url").cloned().unwrap_or(Value::Null),
                "decision_source": commit.get("decision_source").and_then(Value::as_str).unwrap_or("rule_based"),
                "rule_based_result": commit.get("rule_based_result").cloned().unwrap_or_else(|| json!({
                    "vuln_class": commit.get("vuln_class").and_then(Value::as_str).unwrap_or("Security Fix"),
                    "severity": commit.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                    "cwe": commit.get("cwe").cloned().unwrap_or(json!([]))
                })),
                "llm_assisted_result": commit.get("llm_assisted_result").cloned().unwrap_or(Value::Null)
            }));
        }
    }

    // 2. GitHub Security Advisories
    let mut seen_advisories = Vec::new();
    for advisory in intel
        .get("github_advisories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = advisory
            .get("ghsa_id")
            .or_else(|| advisory.get("cve_id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if id.is_empty() || seen_advisories.iter().any(|seen| seen == id) {
            continue;
        }
        seen_advisories.push(id.to_string());
        let summary = advisory
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("GitHub security advisory");
        let cve = advisory.get("cve_id").and_then(Value::as_str).unwrap_or("");
        fingerprints.push(json!({
            "id": format!("fp_{}", id.to_ascii_lowercase().replace('-', "_")),
            "commit_sha": Value::Null,
            "commit_date": advisory.get("published_at").or_else(|| advisory.get("updated_at")).cloned().unwrap_or(Value::Null),
            "commit_subject": summary,
            "vuln_class": vuln_class_from_text(summary),
            "cwe": cwe_from_advisory(advisory).unwrap_or_else(|| cwe_from_text(summary)),
            "components": [security_intel_component(&intel)],
            "sink": security_intel_component(&intel),
            "sink_symbols": [],
            "fix_shape": if cve.is_empty() { "public GitHub security advisory" } else { "public GitHub security advisory with CVE" },
            "severity": advisory.get("severity").and_then(Value::as_str).unwrap_or("medium"),
            "poc": Value::Null,
            "summary": summary,
            "evidence": if cve.is_empty() { json!([id]) } else { json!([id, cve]) },
            "decision_source": "rule_based",
            "rule_based_result": {
                "vuln_class": vuln_class_from_text(summary),
                "cwe": cwe_from_advisory(advisory).unwrap_or_else(|| cwe_from_text(summary)),
                "severity": advisory.get("severity").and_then(Value::as_str).unwrap_or("medium")
            },
            "llm_assisted_result": Value::Null
        }));
    }

    // 3. OSV vulnerabilities
    for vuln in intel
        .get("osv_vulns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = vuln.get("id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() || seen_advisories.iter().any(|seen| seen == id) {
            continue;
        }
        seen_advisories.push(id.to_string());
        let summary = vuln
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("OSV vulnerability");
        fingerprints.push(json!({
            "id": format!("fp_{}", id.to_ascii_lowercase().replace('-', "_")),
            "commit_sha": Value::Null,
            "commit_date": vuln.get("published").or_else(|| vuln.get("modified")).cloned().unwrap_or(Value::Null),
            "commit_subject": summary,
            "vuln_class": vuln_class_from_text(summary),
            "cwe": cwe_from_osv(vuln).unwrap_or_else(|| cwe_from_text(summary)),
            "components": [security_intel_component(&intel)],
            "sink": security_intel_component(&intel),
            "sink_symbols": [],
            "fix_shape": "public OSV vulnerability record",
            "severity": severity_from_osv(vuln).unwrap_or_else(|| severity_from_text(summary)),
            "poc": Value::Null,
            "summary": summary,
            "evidence": vuln.get("aliases").cloned().unwrap_or_else(|| json!([id])),
            "decision_source": "rule_based",
            "rule_based_result": {
                "vuln_class": vuln_class_from_text(summary),
                "cwe": cwe_from_osv(vuln).unwrap_or_else(|| cwe_from_text(summary)),
                "severity": severity_from_osv(vuln).unwrap_or_else(|| severity_from_text(summary))
            },
            "llm_assisted_result": Value::Null
        }));
    }

    // NOTE: critical_flags from trust evidence are NOT included as fingerprints.
    // Trust evidence like "missing_license" is not a security vulnerability fix.

    json!(fingerprints)
}

fn sink_symbols_from_commit(commit: &Value, component: &str) -> Vec<String> {
    let mut symbols = commit
        .get("changed_files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|file| {
            file.get("touched_symbols")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        })
        .filter(|symbol| !symbol.trim().is_empty())
        .map(String::from)
        .collect::<Vec<_>>();
    symbols.sort();
    symbols.dedup();
    // Preserve the legacy fallback for downstream consumers. Regression
    // contracts explicitly ignore a symbol that is identical to the component
    // or sink, so this compatibility value cannot inflate their evidence tier.
    if symbols.is_empty() && !component.is_empty() {
        symbols.push(component.to_string());
    }
    symbols
}

fn security_intel(report: &Value) -> serde_json::Map<String, Value> {
    report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

fn security_intel_component(intel: &serde_json::Map<String, Value>) -> String {
    let ecosystem = intel.get("ecosystem").and_then(Value::as_str).unwrap_or("");
    let package = intel
        .get("package_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !ecosystem.is_empty() && !package.is_empty() {
        format!("{ecosystem}:{package}")
    } else {
        "repository".to_string()
    }
}

fn _severity_rank(value: &str) -> i32 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_from_text(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical") || lower.contains("rce") {
        "critical"
    } else if lower.contains("high") || lower.contains("bypass") {
        "high"
    } else if lower.contains("medium") || lower.contains("moderate") || lower.contains("xss") {
        "medium"
    } else if lower.contains("low") {
        "low"
    } else {
        "medium"
    }
}

fn vuln_class_from_text(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("bypass") || lower.contains("auth") || lower.contains("middleware") {
        "Auth Bypass"
    } else if lower.contains("xss") || lower.contains("cross-site scripting") {
        "Cross-Site Scripting"
    } else if lower.contains("csrf") || lower.contains("cross-site request") {
        "CSRF"
    } else if lower.contains("ssrf") || lower.contains("server-side request") {
        "Server-Side Request Forgery"
    } else if lower.contains("dos") || lower.contains("denial of service") {
        "Denial of Service"
    } else if lower.contains("traversal") || lower.contains("path") {
        "Path Traversal"
    } else if lower.contains("injection")
        || lower.contains("sqli")
        || lower.contains("command injection")
    {
        "Injection"
    } else if lower.contains("use after free")
        || lower.contains("uaf")
        || lower.contains("dangling")
    {
        "Use After Free"
    } else if lower.contains("double free") {
        "Double Free"
    } else if lower.contains("buffer overflow")
        || lower.contains("heap overflow")
        || lower.contains("stack overflow")
    {
        "Buffer Overflow"
    } else if lower.contains("integer overflow") || lower.contains("integer wraparound") {
        "Integer Overflow"
    } else if lower.contains("out of bounds") || lower.contains("oob") {
        "Out-of-Bounds Access"
    } else if lower.contains("null pointer") || lower.contains("null deref") {
        "NULL Pointer Dereference"
    } else if lower.contains("race condition") || lower.contains("toctou") {
        "Race Condition"
    } else if lower.contains("memory leak")
        || lower.contains("disclosure")
        || lower.contains("leak")
    {
        "Information Disclosure"
    } else if lower.contains("rce")
        || lower.contains("arbitrary code")
        || lower.contains("code execution")
    {
        "Remote Code Execution"
    } else if lower.contains("privilege escalation") {
        "Privilege Escalation"
    } else if lower.contains("timing") || lower.contains("side channel") {
        "Timing/Side-Channel"
    } else if lower.contains("format string") {
        "Format String"
    } else if lower.contains("type confusion") {
        "Type Confusion"
    } else if lower.contains("deserial") {
        "Insecure Deserialization"
    } else {
        "Security Fix"
    }
}

fn cwe_from_text(text: &str) -> Vec<String> {
    let class = vuln_class_from_text(text);
    match class {
        "Auth Bypass" => vec!["CWE-287".into()],
        "Cross-Site Scripting" => vec!["CWE-79".into()],
        "CSRF" => vec!["CWE-352".into()],
        "Server-Side Request Forgery" => vec!["CWE-918".into()],
        "Denial of Service" => vec!["CWE-400".into()],
        "Path Traversal" => vec!["CWE-22".into()],
        "Injection" => vec!["CWE-74".into()],
        "Use After Free" => vec!["CWE-416".into()],
        "Double Free" => vec!["CWE-415".into()],
        "Buffer Overflow" => vec!["CWE-120".into()],
        "Integer Overflow" => vec!["CWE-190".into()],
        "Out-of-Bounds Access" => vec!["CWE-125".into()],
        "NULL Pointer Dereference" => vec!["CWE-476".into()],
        "Race Condition" => vec!["CWE-362".into()],
        "Information Disclosure" => vec!["CWE-200".into()],
        "Remote Code Execution" => vec!["CWE-94".into()],
        "Privilege Escalation" => vec!["CWE-269".into()],
        "Timing/Side-Channel" => vec!["CWE-385".into()],
        "Format String" => vec!["CWE-134".into()],
        "Type Confusion" => vec!["CWE-843".into()],
        "Insecure Deserialization" => vec!["CWE-502".into()],
        _ => vec![],
    }
}

fn cwe_from_advisory(advisory: &Value) -> Option<Vec<String>> {
    advisory.get("cwes").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|cwe| cwe.get("cwe_id").and_then(Value::as_str).map(String::from))
            .collect()
    })
}

fn cwe_from_osv(vuln: &Value) -> Option<Vec<String>> {
    vuln.get("database_specific")
        .and_then(|d| d.get("cwe_ids"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
}

fn severity_from_osv(vuln: &Value) -> Option<&'static str> {
    vuln.get("severity")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("score"))
        .and_then(|s| s.as_str())
        .map(cvss_severity)
        .or_else(|| {
            vuln.get("database_specific")
                .and_then(|d| d.get("severity"))
                .and_then(|v| v.as_str())
                .map(|s| match s.to_ascii_lowercase().as_str() {
                    "critical" => "critical",
                    "high" => "high",
                    "moderate" => "medium",
                    "low" => "low",
                    _ => "medium",
                })
        })
}

fn cvss_severity(cvss: &str) -> &'static str {
    if let Some(score) = cvss
        .split('/')
        .find_map(|part| part.strip_prefix("AV:").or_else(|| part.strip_prefix("S:")))
    {
        if let Ok(n) = score.parse::<f64>() {
            return if n >= 9.0 {
                "critical"
            } else if n >= 7.0 {
                "high"
            } else if n >= 4.0 {
                "medium"
            } else {
                "low"
            };
        }
    }
    "medium"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_fingerprint_carries_changed_file_evidence() {
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": [{
                        "sha": "1234567890abcdef",
                        "subject": "fix certificate validation bypass",
                        "component": "src/ssl.c",
                        "vuln_class": "Auth Bypass",
                        "cwe": ["CWE-287"],
                        "severity": "high",
                        "date": "2026-01-01T00:00:00Z",
                        "html_url": "https://github.com/example/repo/commit/1234567890abcdef",
                        "changed_files": [{
                            "path": "src/ssl.c",
                            "status": "modified",
                            "additions": 8,
                            "deletions": 2,
                            "changes": 10,
                            "touched_symbols": ["wolfSSL_accept"]
                        }],
                        "file_evidence_source": "github_commit_detail",
                        "file_evidence_status": "fetched"
                    }]
                }
            }
        });

        let fingerprints = fingerprints_from_report(&report);
        let first = fingerprints.as_array().unwrap().first().unwrap();

        assert_eq!(first["components"], json!(["src/ssl.c"]));
        assert_eq!(first["sink"], json!("src/ssl.c"));
        assert_eq!(first["sink_symbols"], json!(["wolfSSL_accept"]));
        assert_eq!(first["changed_files"][0]["path"], json!("src/ssl.c"));
        assert_eq!(first["file_evidence_status"], json!("fetched"));
    }

    #[test]
    fn commit_fingerprint_defaults_new_fields_for_old_reports() {
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": [{
                        "sha": "1234567890abcdef",
                        "subject": "security fix",
                        "component": "repository",
                        "vuln_class": "Security Fix",
                        "cwe": [],
                        "severity": "medium",
                        "date": "2026-01-01T00:00:00Z",
                        "html_url": "https://github.com/example/repo/commit/1234567890abcdef"
                    }]
                }
            }
        });

        let fingerprints = fingerprints_from_report(&report);
        let first = fingerprints.as_array().unwrap().first().unwrap();

        assert_eq!(first["changed_files"], json!([]));
        assert_eq!(first["file_evidence_source"], Value::Null);
        assert_eq!(first["sink_symbols"], json!(["repository"]));
    }

    #[test]
    fn commit_fingerprints_are_not_capped_at_500() {
        let commits = (0..501)
            .map(|idx| {
                json!({
                    "sha": format!("{idx:040x}"),
                    "subject": "fix certificate validation bypass",
                    "component": "src/ssl.c",
                    "vuln_class": "Auth Bypass",
                    "cwe": ["CWE-287"],
                    "severity": "high",
                    "date": "2026-01-01T00:00:00Z",
                    "html_url": format!("https://github.com/example/repo/commit/{idx:040x}")
                })
            })
            .collect::<Vec<_>>();
        let report = json!({
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": commits
                }
            }
        });

        let fingerprints = fingerprints_from_report(&report);

        assert_eq!(fingerprints.as_array().unwrap().len(), 501);
    }
}
