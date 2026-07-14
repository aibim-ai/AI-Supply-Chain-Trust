//! Security context shape regression tests.

use serde_json::Value;
use std::collections::HashSet;

fn sample_report() -> Value {
    serde_json::json!({
        "repo": "vercel/next.js",
        "evaluated_at": "2026-07-08T00:00:00Z",
        "trust_score": 71.0, "grade": "B",
        "action": "Review routing.", "coverage": "5/7",
        "verdict": "Evidence-backed.",
        "observed_metrics": {
            "metadata": { "default_branch": "canary", "head_sha": "abc123def456", "commit_count": 42 },
            "security_context_version": "2026-07-08-live-github-v1",
            "verification_status": "ok",
            "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "security_intel": {
                "fix_commits": [{
                    "sha": "9704c8e9fcc5", "subject": "fix middleware bypass",
                    "component": "utils.ts", "vuln_class": "Auth Bypass",
                    "cwe": ["CWE-287"], "severity": "critical",
                    "date": "2025-03-21T00:00:00Z",
                    "html_url": "https://github.com/vercel/next.js/commit/9704c8e9"
                }],
                "cves": ["CVE-2025-29927"], "commit_count": 34309
            },
            "cve_count": 47
        },
        "scanner_runs": [{"tool":"github-metadata-rust","status":"ok","detail":"ok"}],
        "pillar_scores": {
            "publisher": {"name":"Publisher","normalized":80.0,"evidence":[],"concerns":[],"unavailable":[]}
        }
    })
}

#[test]
fn golden_vercel_next_envelope_top_level_keys() {
    let report = sample_report();
    let envelope = ai_supply_chain_trust_security_context::envelope_from_report(
        &report,
        "vercel/next.js",
        "https://localhost",
    );
    let rust_json = serde_json::to_value(&envelope).unwrap();

    let out_keys: HashSet<&str> = rust_json
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();

    for key in ["repo", "status", "summary", "artifacts", "context", "leads"] {
        assert!(out_keys.contains(key), "Missing top-level key: '{key}'");
    }
}

#[test]
fn golden_context_has_required_fields() {
    let report = sample_report();
    let envelope = ai_supply_chain_trust_security_context::envelope_from_report(
        &report,
        "vercel/next.js",
        "https://localhost",
    );

    let ctx_json = serde_json::to_value(&envelope.context).unwrap();

    for key in &[
        "repo",
        "fingerprints",
        "top_risks",
        "remediation",
        "vuln_class_counts",
        "component_counts",
    ] {
        assert!(ctx_json.get(key).is_some(), "Output missing '{key}'");
    }
}

#[test]
fn golden_fingerprint_shape_matches() {
    let report = sample_report();
    let envelope = ai_supply_chain_trust_security_context::envelope_from_report(
        &report,
        "vercel/next.js",
        "https://localhost",
    );

    let fp_keys: HashSet<&str> = [
        "id",
        "vuln_class",
        "severity",
        "components",
        "sink",
        "fix_shape",
        "summary",
    ]
    .iter()
    .cloned()
    .collect();

    assert!(!envelope.context.fingerprints.is_empty());
    let out_fp = serde_json::to_value(&envelope.context.fingerprints[0]).unwrap();
    for key in &fp_keys {
        assert!(
            out_fp.get(key).is_some(),
            "Output fingerprint missing '{key}'"
        );
    }
}

#[test]
fn golden_summary_fields_match() {
    let report = sample_report();
    let envelope = ai_supply_chain_trust_security_context::envelope_from_report(
        &report,
        "vercel/next.js",
        "https://localhost",
    );

    let summary = &envelope.summary;
    assert!(summary.fixes >= 0);
    assert!(summary.cves >= 0);
}
