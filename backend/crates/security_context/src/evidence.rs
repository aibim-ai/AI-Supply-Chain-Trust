use ai_supply_chain_trust_models::VerifiedEvidenceBuilder;
use serde_json::{Map, Value};

/// Security context version string. Must match Python `LIVE_SECURITY_CONTEXT_VERSION`.
pub const LIVE_SECURITY_CONTEXT_VERSION: &str = "2026-07-14-history-precision-v2";

/// Checks whether a report has sufficient live evidence to produce a
/// security context. Returns true only if the evidence gate passes.
///
/// Gating rules (from Phase 0 §4):
/// 1. `observed_metrics.verification_status != "mismatch"`
/// 2. `observed_metrics.security_context_version == LIVE_SECURITY_CONTEXT_VERSION`
/// 3. At least one of: commit SHA, advisory/OSV, scanner runs
pub fn has_ready_evidence(report: &Value) -> bool {
    ready_evidence_summary(report).build().is_ok()
}

/// Returns a `VerifiedEvidenceBuilder` populated from the report's observed metrics.
/// The caller can call `.build()` to get a `VerifiedEvidence` if evidence is sufficient,
/// or inspect the error for details.
pub fn ready_evidence_summary(report: &Value) -> VerifiedEvidenceBuilder {
    let metrics = report.get("observed_metrics").and_then(|v| v.as_object());
    let intel = security_intel(report);

    let version_ok = metrics
        .and_then(|m| m.get("security_context_version"))
        .and_then(|v| v.as_str())
        .map(|v| v == LIVE_SECURITY_CONTEXT_VERSION)
        .unwrap_or(false);

    let status_ok = metrics
        .and_then(|m| m.get("verification_status"))
        .and_then(|v| v.as_str())
        .map(|v| v != "mismatch")
        .unwrap_or(true);

    let mut builder = VerifiedEvidenceBuilder::new(version_ok && status_ok);

    let head_sha = metrics
        .and_then(|m| m.get("head_sha"))
        .and_then(|v| v.as_str())
        .or_else(|| intel.get("head_sha").and_then(|v| v.as_str()));
    builder = builder.with_commit_sha(head_sha);

    let cve_count = metrics
        .and_then(|m| m.get("cve_count"))
        .and_then(|v| v.as_i64())
        .map(|count| count as usize)
        .unwrap_or_else(|| {
            intel
                .get("cves")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
                + intel
                    .get("advisories")
                    .or_else(|| intel.get("github_advisories"))
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len)
        });
    builder = builder.with_cve_count(cve_count);

    let osv_count = metrics
        .and_then(|m| m.get("osv_vulnerability_count"))
        .and_then(|v| v.as_i64())
        .map(|count| count as usize)
        .unwrap_or_else(|| {
            intel
                .get("osv_vulns")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
        });
    builder = builder.with_osv_count(osv_count);

    let scanner_runs = report
        .get("scanner_runs")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    builder = builder.with_scanner_runs(scanner_runs);

    builder
}

fn security_intel(report: &Value) -> Map<String, Value> {
    report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_report_fails_evidence_gate() {
        let report = json!({
            "observed_metrics": {},
            "scanner_runs": []
        });
        assert!(!has_ready_evidence(&report));
    }

    #[test]
    fn report_with_version_and_commit_passes() {
        let report = json!({
            "observed_metrics": {
                "security_context_version": LIVE_SECURITY_CONTEXT_VERSION,
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
            },
            "scanner_runs": []
        });
        assert!(has_ready_evidence(&report));
    }

    #[test]
    fn report_with_nested_security_intel_cves_passes() {
        let report = json!({
            "observed_metrics": {
                "security_context_version": LIVE_SECURITY_CONTEXT_VERSION,
                "verification_status": "ok",
                "security_intel": {
                    "cves": ["CVE-2026-0001"],
                    "osv_vulns": []
                }
            },
            "scanner_runs": []
        });
        assert!(has_ready_evidence(&report));
    }

    #[test]
    fn version_mismatch_fails() {
        let report = json!({
            "observed_metrics": {
                "security_context_version": "2020-01-01-old-v1",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
            },
            "scanner_runs": []
        });
        assert!(!has_ready_evidence(&report));
    }
}
