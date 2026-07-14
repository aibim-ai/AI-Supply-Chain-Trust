use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ContextStatus;

// ---------------------------------------------------------------------------
// SecurityContextEnvelope — top-level API response
// ---------------------------------------------------------------------------
/// Matches `security_context.py:envelope_from_report()` output exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContextEnvelope {
    pub repo: String,
    #[serde(flatten)]
    pub status: ContextStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub summary: ContextSummary,
    pub artifacts: ContextArtifacts,
    pub context: SecurityContext,
    pub leads: VulnerabilityLeads,
    #[serde(default)]
    pub created: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ---------------------------------------------------------------------------
// ContextSummary
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSummary {
    pub fixes: i64,
    pub cves: i64,
    pub top_severity: String,
    pub remediation_coverage: f64,
    pub head_sha: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
}

// ---------------------------------------------------------------------------
// ContextArtifacts
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextArtifacts {
    pub security_context_md: String,
    pub security_context_json: String,
    pub vulnerability_leads_md: String,
    pub vulnerability_leads_json: String,
}

// ---------------------------------------------------------------------------
// SecurityContext (the main context object, ~30 fields)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityContext {
    pub repo: RepoRef,
    pub generated_at: String,
    pub commits_scanned: i64,
    pub commits_flagged: i64,
    pub archetype: String,
    #[serde(default)]
    pub excluded_availability: i64,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_summary: Option<Value>,
    pub agent_brief: String,
    pub tool: String,
    pub known_cves: Vec<Value>,
    pub component_counts: HashMap<String, i64>,
    pub vuln_class_counts: HashMap<String, i64>,
    pub remediation: Remediation,
    pub top_risks: Vec<TopRisk>,
    pub shared_surfaces: Vec<SharedSurface>,
    pub fingerprints: Vec<Fingerprint>,
    #[serde(default)]
    pub watchlist: Vec<Value>,
    #[serde(default)]
    pub scanner_runs: Vec<Value>,
    pub themes: Vec<Value>,
    pub trust: TrustMetrics,
    #[serde(default)]
    pub metrics: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_gate: Option<EvidenceGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
    pub url: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub head_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustMetrics {
    pub score: f64,
    pub grade: String,
    pub action: String,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_based_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_assisted_result: Option<Value>,
}

// ---------------------------------------------------------------------------
// Fingerprint (matches Fingerprint in Phase 0 schema)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_subject: Option<String>,
    pub vuln_class: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    pub components: Vec<String>,
    pub sink: String,
    #[serde(default)]
    pub sink_symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_files: Vec<CommitFileEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_evidence_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_evidence_status: Option<String>,
    pub fix_shape: String,
    #[serde(default = "default_medium")]
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc: Option<String>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_based_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_assisted_result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommitFileEvidence {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub additions: i64,
    #[serde(default)]
    pub deletions: i64,
    #[serde(default)]
    pub changes: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub touched_symbols: Vec<String>,
}

fn default_medium() -> String {
    "medium".to_string()
}

// ---------------------------------------------------------------------------
// TopRisk (aggregated from fingerprints)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopRisk {
    pub vuln_class: String,
    pub severity: String,
    pub component: String,
    pub fix_count: i64,
    pub rationale: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_based_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_assisted_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_hint: Option<String>,
}

// ---------------------------------------------------------------------------
// SharedSurface
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSurface {
    pub surface: String,
    pub guard: String,
    pub entry_points: Vec<Value>,
    pub check_hint: String,
    pub evidence: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Remediation {
    pub coverage: f64,
    pub measurable_fixes: i64,
    pub remediated_fixes: i64,
    pub guarded_sites: i64,
    pub open_leads: i64,
}

// ---------------------------------------------------------------------------
// EvidenceGate
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGate {
    pub commit_sha: bool,
    pub advisory_or_osv: bool,
    pub scanner_runs: bool,
}

// ---------------------------------------------------------------------------
// VulnerabilityLeads
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityLeads {
    pub repo: String,
    pub tool: String,
    pub generated_at: String,
    pub head_ref: String,
    pub head_sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_brief: Option<String>,
    pub remediation_coverage: f64,
    pub measurable_fixes: i64,
    pub remediated_fixes: i64,
    pub open_leads: i64,
    #[serde(default)]
    pub guarded_sites: Vec<Value>,
    #[serde(default)]
    pub fingerprints_scanned: i64,
    #[serde(default)]
    pub fingerprints: Vec<Value>,
    pub findings: Vec<Value>,
    pub leads: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Grade, PillarResult};

    #[test]
    fn grade_from_score_without_flags() {
        let (grade, verdict, action, override_applied) = Grade::from_score(92.0, false);
        assert_eq!(grade, Grade::A);
        assert_eq!(verdict, "Eligible for standard review");
        assert_eq!(action, "Proceed with normal intake checks");
        assert!(!override_applied);
    }

    #[test]
    fn grade_from_score_with_critical_flags_forces_f() {
        let (grade, verdict, _action, override_applied) = Grade::from_score(95.0, true);
        assert_eq!(grade, Grade::F);
        assert_eq!(verdict, "Blocked by policy signal");
        assert!(override_applied);
    }

    #[test]
    fn evidence_builder_rejects_empty_evidence() {
        let result = super::super::VerifiedEvidenceBuilder::new(true).build();
        assert!(result.is_err());
    }

    #[test]
    fn evidence_builder_accepts_commit_sha_only() {
        let result = super::super::VerifiedEvidenceBuilder::new(true)
            .with_commit_sha(Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"))
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn evidence_builder_accepts_cve_only() {
        let result = super::super::VerifiedEvidenceBuilder::new(true)
            .with_cve_count(5)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn evidence_builder_rejects_version_mismatch() {
        let result = super::super::VerifiedEvidenceBuilder::new(false)
            .with_commit_sha(Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn json_schema_pillar_result_serializes_normalized() {
        let p = PillarResult::new("publisher", "Publisher Credibility").with_score(18.0, 20.0);
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["key"], "publisher");
        assert_eq!(json["normalized"], 90.0);
        // `normalized_score` field should NOT appear — only `normalized` in JSON
        assert!(json.get("normalized_score").is_none());
    }

    #[test]
    fn json_schema_context_status_serializes_tagged() {
        let ready = ContextStatus::ready(
            super::super::VerifiedEvidenceBuilder::new(true)
                .with_commit_sha(Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"))
                .build()
                .unwrap(),
        );
        let json = serde_json::to_value(&ready).unwrap();
        assert_eq!(json["status"], "ready");
    }

    #[test]
    fn fingerprint_file_evidence_fields_are_backward_compatible() {
        let old_fingerprint: Fingerprint = serde_json::from_value(serde_json::json!({
            "id": "fp_old",
            "commit_sha": "abc",
            "vuln_class": "Security Fix",
            "cwe": [],
            "components": ["repository"],
            "sink": "repository",
            "sink_symbols": ["repository"],
            "fix_shape": "security-relevant commit from GitHub history",
            "severity": "medium",
            "summary": "security fix"
        }))
        .expect("old fingerprint JSON should deserialize");
        assert!(old_fingerprint.changed_files.is_empty());
        assert!(old_fingerprint.file_evidence_source.is_none());
        assert!(old_fingerprint.file_evidence_status.is_none());

        let new_fingerprint: Fingerprint = serde_json::from_value(serde_json::json!({
            "id": "fp_new",
            "commit_sha": "def",
            "vuln_class": "Security Fix",
            "cwe": [],
            "components": ["src/ssl.c"],
            "sink": "src/ssl.c",
            "sink_symbols": ["wolfSSL_accept"],
            "changed_files": [{
                "path": "src/ssl.c",
                "status": "modified",
                "additions": 3,
                "deletions": 1,
                "changes": 4,
                "touched_symbols": ["wolfSSL_accept"]
            }],
            "file_evidence_source": "github_commit_detail",
            "file_evidence_status": "fetched",
            "fix_shape": "security-relevant commit from GitHub history",
            "severity": "medium",
            "summary": "security fix"
        }))
        .expect("new fingerprint JSON should deserialize");
        assert_eq!(new_fingerprint.changed_files[0].path, "src/ssl.c");
        assert_eq!(
            new_fingerprint.file_evidence_source.as_deref(),
            Some("github_commit_detail")
        );
    }
}
