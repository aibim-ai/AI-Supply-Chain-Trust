use std::collections::HashMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Finding, Grade, PillarResult, ScannerRun};

/// Matches `models.py:EvaluationResult.to_dict()` exactly.
///
/// Eight-pillar evaluation output. The primary contract: every field maps 1:1
/// with the Python dataclass serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub repo: String,
    /// ISO 8601 date string (YYYY-MM-DD)
    pub evaluated_at: String,
    /// Optional input context from the scan request
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub context: String,
    /// 0–100 composite trust score
    pub trust_score: f64,
    /// A–F letter grade
    pub grade: Grade,
    /// Human-readable decision label (e.g. "Review with known gaps")
    pub verdict: String,
    /// Recommended next action (e.g. "Review missing evidence and document known gaps")
    pub action: String,
    /// Weighted evidence coverage across the decision pillars, 0.0–1.0.
    #[serde(default)]
    pub evidence_coverage: f64,
    /// Human-readable confidence derived from coverage and missing evidence.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub confidence: String,
    /// Explicit evidence gaps that affected the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_evidence: Vec<String>,
    /// Short reasons for the current decision label.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decision_reasons: Vec<String>,
    /// UI/API-friendly decision envelope.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub trust_decision: Value,
    /// ISO 8601 date for next scheduled review
    pub next_review_date: String,
    /// key → PillarResult for each of the 8 pillars
    pub pillar_scores: HashMap<String, PillarResult>,
    /// Critical flags that triggered auto-fail or warnings
    pub critical_flags: Vec<Finding>,
    /// Raw OpenSSF Scorecard JSON (if available)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scorecard_raw: Option<Value>,
    /// Whether auto-fail override was applied
    #[serde(default)]
    pub override_applied: bool,
    /// Observed metrics from GitHub metadata, git tree, security intel
    #[serde(default)]
    pub observed_metrics: Value,
    /// Data source identifiers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_sources: Vec<String>,
    /// Scanner execution records (one per tool)
    pub scanner_runs: Vec<ScannerRun>,
    /// Coverage string (e.g. "5/7")
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub coverage: String,
    /// Raw OpenSSF JSON (legacy field, may be null)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openssf_raw: Option<Value>,
    /// ISO 8601 datetime of report creation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The scoring version that produced this report
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring_version: Option<String>,
}

impl EvaluationResult {
    /// Maximum trust score possible across all pillars.
    pub const MAX_SCORE: f64 = 100.0;

    /// The 8-pillar scoring version identifier (matches Python `SCORING_VERSION`).
    pub const SCORING_VERSION: &'static str = "2026-07-05-scap-8pillar-v1";

    /// Build a result from the scoring engine output.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: impl Into<String>,
        evaluated_at: NaiveDate,
        trust_score: f64,
        grade: Grade,
        verdict: impl Into<String>,
        action: impl Into<String>,
        next_review_date: NaiveDate,
        pillar_scores: HashMap<String, PillarResult>,
        critical_flags: Vec<Finding>,
        scanner_runs: Vec<ScannerRun>,
    ) -> Self {
        let override_applied = !critical_flags.is_empty();
        Self {
            repo: repo.into(),
            evaluated_at: evaluated_at.to_string(),
            context: String::new(),
            trust_score,
            grade,
            verdict: verdict.into(),
            action: action.into(),
            evidence_coverage: 1.0,
            confidence: "high".into(),
            missing_evidence: Vec::new(),
            decision_reasons: Vec::new(),
            trust_decision: Value::Null,
            next_review_date: next_review_date.to_string(),
            pillar_scores,
            critical_flags,
            scorecard_raw: None,
            override_applied,
            observed_metrics: Value::Object(Default::default()),
            data_sources: Vec::new(),
            scanner_runs,
            coverage: String::new(),
            openssf_raw: None,
            created_at: None,
            scoring_version: Some(Self::SCORING_VERSION.to_string()),
        }
    }
}
