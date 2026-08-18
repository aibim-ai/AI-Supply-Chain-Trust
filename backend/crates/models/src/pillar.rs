use super::Finding;
use serde::{Deserialize, Serialize};

/// Matches `models.py:PillarResult(key, name, score, max_score, evidence, concerns, unavailable, applicable)`
///
/// `findings` is a Rust-side addition: pillars that produce structured
/// [`Finding`]s keep them here so `severity` and `automatic_fail` survive the
/// pillar boundary instead of being flattened into `concerns` strings. It is
/// `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so previously
/// stored reports still deserialize and pillars without findings serialize
/// exactly as before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PillarResult {
    pub key: String,
    pub name: String,
    pub score: f64,
    pub max_score: f64,
    /// Always serialized as `normalized` in JSON (matching Python `.normalized` property)
    #[serde(rename = "normalized")]
    pub normalized_score: f64,
    pub evidence: Vec<String>,
    pub concerns: Vec<String>,
    /// Structured findings produced by this pillar, preserving `severity` and
    /// `automatic_fail`. Human-readable messages are still mirrored into
    /// `concerns` for the report UI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,
    #[serde(default = "default_applicable")]
    pub applicable: bool,
}

fn default_applicable() -> bool {
    true
}

impl PillarResult {
    pub fn new(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            score: 0.0,
            max_score: 0.0,
            normalized_score: 0.0,
            evidence: Vec::new(),
            concerns: Vec::new(),
            findings: Vec::new(),
            unavailable: Vec::new(),
            applicable: true,
        }
    }

    /// Computes the normalized score: (score / max_score) * 100, clamped.
    pub fn compute_normalized(score: f64, max_score: f64) -> f64 {
        if max_score <= 0.0 {
            return 0.0;
        }
        (score / max_score * 100.0).clamp(0.0, 100.0)
    }

    pub fn with_score(mut self, score: f64, max_score: f64) -> Self {
        self.score = score;
        self.max_score = max_score;
        self.normalized_score = Self::compute_normalized(score, max_score);
        self
    }

    pub fn with_evidence(mut self, items: Vec<String>) -> Self {
        self.evidence = items;
        self
    }

    pub fn with_concerns(mut self, items: Vec<String>) -> Self {
        self.concerns = items;
        self
    }

    /// Attach the pillar's structured findings (severity + auto-fail preserved).
    pub fn with_findings(mut self, items: Vec<Finding>) -> Self {
        self.findings = items;
        self
    }

    pub fn with_unavailable(mut self, items: Vec<String>) -> Self {
        self.unavailable = items;
        self
    }

    pub fn with_applicable(mut self, applicable: bool) -> Self {
        self.applicable = applicable;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    #[test]
    fn legacy_json_without_findings_still_deserializes() {
        let legacy = r#"{
            "key": "publisher_credibility",
            "name": "Publisher Credibility",
            "score": 5.0,
            "max_score": 20.0,
            "normalized": 25.0,
            "evidence": [],
            "concerns": ["something"]
        }"#;
        let parsed: PillarResult = serde_json::from_str(legacy).unwrap();
        assert!(parsed.findings.is_empty());
        assert!(parsed.applicable);
    }

    #[test]
    fn empty_findings_are_not_serialized() {
        let result = PillarResult::new("k", "n").with_score(1.0, 2.0);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("findings"), "{json}");
    }

    #[test]
    fn findings_round_trip_with_severity_and_auto_fail() {
        let result = PillarResult::new("k", "n").with_findings(vec![Finding::new(
            "account_takeover",
            Severity::Critical,
            "blocking",
        )
        .with_automatic_fail()]);
        let json = serde_json::to_string(&result).unwrap();
        let parsed: PillarResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.findings.len(), 1);
        assert!(parsed.findings[0].automatic_fail);
        assert_eq!(parsed.findings[0].severity, Severity::Critical);
    }
}
