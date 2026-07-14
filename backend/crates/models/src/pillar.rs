use serde::{Deserialize, Serialize};

/// Matches `models.py:PillarResult(key, name, score, max_score, evidence, concerns, unavailable, applicable)`
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

    pub fn with_unavailable(mut self, items: Vec<String>) -> Self {
        self.unavailable = items;
        self
    }

    pub fn with_applicable(mut self, applicable: bool) -> Self {
        self.applicable = applicable;
        self
    }
}
