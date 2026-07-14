use std::collections::HashMap;

use ai_supply_chain_trust_models::PillarResult;
use chrono::NaiveDate;
use serde_json::Value;

/// The evaluation context passed to each pillar.
/// Contains all fetched evidence — pillars read only what they need.
pub struct PillarContext {
    pub repo: String,
    pub today: NaiveDate,
    pub metadata: Value,
    pub scorecard: Option<Value>,
    pub gitleaks: Option<Value>,
    pub pip_audit: Option<Value>,
    pub npm_audit: Option<Value>,
    pub semgrep: Option<Value>,
    pub bandit: Option<Value>,
    pub trivy: Option<Value>,
    pub hf_metadata: Option<Value>,
    pub artifact_root: Option<String>,
    pub tool_outputs: HashMap<String, Value>,
}

/// A single pillar in the evaluation engine.
///
/// Matches the `pillars/interface.py:Pillar` protocol.
/// Each pillar evaluates one dimension of trust and returns a `PillarResult`.
///
/// # Contract
/// - `key()`: unique identifier, matches `PILLAR_WEIGHTS` key
/// - `name()`: human-readable display name
/// - `max_score()`: maximum possible score (must match `PILLAR_WEIGHTS`)
/// - `evaluate()`: produce a result from the available evidence
pub trait Pillar: Send + Sync {
    /// Unique key (e.g. "publisher_credibility").
    fn key(&self) -> &'static str;

    /// Display name (e.g. "Publisher Credibility").
    fn name(&self) -> &'static str;

    /// Maximum score for this pillar. Must match PILLAR_WEIGHTS.
    fn max_score(&self) -> f64;

    /// Evaluate this pillar against the given context.
    /// Returns a PillarResult with score and evidence.
    fn evaluate(&self, ctx: &PillarContext) -> PillarResult;
}
