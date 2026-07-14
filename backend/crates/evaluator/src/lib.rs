//! Eight-pillar evaluation engine. Matches `evaluator.py` exactly.
//!
//! Each pillar implements the `Pillar` trait. The `evaluate_repository` function
//! orchestrates all pillars and produces an `EvaluationResult`.
//!
//! # Pillar Contract (FROZEN — from Phase 0)
//! Each pillar receives a `PillarContext` and returns a `PillarResult`.
//! Auto-fail flags propagate up to the engine, which forces grade F.

use std::collections::HashMap;

use ai_supply_chain_trust_models::{EvaluationResult, Finding, PillarResult, ScannerRun, Severity};
use ai_supply_chain_trust_scoring::{composite_score, grade_for_score, next_review_date};
use chrono::{DateTime, NaiveDate, NaiveDateTime};
use tracing::info;

pub mod ai_mcp;
pub mod code_safety;
pub mod model_integrity;
pub mod openssf_scorecard;
pub mod patterns;
pub mod pig;
pub mod pillar;
pub mod publisher;
pub mod repo_health;
pub mod supply_chain;
pub mod trust_signals;

#[cfg(feature = "seed-data")]
pub mod seed;

pub use pillar::{Pillar, PillarContext};

pub(crate) fn age_days_from_github_timestamp(today: NaiveDate, timestamp: &str) -> Option<i64> {
    if timestamp.trim().is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
        return Some((today - dt.date_naive()).num_days());
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(timestamp, fmt) {
            return Some((today - dt.date()).num_days());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Pillar Registry
// ---------------------------------------------------------------------------

/// All 8 pillars, in evaluation order. Each produces a `PillarResult`.
pub fn pillar_registry() -> Vec<Box<dyn Pillar>> {
    vec![
        Box::new(publisher::PublisherCredibility),
        Box::new(repo_health::RepoHealth),
        Box::new(openssf_scorecard::OpenSSFScorecard),
        Box::new(code_safety::CodeSafety),
        Box::new(model_integrity::ModelIntegrity),
        Box::new(supply_chain::SupplyChainAttackPrediction),
        Box::new(pig::PublisherIdentityGraph),
        Box::new(ai_mcp::AiMcpRisk),
    ]
}

// ---------------------------------------------------------------------------
// Evidence Sources (inputs to evaluation)
// ---------------------------------------------------------------------------

/// All evidence sources fed into the evaluation pipeline.
/// Matches the parameters of `evaluate_repository()` in evaluator.py.
pub struct EvidenceSources {
    /// Raw GitHub repository metadata JSON
    pub github_metadata: serde_json::Value,
    /// Raw OpenSSF Scorecard JSON (or None if scanner unavailable)
    pub scorecard: Option<serde_json::Value>,
    /// Gitleaks scan results
    pub gitleaks: Option<serde_json::Value>,
    /// pip-audit scan results
    pub pip_audit: Option<serde_json::Value>,
    /// npm audit scan results
    pub npm_audit: Option<serde_json::Value>,
    /// Semgrep scan results
    pub semgrep: Option<serde_json::Value>,
    /// Bandit scan results
    pub bandit: Option<serde_json::Value>,
    /// Trivy scan results
    pub trivy: Option<serde_json::Value>,
    /// HuggingFace model metadata (if AI model repo)
    pub hf_metadata: Option<serde_json::Value>,
    /// Path to downloaded HF artifacts
    pub artifact_root: Option<String>,
    /// Unified tool outputs map (scanner_name → JSON)
    pub tool_outputs: HashMap<String, serde_json::Value>,
    /// Data source identifiers
    pub data_sources: Vec<String>,
    /// Scanner execution records
    pub scanner_runs: Vec<ScannerRun>,
}

// ---------------------------------------------------------------------------
// Main Engine
// ---------------------------------------------------------------------------

/// The core evaluation function. Matches `evaluator.py:evaluate_repository()`.
///
/// # Parameters
/// - `repo`: GitHub repo identifier (owner/name)
/// - `context`: optional input context string
/// - `today`: evaluation date (for staleness calculations)
/// - `evidence`: all fetched evidence sources
///
/// # Returns
/// A complete `EvaluationResult` with all 8 pillars, composite score,
/// grade, verdict, auto-fail handling, and next review date.
pub fn evaluate_repository(
    repo: &str,
    _context: Option<&str>,
    today: NaiveDate,
    evidence: EvidenceSources,
) -> EvaluationResult {
    info!(repo, "Starting 8-pillar evaluation");

    let mut pillar_results: HashMap<String, PillarResult> = HashMap::new();
    let mut critical_flags: Vec<Finding> = Vec::new();

    let ctx = PillarContext {
        repo: repo.to_string(),
        today,
        metadata: evidence.github_metadata.clone(),
        scorecard: evidence.scorecard.clone(),
        gitleaks: evidence.gitleaks.clone(),
        pip_audit: evidence.pip_audit.clone(),
        npm_audit: evidence.npm_audit.clone(),
        semgrep: evidence.semgrep.clone(),
        bandit: evidence.bandit.clone(),
        trivy: evidence.trivy.clone(),
        hf_metadata: evidence.hf_metadata.clone(),
        artifact_root: evidence.artifact_root.clone(),
        tool_outputs: evidence.tool_outputs.clone(),
    };

    for pillar in pillar_registry() {
        let key = pillar.key().to_string();
        let _name = pillar.name().to_string();
        let max_score = pillar.max_score();

        info!(key, "Evaluating pillar");
        let result = pillar.evaluate(&ctx);
        let score = result.score;
        let result = result.with_score(score, max_score);

        for flag in &result.concerns {
            if result.normalized_score <= 2.0 {
                critical_flags.push(Finding::new(key.clone(), Severity::High, flag.clone()));
            }
        }

        pillar_results.insert(key, result);
    }

    let score = composite_score(&pillar_results);
    let (grade, verdict, action, override_applied) = grade_for_score(score, &critical_flags);

    if override_applied {
        info!(repo, score, "Auto-fail override applied");
    }

    let next_review = next_review_date(grade, &today);

    EvaluationResult::new(
        repo,
        today,
        score,
        grade,
        verdict,
        action,
        next_review,
        pillar_results,
        critical_flags,
        evidence.scanner_runs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use serde_json::json;
    use std::collections::HashMap;

    fn sample_metadata() -> serde_json::Value {
        serde_json::json!({
            "full_name": "owner/repo",
            "stargazers_count": 5000,
            "forks_count": 200,
            "open_issues_count": 10,
            "pushed_at": "2026-06-01T00:00:00Z",
            "license": {"spdx_id": "MIT"},
            "archived": false,
            "disabled": false,
            "owner": {
                "login": "owner",
                "type": "Organization",
                "created_at": "2020-01-01T00:00:00Z"
            }
        })
    }

    fn empty_evidence(metadata: serde_json::Value) -> EvidenceSources {
        EvidenceSources {
            github_metadata: metadata,
            scorecard: None,
            gitleaks: None,
            pip_audit: None,
            npm_audit: None,
            semgrep: None,
            bandit: None,
            trivy: None,
            hf_metadata: None,
            artifact_root: None,
            tool_outputs: HashMap::new(),
            data_sources: vec!["github".into()],
            scanner_runs: vec![],
        }
    }

    #[test]
    fn evaluate_repository_produces_all_eight_pillars() {
        let evidence = empty_evidence(sample_metadata());

        let result = evaluate_repository(
            "owner/repo",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            evidence,
        );

        assert_eq!(result.pillar_scores.len(), 8);
        assert!((0.0..=100.0).contains(&result.trust_score));
        assert!(!result.grade.to_string().is_empty());
    }

    #[test]
    fn github_rfc3339_dates_are_used_for_health_and_publisher_age() {
        let evidence = empty_evidence(json!({
            "full_name": "wolfSSL/wolfssl",
            "stargazers_count": 2868,
            "forks_count": 1005,
            "open_issues_count": 148,
            "pushed_at": "2026-07-09T17:14:49Z",
            "license": {"spdx_id": "GPL-3.0"},
            "archived": false,
            "disabled": false,
            "owner": {
                "login": "wolfSSL",
                "type": "Organization",
                "created_at": "2013-11-08T19:02:42Z"
            }
        }));

        let result = evaluate_repository(
            "wolfssl/wolfssl",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            evidence,
        );

        let health = result.pillar_scores.get("repo_health").unwrap();
        assert!(
            health.evidence.iter().any(|item| item == "stale_days=0"),
            "repo health evidence should use pushed_at, got {:?}",
            health.evidence
        );
        assert!(
            !health
                .concerns
                .iter()
                .any(|item| item.contains("9999 days")),
            "repo health should not emit sentinel stale-days concerns"
        );

        let publisher = result.pillar_scores.get("publisher_credibility").unwrap();
        let owner_age = publisher
            .evidence
            .iter()
            .find_map(|item| item.strip_prefix("owner_age_days="))
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap();
        assert!(
            owner_age > 4000,
            "owner age should be real, got {owner_age}"
        );
    }

    #[test]
    fn missing_scanners_and_scorecard_are_unavailable_not_confident_or_hard_zero() {
        let result = evaluate_repository(
            "owner/repo",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            empty_evidence(sample_metadata()),
        );

        let code_safety = result.pillar_scores.get("code_safety").unwrap();
        assert!(!code_safety.applicable);
        assert!(!code_safety.unavailable.is_empty());
        assert_eq!(code_safety.normalized_score, 0.0);

        let scorecard = result.pillar_scores.get("openssf_scorecard").unwrap();
        assert!(!scorecard.applicable);
        assert!(!scorecard.unavailable.is_empty());
        assert_eq!(scorecard.normalized_score, 0.0);
    }

    #[test]
    fn scap_detects_typosquat() {
        let evidence = EvidenceSources {
            github_metadata: json!({
                "full_name": "evilcorp/twnsorflow",
                "stargazers_count": 10,
                "forks_count": 1,
                "open_issues_count": 0,
                "pushed_at": "2026-06-01T00:00:00Z",
                "license": null,
                "archived": false,
                "disabled": false,
                "description": "A machine learning library",
                "owner": {"login": "evilcorp", "type": "User", "created_at": "2026-07-01T00:00:00Z"}
            }),
            scorecard: None,
            gitleaks: None,
            pip_audit: None,
            npm_audit: None,
            semgrep: None,
            bandit: None,
            trivy: None,
            hf_metadata: None,
            artifact_root: None,
            tool_outputs: HashMap::new(),
            data_sources: vec!["github".into()],
            scanner_runs: vec![],
        };

        let result = evaluate_repository(
            "evilcorp/twnsorflow",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            evidence,
        );

        let scap = result
            .pillar_scores
            .get("supply_chain_attack_prediction")
            .unwrap();
        // Typosquat should reduce SCAP score significantly
        assert!(
            scap.normalized_score < 70.0,
            "Expected SCAP score < 70 for typosquat, got {}",
            scap.normalized_score
        );
        assert!(!scap.concerns.is_empty(), "Expected concerns for typosquat");
    }

    #[test]
    fn publisher_credibility_for_new_account() {
        let evidence = EvidenceSources {
            github_metadata: json!({
                "full_name": "newuser/test",
                "stargazers_count": 0,
                "forks_count": 0,
                "open_issues_count": 0,
                "pushed_at": "2026-07-01T00:00:00Z",
                "license": null,
                "archived": false, "disabled": false,
                "owner": {"login": "newuser", "type": "User", "created_at": "2026-07-01T00:00:00Z"}
            }),
            scorecard: None,
            gitleaks: None,
            pip_audit: None,
            npm_audit: None,
            semgrep: None,
            bandit: None,
            trivy: None,
            hf_metadata: None,
            artifact_root: None,
            tool_outputs: HashMap::new(),
            data_sources: vec!["github".into()],
            scanner_runs: vec![],
        };

        let result = evaluate_repository(
            "newuser/test",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            evidence,
        );

        let pub_cred = result.pillar_scores.get("publisher_credibility").unwrap();
        // Brand new user with 0 stars should get very low publisher credibility
        assert!(
            pub_cred.normalized_score < 30.0,
            "Expected pub cred < 30 for new user, got {}",
            pub_cred.normalized_score
        );
    }

    #[test]
    fn microsoft_repo_gets_high_trust() {
        let evidence = EvidenceSources {
            github_metadata: json!({
                "full_name": "microsoft/typescript",
                "stargazers_count": 100000,
                "forks_count": 10000,
                "open_issues_count": 50,
                "pushed_at": "2026-07-01T00:00:00Z",
                "license": {"spdx_id": "Apache-2.0"},
                "archived": false, "disabled": false,
                "owner": {"login": "microsoft", "type": "Organization", "created_at": "2010-01-01T00:00:00Z"}
            }),
            scorecard: None,
            gitleaks: None,
            pip_audit: None,
            npm_audit: None,
            semgrep: None,
            bandit: None,
            trivy: None,
            hf_metadata: None,
            artifact_root: None,
            tool_outputs: HashMap::new(),
            data_sources: vec!["github".into()],
            scanner_runs: vec![],
        };

        let result = evaluate_repository(
            "microsoft/typescript",
            None,
            NaiveDate::from_ymd_opt(2026, 7, 9).unwrap(),
            evidence,
        );

        let pub_cred = result.pillar_scores.get("publisher_credibility").unwrap();
        assert!(
            pub_cred.normalized_score > 70.0,
            "Expected pub cred > 70 for Microsoft, got {}",
            pub_cred.normalized_score
        );

        let pig = result
            .pillar_scores
            .get("publisher_identity_graph")
            .unwrap();
        assert!(
            pig.normalized_score > 50.0,
            "Expected PIG > 50 for Microsoft, got {}",
            pig.normalized_score
        );
    }
}
