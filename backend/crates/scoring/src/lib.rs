//! Pure scoring functions — no I/O, no side effects.
//! Matches `scoring.py` exactly. Must NOT be modified during the port.
//!
//! # Scoring Contract (FROZEN — from Phase 0 §1.3)
//! - 8 pillars with fixed weights, total max 100
//! - Grade table with fixed thresholds
//! - Auto-fail rule: non-empty critical_flags → grade F
//! - Next review: A/B=90d, C=30d, D/F=today

use std::collections::HashMap;

use ai_supply_chain_trust_models::{Finding, Grade, PillarResult};

// ---------------------------------------------------------------------------
// Pillar Weights (FROZEN — must match Python PILLAR_WEIGHTS exactly)
// ---------------------------------------------------------------------------
pub const PILLAR_WEIGHTS: &[(&str, f64)] = &[
    ("publisher_credibility", 20.0),
    ("repo_health", 15.0),
    ("openssf_scorecard", 25.0),
    ("code_safety", 15.0),
    ("model_integrity", 10.0),
    ("supply_chain_attack_prediction", 8.0),
    ("publisher_identity_graph", 4.0),
    ("ai_mcp_specific_risk", 3.0),
];

/// Total maximum score across all pillars.
pub const MAX_SCORE: f64 = 100.0;

/// Look up the weight for a pillar by key. Returns 0.0 for unknown pillars.
pub fn pillar_weight(key: &str) -> f64 {
    PILLAR_WEIGHTS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, w)| *w)
        .unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// Composite Score (Python: scoring.composite_score)
// ---------------------------------------------------------------------------
/// Computes the weighted composite trust score from all pillar results.
///
/// Formula: sum(pillar.normalized * weight) / sum(weight), clamped to [0, 100].
pub fn composite_score(pillars: &HashMap<String, PillarResult>) -> f64 {
    let mut total_weighted = 0.0_f64;
    let mut total_weight = 0.0_f64;

    for (key, pillar) in pillars {
        if !pillar.applicable {
            continue;
        }
        let weight = pillar_weight(key);
        total_weighted += pillar.normalized_score * weight;
        total_weight += weight;
    }

    if total_weight <= 0.0 {
        return 0.0;
    }
    (total_weighted / total_weight).clamp(0.0, 100.0)
}

// ---------------------------------------------------------------------------
// Grade (Python: scoring.grade_for_score)
// ---------------------------------------------------------------------------
/// Returns `(grade, verdict, action, override_applied)`.
/// Auto-fail: if `critical_flags` is non-empty → forces grade F.
pub fn grade_for_score(
    score: f64,
    critical_flags: &[Finding],
) -> (Grade, &'static str, &'static str, bool) {
    Grade::from_score(score, !critical_flags.is_empty())
}

// ---------------------------------------------------------------------------
// Next Review Date (Python: scoring.next_review_date)
// ---------------------------------------------------------------------------
pub fn next_review_date(grade: Grade, evaluated_at: &chrono::NaiveDate) -> chrono::NaiveDate {
    let days = grade.review_days();
    *evaluated_at + chrono::Duration::days(days)
}

// ---------------------------------------------------------------------------
// Scorecard Points Mapping (Python: scoring.scorecard_points)
// ---------------------------------------------------------------------------
/// Maps OpenSSF Scorecard raw score (0–10) to pillar points (0–25).
pub fn scorecard_points(raw_score: f64) -> f64 {
    // Linear mapping: raw/10 * 25
    ((raw_score / 10.0) * 25.0).clamp(0.0, 25.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pillar(key: &str, normalized: f64) -> PillarResult {
        PillarResult::new(key, key).with_score(normalized, 100.0)
    }

    #[test]
    fn composite_score_perfect() {
        let pillars: HashMap<String, PillarResult> = PILLAR_WEIGHTS
            .iter()
            .map(|(k, _)| (k.to_string(), pillar(k, 100.0)))
            .collect();
        assert!((composite_score(&pillars) - 100.0).abs() < 0.01);
    }

    #[test]
    fn composite_score_zero() {
        let pillars: HashMap<String, PillarResult> = PILLAR_WEIGHTS
            .iter()
            .map(|(k, _)| (k.to_string(), pillar(k, 0.0)))
            .collect();
        assert_eq!(composite_score(&pillars), 0.0);
    }

    #[test]
    fn grade_a_threshold() {
        let (grade, _, _, _) = grade_for_score(85.0, &[]);
        assert_eq!(grade, Grade::A);
    }

    #[test]
    fn grade_b_threshold() {
        let (grade, _, _, _) = grade_for_score(70.0, &[]);
        assert_eq!(grade, Grade::B);
    }

    #[test]
    fn grade_c_threshold() {
        let (grade, _, _, _) = grade_for_score(50.0, &[]);
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn grade_d_threshold() {
        let (grade, _, _, _) = grade_for_score(30.0, &[]);
        assert_eq!(grade, Grade::D);
    }

    #[test]
    fn auto_fail_override() {
        let flags = vec![Finding::new(
            "test_flag",
            ai_supply_chain_trust_models::Severity::Critical,
            "test",
        )];
        let (grade, verdict, _, override_applied) = grade_for_score(95.0, &flags);
        assert_eq!(grade, Grade::F);
        assert_eq!(verdict, "Blocked by policy signal");
        assert!(override_applied);
    }

    #[test]
    fn next_review_days() {
        let today = chrono::NaiveDate::from_ymd_opt(2026, 7, 9).unwrap();
        assert_eq!(
            next_review_date(Grade::A, &today),
            chrono::NaiveDate::from_ymd_opt(2026, 10, 7).unwrap()
        );
        assert_eq!(
            next_review_date(Grade::C, &today),
            chrono::NaiveDate::from_ymd_opt(2026, 8, 8).unwrap()
        );
        assert_eq!(next_review_date(Grade::F, &today), today);
    }

    #[test]
    fn scorecard_points_mapping() {
        assert!((scorecard_points(10.0) - 25.0).abs() < 0.01);
        assert!((scorecard_points(0.0) - 0.0).abs() < 0.01);
        assert!((scorecard_points(5.0) - 12.5).abs() < 0.01);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    proptest! {
        /// Composite score is always in [0, 100].
        #[test]
        fn composite_score_in_range(
            publisher in 0.0..=100.0f64,
            repo_health in 0.0..=100.0f64,
            scorecard in 0.0..=100.0f64,
            code_safety in 0.0..=100.0f64,
            model_integrity in 0.0..=100.0f64,
            scap in 0.0..=100.0f64,
            pig in 0.0..=100.0f64,
            ai_mcp in 0.0..=100.0f64,
        ) {
            let mut pillars = HashMap::new();
            let pillars_data = [
                ("publisher_credibility", publisher),
                ("repo_health", repo_health),
                ("openssf_scorecard", scorecard),
                ("code_safety", code_safety),
                ("model_integrity", model_integrity),
                ("supply_chain_attack_prediction", scap),
                ("publisher_identity_graph", pig),
                ("ai_mcp_specific_risk", ai_mcp),
            ];
            for (key, score) in pillars_data {
                pillars.insert(key.to_string(), PillarResult::new(key, key).with_score(score, 100.0));
            }
            let result = composite_score(&pillars);
            assert!(result >= 0.0, "Score {result} < 0");
            assert!(result <= 100.0, "Score {result} > 100");
        }

        /// Auto-fail always returns grade F with override_applied=true when flags present.
        #[test]
        fn auto_fail_always_forces_f(score in 0.0..=100.0f64) {
            let flags = vec![Finding::new("test", ai_supply_chain_trust_models::Severity::Critical, "test")];
            let (grade, verdict, _, override_applied) = grade_for_score(score, &flags);
            assert_eq!(grade, Grade::F);
            assert_eq!(verdict, "Blocked by policy signal");
            assert!(override_applied);
        }

        /// Grade is monotonic: higher score → same or better grade (when no flags).
        #[test]
        fn grade_monotonic(s1 in 0.0..=100.0f64, s2 in 0.0..=100.0f64) {
            let (g1, _, _, _) = grade_for_score(s1, &[]);
            let (g2, _, _, _) = grade_for_score(s2, &[]);
            if s1 >= s2 {
                // Better grade = lower discriminant (A=0, B=1, ..., F=4)
                assert!(g1 as i32 <= g2 as i32,
                    "s1={s1}→{g1:?}, s2={s2}→{g2:?}: higher score got worse grade");
            }
        }
    }
}
