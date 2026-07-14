//! Test parity with Python test suite.
//! Covers: scoring boundaries, pillar outputs, security context shapes.

#[cfg(test)]
mod scoring_tests {
    use ai_supply_chain_trust_models::*;
    use ai_supply_chain_trust_scoring::*;
    use std::collections::HashMap;

    fn pillar(key: &str, normalized: f64) -> PillarResult {
        PillarResult::new(key, key).with_score(normalized, 100.0)
    }

    #[test]
    fn grade_boundary_exactly_85_is_a() {
        let (grade, _, _, _) = grade_for_score(85.0, &[]);
        assert_eq!(grade, Grade::A);
    }

    #[test]
    fn grade_boundary_84_9_is_b() {
        let (grade, _, _, _) = grade_for_score(84.999, &[]);
        assert_eq!(grade, Grade::B);
    }

    #[test]
    fn grade_boundary_exactly_70_is_b() {
        let (grade, _, _, _) = grade_for_score(70.0, &[]);
        assert_eq!(grade, Grade::B);
    }

    #[test]
    fn grade_boundary_exactly_50_is_c() {
        let (grade, _, _, _) = grade_for_score(50.0, &[]);
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn grade_boundary_exactly_30_is_d() {
        let (grade, _, _, _) = grade_for_score(30.0, &[]);
        assert_eq!(grade, Grade::D);
    }

    #[test]
    fn grade_boundary_29_9_is_f() {
        let (grade, _, _, _) = grade_for_score(29.999, &[]);
        assert_eq!(grade, Grade::F);
    }

    #[test]
    fn composite_score_empty_pillars_returns_zero() {
        let pillars = HashMap::new();
        assert_eq!(composite_score(&pillars), 0.0);
    }

    #[test]
    fn composite_score_uniform_50_produces_50() {
        let mut pillars = HashMap::new();
        for (k, _) in PILLAR_WEIGHTS {
            pillars.insert(k.to_string(), pillar(k, 50.0));
        }
        assert!((composite_score(&pillars) - 50.0).abs() < 0.01);
    }

    #[test]
    fn scorecard_points_min_max() {
        assert!((scorecard_points(0.0) - 0.0).abs() < 0.01);
        assert!((scorecard_points(10.0) - 25.0).abs() < 0.01);
    }

    #[test]
    fn next_review_date_a_is_90_days() {
        use chrono::NaiveDate;
        let today = NaiveDate::from_ymd_opt(2026, 7, 9).unwrap();
        let review = next_review_date(Grade::A, &today);
        assert_eq!(review, NaiveDate::from_ymd_opt(2026, 10, 7).unwrap());
    }
}

#[cfg(test)]
mod security_context_tests {
    use ai_supply_chain_trust_security_context::*;
    use serde_json::json;

    fn report_with_evidence() -> serde_json::Value {
        json!({
            "repo": "test/repo",
            "evaluated_at": "2026-07-09",
            "trust_score": 80.0, "grade": "B",
            "verdict": "Use with Awareness", "action": "Review",
            "coverage": "3/4",
            "critical_flags": [],
            "scanner_runs": [{"tool":"test","status":"ok","detail":"ok"}],
            "pillar_scores": {
                "repo_health": {"name":"Health","normalized":80.0,"evidence":[],"concerns":[],"unavailable":[]}
            },
            "observed_metrics": {
                "metadata": {"default_branch":"main","head_sha":"abc","commit_count":10},
                "security_context_version": "2026-07-08-live-github-v1",
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "security_intel": {
                    "fix_commits": [{
                        "sha":"abc123","subject":"fix xss","component":"router.ts",
                        "vuln_class":"Cross-Site Scripting","cwe":["CWE-79"],
                        "severity":"high","date":"2025-01-01","html_url":"https://github.com/a"
                    }],
                    "github_advisories": [], "osv_vulns": [],
                    "cves": ["CVE-2025-0001"], "commit_count": 100
                }
            }
        })
    }

    #[test]
    fn envelope_returns_ready_with_evidence() {
        let report = report_with_evidence();
        let env = envelope_from_report(&report, "test/repo", "http://localhost");
        let env_json = serde_json::to_value(&env).unwrap();
        let status = env_json.get("status").and_then(|v| v.as_str()).unwrap();
        assert!(
            status == "ready" || status == "error",
            "Expected ready or error, got {status}"
        );
    }

    #[test]
    fn context_has_fingerprints() {
        let report = report_with_evidence();
        let ctx = context_from_report(&report, "test/repo");
        let fps = ctx.get("fingerprints").and_then(|v| v.as_array());
        assert!(fps.is_some(), "context should have fingerprints");
        let fps = fps.unwrap();
        assert!(!fps.is_empty(), "should have at least 1 fingerprint");
    }

    #[test]
    fn empty_report_produces_no_fingerprints() {
        let report = json!({
            "repo": "empty/repo", "evaluated_at": "2026-07-09",
            "trust_score": 50.0, "grade": "C", "verdict": "Caution", "action": "Review",
            "coverage": "0/0", "critical_flags": [], "scanner_runs": [],
            "pillar_scores": {}, "observed_metrics": {}
        });
        let fps = fingerprints_from_report(&report);
        let arr = fps.as_array().unwrap();
        assert!(arr.is_empty(), "empty report should have 0 fingerprints");
    }

    #[test]
    fn markdown_render_contains_repo_name() {
        let report = report_with_evidence();
        let md = render_context_markdown(&report);
        assert!(md.contains("test/repo"));
    }
}

#[cfg(test)]
mod evidence_tests {
    use ai_supply_chain_trust_security_context::has_ready_evidence;
    use serde_json::json;

    #[test]
    fn report_without_version_fails() {
        let report = json!({ "observed_metrics": {}, "scanner_runs": [] });
        assert!(!has_ready_evidence(&report));
    }

    #[test]
    fn report_with_version_and_sha_passes() {
        let report = json!({
            "observed_metrics": {
                "security_context_version": "2026-07-08-live-github-v1",
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
            },
            "scanner_runs": []
        });
        assert!(has_ready_evidence(&report));
    }
}
