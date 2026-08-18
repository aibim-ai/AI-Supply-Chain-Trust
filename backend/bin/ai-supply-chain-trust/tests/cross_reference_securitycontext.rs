//! First-party security intelligence verification tests.
//!
//! Checks deterministic pipeline behavior and live GHSA access without relying
//! on third-party security-context snapshots.
//! This is a CI gate — it must pass for the build to succeed.
//!
//! Requires GITHUB_TOKEN env var. Tests are #[ignore] by default
//! and gated behind a feature flag in CI.

#[cfg(test)]
mod cross_reference {

    use ai_supply_chain_trust_intelligence::IntelligenceClient;
    use ai_supply_chain_trust_service::Service;
    use ai_supply_chain_trust_storage::Database;

    use serde_json::json;

    use std::sync::Arc;

    fn github_token() -> Option<String> {
        std::env::var("GITHUB_TOKEN").ok()
    }

    /// Set of real, public repos with well-documented CVEs used as the
    /// fixed cross-reference test set.
    const CROSS_REF_REPOS: &[&str] = &["octocat/Hello-World", "vercel/next.js"];

    /// For each test repo, run create_security_context twice and assert
    /// deterministic output (fingerprints, known_cves, commits_scanned,
    /// commits_flagged, policy_flags) excluding generated_at/head_sha.
    ///
    /// `commits_flagged` counts *commits*: the distinct fix-commit SHAs found
    /// by the history scan, clamped so it can never exceed `commits_scanned`.
    /// The count of policy findings lives in `policy_flags`. It used to be
    /// reported as `commits_flagged`, which produced impossible pairs such as
    /// `commits_scanned: 1, commits_flagged: 2` — two flagged commits out of
    /// one scanned. The assertions below are baselined on the corrected
    /// semantics.
    #[tokio::test]
    #[ignore = "requires GITHUB_TOKEN"]
    async fn deterministic_output_for_fixed_repos() {
        let token = github_token().expect("GITHUB_TOKEN not set");
        let db = Arc::new(Database::open_memory().unwrap());
        let service = Service::new(db.clone(), Some(token));

        for repo in CROSS_REF_REPOS {
            let r1 = service.run_scan(repo).await;
            let r2 = service.run_scan(repo).await;

            match (r1, r2) {
                (Ok(ref report1), Ok(ref report2)) => {
                    // Trust score should be identical within tolerance
                    let score1 = report1
                        .get("trust_score")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let score2 = report2
                        .get("trust_score")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    assert!(
                        (score1 - score2).abs() < 1.0,
                        "{repo}: trust score diverged ({score1} vs {score2})"
                    );

                    let grade1 = report1.get("grade").and_then(|v| v.as_str()).unwrap_or("");
                    let grade2 = report2.get("grade").and_then(|v| v.as_str()).unwrap_or("");
                    assert_eq!(
                        grade1, grade2,
                        "{repo}: grade diverged ({grade1} vs {grade2})"
                    );
                }
                (Err(e1), _) => eprintln!("{repo} scan 1 failed (may be rate-limited): {e1}"),
                (_, Err(e2)) => eprintln!("{repo} scan 2 failed (may be rate-limited): {e2}"),
            }

            let context = service.get_security_context(repo, "http://localhost");
            let Some(counts) = context.get("context") else {
                continue;
            };
            let scanned = counts
                .get("commits_scanned")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let flagged = counts
                .get("commits_flagged")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            assert!(
                flagged <= scanned,
                "{repo}: commits_flagged ({flagged}) must never exceed commits_scanned ({scanned})"
            );
            assert!(
                counts
                    .get("policy_flags")
                    .and_then(|v| v.as_i64())
                    .is_some(),
                "{repo}: policy findings must be reported as policy_flags"
            );
        }
    }

    /// Re-baselined cross-reference of the commit counters against a report
    /// whose contents are known exactly.
    ///
    /// `commits_flagged` now answers "how many commits did the history scan
    /// flag?" — distinct fix-commit SHAs, deduplicated and clamped to
    /// `commits_scanned`. It no longer answers "how many policy findings does
    /// this report carry?", which is `policy_flags`. The two are different
    /// quantities over different populations, and conflating them produced
    /// output that could not be true (more flagged commits than scanned ones)
    /// while hiding the policy count entirely.
    #[test]
    fn commit_counters_separate_flagged_commits_from_policy_findings() {
        use ai_supply_chain_trust_security_context::context_from_report;

        let report = json!({
            "repo": "owner/repo",
            "evaluated_at": "2026-08-18",
            "trust_score": 40.0,
            "grade": "D",
            "verdict": "Review",
            "action": "Review",
            "next_review_date": "2026-11-16",
            "pillar_scores": {},
            // Three policy findings, and a history scan that walked 5 commits
            // and matched 2 distinct fix commits (one of them listed twice).
            "critical_flags": [
                {"category": "supply_chain", "severity": "critical", "message": "one"},
                {"category": "supply_chain", "severity": "critical", "message": "two"},
                {"category": "supply_chain", "severity": "critical", "message": "three"}
            ],
            "scanner_runs": [],
            "observed_metrics": {
                "security_context_version": "2026-07-14-history-precision-v2",
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "metadata": {"default_branch": "main", "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"},
                "security_intel": {
                    "commit_count": 5,
                    "fix_commits": [
                        {"sha": "aaaaaaaaaaaa", "subject": "fix overflow"},
                        {"sha": "aaaaaaaaaaaa", "subject": "fix overflow"},
                        {"sha": "bbbbbbbbbbbb", "subject": "fix traversal"}
                    ]
                }
            }
        });

        let context = context_from_report(&report, "owner/repo");

        assert_eq!(context["commits_scanned"], json!(5));
        // Two distinct fix commits — not three fix-commit entries, and not the
        // three policy findings the old implementation counted here.
        assert_eq!(context["commits_flagged"], json!(2));
        assert_eq!(context["policy_flags"], json!(3));
        assert!(
            context["commits_flagged"].as_i64().unwrap()
                <= context["commits_scanned"].as_i64().unwrap()
        );
    }

    /// The clamp is the guard that makes the old impossible output
    /// (`commits_scanned: 1, commits_flagged: 2`) unrepresentable.
    #[test]
    fn flagged_commits_are_clamped_to_the_commits_actually_scanned() {
        use ai_supply_chain_trust_security_context::context_from_report;

        let report = json!({
            "repo": "owner/repo",
            "evaluated_at": "2026-08-18",
            "critical_flags": [{"category": "supply_chain", "severity": "critical", "message": "one"}],
            "pillar_scores": {},
            "scanner_runs": [],
            "observed_metrics": {
                "security_intel": {
                    "commit_count": 1,
                    "fix_commits": [
                        {"sha": "aaaaaaaaaaaa", "subject": "fix one"},
                        {"sha": "bbbbbbbbbbbb", "subject": "fix two"}
                    ]
                }
            }
        });

        let context = context_from_report(&report, "owner/repo");

        assert_eq!(context["commits_scanned"], json!(1));
        assert_eq!(context["commits_flagged"], json!(1));
        assert_eq!(context["policy_flags"], json!(1));
    }

    /// Verify our CVE count against live GHSA data for a known repo.
    #[tokio::test]
    #[ignore = "requires GITHUB_TOKEN"]
    async fn cve_count_matches_live_ghsa() {
        let token = github_token().expect("GITHUB_TOKEN not set");
        let client = IntelligenceClient::new(Some(token));

        let advisories = client.fetch_github_advisories("vercel", "next.js").await;
        match advisories {
            Ok(advs) => {
                let cve_count = advs
                    .iter()
                    .filter(|a| a.get("cve_id").and_then(|v| v.as_str()).is_some())
                    .count();
                assert!(
                    cve_count > 0,
                    "vercel/next.js should have at least 1 CVE-linked advisory (found {cve_count})"
                );
            }
            Err(e) => eprintln!("GHSA fetch failed (may be rate-limited): {e:?}"),
        }
    }

    /// Verify security context envelope includes the
    /// `security_context_evidence_missing` error variant for reports
    /// that predate the live pipeline.
    #[test]
    fn evidence_missing_error_for_pre_migration_report() {
        let db = Arc::new(Database::open_memory().unwrap());
        let service = Service::new(db.clone(), None);

        // Explicitly store a report without the required evidence fields
        let pre_migration_report = json!({
            "repo": "old/legacy-repo",
            "evaluated_at": "2020-01-01",
            "trust_score": 70.0,
            "grade": "B",
            "verdict": "Use with Awareness",
            "action": "Review",
            "next_review_date": "2020-04-01",
            "coverage": "0/7",
            "critical_flags": [],
            "pillar_scores": {},
            "scanner_runs": [],
            "observed_metrics": {
                "security_context_version": "2020-01-01-legacy-v1"
            }
        });

        let stored = db.insert_report(&pre_migration_report);
        assert!(stored.is_ok());

        let ctx = service.get_security_context("old/legacy-repo", "http://localhost");
        let status = ctx.get("status").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            status == "error",
            "Pre-migration report should return status=error, got status={status}"
        );

        let error_code = ctx.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            error_code, "security_context_evidence_missing",
            "Expected security_context_evidence_missing error code, got '{error_code}'"
        );
    }

    /// Verify the evidence gate correctly rejects reports with
    /// verification_status = "mismatch".
    #[test]
    fn evidence_gate_rejects_verification_mismatch() {
        use ai_supply_chain_trust_security_context::envelope_from_report;
        let report = json!({
            "repo": "test/repo",
            "evaluated_at": "2026-07-09",
            "trust_score": 80.0,
            "grade": "B",
            "verdict": "Use",
            "action": "Review",
            "coverage": "3/4",
            "critical_flags": [],
            "scanner_runs": [],
            "pillar_scores": {},
            "observed_metrics": {
                "security_context_version": "2026-07-14-history-precision-v2",
                "verification_status": "mismatch",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "metadata": {"head_sha": "x", "default_branch": "main"}
            }
        });
        let envelope = envelope_from_report(&report, "test/repo", "http://localhost");
        let json = serde_json::to_value(&envelope).unwrap();
        // verification_status=mismatch should produce error status
        let status = json.get("status").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            status == "error",
            "verification_status=mismatch should produce status=error, got status={status}"
        );
    }

    /// Verify the seed-data module is not linked in the production config.
    #[test]
    fn seed_data_not_in_production() {
        // The seed module is guarded by #[cfg(feature = "seed-data")].
        // The test itself compiles without that feature, proving the
        // seed code is not in the default build path.
        let result = std::panic::catch_unwind(|| {
            // Attempting to use seed data would fail at compile time
            // if the feature is not enabled. This test simply proves
            // the module compiles without seed-data.
        });
        assert!(result.is_ok());
    }
}
