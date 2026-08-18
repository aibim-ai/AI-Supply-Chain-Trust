//! Supply Chain Attack Prediction pillar — max 8 points.
//! Ported from `scap.py` + `evaluate_github_metadata` in main.rs.

use super::{age_days_from_github_timestamp, Pillar, PillarContext};
use ai_supply_chain_trust_models::{Finding, PillarResult, Severity};
use serde_json::Value;

const _ATTACK_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "typosquat",
        "Repository name closely resembles a known popular repo",
        "typosquat",
    ),
    (
        "account_takeover",
        "Publisher has no org affiliation and recent account creation",
        "account_takeover",
    ),
    (
        "install_scripts",
        "Untrusted install scripts detected in repository metadata",
        "malicious_install",
    ),
    (
        "dependency_confusion",
        "Package name matches internal/proprietary package patterns",
        "dep_confusion",
    ),
    (
        "fake_stars",
        "Abnormal star growth pattern detected",
        "fake_stars",
    ),
    (
        "mcp_poison",
        "MCP server indicators without trust signals",
        "mcp_poison",
    ),
    (
        "malware_network",
        "Repository connected to known malware distribution patterns",
        "malware_network",
    ),
    (
        "stale_unmaintained",
        "Repository not maintained but heavily depended on",
        "stale_critical",
    ),
];

/// A publisher account younger than this (in days) is treated as a takeover risk.
const NEW_PUBLISHER_ACCOUNT_DAYS: i64 = 30;
/// A repository younger than this (in days) is treated as newly created.
const NEW_REPOSITORY_DAYS: i64 = 30;
/// Star-growth window: stars accumulated on a repository younger than this look abnormal.
const RAPID_STAR_GROWTH_DAYS: i64 = 90;
/// MCP tooling published from a subject younger than this without trust signals.
const UNSEASONED_MCP_DAYS: i64 = 180;

pub struct SupplyChainAttackPrediction;

/// Which subject an age value describes. Publisher-account age and repository
/// age are *different facts* and must never be presented as one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgeSubject {
    /// Age of the GitHub account that owns the repository (`owner.created_at`).
    PublisherAccount,
    /// Age of the repository itself (top-level `created_at`).
    Repository,
}

/// Raw outcome of the supply-chain assessment, before it is folded into a
/// `PillarResult`. Exposed to unit tests so auto-fail behaviour can be asserted.
struct Assessment {
    score: f64,
    flags: Vec<Finding>,
    evidence: Vec<String>,
}

impl Pillar for SupplyChainAttackPrediction {
    fn key(&self) -> &'static str {
        "supply_chain_attack_prediction"
    }
    fn name(&self) -> &'static str {
        "Supply Chain Attack Prediction"
    }
    fn max_score(&self) -> f64 {
        8.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let assessment = assess(ctx);

        // `concerns` keeps the human-readable text the report UI and the
        // evidence-aware decision logic read; `findings` carries the structured
        // findings so severity/auto-fail survive the pillar boundary.
        let concerns: Vec<String> = assessment.flags.iter().map(|f| f.message.clone()).collect();

        PillarResult::new(self.key(), self.name())
            .with_score(assessment.score.clamp(0.0, 8.0), 8.0)
            .with_evidence(assessment.evidence)
            .with_concerns(concerns)
            .with_findings(assessment.flags)
    }
}

fn assess(ctx: &PillarContext) -> Assessment {
    let mut score: f64 = 8.0;
    let mut flags: Vec<Finding> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();

    let owner = ctx
        .metadata
        .get("owner")
        .and_then(|o| o.get("login"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let owner_type = ctx
        .metadata
        .get("owner")
        .and_then(|o| o.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("User");
    let stars = ctx
        .metadata
        .get("stargazers_count")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let description = ctx
        .metadata
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");

    // Creation timestamp of the *publisher account* (the GitHub user/org that
    // owns the repository). This is only ever `owner.created_at` — the top-level
    // `created_at` belongs to the repository and must NOT stand in for it.
    let publisher_created_at = ctx
        .metadata
        .get("owner")
        .and_then(|o| o.get("created_at"))
        .and_then(Value::as_str)
        .unwrap_or("");

    // Creation timestamp of the *repository*.
    let repo_created_at = ctx
        .metadata
        .get("created_at")
        .and_then(Value::as_str)
        .unwrap_or("");

    // Two distinct facts. Either may be unknown; neither substitutes for the other.
    let publisher_account_age_days =
        age_days_from_github_timestamp(ctx.today, publisher_created_at);
    let repository_age_days = age_days_from_github_timestamp(ctx.today, repo_created_at);
    let is_org = owner_type == "Organization";

    // 1. Typosquat detection
    if let Some(similar) = check_typosquat(ctx.repo.as_str()) {
        score -= 3.0;
        flags.push(
            Finding::new(
                "typosquat",
                Severity::Critical,
                format!("Repo name resembles known target: {similar}"),
            )
            .with_evidence(format!("similar_to={similar}")),
        );
        evidence.push(format!("typosquat_risk={similar}"));
    }

    // 2. Account takeover risk.
    //
    // The auto-fail (which forces grade F) may only fire on a *known* publisher
    // account age below the threshold. When the owner's `created_at` is missing
    // from the GitHub payload we must not guess — and we must never describe the
    // repository's creation date as the publisher's account age.
    match publisher_account_age_days {
        Some(age) if age < NEW_PUBLISHER_ACCOUNT_DAYS && !is_org => {
            score -= 3.0;
            flags.push(
                Finding::new(
                    "account_takeover",
                    Severity::Critical,
                    format!("Publisher account is only {age} days old and not an organization."),
                )
                .with_automatic_fail(),
            );
            evidence.push(format!("publisher_account_age_days={age}"));
        }
        None => {
            // Publisher account age unverifiable. A brand-new repository is still
            // worth a mild, clearly-worded signal — but never an auto-fail, and
            // never phrased as a claim about the account.
            if let Some(repo_age) = repository_age_days {
                if repo_age < NEW_REPOSITORY_DAYS && !is_org {
                    score -= 1.0;
                    flags.push(Finding::new(
                        "new_repo_unverified_publisher",
                        Severity::Medium,
                        format!(
                            "Repository was created {repo_age} days ago and the publisher \
                             account age could not be verified from GitHub metadata."
                        ),
                    ));
                    evidence.push(format!(
                        "repository_age_days={repo_age},publisher_account_age_days=unknown"
                    ));
                }
            }
        }
        _ => {}
    }

    // 3. Dependency confusion risk
    if description.to_lowercase().contains("internal")
        || description.to_lowercase().contains("private")
    {
        score -= 2.0;
        flags.push(Finding::new(
            "dependency_confusion",
            Severity::High,
            "Repository description suggests internal/private use — dependency confusion risk.",
        ));
    }

    // 4. Fake stars detection — star growth is a property of the *repository*,
    // so it is measured against the repository's age. Unknown repo age = no signal.
    if stars > 100 && stars < 500 {
        if let Some(repo_age) = repository_age_days {
            if repo_age < RAPID_STAR_GROWTH_DAYS {
                score -= 1.0;
                evidence.push(format!(
                    "rapid_growth_stars={stars},repository_age_days={repo_age}"
                ));
            }
        }
    }

    // 5. MCP indicators without trust signals. Prefer the publisher account age
    // when it is known; otherwise fall back to the repository age — and say which
    // one the finding is actually based on.
    let has_mcp = ctx
        .metadata
        .get("has_mcp_indicators")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if has_mcp && !is_established_org(owner_type, stars) {
        let basis = publisher_account_age_days
            .map(|days| (AgeSubject::PublisherAccount, days))
            .or_else(|| repository_age_days.map(|days| (AgeSubject::Repository, days)));
        if let Some((subject, days)) = basis {
            if days < UNSEASONED_MCP_DAYS {
                score -= 2.0;
                let message = match subject {
                    AgeSubject::PublisherAccount => format!(
                        "MCP indicators detected in a repository whose publisher account is \
                         only {days} days old and shows no established trust signals."
                    ),
                    AgeSubject::Repository => format!(
                        "MCP indicators detected in a repository created {days} days ago with \
                         no established publisher trust signals (publisher account age \
                         unverified)."
                    ),
                };
                flags.push(Finding::new("mcp_poison", Severity::High, message));
            }
        }
    }

    // 6. Stale + high dependency
    let pushed_at = ctx
        .metadata
        .get("pushed_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let stale_days = age_days_from_github_timestamp(ctx.today, pushed_at);
    if stale_days.unwrap_or_default() > 365 && stars > 1000 {
        score -= 2.0;
        flags.push(Finding::new(
            "stale_critical",
            Severity::High,
            format!(
                "Repository untouched for {} days but has {stars} stars.",
                stale_days.unwrap_or_default()
            ),
        ));
        evidence.push(format!("stale_days={}", stale_days.unwrap_or_default()));
    }

    evidence.push(format!(
        "owner={owner},stars={stars},publisher_account_age_days={},repository_age_days={},stale_days={}",
        render_days(publisher_account_age_days),
        render_days(repository_age_days),
        render_days(stale_days)
    ));

    Assessment {
        score,
        flags,
        evidence,
    }
}

fn render_days(days: Option<i64>) -> String {
    days.map(|d| d.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn check_typosquat(repo: &str) -> Option<String> {
    let known: &[&str] = &[
        "tensorflow",
        "pytorch",
        "transformers",
        "langchain",
        "llama",
        "openai",
        "huggingface",
        "microsoft",
        "google",
        "react",
        "vue",
        "next.js",
        "express",
        "django",
        "flask",
        "fastapi",
        "kubernetes",
    ];
    let lower = repo.to_lowercase();
    for name in known {
        let dist = levenshtein_distance(name, lower.split('/').next_back().unwrap_or(&lower));
        if dist > 0 && dist <= 2 {
            return Some(name.to_string());
        }
    }
    None
}

fn is_established_org(owner_type: &str, stars: i64) -> bool {
    owner_type == "Organization" || stars >= 5000
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate().take(m + 1) {
        row[0] = i;
    }
    for (j, col) in dp[0].iter_mut().enumerate().take(n + 1).skip(1) {
        *col = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use serde_json::json;
    use std::collections::HashMap;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 17).unwrap()
    }

    fn ctx_with(repo: &str, metadata: Value) -> PillarContext {
        PillarContext {
            repo: repo.to_string(),
            today: today(),
            metadata,
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
        }
    }

    fn has_auto_fail(assessment: &Assessment) -> bool {
        assessment.flags.iter().any(|f| f.automatic_fail)
    }

    fn all_text(assessment: &Assessment) -> String {
        let mut text: Vec<String> = assessment.flags.iter().map(|f| f.message.clone()).collect();
        text.extend(assessment.evidence.iter().cloned());
        text.join(" | ")
    }

    /// Regression: KasraAhmadi/job-eval — account created 2019, repo created
    /// 2026-08-11. The repository's age must never be reported as the account's,
    /// and a 7-year-old account must never trigger the auto-fail.
    #[test]
    fn old_account_with_brand_new_repo_does_not_auto_fail() {
        let assessment = assess(&ctx_with(
            "KasraAhmadi/job-eval",
            json!({
                "created_at": "2026-08-11T00:00:00Z",
                "stargazers_count": 1,
                "owner": {
                    "login": "KasraAhmadi",
                    "type": "User",
                    "created_at": "2019-02-15T00:00:00Z"
                }
            }),
        ));

        assert!(
            !has_auto_fail(&assessment),
            "known 7-year-old account must not auto-fail: {:?}",
            assessment.flags
        );
        let text = all_text(&assessment);
        assert!(
            !text.contains("Publisher account is only"),
            "must not claim a young publisher account: {text}"
        );
        assert!(
            !text.contains("account_age_days=6"),
            "repository age must not be reported as account age: {text}"
        );
        assert!(
            text.contains("publisher_account_age_days=2740"),
            "real account age should be surfaced: {text}"
        );
        assert!(
            text.contains("repository_age_days=6"),
            "repository age should be surfaced separately: {text}"
        );
    }

    #[test]
    fn genuinely_new_non_org_account_still_auto_fails() {
        let assessment = assess(&ctx_with(
            "newuser/thing",
            json!({
                "created_at": "2026-08-11T00:00:00Z",
                "stargazers_count": 0,
                "owner": {
                    "login": "newuser",
                    "type": "User",
                    "created_at": "2026-08-01T00:00:00Z"
                }
            }),
        ));

        assert!(
            has_auto_fail(&assessment),
            "brand-new account must auto-fail"
        );
        let text = all_text(&assessment);
        assert!(
            text.contains("Publisher account is only 16 days old"),
            "{text}"
        );
    }

    #[test]
    fn new_org_account_does_not_auto_fail() {
        let assessment = assess(&ctx_with(
            "neworg/thing",
            json!({
                "created_at": "2026-08-11T00:00:00Z",
                "stargazers_count": 0,
                "owner": {
                    "login": "neworg",
                    "type": "Organization",
                    "created_at": "2026-08-01T00:00:00Z"
                }
            }),
        ));

        assert!(!has_auto_fail(&assessment));
    }

    /// Production shape: owner metadata arrives as `{}`, so the account age is
    /// unknown. Unknown must never auto-fail.
    #[test]
    fn unknown_account_age_does_not_auto_fail() {
        let assessment = assess(&ctx_with(
            "someone/new-repo",
            json!({
                "created_at": "2026-08-11T00:00:00Z",
                "stargazers_count": 0,
                "owner": {}
            }),
        ));

        assert!(
            !has_auto_fail(&assessment),
            "unknown account age must not auto-fail: {:?}",
            assessment.flags
        );
        let text = all_text(&assessment);
        assert!(
            !text.contains("Publisher account is only"),
            "must not assert an account age it does not know: {text}"
        );
        assert!(
            text.contains("could not be verified"),
            "unverified publisher wording expected: {text}"
        );
        assert!(
            text.contains("publisher_account_age_days=unknown"),
            "{text}"
        );
    }

    #[test]
    fn unknown_account_age_with_old_repo_emits_no_age_signal() {
        let assessment = assess(&ctx_with(
            "someone/old-repo",
            json!({
                "created_at": "2015-01-01T00:00:00Z",
                "stargazers_count": 20,
                "owner": {}
            }),
        ));

        assert!(!has_auto_fail(&assessment));
        assert!(assessment.flags.is_empty(), "{:?}", assessment.flags);
        assert_eq!(assessment.score, 8.0);
    }

    #[test]
    fn fake_star_signal_uses_repository_age_not_account_age() {
        // Old account, young repo with a suspicious star count: signal fires,
        // and is described in repository terms.
        let assessment = assess(&ctx_with(
            "veteran/hot-repo",
            json!({
                "created_at": "2026-07-01T00:00:00Z",
                "stargazers_count": 300,
                "owner": {"login": "veteran", "type": "User", "created_at": "2012-01-01T00:00:00Z"}
            }),
        ));
        let text = all_text(&assessment);
        assert!(text.contains("rapid_growth_stars=300"), "{text}");
        assert!(text.contains("repository_age_days=47"), "{text}");

        // Old account, old repo: no fake-star signal.
        let assessment = assess(&ctx_with(
            "veteran/old-repo",
            json!({
                "created_at": "2018-07-01T00:00:00Z",
                "stargazers_count": 300,
                "owner": {"login": "veteran", "type": "User", "created_at": "2012-01-01T00:00:00Z"}
            }),
        ));
        assert!(!all_text(&assessment).contains("rapid_growth_stars"));
    }

    #[test]
    fn mcp_signal_names_the_age_it_is_based_on() {
        // Publisher account age known and young.
        let assessment = assess(&ctx_with(
            "newbie/mcp-server",
            json!({
                "created_at": "2026-08-01T00:00:00Z",
                "stargazers_count": 3,
                "has_mcp_indicators": true,
                "owner": {"login": "newbie", "type": "User", "created_at": "2026-05-01T00:00:00Z"}
            }),
        ));
        let text = all_text(&assessment);
        assert!(
            text.contains("publisher account is only 108 days old"),
            "{text}"
        );

        // Publisher account age unknown — wording must fall back to repository age.
        let assessment = assess(&ctx_with(
            "someone/mcp-server",
            json!({
                "created_at": "2026-08-01T00:00:00Z",
                "stargazers_count": 3,
                "has_mcp_indicators": true,
                "owner": {}
            }),
        ));
        let text = all_text(&assessment);
        assert!(text.contains("created 16 days ago"), "{text}");
        assert!(text.contains("publisher account age unverified"), "{text}");
        assert!(!has_auto_fail(&assessment));

        // Old publisher account: no MCP age signal at all.
        let assessment = assess(&ctx_with(
            "veteran/mcp-server",
            json!({
                "created_at": "2026-08-01T00:00:00Z",
                "stargazers_count": 3,
                "has_mcp_indicators": true,
                "owner": {"login": "veteran", "type": "User", "created_at": "2012-01-01T00:00:00Z"}
            }),
        ));
        assert!(!all_text(&assessment).contains("MCP indicators"));
    }

    #[test]
    fn typosquat_detects_near_miss() {
        assert!(check_typosquat("evilcorp/twnsorflow").is_some());
        assert!(check_typosquat("owner/pytorch").is_none()); // exact match
        assert!(check_typosquat("owner/my-unique-name").is_none());
    }

    #[test]
    fn levenshtein_exact() {
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
    }
}
