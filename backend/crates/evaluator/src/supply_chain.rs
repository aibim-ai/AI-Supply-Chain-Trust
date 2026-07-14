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

pub struct SupplyChainAttackPrediction;

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
        let created_at = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("created_at"))
            .or_else(|| ctx.metadata.get("created_at"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let repo_created_at = ctx
            .metadata
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("");

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

        // 2. Account takeover risk (new account, not org)
        let account_age = age_days_from_github_timestamp(ctx.today, created_at)
            .or_else(|| age_days_from_github_timestamp(ctx.today, repo_created_at));
        if account_age.unwrap_or(i64::MAX) < 30 && owner_type != "Organization" {
            score -= 3.0;
            flags.push(
                Finding::new(
                    "account_takeover",
                    Severity::Critical,
                    format!(
                        "Publisher account is only {} days old and not an organization.",
                        account_age.unwrap_or_default()
                    ),
                )
                .with_automatic_fail(),
            );
            evidence.push(format!(
                "account_age_days={}",
                account_age
                    .map(|days| days.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ));
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

        // 4. Fake stars detection
        if stars > 100 && stars < 500 && account_age.unwrap_or(i64::MAX) < 90 {
            score -= 1.0;
            evidence.push(format!(
                "rapid_growth_stars={stars},age={}",
                account_age.unwrap_or_default()
            ));
        }

        // 5. MCP indicators without trust
        let has_mcp = ctx
            .metadata
            .get("has_mcp_indicators")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if has_mcp
            && account_age.unwrap_or(i64::MAX) < 180
            && !is_established_org(owner_type, stars)
        {
            score -= 2.0;
            flags.push(Finding::new(
                "mcp_poison",
                Severity::High,
                "MCP indicators detected in untrusted repository.",
            ));
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
            "owner={owner},stars={stars},account_age_days={},stale_days={}",
            account_age
                .map(|days| days.to_string())
                .unwrap_or_else(|| "unknown".into()),
            stale_days
                .map(|days| days.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));

        let _risk_level = if score <= 2.0 {
            "critical"
        } else if score <= 4.0 {
            "high"
        } else if score <= 6.0 {
            "medium"
        } else {
            "low"
        };

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 8.0), 8.0)
            .with_evidence(evidence)
            .with_concerns(flags.iter().map(|f| f.message.clone()).collect())
    }
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
