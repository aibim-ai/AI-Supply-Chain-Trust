use super::{age_days_from_github_timestamp, Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct RepoHealth;

impl Pillar for RepoHealth {
    fn key(&self) -> &'static str {
        "repo_health"
    }
    fn name(&self) -> &'static str {
        "Repository Health & Activity"
    }
    fn max_score(&self) -> f64 {
        15.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let stars = ctx
            .metadata
            .get("stargazers_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as f64;
        let forks = ctx
            .metadata
            .get("forks_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as f64;
        let issues = ctx
            .metadata
            .get("open_issues_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as f64;
        let archived = ctx
            .metadata
            .get("archived")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let disabled = ctx
            .metadata
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let pushed_at = ctx
            .metadata
            .get("pushed_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let license = ctx
            .metadata
            .get("license")
            .and_then(|l| l.get("spdx_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let stale_days = age_days_from_github_timestamp(ctx.today, pushed_at);

        let mut score = 0.0_f64;
        let mut concerns = Vec::new();

        if archived {
            concerns.push("Repository is archived.".into());
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 15.0)
                .with_concerns(concerns)
                .with_evidence(vec!["archived=true".into()]);
        }

        if disabled {
            concerns.push("Repository is disabled.".into());
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 15.0)
                .with_concerns(concerns)
                .with_evidence(vec!["disabled=true".into()]);
        }

        if stars >= 5000.0 {
            score += 5.0;
        } else if stars >= 1000.0 {
            score += 3.0;
        } else if stars >= 100.0 {
            score += 1.0;
        }

        if forks >= 500.0 {
            score += 2.0;
        } else if forks >= 50.0 {
            score += 1.0;
        }

        if stale_days.is_none() {
            concerns.push("Repository push timestamp unavailable or invalid.".into());
        } else if stale_days.unwrap_or_default() <= 90 {
            score += 4.0;
        } else if stale_days.unwrap_or_default() <= 365 {
            score += 2.0;
        } else {
            score += 0.0;
            concerns.push(format!(
                "Repository last pushed {} days ago.",
                stale_days.unwrap_or_default()
            ));
        }

        if !license.is_empty() {
            score += 2.0;
        } else {
            concerns.push("No license detected.".into());
        }

        if issues < 50.0 {
            score += 2.0;
        }

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 15.0), 15.0)
            .with_evidence(vec![
                format!("stars={stars}"),
                format!("forks={forks}"),
                format!(
                    "stale_days={}",
                    stale_days
                        .map(|days| days.to_string())
                        .unwrap_or_else(|| "unknown".into())
                ),
            ])
            .with_concerns(concerns)
    }
}
