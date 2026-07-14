use super::{age_days_from_github_timestamp, Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct PublisherCredibility;

impl Pillar for PublisherCredibility {
    fn key(&self) -> &'static str {
        "publisher_credibility"
    }
    fn name(&self) -> &'static str {
        "Publisher Credibility"
    }
    fn max_score(&self) -> f64 {
        20.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let owner = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("login"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let owner_type = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("User");

        let stars = ctx
            .metadata
            .get("stargazers_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as f64;

        let created_at = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("created_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let owner_age_days = age_days_from_github_timestamp(ctx.today, created_at);

        let is_org = owner_type == "Organization";
        let is_high_trust = matches!(
            owner.to_lowercase().as_str(),
            "huggingface"
                | "meta-llama"
                | "google"
                | "microsoft"
                | "openai"
                | "ossf"
                | "cncf"
                | "pytorch"
                | "tensorflow"
                | "apache"
                | "nginx"
        );

        let mut score: f64 = 0.0;
        let mut concerns = Vec::new();

        if is_high_trust {
            score += 10.0;
        }
        if is_org {
            score += 5.0;
        }
        if stars >= 1000.0 {
            score += 3.0;
        }
        if stars >= 100.0 {
            score += 2.0;
        }
        if stars < 10.0 {
            concerns.push(format!("Owner {owner} has very few stars on this repo."));
        }
        if owner_age_days.is_none() {
            concerns.push("Publisher account creation timestamp unavailable or invalid.".into());
        } else if owner_age_days.unwrap_or_default() < 30 && !is_org {
            concerns.push("Publisher account is less than 30 days old.".into());
            score = 0.0; // auto-fail for brand-new publishers
        }

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 20.0), 20.0)
            .with_evidence(vec![
                format!("owner_type={owner_type}"),
                format!("stars={stars}"),
                format!(
                    "owner_age_days={}",
                    owner_age_days
                        .map(|days| days.to_string())
                        .unwrap_or_else(|| "unknown".into())
                ),
            ])
            .with_concerns(concerns)
    }
}
