//! Publisher Identity Graph pillar — max 4 points.
//! Aggregates trust signals across repos owned by the same publisher.

use super::{Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;
use serde_json::Value;

pub struct PublisherIdentityGraph;

impl Pillar for PublisherIdentityGraph {
    fn key(&self) -> &'static str {
        "publisher_identity_graph"
    }
    fn name(&self) -> &'static str {
        "Publisher Identity Graph"
    }
    fn max_score(&self) -> f64 {
        4.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let is_org = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("type"))
            .and_then(Value::as_str)
            .map(|t| t == "Organization")
            .unwrap_or(false);

        let owner_login = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("login"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let stars = ctx
            .metadata
            .get("stargazers_count")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let public_repos = ctx
            .metadata
            .get("owner")
            .and_then(|o| o.get("public_repos"))
            .and_then(Value::as_i64)
            .unwrap_or(0);

        let mut score = 0.0_f64;

        // Organization identity carries weight
        if is_org {
            score += 2.0;
        }

        // Established publisher (stars > 1000)
        if stars >= 1000 {
            score += 1.0;
        }

        // Active publisher with multiple public repos
        if public_repos >= 5 {
            score += 1.0;
        }

        // High-trust orgs get full score
        if is_high_trust_org(owner_login) {
            score = 4.0;
        }

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 4.0), 4.0)
            .with_evidence(vec![
                format!(
                    "publisher_type={}",
                    if is_org { "Organization" } else { "User" }
                ),
                format!("public_repos={public_repos}"),
                format!("stars={stars}"),
            ])
    }
}

fn is_high_trust_org(login: &str) -> bool {
    matches!(
        login.to_lowercase().as_str(),
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
            | "github"
            | "rust-lang"
            | "nodejs"
            | "python"
            | "apple"
    )
}
