use super::{Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct AiMcpRisk;

impl Pillar for AiMcpRisk {
    fn key(&self) -> &'static str {
        "ai_mcp_specific_risk"
    }
    fn name(&self) -> &'static str {
        "AI/MCP-Specific Risk"
    }
    fn max_score(&self) -> f64 {
        3.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let has_mcp = ctx
            .metadata
            .get("has_mcp_indicators")
            .and_then(|v| v.as_bool());
        let has_model = ctx
            .metadata
            .get("has_model_artifacts")
            .and_then(|v| v.as_bool());
        let (Some(has_mcp), Some(has_model)) = (has_mcp, has_model) else {
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 3.0)
                .with_applicable(false)
                .with_unavailable(vec!["AI/MCP detection evidence is unavailable.".into()]);
        };

        let mut score = 3.0_f64;
        let mut concerns = Vec::new();

        if has_mcp {
            score -= 1.0;
            concerns.push("MCP indicators found — AI-tooling review required.".into());
        }
        if has_model {
            score -= 1.0;
            concerns.push("Model artifacts found — provenance review required.".into());
        }

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 3.0), 3.0)
            .with_evidence(vec![
                format!("has_mcp={has_mcp}"),
                format!("has_model={has_model}"),
            ])
            .with_concerns(concerns)
    }
}
