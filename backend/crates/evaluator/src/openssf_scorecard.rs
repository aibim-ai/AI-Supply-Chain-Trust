use super::{Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct OpenSSFScorecard;

impl Pillar for OpenSSFScorecard {
    fn key(&self) -> &'static str {
        "openssf_scorecard"
    }
    fn name(&self) -> &'static str {
        "OpenSSF Scorecard"
    }
    fn max_score(&self) -> f64 {
        25.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let Some(scorecard) = &ctx.scorecard else {
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 25.0)
                .with_applicable(false)
                .with_unavailable(vec![
                    "Scorecard data not available for this repository.".into()
                ]);
        };

        let raw_score = scorecard
            .get("score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let points = ai_supply_chain_trust_scoring::scorecard_points(raw_score);

        let high_impact_checks = [
            "Dangerous-Workflow",
            "Token-Permissions",
            "Vulnerabilities",
            "Branch-Protection",
            "Security-Policy",
            "Code-Review",
            "Maintained",
        ];
        let mut concerns = Vec::new();

        if let Some(checks) = scorecard.get("checks").and_then(|v| v.as_array()) {
            for check in checks {
                let name = check.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if high_impact_checks.contains(&name) {
                    let score = check.get("score").and_then(|v| v.as_i64()).unwrap_or(-1);
                    if score == 0 {
                        concerns.push(format!("Scorecard check '{name}' scored 0 — high risk."));
                    }
                }
            }
        }

        let mut evidence = vec![format!("raw_scorecard_score={raw_score}")];
        if let Some(date) = scorecard.get("date").and_then(|v| v.as_str()) {
            evidence.push(format!("scorecard_date={date}"));
        }

        PillarResult::new(self.key(), self.name())
            .with_score(points, 25.0)
            .with_evidence(evidence)
            .with_concerns(concerns)
    }
}
