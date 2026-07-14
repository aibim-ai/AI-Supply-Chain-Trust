use super::{Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct ModelIntegrity;

const UNSAFE_SUFFIXES: &[&str] = &[".pkl", ".pickle", ".pt", ".pth", ".bin"];
const _SAFE_SUFFIXES: &[&str] = &[".safetensors", ".onnx"];

impl Pillar for ModelIntegrity {
    fn key(&self) -> &'static str {
        "model_integrity"
    }
    fn name(&self) -> &'static str {
        "Model / Artifact Integrity"
    }
    fn max_score(&self) -> f64 {
        10.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let Some(_hf) = &ctx.hf_metadata else {
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 10.0)
                .with_applicable(false)
                .with_unavailable(vec![
                    "Model artifact detection evidence is unavailable.".into()
                ]);
        };

        let mut score = 10.0_f64;
        let mut concerns = Vec::new();

        if let Some(artifacts) = ctx.tool_outputs.get("model_artifacts") {
            if let Some(list) = artifacts.as_array() {
                let mut unsafe_count = 0;
                for path in list {
                    let p = path.as_str().unwrap_or("");
                    if UNSAFE_SUFFIXES.iter().any(|s| p.ends_with(s)) {
                        unsafe_count += 1;
                    }
                }
                if unsafe_count > 0 {
                    score -= (unsafe_count as f64).min(8.0);
                    concerns.push(format!(
                        "{unsafe_count} unsafe model artifact(s) require provenance review."
                    ));
                }
            }
        }

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 10.0), 10.0)
            .with_evidence(vec!["model_artifact_scan_complete".into()])
            .with_concerns(concerns)
    }
}
