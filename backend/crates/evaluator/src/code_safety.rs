use super::{Pillar, PillarContext};
use ai_supply_chain_trust_models::PillarResult;

pub struct CodeSafety;

impl Pillar for CodeSafety {
    fn key(&self) -> &'static str {
        "code_safety"
    }
    fn name(&self) -> &'static str {
        "Code & Dependency Safety"
    }
    fn max_score(&self) -> f64 {
        15.0
    }

    fn evaluate(&self, ctx: &PillarContext) -> PillarResult {
        let mut score = 15.0_f64;
        let mut concerns = Vec::new();
        let mut evidence = Vec::new();
        let scanner_count = [
            ctx.gitleaks.as_ref().is_some_and(|value| value.is_array()),
            ctx.npm_audit.as_ref().is_some_and(|value| {
                value
                    .pointer("/metadata/vulnerabilities/total")
                    .and_then(|v| v.as_i64())
                    .is_some()
            }),
            ctx.pip_audit
                .as_ref()
                .is_some_and(|value| value.get("vulnerabilities").is_some_and(|v| v.is_array())),
            ctx.semgrep
                .as_ref()
                .is_some_and(|value| value.get("results").is_some_and(|v| v.is_array())),
            ctx.bandit.as_ref().is_some_and(|value| value.is_object()),
            ctx.trivy.as_ref().is_some_and(|value| value.is_object()),
        ]
        .into_iter()
        .filter(|valid| *valid)
        .count();

        if scanner_count == 0 {
            return PillarResult::new(self.key(), self.name())
                .with_score(0.0, 15.0)
                .with_applicable(false)
                .with_unavailable(vec![
                    "Code safety scanner data not available for this repository.".into(),
                ]);
        }

        if let Some(gitleaks) = &ctx.gitleaks {
            let leak_count = gitleaks.as_array().map(|a| a.len()).unwrap_or(0);
            if leak_count > 0 {
                score -= leak_count.min(10) as f64;
                concerns.push(format!("Gitleaks found {leak_count} potential secret(s)."));
            }
            evidence.push(format!("gitleaks_hits={leak_count}"));
        }

        if let Some(npm) = &ctx.npm_audit {
            let vulns = npm
                .get("metadata")
                .and_then(|m| m.get("vulnerabilities"))
                .and_then(|v| v.get("total"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if vulns > 0 {
                score -= (vulns as f64).min(5.0);
                concerns.push(format!("npm audit found {vulns} vulnerability(s)."));
            }
            evidence.push(format!("npm_vulns={vulns}"));
        }

        if let Some(pip) = &ctx.pip_audit {
            let vulns = pip
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if vulns > 0 {
                score -= (vulns as f64).min(5.0);
                concerns.push(format!("pip-audit found {vulns} vulnerability(s)."));
            }
            evidence.push(format!("pip_vulns={vulns}"));
        }

        if let Some(semgrep) = &ctx.semgrep {
            let results = semgrep
                .get("results")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if results > 0 {
                score -= (results as f64).min(5.0);
                concerns.push(format!("Semgrep found {results} finding(s)."));
            }
            evidence.push(format!("semgrep_findings={results}"));
        }

        evidence.push(format!("scanners_available={scanner_count}"));

        PillarResult::new(self.key(), self.name())
            .with_score(score.clamp(0.0, 15.0), 15.0)
            .with_evidence(evidence)
            .with_concerns(concerns)
    }
}
