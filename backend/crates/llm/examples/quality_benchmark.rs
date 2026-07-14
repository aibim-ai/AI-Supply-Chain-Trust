use ai_supply_chain_trust_llm::{tasks, GuardrailError, LlmUnavailableError};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Case {
    id: String,
    input: Value,
    expected_vuln_class: String,
    expected_severity: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUN_OPENROUTER_LIVE_TESTS").ok().as_deref() != Some("1") {
        anyhow::bail!(
            "set RUN_OPENROUTER_LIVE_TESTS=1 to run the opt-in live model quality benchmark"
        );
    }
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../tests/fixtures/model-quality-v2.json"))?;
    let total = cases.len();
    let mut rule_class_correct = 0usize;
    let mut rule_severity_correct = 0usize;
    let mut llm_class_correct = 0usize;
    let mut llm_severity_correct = 0usize;
    let mut combined_class_correct = 0usize;
    let mut combined_severity_correct = 0usize;
    let mut llm_responses = 0usize;
    let mut unsupported_claims = 0usize;
    let mut fallbacks = 0usize;

    for case in &cases {
        let rule = &case.input["rule_based_result"];
        rule_class_correct += field_matches(rule, "vuln_class", &case.expected_vuln_class) as usize;
        rule_severity_correct += field_matches(rule, "severity", &case.expected_severity) as usize;

        match tasks::classify_vulnerability(&case.input).await {
            Ok(output) => {
                llm_responses += 1;
                let class_correct = field_matches(&output, "vuln_class", &case.expected_vuln_class);
                let severity_correct = field_matches(&output, "severity", &case.expected_severity);
                llm_class_correct += class_correct as usize;
                llm_severity_correct += severity_correct as usize;
                if output.get("status").and_then(Value::as_str) == Some("insufficient_evidence") {
                    fallbacks += 1;
                    combined_class_correct +=
                        field_matches(rule, "vuln_class", &case.expected_vuln_class) as usize;
                    combined_severity_correct +=
                        field_matches(rule, "severity", &case.expected_severity) as usize;
                } else {
                    combined_class_correct += class_correct as usize;
                    combined_severity_correct += severity_correct as usize;
                }
            }
            Err(GuardrailError::Rejected(error)) => {
                llm_responses += 1;
                unsupported_claims += 1;
                fallbacks += 1;
                combined_class_correct +=
                    field_matches(rule, "vuln_class", &case.expected_vuln_class) as usize;
                combined_severity_correct +=
                    field_matches(rule, "severity", &case.expected_severity) as usize;
                eprintln!("{}: guardrail rejected output: {error}", case.id);
            }
            Err(GuardrailError::Unavailable(LlmUnavailableError::HttpStatus {
                status: 429,
                ..
            })) => {
                anyhow::bail!(
                    "benchmark inconclusive: OpenRouter provider rate-limited case {} (HTTP 429)",
                    case.id
                );
            }
            Err(error) => {
                anyhow::bail!("benchmark inconclusive on case {}: {error}", case.id);
            }
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "dataset": "model-quality-v2",
            "cases": total,
            "rule_based": scores(rule_class_correct, rule_severity_correct, total),
            "model": scores(llm_class_correct, llm_severity_correct, total),
            "combined": scores(combined_class_correct, combined_severity_correct, total),
            "unsupported_claim_rate": ratio(unsupported_claims, llm_responses),
            "guardrail_fallbacks": fallbacks,
            "llm_responses": llm_responses
        }))?
    );
    Ok(())
}

fn field_matches(value: &Value, field: &str, expected: &str) -> bool {
    value.get(field).and_then(Value::as_str) == Some(expected)
}

fn scores(class_correct: usize, severity_correct: usize, total: usize) -> Value {
    json!({
        "classification_micro_precision": ratio(class_correct, total),
        "classification_micro_recall": ratio(class_correct, total),
        "severity_agreement": ratio(severity_correct, total)
    })
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labeled_fixture_is_parseable_and_has_rule_baselines() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../tests/fixtures/model-quality-v2.json")).unwrap();
        assert!(cases.len() >= 4);
        assert!(cases.iter().all(|case| {
            case.input.get("rule_based_result").is_some()
                && !case.expected_vuln_class.is_empty()
                && !case.expected_severity.is_empty()
        }));
    }
}
