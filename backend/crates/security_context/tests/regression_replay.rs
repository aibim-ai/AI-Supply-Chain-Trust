use ai_supply_chain_trust_security_context::regression_contracts_from_report;
use serde_json::{json, Value};

#[test]
fn replay_corpus_preserves_interpretable_policy_boundaries() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/regression_replay.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let input = if let Some(files) = case.get("changed_files") {
            json!({"base_sha":"base", "head_sha":"head", "changed_files":files})
        } else {
            json!({"base_sha":"base", "head_sha":"head"})
        };
        let report = json!({
            "regression_assessment_input": input,
            "observed_metrics":{"security_intel":{"fix_commits":[{
                "sha":"fix", "subject":"validate packet bounds", "component":"src/parser",
                "vuln_class":"Out-of-Bounds Access", "severity":"high",
                "html_url":"https://example.test/commit/fix",
                "changed_files":[{"path":"src/parser.rs","touched_symbols":["parse_packet"]}]
            }]}}
        });
        let contracts = regression_contracts_from_report(&report, "example/parser");
        assert_eq!(
            contracts[0]["assessment"]["state"], case["expected_state"],
            "{}",
            case["name"]
        );
        assert_eq!(
            contracts[0]["assessment"]["disposition"], case["expected_disposition"],
            "{}",
            case["name"]
        );
    }
}
