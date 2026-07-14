//! Evidence-backed regression contracts derived from historical fingerprints.
//!
//! Contracts are deliberately conservative: they describe observed historical
//! surfaces and available guards, but never claim a current regression without
//! a base/head diff and guard result.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::fingerprints::fingerprints_from_report;

pub const CONTRACT_SCHEMA_VERSION: &str = "1.0";
pub const MATCHER_VERSION: &str = "match_fingerprint/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    E0,
    E1,
    E2,
    E3,
    E4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionContract {
    pub id: String,
    pub schema_version: String,
    pub repo: String,
    pub title: String,
    pub invariant: String,
    pub vulnerability_class: String,
    pub cwes: Vec<String>,
    pub impact: String,
    pub evidence_tier: EvidenceTier,
    pub source_evidence: Vec<SourceEvidence>,
    pub surfaces: Vec<ContractSurface>,
    pub fix_shape: FixShape,
    pub guards: Vec<GuardEvidence>,
    pub owner: ContractOwner,
    pub recommendations: Vec<String>,
    pub lifecycle: Lifecycle,
    pub matcher: Matcher,
    pub assessment: RegressionAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEvidence {
    pub relation: String,
    pub id: String,
    pub url: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSurface {
    pub path: String,
    pub component: String,
    pub symbols: Vec<String>,
    pub sinks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixShape {
    pub description: String,
    pub provenance: String,
    pub primitives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvidence {
    pub kind: String,
    pub id: String,
    pub path: String,
    pub status: String,
    pub required: bool,
    pub evidence_ref: String,
    pub observed_sha: Option<String>,
    pub run_url: Option<String>,
    pub tool_configuration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOwner {
    pub codeowners: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    pub version: String,
    pub partial_fingerprints: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionAssessment {
    pub state: String,
    pub disposition: String,
    pub explanation: String,
    pub matches: Vec<Value>,
    pub guard_status: String,
    pub missing_analysis: Vec<String>,
    pub check_conclusion: String,
}

pub fn regression_contracts_from_report(report: &Value, repo: &str) -> Value {
    let fingerprints = fingerprints_from_report(report);
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for fingerprint in fingerprints.as_array().into_iter().flatten() {
        let class = text(fingerprint, "vuln_class", "Security Fix");
        let component = primary_component(fingerprint);
        let sink = text(fingerprint, "sink", &component);
        groups
            .entry(format!("{class}\u{1f}{component}\u{1f}{sink}"))
            .or_default()
            .push(fingerprint);
    }

    let mut contracts = groups
        .values()
        .filter_map(|rows| contract_from_group(rows, repo))
        .collect::<Vec<_>>();
    if let Some(input) = report.get("regression_assessment_input") {
        for contract in &mut contracts {
            contract.owner = resolve_contract_owner(contract, input);
            apply_guard_evidence(contract, input);
            contract.assessment = assess_contract(contract, input);
        }
    }
    json!(contracts)
}

pub fn assess_contract(contract: &RegressionContract, input: &Value) -> RegressionAssessment {
    let base_sha = input.get("base_sha").and_then(Value::as_str).unwrap_or("");
    let head_sha = input.get("head_sha").and_then(Value::as_str).unwrap_or("");
    let Some(changed_files) = input.get("changed_files").and_then(Value::as_array) else {
        return unavailable_assessment(
            "No changed-file evidence was supplied for the base/head comparison.",
        );
    };
    if base_sha.is_empty() || head_sha.is_empty() {
        return unavailable_assessment(
            "Both base_sha and head_sha are required for a ref-specific assessment.",
        );
    }

    let mut matches = Vec::new();
    let mut changed_surfaces = Vec::new();
    for changed in changed_files {
        let changed_path = text(changed, "path", "");
        if changed_path.is_empty() {
            continue;
        }
        for surface in &contract.surfaces {
            if paths_overlap(&changed_path, &surface.path, &surface.component) {
                changed_surfaces.push(changed_path.clone());
                matches.push(json!({
                    "dimension": "path",
                    "result": if changed_path == surface.path { "exact" } else { "component_overlap" },
                    "evidence_ref": format!("diff:{head_sha}:{changed_path}")
                }));
            }
            let changed_symbols = array_strings(changed.get("touched_symbols")).collect::<Vec<_>>();
            for symbol in &changed_symbols {
                if surface.symbols.iter().any(|expected| expected == symbol) {
                    matches.push(json!({
                        "dimension": "symbol_or_sink",
                        "result": "exact",
                        "evidence_ref": format!("diff:{head_sha}:{changed_path}#{symbol}")
                    }));
                }
            }
        }
    }
    changed_surfaces.sort();
    changed_surfaces.dedup();
    matches.sort_by_key(|reason| reason.to_string());
    matches.dedup();

    let guard_results = input
        .get("guard_results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let relevant_guard_results = guard_results
        .iter()
        .filter(|result| {
            let id = result.get("guard_id").and_then(Value::as_str).unwrap_or("");
            contract.guards.iter().any(|guard| guard.id == id)
        })
        .collect::<Vec<_>>();
    let guard_failed = relevant_guard_results
        .iter()
        .any(|result| result.get("status").and_then(Value::as_str) == Some("failed"));
    let guard_passed = relevant_guard_results
        .iter()
        .any(|result| result.get("status").and_then(Value::as_str) == Some("passed"));
    let guard_status = if guard_failed {
        "failed"
    } else if guard_passed {
        "passed"
    } else if contract.guards.is_empty() {
        "not_found"
    } else {
        "not_run"
    };

    if matches.is_empty() {
        return RegressionAssessment {
            state: "not_touched".to_string(),
            disposition: "observe".to_string(),
            explanation: format!(
                "The supplied {base_sha}..{head_sha} diff does not overlap this contract's observed surfaces."
            ),
            matches,
            guard_status: guard_status.to_string(),
            missing_analysis: Vec::new(),
            check_conclusion: "success".to_string(),
        };
    }

    let removed_primitives = array_strings(input.get("removed_fix_primitives")).collect::<Vec<_>>();
    for primitive in &contract.fix_shape.primitives {
        if removed_primitives
            .iter()
            .any(|removed| removed == primitive)
        {
            matches.push(json!({
                "dimension": "fix_primitive", "result": "weakened",
                "evidence_ref": format!("diff:{head_sha}:primitive:{primitive}")
            }));
        }
    }
    let has_symbol_match = matches
        .iter()
        .any(|reason| reason.get("dimension").and_then(Value::as_str) == Some("symbol_or_sink"));
    let weakened_primitive = matches
        .iter()
        .any(|reason| reason.get("dimension").and_then(Value::as_str) == Some("fix_primitive"));
    let (state, disposition) = if guard_failed && contract.evidence_tier == EvidenceTier::E4 {
        ("guard_failed", "block")
    } else if guard_failed
        || weakened_primitive
        || has_symbol_match && tier_rank(&contract.evidence_tier) >= 3
    {
        ("potential_regression", "verify")
    } else {
        ("needs_review", "review")
    };
    let mut missing_analysis = Vec::new();
    if relevant_guard_results.is_empty() {
        missing_analysis.push("guard_execution".to_string());
    }
    RegressionAssessment {
        state: state.to_string(),
        disposition: disposition.to_string(),
        explanation: format!(
            "The supplied {base_sha}..{head_sha} diff overlaps {} historical contract surface(s). This is a heuristic match, not a confirmed vulnerability.",
            changed_surfaces.len()
        ),
        matches,
        guard_status: guard_status.to_string(),
        missing_analysis,
        check_conclusion: match disposition {
            "block" => "failure",
            "verify" => "action_required",
            "review" => "neutral",
            _ => "success",
        }
        .to_string(),
    }
}

fn unavailable_assessment(explanation: &str) -> RegressionAssessment {
    RegressionAssessment {
        state: "analysis_unavailable".to_string(),
        disposition: "unknown".to_string(),
        explanation: explanation.to_string(),
        matches: Vec::new(),
        guard_status: "analysis_unavailable".to_string(),
        missing_analysis: vec!["base_head_diff".to_string(), "guard_execution".to_string()],
        check_conclusion: "action_required".to_string(),
    }
}

fn paths_overlap(changed: &str, historical: &str, component: &str) -> bool {
    if changed == historical || changed == component {
        return true;
    }
    let component = component.trim_matches('/');
    !component.is_empty()
        && component != "repository"
        && (changed.starts_with(&format!("{component}/"))
            || historical.starts_with(&format!("{component}/")))
}

fn contract_from_group(rows: &[&Value], repo: &str) -> Option<RegressionContract> {
    let first = *rows.first()?;
    let vulnerability_class = text(first, "vuln_class", "Security Fix");
    let component = primary_component(first);
    let sink = text(first, "sink", &component);
    let source_evidence = source_evidence(rows);
    let surfaces = surfaces(rows, &component, &sink);
    let guards = discover_guards(rows);
    let symbols = surfaces
        .iter()
        .flat_map(|surface| surface.symbols.iter())
        .filter(|symbol| symbol.as_str() != component && symbol.as_str() != sink)
        .count();
    let has_specific_surface = surfaces
        .iter()
        .any(|surface| surface.path != "repository" && surface.component != "repository");
    let has_fix_shape = rows.iter().any(|row| {
        let shape = text(row, "fix_shape", "");
        !shape.is_empty() && shape != "security-relevant commit from GitHub history"
    });
    let tier = evidence_tier(
        &vulnerability_class,
        !source_evidence.is_empty(),
        has_specific_surface,
        has_fix_shape,
        symbols > 0,
        guards.iter().any(|guard| guard.status == "verified"),
    );
    if tier == EvidenceTier::E0 {
        return None;
    }

    let cwes = unique_strings(rows.iter().flat_map(|row| array_strings(row.get("cwe"))));
    let impact = rows
        .iter()
        .map(|row| text(row, "severity", "unknown"))
        .max_by_key(|severity| severity_rank(severity))
        .unwrap_or_else(|| "unknown".to_string());
    let guard_status = if guards.iter().any(|guard| guard.status == "verified") {
        "verified"
    } else if guards.is_empty() {
        "not_found"
    } else {
        "present_unverified"
    };
    let id_seed = format!("{vulnerability_class}-{component}-{sink}");
    let id = format!("rc_{}", stable_slug(&id_seed));
    let source_ids = source_evidence
        .iter()
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>()
        .join(",");
    let mut partial_fingerprints = BTreeMap::new();
    partial_fingerprints.insert("class/v1".to_string(), stable_slug(&vulnerability_class));
    partial_fingerprints.insert("surface/v1".to_string(), stable_slug(&component));
    partial_fingerprints.insert("sink/v1".to_string(), stable_slug(&sink));
    if !source_ids.is_empty() {
        partial_fingerprints.insert("sources/v1".to_string(), source_ids);
    }

    let lifecycle_state = if tier_rank(&tier) >= tier_rank(&EvidenceTier::E2) {
        "active"
    } else {
        "candidate"
    };
    let recommendations = if guards.is_empty() {
        vec![format!(
            "Add a human-reviewed executable regression test or static rule for {component}; no guard was found in the cited fix evidence."
        )]
    } else if guards.iter().all(|guard| guard.status != "verified") {
        vec!["Run the discovered guard on an exact commit SHA and retain its run URL and tool configuration before treating it as verified.".to_string()]
    } else {
        Vec::new()
    };
    Some(RegressionContract {
        id,
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        repo: repo.to_string(),
        title: format!("Preserve {vulnerability_class} protection in {component}"),
        invariant: format!(
            "Changes to {component} must preserve the security boundary established by the cited historical evidence."
        ),
        vulnerability_class,
        cwes,
        impact,
        evidence_tier: tier,
        source_evidence,
        surfaces,
        fix_shape: FixShape {
            description: rows
                .iter()
                .map(|row| text(row, "fix_shape", ""))
                .find(|shape| !shape.is_empty())
                .unwrap_or_else(|| "No structured fix shape was observed.".to_string()),
            provenance: "historical_fingerprint".to_string(),
            primitives: fix_primitives(rows),
        },
        guards,
        owner: ContractOwner {
            codeowners: Vec::new(),
            source: "unavailable".to_string(),
        },
        recommendations,
        lifecycle: Lifecycle {
            state: lifecycle_state.to_string(),
            reason: "deterministic_evidence_tiering".to_string(),
        },
        matcher: Matcher {
            version: MATCHER_VERSION.to_string(),
            partial_fingerprints,
        },
        assessment: RegressionAssessment {
            state: "analysis_unavailable".to_string(),
            disposition: "unknown".to_string(),
            explanation: "Historical evidence is available, but no base/head diff or guard execution result was supplied for this context.".to_string(),
            matches: Vec::new(),
            guard_status: guard_status.to_string(),
            missing_analysis: vec!["base_head_diff".to_string(), "guard_execution".to_string()],
            check_conclusion: "action_required".to_string(),
        },
    })
}

fn evidence_tier(
    vulnerability_class: &str,
    has_source: bool,
    has_surface: bool,
    has_fix_shape: bool,
    has_symbol: bool,
    verified_guard: bool,
) -> EvidenceTier {
    if !has_source || vulnerability_class == "Security Fix" && !has_surface {
        EvidenceTier::E0
    } else if verified_guard && has_symbol && has_surface {
        EvidenceTier::E4
    } else if has_symbol && has_surface {
        EvidenceTier::E3
    } else if has_surface && has_fix_shape {
        EvidenceTier::E2
    } else {
        EvidenceTier::E1
    }
}

fn source_evidence(rows: &[&Value]) -> Vec<SourceEvidence> {
    let mut evidence = Vec::new();
    for row in rows {
        if let Some(sha) = row
            .get("commit_sha")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            evidence.push(SourceEvidence {
                relation: "fixed_by".to_string(),
                id: format!("commit:{sha}"),
                url: row
                    .get("evidence")
                    .and_then(Value::as_str)
                    .map(String::from),
                summary: text(row, "summary", "Historical security fix"),
            });
            continue;
        }
        let ids = array_strings(row.get("evidence")).collect::<Vec<_>>();
        for id in ids {
            if id.starts_with("CVE-") || id.starts_with("GHSA-") || id.starts_with("OSV-") {
                evidence.push(SourceEvidence {
                    relation: "described_by".to_string(),
                    id,
                    url: None,
                    summary: text(row, "summary", "Published vulnerability record"),
                });
            }
        }
    }
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    evidence.dedup_by(|a, b| a.id == b.id && a.relation == b.relation);
    evidence
}

fn surfaces(rows: &[&Value], component: &str, sink: &str) -> Vec<ContractSurface> {
    let mut by_path: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        for file in row
            .get("changed_files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = text(file, "path", component);
            let symbols = array_strings(file.get("touched_symbols")).collect::<Vec<_>>();
            by_path.entry(path).or_default().extend(symbols);
        }
    }
    if by_path.is_empty() {
        by_path.insert(component.to_string(), Vec::new());
    }
    by_path
        .into_iter()
        .map(|(path, symbols)| ContractSurface {
            path,
            component: component.to_string(),
            symbols: unique_strings(symbols.into_iter()),
            sinks: if sink == "repository" {
                Vec::new()
            } else {
                vec![sink.to_string()]
            },
        })
        .collect()
}

fn discover_guards(rows: &[&Value]) -> Vec<GuardEvidence> {
    let mut guards = Vec::new();
    for row in rows {
        let source = row
            .get("commit_sha")
            .and_then(Value::as_str)
            .map(|sha| format!("commit:{sha}"))
            .unwrap_or_else(|| text(row, "id", "fingerprint:unknown"));
        for file in row
            .get("changed_files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = text(file, "path", "");
            let lower = path.to_ascii_lowercase();
            if lower.contains("test") || lower.contains("spec") {
                guards.push(GuardEvidence {
                    kind: "test_candidate".to_string(),
                    id: format!("test:{}", stable_slug(&path)),
                    path,
                    status: "present_unverified".to_string(),
                    required: false,
                    evidence_ref: source.clone(),
                    observed_sha: None,
                    run_url: None,
                    tool_configuration: None,
                });
            }
        }
    }
    guards.sort_by(|a, b| a.id.cmp(&b.id));
    guards.dedup_by(|a, b| a.id == b.id);
    guards
}

fn fix_primitives(rows: &[&Value]) -> Vec<String> {
    let mut primitives = Vec::new();
    for row in rows {
        let value = format!(
            "{} {}",
            text(row, "summary", ""),
            text(row, "fix_shape", "")
        )
        .to_ascii_lowercase();
        for (needle, primitive) in [
            ("validat", "validate-before-use"),
            ("reject", "reject-invalid-input"),
            ("bound", "bound-before-access"),
            ("limit", "limit-resource-use"),
            ("authoriz", "authorize-before-access"),
            ("authenticat", "authenticate-before-access"),
            ("escap", "escape-before-render"),
            ("sanitiz", "sanitize-before-sink"),
            ("canonical", "canonicalize-before-path-use"),
        ] {
            if value.contains(needle) {
                primitives.push(primitive.to_string());
            }
        }
    }
    unique_strings(primitives.into_iter())
}

fn apply_guard_evidence(contract: &mut RegressionContract, input: &Value) {
    for result in input
        .get("verified_guards")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = text(result, "guard_id", "");
        let Some(guard) = contract.guards.iter_mut().find(|guard| guard.id == id) else {
            continue;
        };
        guard.status = "verified".to_string();
        guard.observed_sha = result
            .get("observed_sha")
            .and_then(Value::as_str)
            .map(String::from);
        guard.run_url = result
            .get("run_url")
            .and_then(Value::as_str)
            .map(String::from);
        guard.tool_configuration = result
            .get("tool_configuration")
            .and_then(Value::as_str)
            .map(String::from);
    }
    if tier_rank(&contract.evidence_tier) >= 3
        && contract.guards.iter().any(|guard| {
            guard.status == "verified"
                && guard
                    .observed_sha
                    .as_deref()
                    .is_some_and(|sha| !sha.is_empty())
                && guard.run_url.as_deref().is_some_and(|url| !url.is_empty())
                && guard
                    .tool_configuration
                    .as_deref()
                    .is_some_and(|configuration| !configuration.is_empty())
        })
    {
        contract.evidence_tier = EvidenceTier::E4;
        contract.lifecycle.state = "verified".to_string();
        contract.lifecycle.reason = "sha_bound_guard_result".to_string();
        contract.recommendations.clear();
    }
}

fn resolve_contract_owner(contract: &RegressionContract, input: &Value) -> ContractOwner {
    let Some(contents) = input.get("codeowners").and_then(Value::as_str) else {
        return ContractOwner {
            codeowners: Vec::new(),
            source: "unavailable".to_string(),
        };
    };
    let path = contract
        .surfaces
        .first()
        .map(|surface| surface.path.as_str())
        .unwrap_or("repository");
    let mut owners = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() >= 2 && codeowners_pattern_matches(parts[0], path) {
            // GitHub CODEOWNERS uses the last matching pattern.
            owners = parts[1..]
                .iter()
                .map(|owner| (*owner).to_string())
                .collect();
        }
    }
    ContractOwner {
        codeowners: owners,
        source: "CODEOWNERS".to_string(),
    }
}

fn codeowners_pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_start_matches('/');
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern || path.starts_with(&format!("{pattern}/"))
}

fn primary_component(fingerprint: &Value) -> String {
    fingerprint
        .get("components")
        .and_then(Value::as_array)
        .and_then(|components| components.first())
        .and_then(Value::as_str)
        .filter(|component| !component.is_empty())
        .map(String::from)
        .unwrap_or_else(|| text(fingerprint, "sink", "repository"))
}

fn text(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default)
        .to_string()
}

fn array_strings(value: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(String::from)
}

fn unique_strings(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut values = values.collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn stable_slug(value: &str) -> String {
    let slug = value
        .chars()
        .flat_map(char::to_lowercase)
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let compact = slug
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    compact.chars().take(96).collect()
}

fn severity_rank(value: &str) -> i32 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn tier_rank(tier: &EvidenceTier) -> i32 {
    match tier {
        EvidenceTier::E0 => 0,
        EvidenceTier::E1 => 1,
        EvidenceTier::E2 => 2,
        EvidenceTier::E3 => 3,
        EvidenceTier::E4 => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_typed_contract_with_explicit_unavailable_assessment() {
        let report = json!({
            "observed_metrics": { "security_intel": { "fix_commits": [{
                "sha": "abc123", "subject": "reject parent paths before extraction",
                "component": "src/unpack/archive.rs", "vuln_class": "Path Traversal",
                "cwe": ["CWE-22"], "severity": "high",
                "html_url": "https://example.test/commit/abc123",
                "changed_files": [{"path":"src/unpack/archive.rs", "touched_symbols":["extract_entry"]}]
            }]}}
        });

        let contracts = regression_contracts_from_report(&report, "example/archive");
        let contract = contracts.as_array().unwrap().first().unwrap();

        assert_eq!(contract["evidence_tier"], json!("e3"));
        assert_eq!(
            contract["source_evidence"][0]["relation"],
            json!("fixed_by")
        );
        assert_eq!(
            contract["assessment"]["state"],
            json!("analysis_unavailable")
        );
        assert_eq!(contract["assessment"]["disposition"], json!("unknown"));
        assert_eq!(contract["matcher"]["version"], json!(MATCHER_VERSION));
    }

    #[test]
    fn test_file_is_only_a_present_unverified_guard() {
        let report = json!({
            "observed_metrics": { "security_intel": { "fix_commits": [{
                "sha": "def456", "subject": "bound nested fields",
                "component": "src/parser.rs", "vuln_class": "Denial of Service",
                "severity": "medium", "html_url": "https://example.test/commit/def456",
                "changed_files": [
                    {"path":"src/parser.rs", "touched_symbols":["parse_fields"]},
                    {"path":"tests/parser_limits.rs", "touched_symbols":["rejects_deep_nesting"]}
                ]
            }]}}
        });

        let contracts = regression_contracts_from_report(&report, "example/parser");
        let contract = contracts.as_array().unwrap().first().unwrap();

        assert_eq!(contract["guards"][0]["status"], json!("present_unverified"));
        assert_eq!(
            contract["assessment"]["guard_status"],
            json!("present_unverified")
        );
        assert_ne!(contract["evidence_tier"], json!("e4"));
    }

    #[test]
    fn excludes_generic_keyword_only_rows() {
        let report = json!({
            "observed_metrics": { "security_intel": { "fix_commits": [{
                "sha": "123", "subject": "security cleanup", "component": "repository",
                "vuln_class": "Security Fix", "severity": "medium",
                "html_url": "https://example.test/commit/123"
            }]}}
        });

        assert_eq!(
            regression_contracts_from_report(&report, "example/repo"),
            json!([])
        );
    }

    #[test]
    fn supplied_diff_emits_reason_vector_without_claiming_confirmation() {
        let report = json!({
            "regression_assessment_input": {
                "base_sha": "base123", "head_sha": "head456",
                "changed_files": [{"path":"src/unpack/archive.rs", "touched_symbols":["extract_entry"]}]
            },
            "observed_metrics": { "security_intel": { "fix_commits": [{
                "sha": "abc123", "subject": "reject parent paths before extraction",
                "component": "src/unpack/archive.rs", "vuln_class": "Path Traversal",
                "severity": "high", "html_url": "https://example.test/commit/abc123",
                "changed_files": [{"path":"src/unpack/archive.rs", "touched_symbols":["extract_entry"]}]
            }]}}
        });

        let contracts = regression_contracts_from_report(&report, "example/archive");
        let assessment = &contracts[0]["assessment"];
        assert_eq!(assessment["state"], json!("potential_regression"));
        assert_eq!(assessment["disposition"], json!("verify"));
        assert_eq!(assessment["matches"][0]["dimension"], json!("path"));
        assert_eq!(
            assessment["matches"][1]["dimension"],
            json!("symbol_or_sink")
        );
        assert!(assessment["explanation"]
            .as_str()
            .unwrap()
            .contains("not a confirmed vulnerability"));
    }

    #[test]
    fn supplied_non_overlapping_diff_is_observation_not_a_pass_claim() {
        let report = json!({
            "regression_assessment_input": {
                "base_sha": "base123", "head_sha": "head456",
                "changed_files": [{"path":"docs/readme.md", "touched_symbols":[]}]
            },
            "observed_metrics": { "security_intel": { "fix_commits": [{
                "sha": "abc123", "subject": "reject parent paths before extraction",
                "component": "src/unpack/archive.rs", "vuln_class": "Path Traversal",
                "severity": "high", "html_url": "https://example.test/commit/abc123",
                "changed_files": [{"path":"src/unpack/archive.rs", "touched_symbols":["extract_entry"]}]
            }]}}
        });

        let contracts = regression_contracts_from_report(&report, "example/archive");
        assert_eq!(contracts[0]["assessment"]["state"], json!("not_touched"));
        assert_eq!(contracts[0]["assessment"]["disposition"], json!("observe"));
    }

    #[test]
    fn codeowners_and_sha_bound_guard_enable_selective_blocking() {
        let guard_id = "test:tests_parser_limits_rs";
        let report = json!({
            "regression_assessment_input": {
                "base_sha":"base", "head_sha":"head",
                "codeowners":"* @fallback\nsrc/** @platform\nsrc/parser.rs @appsec @parser",
                "changed_files":[{"path":"src/parser.rs","touched_symbols":["parse"]}],
                "guard_results":[{
                    "guard_id":guard_id, "status":"failed", "observed_sha":"head",
                    "run_url":"https://ci.example/runs/1", "tool_configuration":"security-tests-v1"
                }],
                "verified_guards":[{
                    "guard_id":guard_id, "observed_sha":"known-good",
                    "run_url":"https://ci.example/runs/0", "tool_configuration":"security-tests-v1"
                }]
            },
            "observed_metrics":{"security_intel":{"fix_commits":[{
                "sha":"fix", "subject":"validate and bound parser input",
                "component":"src/parser.rs", "vuln_class":"Out-of-Bounds Access",
                "severity":"high", "html_url":"https://example.test/commit/fix",
                "changed_files":[
                    {"path":"src/parser.rs","touched_symbols":["parse"]},
                    {"path":"tests/parser_limits.rs","touched_symbols":["rejects_large"]}
                ]
            }]}}
        });

        let contracts = regression_contracts_from_report(&report, "example/parser");
        assert_eq!(
            contracts[0]["owner"]["codeowners"],
            json!(["@appsec", "@parser"])
        );
        assert_eq!(contracts[0]["evidence_tier"], json!("e4"), "{contracts:#}");
        assert_eq!(contracts[0]["assessment"]["disposition"], json!("block"));
        assert_eq!(
            contracts[0]["assessment"]["check_conclusion"],
            json!("failure")
        );
    }
}
