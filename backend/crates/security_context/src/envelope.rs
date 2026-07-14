use ai_supply_chain_trust_models::{
    ContextArtifacts, ContextStatus, ContextSummary, SecurityContext, SecurityContextEnvelope,
    VulnerabilityLeads,
};
use serde_json::{json, Value};

use super::context::context_from_report;
use super::evidence::ready_evidence_summary;
use super::leads::leads_from_report;

/// Builds the full SecurityContextEnvelope from a trust evaluation report.
/// Matches `security_context.py:envelope_from_report()`.
pub fn envelope_from_report(report: &Value, repo: &str, base_url: &str) -> SecurityContextEnvelope {
    let evidence = ready_evidence_summary(report);

    let status = match evidence.build() {
        Ok(ev) => ContextStatus::ready(ev),
        Err(_) => {
            let owner_name: Vec<&str> = repo.splitn(2, '/').collect();
            let (owner, name) = if owner_name.len() == 2 {
                (owner_name[0], owner_name[1])
            } else {
                (repo, "")
            };

            let ctx_summary = make_summary(report);
            let artifacts = make_artifacts(base_url, owner, name);
            let empty_context = make_empty_context(owner, name);
            let leads = make_empty_leads(repo);

            return SecurityContextEnvelope {
                repo: repo.to_string(),
                status: ContextStatus::Error {
                    code: "security_context_evidence_missing".into(),
                    message: "Security context evidence insufficient. Run a new scan to collect live data.".into(),
                },
                message: Some("Security context evidence insufficient. Run a new scan to collect live data.".into()),
                error: Some("security_context_evidence_missing".into()),
                summary: ctx_summary,
                artifacts,
                context: empty_context,
                leads,
                created: false,
                updated_at: None,
            };
        }
    };

    let context = context_from_report(report, repo);
    let leads = leads_from_report(report, repo);

    let fixes = context
        .get("fingerprints")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);

    let cves = context
        .get("known_cves")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);

    let head_sha = context
        .get("repo")
        .and_then(|r| r.get("head_sha"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let generated_at = context
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let top_sev =
        super::top_risks::top_severity_from(context.get("fingerprints").unwrap_or(&json!([])));

    let coverage = context
        .get("remediation")
        .and_then(|r| r.get("coverage"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let summary = ContextSummary {
        fixes,
        cves,
        top_severity: top_sev,
        remediation_coverage: coverage,
        head_sha,
        generated_at,
        trust_score: None,
        grade: None,
    };

    let owner_name: Vec<&str> = repo.splitn(2, '/').collect();
    let (owner, name) = if owner_name.len() == 2 {
        (owner_name[0], owner_name[1])
    } else {
        (repo, "")
    };

    let artifacts = make_artifacts(base_url, owner, name);

    let context_obj: SecurityContext =
        serde_json::from_value(context).unwrap_or_else(|_| make_empty_context(owner, name));

    let leads_obj: VulnerabilityLeads =
        serde_json::from_value(leads).unwrap_or_else(|_| make_empty_leads(repo));

    SecurityContextEnvelope {
        repo: repo.to_string(),
        status,
        message: None,
        error: None,
        summary,
        artifacts,
        context: context_obj,
        leads: leads_obj,
        created: false,
        updated_at: report
            .get("evaluated_at")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

fn make_summary(report: &Value) -> ContextSummary {
    ContextSummary {
        fixes: 0,
        cves: 0,
        top_severity: "unknown".into(),
        remediation_coverage: 0.0,
        head_sha: report
            .get("metadata")
            .and_then(|m| m.get("head_sha"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .into(),
        generated_at: report
            .get("evaluated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        trust_score: None,
        grade: None,
    }
}

fn make_artifacts(base_url: &str, owner: &str, name: &str) -> ContextArtifacts {
    let base = base_url.trim_end_matches('/');
    ContextArtifacts {
        security_context_md: format!("{base}/r/{owner}/{name}.md"),
        security_context_json: format!("{base}/r/{owner}/{name}.json"),
        vulnerability_leads_md: format!("{base}/r/{owner}/{name}.leads.md"),
        vulnerability_leads_json: format!("{base}/r/{owner}/{name}.leads.json"),
    }
}

fn make_empty_context(owner: &str, name: &str) -> SecurityContext {
    serde_json::from_value(json!({
        "repo": {
            "owner": owner, "name": name,
            "url": format!("https://github.com/{owner}/{name}.git"),
            "ref": "unknown", "head_sha": "unknown"
        },
        "generated_at": "",
        "commits_scanned": 0, "commits_flagged": 0,
        "archetype": "repository", "excluded_availability": 0,
        "summary": "No verified evidence available.",
        "agent_brief": "",
        "tool": "AI Supply Chain Trust",
        "known_cves": [],
        "component_counts": {}, "vuln_class_counts": {},
        "remediation": {"coverage": 0.0, "measurable_fixes": 0, "remediated_fixes": 0, "guarded_sites": 0, "open_leads": 0},
        "top_risks": [], "shared_surfaces": [], "fingerprints": [], "themes": [],
        "trust": {"score": 0.0, "grade": "-", "action": "", "coverage": ""}
    })).unwrap()
}

fn make_empty_leads(repo: &str) -> VulnerabilityLeads {
    serde_json::from_value(json!({
        "repo": repo,
        "tool": "AI Supply Chain Trust",
        "generated_at": "",
        "head_ref": "unknown", "head_sha": "unknown",
        "remediation_coverage": 0.0, "measurable_fixes": 0, "remediated_fixes": 0, "open_leads": 0,
        "findings": [], "leads": []
    }))
    .unwrap()
}
