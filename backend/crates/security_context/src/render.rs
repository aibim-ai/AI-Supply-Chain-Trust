use serde_json::Value;

pub fn render_context_markdown(report: &Value) -> String {
    let repo = report
        .get("repo")
        .and_then(Value::as_str)
        .unwrap_or("unknown/repo");
    let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
    let score = report
        .get("trust_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let verdict = report.get("verdict").and_then(Value::as_str).unwrap_or("");
    let mut md = format!(
        "# Security Context: {repo}\n\nTrust score: {score:.0}/100, Grade: {grade}, Verdict: {verdict}\n\n"
    );
    md.push_str("## Fingerprints\n\n");
    if let Some(fps) = report.get("fingerprints").and_then(Value::as_array) {
        for fp in fps {
            let cls = fp
                .get("vuln_class")
                .and_then(Value::as_str)
                .unwrap_or("Security Fix");
            let sev = fp
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let summary = fp.get("summary").and_then(Value::as_str).unwrap_or("");
            md.push_str(&format!("- **{cls}** ({sev}): {summary}\n"));
        }
    }
    if let Some(risks) = report.get("top_risks").and_then(Value::as_array) {
        md.push_str("\n## Top Risks\n\n");
        for risk in risks {
            let cls = risk
                .get("vuln_class")
                .and_then(Value::as_str)
                .unwrap_or("risk");
            let count = risk.get("fix_count").and_then(Value::as_i64).unwrap_or(0);
            md.push_str(&format!("- {cls}: {count} fix(es)\n"));
        }
    }
    md
}

pub fn render_leads_markdown(report: &Value) -> String {
    let repo = report
        .get("repo")
        .and_then(Value::as_str)
        .unwrap_or("unknown/repo");
    let mut md = format!("# Vulnerability Leads: {repo}\n\n");
    if let Some(leads) = report.get("leads").and_then(Value::as_array) {
        for lead in leads {
            let cls = lead
                .get("vuln_class")
                .and_then(Value::as_str)
                .unwrap_or("finding");
            let why = lead.get("why").and_then(Value::as_str).unwrap_or("");
            md.push_str(&format!("- **{cls}**: {why}\n"));
        }
    }
    md
}
