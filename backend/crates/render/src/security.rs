use super::{clip, esc, severity_pill, short_sha};
use serde_json::Value;

pub fn render_security_context_page(report: &Value, repo: &str) -> (String, String) {
    let mut head = super::head::build_head(
        &format!("{repo} Security Context | AI Supply Chain Trust"),
        &format!("{repo} has a generated security context."),
        &super::security_repo_to_path(repo),
        "https://ai-supply-chain-trust.aibim.ai",
        false,
        "",
    );
    head.push_str("\n  <link rel=\"stylesheet\" href=\"/assets/css/design-system.css\">");

    let context = report.get("context").unwrap_or(report);
    let fingerprints = context
        .get("fingerprints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let cves = context
        .get("known_cves")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fixes = fingerprints.len();
    let cve_count = cves.len();
    let coverage = context
        .get("remediation")
        .and_then(|r| r.get("coverage"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let summary = report.get("summary").unwrap_or(report);

    let top_sev = summary
        .get("top_severity")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let head_sha = summary
        .get("head_sha")
        .and_then(Value::as_str)
        .unwrap_or("current");
    let generated_at = report
        .get("generated_at")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let branch = context
        .get("repo")
        .and_then(|r| r.get("ref"))
        .and_then(Value::as_str)
        .unwrap_or("main");

    // Highlights
    let highlights = if fixes > 0 {
        let top_class = context
            .get("vuln_class_counts")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .max_by_key(|(_, v)| v.as_i64().unwrap_or(0))
                    .map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(0)))
                    .unwrap_or(("Security Fix".into(), 0))
            })
            .unwrap_or(("Security Fix".into(), 0));
        let high_count = fingerprints
            .iter()
            .filter(|fp| {
                let sev = fp.get("severity").and_then(Value::as_str).unwrap_or("");
                matches!(sev.to_ascii_lowercase().as_str(), "critical" | "high")
            })
            .count();
        format!(
            "<div class=\"sc-highlight\"><strong>{}:</strong> {} prior fixes.</div>
             <div class=\"sc-highlight\"><strong>{}</strong> high-severity fixes in this history.</div>",
            esc(&top_class.0), top_class.1, high_count
        )
    } else {
        "<div class=\"sc-highlight\">No prior security fixes were found in this repository history.</div>".to_string()
    };

    // Fixes table
    let fix_rows: String = fingerprints.iter().take(12).map(|fp| {
        let _cls = fp.get("vuln_class").and_then(Value::as_str).unwrap_or("Security Fix");
        let sev = fp.get("severity").and_then(Value::as_str).unwrap_or("medium");
        let sum = fp.get("summary").and_then(Value::as_str).unwrap_or("");
        let comp = fp.get("components").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("repository");
        let date = fp.get("commit_date").and_then(Value::as_str).unwrap_or("");
        let sha = fp.get("commit_sha").and_then(Value::as_str).unwrap_or("");
        format!(
            "<tr><td>▸</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
            severity_pill(sev), esc(&clip(sum, 110)), esc(&clip(comp, 34)),
            esc(&date.chars().take(10).collect::<String>()),
            esc(&short_sha(sha))
        )
    }).collect();
    let fix_table = if fix_rows.is_empty() {
        "<tr><td colspan=\"6\">No fixed vulnerability fingerprints were generated.</td></tr>"
            .to_string()
    } else {
        fix_rows
    };

    // CVE rows
    let cve_rows: String =
        cves.iter()
            .take(6)
            .map(|cve| {
                let id = cve.get("id").and_then(Value::as_str).unwrap_or("CVE");
                let sev = cve
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let cvss = cve
                    .get("cvss")
                    .and_then(|v| if v.is_null() { Some("-") } else { v.as_str() })
                    .unwrap_or("-");
                let sum = cve
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("No summary.");
                format!(
            "<article><div><strong>{}</strong>{}<span>CVSS {}</span></div><p>{}</p></article>",
            esc(id), severity_pill(sev), esc(cvss), esc(sum)
        )
            })
            .collect();
    let cve_html = if cve_rows.is_empty() {
        "<div class=\"empty-state\">No disclosed CVEs were returned.</div>".to_string()
    } else {
        cve_rows
    };

    let main = format!(
        r#"<section class="securitycontext-page">
      <div class="sc-title"><h1>Security context</h1><p>What an agent needs to avoid regressing past fixes and find the next vuln in this repo.</p></div>
      <section class="sc-hero">
        <aside class="sc-sidebar">
          <div class="sc-repo"><span>▲</span><strong>{repo}</strong></div>
          <div class="sc-refline"><span>{branch}</span><code>@ {head}</code></div>
          <dl><dt>Fixes</dt><dd>{fixes}</dd><dt>CVEs</dt><dd>{cve_count}</dd><dt>Peak severity</dt><dd>{top_sev_html}</dd><dt>Commits</dt><dd>{commits}</dd></dl>
          <div class="sc-coverage"><div><span>Regression coverage</span><strong>{coverage_pct}%</strong></div><small>{coverage_ctx}</small></div>
        </aside>
        <div class="sc-brief"><span class="eyebrow">Highlights</span>{highlights}</div>
        <footer>Last analyzed {generated_at}</footer>
      </section>
      <section class="sc-section"><h2>Every fixed vulnerability <span>({fixes})</span></h2>
        <table class="sc-fixes"><tbody>{fix_table}</tbody></table>
      </section>
      <section class="sc-section"><h2>Disclosed CVEs <span>({cve_count})</span></h2>
        <div class="sc-cves">{cve_html}</div>
      </section>
    </section>"#,
        repo = esc(repo),
        branch = esc(branch),
        head = esc(&short_sha(head_sha)),
        fixes = fixes,
        cve_count = cve_count,
        top_sev_html = severity_pill(top_sev),
        commits = fmt_number(
            context
                .get("commits_scanned")
                .and_then(Value::as_i64)
                .unwrap_or(0)
        ),
        coverage_pct = (coverage * 10.0).round() / 10.0,
        coverage_ctx = if fixes > 0 {
            format!("{} / 34", ((coverage / 100.0) * 34.0).round() as i64)
        } else {
            "No security fixes to measure.".into()
        },
        generated_at = esc(generated_at),
        fix_table = fix_table,
        cve_html = cve_html,
        highlights = highlights,
    );

    (head, main)
}

fn fmt_number(n: i64) -> String {
    let mut s = n.to_string();
    let len = s.len();
    for i in (1..len).rev() {
        if (len - i).is_multiple_of(3) {
            s.insert(i, ',');
        }
    }
    s
}
