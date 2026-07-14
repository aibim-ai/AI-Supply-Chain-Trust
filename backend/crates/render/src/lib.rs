//! Server-side HTML rendering — matches `render.py`.
//! Generates SEO <head>, JSON-LD, crawlable body content, and route mapping.

mod head;
mod pages;
mod security;

pub use head::build_head;
pub use pages::{render_home, render_leaderboard, render_result};
pub use security::render_security_context_page;

/// Escape HTML entities.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Map repo "owner/name" to result path.
pub fn repo_to_path(repo: &str) -> String {
    format!("/github/{repo}")
}

/// Map repo "owner/name" to security context path.
pub fn security_repo_to_path(repo: &str) -> String {
    format!("/r/{repo}")
}

/// Short SHA (7 chars).
pub fn short_sha(value: &str) -> String {
    value.chars().take(7).collect()
}

/// Clip text to limit.
pub fn clip(value: &str, limit: usize) -> String {
    let s: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= limit {
        s
    } else {
        let mut out: String = s.chars().take(limit.saturating_sub(1)).collect();
        out = out.trim_end().to_string();
        out.push_str("...");
        out
    }
}

/// Severity pill HTML.
pub fn severity_pill(severity: &str) -> String {
    let text = severity.to_ascii_lowercase();
    let tone = match text.as_str() {
        "critical" => "danger",
        "high" => "high-risk",
        "medium" => "warning",
        "low" => "success",
        _ => "info",
    };
    format!(
        r#"<span class="sc-pill pill-{tone}">{}</span>"#,
        esc(&text.to_ascii_uppercase())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_helpers_escape_and_bound_untrusted_values() {
        assert_eq!(esc("<&\"'>"), "&lt;&amp;&quot;&#39;&gt;");
        assert_eq!(short_sha("123456789"), "1234567");
        assert_eq!(clip("  one   two three  ", 9), "one two...");
        assert_eq!(repo_to_path("owner/repo"), "/github/owner/repo");
        assert_eq!(security_repo_to_path("owner/repo"), "/r/owner/repo");
        assert!(severity_pill("critical").contains("pill-danger"));
        assert!(severity_pill("unknown").contains("pill-info"));
    }

    #[test]
    fn head_escapes_metadata_and_respects_index_policy() {
        let head = build_head(
            "Title <unsafe>",
            "Description \"quoted\"",
            "/r/owner/repo",
            "https://example.test",
            false,
            "<script type=\"application/ld+json\">{}</script>",
        );
        assert!(head.contains("Title &lt;unsafe&gt;"));
        assert!(head.contains("Description &quot;quoted&quot;"));
        assert!(head.contains("noindex,follow"));
        assert!(head.contains("https://example.test/r/owner/repo"));
        assert!(head.contains("application/ld+json"));
    }

    #[test]
    fn page_renderers_emit_crawlable_sanitized_content() {
        let (home_head, home) = render_home();
        assert!(home_head.contains("index,follow"));
        assert!(home.contains("AI Supply Chain Trust"));

        let (leaderboard_head, leaderboard) = render_leaderboard(&[json!({
            "repo": "owner/<script>", "trust_score": 72.4, "grade": "B"
        })]);
        assert!(leaderboard_head.contains("Leaderboard"));
        assert!(!leaderboard.contains("<script>"));
        assert!(leaderboard.contains("owner/&lt;script&gt;"));

        let (result_head, result) = render_result(&json!({
            "repo": "owner/repo", "trust_score": 35.0, "grade": "F",
            "verdict": "Do not use", "evaluated_at": "2026-07-12"
        }));
        assert!(result_head.contains("noindex,follow"));
        assert!(result.contains("score-danger"));
        assert!(result.contains("Do not use"));
    }

    #[test]
    fn security_context_renderer_includes_evidence_sections() {
        let report = json!({
            "generated_at": "2026-07-12T00:00:00Z",
            "summary": {"top_severity": "high", "head_sha": "abcdef1234567890"},
            "context": {
                "repo": {"ref": "main"},
                "commits_scanned": 12345,
                "remediation": {"coverage": 50.0},
                "vuln_class_counts": {"Denial of Service": 1},
                "fingerprints": [{
                    "vuln_class": "Denial of Service", "severity": "high",
                    "summary": "Bound request memory", "components": ["context.rs"],
                    "commit_date": "2020-12-22T00:00:00Z", "commit_sha": "1234567890"
                }],
                "known_cves": [{
                    "id": "CVE-2026-0001", "severity": "high", "cvss": "7.5",
                    "summary": "Resource exhaustion"
                }]
            }
        });

        let (head, body) = render_security_context_page(&report, "owner/repo");
        assert!(head.contains("owner/repo Security Context"));
        assert!(body.contains("Denial of Service"));
        assert!(body.contains("CVE-2026-0001"));
        assert!(body.contains("12,345"));
        assert!(body.contains("1234567"));
    }
}
