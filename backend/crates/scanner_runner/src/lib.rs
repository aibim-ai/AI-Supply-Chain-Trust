//! Scanner runner — matches `scanner_runner.py` + `scanner_policy.py`.
//! Executes external CLI security scanners and captures JSON output.

use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Scanner registry
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerTool {
    Scorecard, // openssf/scorecard
    Gitleaks,  // secret scanner
    PipAudit,  // Python dependency audit
    NpmAudit,  // Node dependency audit
    Semgrep,   // static analysis
    Bandit,    // Python security linter
    Trivy,     // vulnerability + misconfig scanner
}

impl ScannerTool {
    pub fn all() -> Vec<ScannerTool> {
        vec![
            ScannerTool::Scorecard,
            ScannerTool::Gitleaks,
            ScannerTool::PipAudit,
            ScannerTool::NpmAudit,
            ScannerTool::Semgrep,
            ScannerTool::Bandit,
            ScannerTool::Trivy,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            ScannerTool::Scorecard => "scorecard",
            ScannerTool::Gitleaks => "gitleaks",
            ScannerTool::PipAudit => "pip-audit",
            ScannerTool::NpmAudit => "npm-audit",
            ScannerTool::Semgrep => "semgrep",
            ScannerTool::Bandit => "bandit",
            ScannerTool::Trivy => "trivy",
        }
    }

    pub fn binary(&self) -> &'static str {
        self.name()
    }

    pub fn timeout_seconds(&self) -> u64 {
        match self {
            ScannerTool::Scorecard | ScannerTool::Semgrep | ScannerTool::Trivy => 300,
            _ => 120,
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner result
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ScannerResult {
    pub tool: String,
    pub status: String,
    pub detail: String,
    pub output: Option<Value>,
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
pub struct ScannerRunner {
    pub repo_url: String,
    pub source_path: Option<String>,
}

impl ScannerRunner {
    pub fn new(repo_url: impl Into<String>) -> Self {
        Self {
            repo_url: repo_url.into(),
            source_path: None,
        }
    }

    pub fn with_source(mut self, path: impl Into<String>) -> Self {
        self.source_path = Some(path.into());
        self
    }

    pub async fn run_all(&self) -> Vec<ScannerResult> {
        let mut results = Vec::new();
        for tool in ScannerTool::all() {
            if !is_tool_available(tool.binary()) {
                results.push(ScannerResult {
                    tool: tool.name().into(),
                    status: "unavailable".into(),
                    detail: format!("{} binary not found in PATH", tool.binary()),
                    output: None,
                    duration_ms: 0,
                });
                continue;
            }
            results.push(self.run_one(tool).await);
        }
        results
    }

    pub async fn run_one(&self, tool: ScannerTool) -> ScannerResult {
        let start = Instant::now();
        match tool {
            ScannerTool::Scorecard => self.run_scorecard().await,
            ScannerTool::Gitleaks => self.run_gitleaks().await,
            ScannerTool::PipAudit => self.run_pip_audit().await,
            ScannerTool::NpmAudit => self.run_npm_audit().await,
            ScannerTool::Semgrep => self.run_semgrep().await,
            ScannerTool::Bandit => self.run_bandit().await,
            ScannerTool::Trivy => self.run_trivy().await,
        }
        .map(|(status, detail, output)| ScannerResult {
            tool: tool.name().into(),
            status,
            detail,
            output,
            duration_ms: start.elapsed().as_millis() as u64,
        })
        .unwrap_or_else(|e| ScannerResult {
            tool: tool.name().into(),
            status: "failed".into(),
            detail: e.to_string(),
            output: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // -------------------------------------------------------------------
    // Scorecard: scorecard --repo={url} --format=json
    // -------------------------------------------------------------------
    async fn run_scorecard(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let output = run_cmd(
            "scorecard",
            &["--repo", &self.repo_url, "--format", "json"],
            ScannerTool::Scorecard.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let score = json.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        Ok((
            "ok".into(),
            format!("Scorecard score: {score:.1}/10"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Gitleaks: gitleaks detect --source={path} --no-git -f json
    // -------------------------------------------------------------------
    async fn run_gitleaks(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        if !Path::new(path).exists() {
            return Ok((
                "skipped".into(),
                "No source directory available for gitleaks".into(),
                None,
            ));
        }
        let output = run_cmd(
            "gitleaks",
            &["detect", "--source", path, "--no-git", "-f", "json"],
            ScannerTool::Gitleaks.timeout_seconds(),
        )?;
        if output.trim().is_empty() {
            return Ok(("ok".into(), "No secrets found".into(), Some(json!([]))));
        }
        let json: Value = serde_json::from_str(&output)?;
        let count = json.as_array().map(|a| a.len()).unwrap_or(0);
        Ok((
            "ok".into(),
            format!("Gitleaks: {count} secrets found"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // pip-audit: pip-audit -r {requirements} -f json
    // -------------------------------------------------------------------
    async fn run_pip_audit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        let req = find_file(path, &["requirements.txt", "pyproject.toml", "setup.py"]);
        let Some(req) = req else {
            return Ok(("skipped".into(), "No Python manifest found".into(), None));
        };
        let output = run_cmd(
            "pip-audit",
            &["-r", &req, "-f", "json"],
            ScannerTool::PipAudit.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let vulns = json
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            "ok".into(),
            format!("pip-audit: {vulns} vulnerabilities"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // npm audit: npm audit --json --prefix {path}
    // -------------------------------------------------------------------
    async fn run_npm_audit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        let pkg = find_file(path, &["package.json"]);
        let Some(_pkg) = pkg else {
            return Ok(("skipped".into(), "No package.json found".into(), None));
        };
        let output = run_cmd(
            "npm",
            &["audit", "--json", "--prefix", path],
            ScannerTool::NpmAudit.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let vulns = json
            .get("metadata")
            .and_then(|m| m.get("vulnerabilities"))
            .and_then(|v| v.get("total"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        Ok((
            "ok".into(),
            format!("npm audit: {vulns} vulnerabilities"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Semgrep: semgrep --config=auto --json {path}
    // -------------------------------------------------------------------
    async fn run_semgrep(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        let output = run_cmd(
            "semgrep",
            &["--config=auto", "--json", path],
            ScannerTool::Semgrep.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let findings = json
            .get("results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            "ok".into(),
            format!("Semgrep: {findings} findings"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Bandit: bandit -r {path} -f json
    // -------------------------------------------------------------------
    async fn run_bandit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        let output = run_cmd(
            "bandit",
            &["-r", path, "-f", "json"],
            ScannerTool::Bandit.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let issues = json
            .get("results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok(("ok".into(), format!("Bandit: {issues} issues"), Some(json)))
    }

    // -------------------------------------------------------------------
    // Trivy: trivy fs --scanners vuln,secret,misconfig -f json {path}
    // -------------------------------------------------------------------
    async fn run_trivy(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let path = self.source_path.as_deref().unwrap_or(".");
        let output = run_cmd(
            "trivy",
            &[
                "fs",
                "--scanners",
                "vuln,secret,misconfig",
                "-f",
                "json",
                path,
            ],
            ScannerTool::Trivy.timeout_seconds(),
        )?;
        let json: Value = serde_json::from_str(&output)?;
        let results = json
            .get("Results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            "ok".into(),
            format!("Trivy: {results} result groups"),
            Some(json),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
fn run_cmd(binary: &str, args: &[&str], _timeout_secs: u64) -> anyhow::Result<String> {
    let output = Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute {binary}: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{binary} failed: {stderr}")
    }
}

fn is_tool_available(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_file(root: &str, candidates: &[&str]) -> Option<String> {
    for name in candidates {
        let path = Path::new(root).join(name);
        if path.exists() {
            return Some(path.to_string_lossy().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn all_scanners_registered() {
        assert_eq!(ScannerTool::all().len(), 7);
    }

    #[test]
    fn scanner_names_unique() {
        let names: Vec<&str> = ScannerTool::all().iter().map(|t| t.name()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn scanner_registry_exposes_binary_and_timeout_contracts() {
        for tool in ScannerTool::all() {
            assert_eq!(tool.binary(), tool.name());
            assert!(matches!(tool.timeout_seconds(), 120 | 300));
        }
        assert_eq!(ScannerTool::Scorecard.timeout_seconds(), 300);
        assert_eq!(ScannerTool::Gitleaks.timeout_seconds(), 120);
    }

    #[tokio::test]
    async fn missing_manifests_and_source_paths_are_skipped_without_processes() {
        let runner = ScannerRunner::new("https://github.com/owner/repo")
            .with_source("/definitely/missing/ai-supply-chain-trust-source");

        for tool in [
            ScannerTool::Gitleaks,
            ScannerTool::PipAudit,
            ScannerTool::NpmAudit,
        ] {
            let result = runner.run_one(tool).await;
            assert_eq!(result.status, "skipped");
            assert!(result.output.is_none());
            assert!(!result.detail.is_empty());
        }
    }

    #[test]
    fn file_lookup_and_command_execution_report_success_and_failure() {
        let root = std::env::temp_dir().join(format!("scanner-runner-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package.json"), "{}").unwrap();

        assert_eq!(
            find_file(root.to_str().unwrap(), &["missing", "package.json"]),
            Some(root.join("package.json").to_string_lossy().to_string())
        );
        assert_eq!(run_cmd("printf", &["scanner-ok"], 1).unwrap(), "scanner-ok");
        assert!(run_cmd("false", &[], 1)
            .unwrap_err()
            .to_string()
            .contains("failed"));
        assert!(!is_tool_available("definitely-not-a-real-scanner-binary"));

        fs::remove_dir_all(root).unwrap();
    }
}
