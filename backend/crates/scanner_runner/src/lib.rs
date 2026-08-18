//! Scanner runner — matches `scanner_runner.py` + `scanner_policy.py`.
//! Executes external CLI security scanners and captures JSON output.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

    /// The executable actually invoked for this tool. This is *not* always the
    /// tool name: `npm-audit` is a subcommand of the `npm` binary, and probing
    /// PATH for a non-existent `npm-audit` executable would report the tool as
    /// missing even on an image that ships Node.
    pub fn binary(&self) -> &'static str {
        match self {
            ScannerTool::NpmAudit => "npm",
            _ => self.name(),
        }
    }

    /// Whether the tool needs a local checkout of the repository. Tools that
    /// query the remote repository directly (Scorecard) do not.
    pub fn requires_source(&self) -> bool {
        !matches!(self, ScannerTool::Scorecard)
    }

    pub fn timeout_seconds(&self) -> u64 {
        match self {
            ScannerTool::Scorecard | ScannerTool::Semgrep | ScannerTool::Trivy => 300,
            _ => 120,
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner outcome states
// ---------------------------------------------------------------------------
// These are deliberately finer-grained than the persisted `ScannerStatus`
// variants, because "we never installed the tool", "we never checked out the
// source" and "this manifest does not exist in this repository" are three
// different facts about a scan and only the last one is a property of the
// repository being scanned. Collapsing them into a single "data not available"
// sentence hides deployment gaps from operators and mislabels them as findings
// about the repository.

/// The tool ran and produced output.
pub const STATUS_OK: &str = "ok";
/// The tool's binary is not present in this deployment image (a deployment gap).
pub const STATUS_NOT_INSTALLED: &str = "not_installed";
/// The tool needs a local checkout and none was provided (a deployment gap).
pub const STATUS_NO_SOURCE: &str = "no_source";
/// The tool ran against a checkout but the ecosystem it audits is absent from
/// this repository (a genuine property of the repository).
pub const STATUS_NOT_APPLICABLE: &str = "not_applicable";
/// The tool was invoked and errored or timed out.
pub const STATUS_FAILED: &str = "failed";

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
    pub github_token: Option<String>,
}

impl ScannerRunner {
    pub fn new(repo_url: impl Into<String>) -> Self {
        Self {
            repo_url: repo_url.into(),
            source_path: None,
            github_token: None,
        }
    }

    pub fn with_source(mut self, path: impl Into<String>) -> Self {
        self.source_path = Some(path.into());
        self
    }

    pub fn with_github_token(mut self, token: impl Into<String>) -> Self {
        self.github_token = Some(token.into());
        self
    }

    pub async fn run_all(&self) -> Vec<ScannerResult> {
        let mut results = Vec::new();
        for tool in ScannerTool::all() {
            if !is_tool_available(tool.binary()) {
                // A missing binary wins over a missing checkout: it is the
                // earlier and more specific fact about why nothing ran.
                results.push(not_installed_result(tool));
                continue;
            }
            if tool.requires_source() && self.available_source().is_none() {
                results.push(ScannerResult {
                    tool: tool.name().into(),
                    status: STATUS_NO_SOURCE.into(),
                    detail: self.missing_source_detail(tool),
                    output: None,
                    duration_ms: 0,
                });
                continue;
            }
            results.push(self.run_one(tool).await);
        }
        results
    }

    /// Explain *why* no checkout was available: never requested, or requested
    /// and unusable. Operators need to tell a disabled feature apart from a
    /// broken clone.
    fn missing_source_detail(&self, tool: ScannerTool) -> String {
        match self.source_path.as_deref() {
            None => format!(
                "{} was not run: it needs a local checkout of the repository and none was \
                 provided (source checkout is disabled for this deployment). This is a scanner \
                 deployment gap, not a finding about the repository.",
                tool.name()
            ),
            Some(path) => format!(
                "{} was not run: the configured source checkout '{path}' does not exist or is \
                 not readable. This is a scanner deployment gap, not a finding about the \
                 repository.",
                tool.name()
            ),
        }
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
            status: STATUS_FAILED.into(),
            detail: e.to_string(),
            output: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // -------------------------------------------------------------------
    // Scorecard: scorecard --repo={url} --format=json
    // -------------------------------------------------------------------
    async fn run_scorecard(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let auth_env = self
            .github_token
            .as_deref()
            .map(|token| vec![("GITHUB_AUTH_TOKEN", token)])
            .unwrap_or_default();
        let output = run_cmd(
            "scorecard",
            &["--repo", &self.repo_url, "--format", "json"],
            ScannerTool::Scorecard.timeout_seconds(),
            &auth_env,
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let score = json.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        Ok((
            STATUS_OK.into(),
            format!("Scorecard score: {score:.1}/10"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Gitleaks: gitleaks detect --source={path} --no-git -f json
    // -------------------------------------------------------------------
    /// Argument list for the gitleaks working-tree scan.
    ///
    /// Two flags here are load-bearing and were verified against gitleaks
    /// v8.21.2 rather than assumed:
    ///
    /// * `--report-path /dev/stdout` — with only `-f json`, gitleaks writes a
    ///   human-readable log to stderr and *nothing* to stdout. The caller would
    ///   then see empty output and report every repository as having no secrets,
    ///   which is a false negative on a security result.
    /// * `--exit-code 0` — gitleaks exits 1 when it finds leaks, and `run_cmd`
    ///   treats a non-zero status as a scanner failure. Without this, the scan
    ///   fails on exactly the repositories that do contain secrets.
    fn gitleaks_args(source: &str) -> Vec<String> {
        [
            "detect",
            "--source",
            source,
            "--no-git",
            "-f",
            "json",
            "--report-path",
            "/dev/stdout",
            "--exit-code",
            "0",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    async fn run_gitleaks(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::Gitleaks),
                None,
            ));
        };
        let args = Self::gitleaks_args(&path);
        let output = run_cmd(
            "gitleaks",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            ScannerTool::Gitleaks.timeout_seconds(),
            &[],
        )
        .await?;
        if output.trim().is_empty() {
            // Reachable only if gitleaks produced no report at all; treat it as a
            // scanner problem rather than silently claiming the repository is clean.
            anyhow::bail!("gitleaks produced no report on stdout");
        }
        let json: Value = serde_json::from_str(&output)?;
        let count = json.as_array().map(|a| a.len()).unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("Gitleaks: {count} secrets found"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // pip-audit: pip-audit -r {requirements} -f json
    // -------------------------------------------------------------------
    async fn run_pip_audit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::PipAudit),
                None,
            ));
        };
        let req = find_file(&path, &["requirements.txt", "pyproject.toml", "setup.py"]);
        let Some(req) = req else {
            return Ok((
                STATUS_NOT_APPLICABLE.into(),
                format!(
                    "pip-audit does not apply: no Python manifest (requirements.txt, \
                     pyproject.toml or setup.py) exists in {path}."
                ),
                None,
            ));
        };
        let output = run_cmd(
            "pip-audit",
            &["-r", &req, "-f", "json"],
            ScannerTool::PipAudit.timeout_seconds(),
            &[],
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let vulns = json
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("pip-audit: {vulns} vulnerabilities"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // npm audit: npm audit --json --prefix {path}
    // -------------------------------------------------------------------
    async fn run_npm_audit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::NpmAudit),
                None,
            ));
        };
        let pkg = find_file(&path, &["package.json"]);
        let Some(_pkg) = pkg else {
            return Ok((
                STATUS_NOT_APPLICABLE.into(),
                format!("npm audit does not apply: no package.json exists in {path}."),
                None,
            ));
        };
        let output = run_cmd(
            "npm",
            &["audit", "--json", "--prefix", &path],
            ScannerTool::NpmAudit.timeout_seconds(),
            &[],
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let vulns = json
            .get("metadata")
            .and_then(|m| m.get("vulnerabilities"))
            .and_then(|v| v.get("total"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("npm audit: {vulns} vulnerabilities"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Semgrep: semgrep --config=auto --json {path}
    // -------------------------------------------------------------------
    async fn run_semgrep(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::Semgrep),
                None,
            ));
        };
        let output = run_cmd(
            "semgrep",
            &["--config=auto", "--json", &path],
            ScannerTool::Semgrep.timeout_seconds(),
            &[],
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let findings = json
            .get("results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("Semgrep: {findings} findings"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Bandit: bandit -r {path} -f json
    // -------------------------------------------------------------------
    async fn run_bandit(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::Bandit),
                None,
            ));
        };
        let output = run_cmd(
            "bandit",
            &["-r", &path, "-f", "json"],
            ScannerTool::Bandit.timeout_seconds(),
            &[],
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let issues = json
            .get("results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("Bandit: {issues} issues"),
            Some(json),
        ))
    }

    // -------------------------------------------------------------------
    // Trivy: trivy fs --scanners vuln,secret,misconfig -f json {path}
    // -------------------------------------------------------------------
    async fn run_trivy(&self) -> anyhow::Result<(String, String, Option<Value>)> {
        let Some(path) = self.available_source() else {
            return Ok((
                STATUS_NO_SOURCE.into(),
                self.missing_source_detail(ScannerTool::Trivy),
                None,
            ));
        };
        let output = run_cmd(
            "trivy",
            &[
                "fs",
                "--scanners",
                "vuln,secret,misconfig",
                "-f",
                "json",
                &path,
            ],
            ScannerTool::Trivy.timeout_seconds(),
            &[],
        )
        .await?;
        let json: Value = serde_json::from_str(&output)?;
        let results = json
            .get("Results")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok((
            STATUS_OK.into(),
            format!("Trivy: {results} result groups"),
            Some(json),
        ))
    }

    /// Resolve and canonicalize the source path before handing it to external
    /// scanners. Missing or unspecified sources are never replaced with the
    /// service process's working directory.
    fn available_source(&self) -> Option<String> {
        self.source_path
            .as_deref()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .map(|path| path.to_string_lossy().into_owned())
    }
}

/// The tool's binary is absent from the image, so nothing was attempted. This
/// is a deployment gap and must never read as evidence about the repository.
fn not_installed_result(tool: ScannerTool) -> ScannerResult {
    ScannerResult {
        tool: tool.name().into(),
        status: STATUS_NOT_INSTALLED.into(),
        detail: format!(
            "{} was not run: the '{}' binary is not installed in this deployment image. \
             This is a scanner deployment gap, not a finding about the repository.",
            tool.name(),
            tool.binary()
        ),
        output: None,
        duration_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Source checkout (opt-in)
// ---------------------------------------------------------------------------
/// Bounds applied to a repository checkout. Cloning arbitrary public
/// repositories onto the host has real disk and security implications, so every
/// bound is explicit and enforced rather than best-effort.
#[derive(Debug, Clone)]
pub struct CheckoutOptions {
    /// Wall-clock limit for the clone.
    pub timeout_seconds: u64,
    /// Hard cap on the checkout size; a larger clone is deleted, not scanned.
    pub max_bytes: u64,
    /// Parent directory the temporary checkout is created under.
    pub root: PathBuf,
}

impl Default for CheckoutOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: 120,
            max_bytes: 1024 * 1024 * 1024,
            root: std::env::temp_dir(),
        }
    }
}

/// A temporary shallow checkout of a public repository.
///
/// The directory is removed when this value is dropped — including on the error
/// paths below, which construct the guard *before* running `git` so that a
/// timed-out or oversized clone still cleans up after itself.
#[derive(Debug)]
pub struct SourceCheckout {
    path: PathBuf,
}

impl SourceCheckout {
    /// Shallow-clone (`--depth 1`) a public HTTPS repository into a bounded
    /// temporary directory.
    pub async fn shallow_clone(
        repo_url: &str,
        options: &CheckoutOptions,
    ) -> anyhow::Result<SourceCheckout> {
        let url = validated_clone_url(repo_url)?;
        if !is_tool_available("git") {
            anyhow::bail!("git binary is not installed in this deployment image");
        }
        let path = options.root.join(format!(
            "ai-supply-chain-trust-src-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path).ok();
        }
        std::fs::create_dir_all(&path)?;
        // Own the directory before the clone so every early return removes it.
        let checkout = SourceCheckout { path };
        let destination = checkout.path.to_string_lossy().into_owned();

        run_cmd(
            "git",
            &[
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--quiet",
                "--",
                &url,
                &destination,
            ],
            options.timeout_seconds,
            &[
                ("GIT_TERMINAL_PROMPT", "0"),
                ("GIT_ASKPASS", "/bin/true"),
                ("GCM_INTERACTIVE", "never"),
            ],
        )
        .await?;

        let size = directory_size_bytes(&checkout.path, options.max_bytes);
        if size > options.max_bytes {
            anyhow::bail!(
                "checkout of {url} exceeded the {} byte limit",
                options.max_bytes
            );
        }
        Ok(checkout)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SourceCheckout {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "Failed to remove scanner source checkout"
                );
            }
        }
    }
}

/// Accept only plain public HTTPS git URLs. This keeps the clone away from
/// local paths, `file://`, ssh remotes, and `--upload-pack`-style argument
/// injection.
fn validated_clone_url(repo_url: &str) -> anyhow::Result<String> {
    let url = repo_url.trim();
    if !url.starts_with("https://") {
        anyhow::bail!("only https clone URLs are allowed, got {url}");
    }
    if url.len() > 512 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        anyhow::bail!("clone URL is malformed");
    }
    let rest = &url["https://".len()..];
    let host = rest.split('/').next().unwrap_or_default();
    if host.contains('@') || host.is_empty() {
        anyhow::bail!("clone URL must not carry credentials");
    }
    Ok(url.to_string())
}

/// Sum file sizes under `root`, stopping early once `limit` is exceeded so an
/// oversized checkout is rejected without walking all of it.
fn directory_size_bytes(root: &Path, limit: u64) -> u64 {
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // symlink_metadata: never follow links out of the checkout, and
            // never walk a symlink cycle.
            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(metadata.len());
                if total > limit {
                    return total;
                }
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
async fn run_cmd(
    binary: &str,
    args: &[&str],
    timeout_secs: u64,
    env: &[(&str, &str)],
) -> anyhow::Result<String> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .envs(env.iter().copied())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), command.output())
        .await
        .map_err(|_| anyhow::anyhow!("{binary} timed out after {timeout_secs}s"))?
        .map_err(|e| anyhow::anyhow!("Failed to execute {binary}: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{binary} failed: {stderr}")
    }
}

/// Whether `binary` resolves to an executable on PATH. Resolved in-process
/// rather than by spawning `which`, so probing seven tools costs no processes
/// and cannot be confused by a missing `which`.
pub fn is_tool_available(binary: &str) -> bool {
    if binary.contains('/') {
        return is_executable(Path::new(binary));
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| is_executable(&dir.join(binary)))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
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
    fn gitleaks_argv_keeps_the_flags_that_make_its_output_usable() {
        let args = ScannerRunner::gitleaks_args("/tmp/checkout");

        // Verified against gitleaks v8.21.2: without --report-path the JSON
        // report never reaches stdout and every repository reads as clean;
        // without --exit-code 0 the process exits 1 whenever it finds secrets
        // and the run is recorded as a scanner failure.
        let report_path = args.iter().position(|a| a == "--report-path");
        assert!(report_path.is_some(), "missing --report-path: {args:?}");
        assert_eq!(args[report_path.unwrap() + 1], "/dev/stdout");

        let exit_code = args.iter().position(|a| a == "--exit-code");
        assert!(exit_code.is_some(), "missing --exit-code: {args:?}");
        assert_eq!(args[exit_code.unwrap() + 1], "0");

        let source = args.iter().position(|a| a == "--source").unwrap();
        assert_eq!(args[source + 1], "/tmp/checkout");
        assert!(args.contains(&"--no-git".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

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
            assert!(matches!(tool.timeout_seconds(), 120 | 300));
        }
        // npm-audit is the only tool whose executable differs from its name.
        assert_eq!(ScannerTool::NpmAudit.binary(), "npm");
        for tool in ScannerTool::all()
            .into_iter()
            .filter(|tool| *tool != ScannerTool::NpmAudit)
        {
            assert_eq!(tool.binary(), tool.name());
        }
        assert!(!ScannerTool::Scorecard.requires_source());
        assert!(ScannerTool::Gitleaks.requires_source());
        assert_eq!(ScannerTool::Scorecard.timeout_seconds(), 300);
        assert_eq!(ScannerTool::Gitleaks.timeout_seconds(), 120);
    }

    #[tokio::test]
    async fn unusable_source_paths_report_a_deployment_gap_not_a_repository_finding() {
        let runner = ScannerRunner::new("https://github.com/owner/repo")
            .with_source("/definitely/missing/ai-supply-chain-trust-source");

        for tool in [
            ScannerTool::Gitleaks,
            ScannerTool::PipAudit,
            ScannerTool::NpmAudit,
        ] {
            let result = runner.run_one(tool).await;
            assert_eq!(result.status, STATUS_NO_SOURCE);
            assert!(result.output.is_none());
            assert!(
                result.detail.contains("deployment gap"),
                "detail must name the deployment gap, got {}",
                result.detail
            );
        }
    }

    #[tokio::test]
    async fn missing_manifests_are_reported_as_not_applicable_to_the_repository() {
        let root = std::env::temp_dir().join(format!(
            "scanner-runner-manifests-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&root).unwrap();
        let runner = ScannerRunner::new("https://github.com/owner/repo")
            .with_source(root.to_string_lossy().to_string());

        for tool in [ScannerTool::PipAudit, ScannerTool::NpmAudit] {
            let result = runner.run_one(tool).await;
            assert_eq!(result.status, STATUS_NOT_APPLICABLE);
            assert!(
                result.detail.contains("does not apply"),
                "detail must say the ecosystem is absent, got {}",
                result.detail
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uninstalled_tools_name_the_image_gap_and_the_missing_binary() {
        let result = not_installed_result(ScannerTool::NpmAudit);

        assert_eq!(result.tool, "npm-audit");
        assert_eq!(result.status, STATUS_NOT_INSTALLED);
        assert!(result.detail.contains("'npm' binary is not installed"));
        assert!(result.detail.contains("not a finding about the repository"));
        assert!(result.output.is_none());
    }

    #[test]
    fn tool_availability_resolves_against_path_without_spawning_processes() {
        assert!(!is_tool_available("definitely-not-a-real-scanner-binary"));
        assert!(is_tool_available("sh") || is_tool_available("/bin/sh"));
        assert!(!is_tool_available("/definitely/missing/binary"));
    }

    #[test]
    fn clone_urls_are_restricted_to_public_https_remotes() {
        assert_eq!(
            validated_clone_url("https://github.com/owner/repo").unwrap(),
            "https://github.com/owner/repo"
        );
        for rejected in [
            "file:///etc",
            "git@github.com:owner/repo.git",
            "ssh://github.com/owner/repo",
            "--upload-pack=touch /tmp/pwned",
            "https://user:token@github.com/owner/repo",
            "https://github.com/owner/repo --config=core.sshCommand=id",
        ] {
            assert!(
                validated_clone_url(rejected).is_err(),
                "{rejected} should be rejected"
            );
        }
    }

    #[test]
    fn checkout_directories_are_bounded_and_always_removed() {
        let root = std::env::temp_dir().join(format!("scanner-checkout-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("blob.bin"), vec![0_u8; 4096]).unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/blob.bin"), vec![0_u8; 4096]).unwrap();

        assert!(directory_size_bytes(&root, u64::MAX) >= 8192);
        // Early exit: the walk stops as soon as the limit is passed.
        assert!(directory_size_bytes(&root, 1024) > 1024);

        let checkout = SourceCheckout { path: root.clone() };
        drop(checkout);
        assert!(!root.exists(), "checkout directory must be removed on drop");
    }

    #[tokio::test]
    async fn checkout_rejects_non_https_urls_without_touching_the_filesystem() {
        let options = CheckoutOptions::default();
        let error = SourceCheckout::shallow_clone("file:///etc", &options)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("https"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn file_lookup_and_command_execution_report_success_and_failure() {
        let root = std::env::temp_dir().join(format!("scanner-runner-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package.json"), "{}").unwrap();

        assert_eq!(
            find_file(root.to_str().unwrap(), &["missing", "package.json"]),
            Some(root.join("package.json").to_string_lossy().to_string())
        );
        assert_eq!(
            run_cmd("printf", &["scanner-ok"], 1, &[]).await.unwrap(),
            "scanner-ok"
        );
        assert!(run_cmd("false", &[], 1, &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("failed"));
        assert!(!is_tool_available("definitely-not-a-real-scanner-binary"));

        fs::remove_dir_all(root).unwrap();
    }
}
