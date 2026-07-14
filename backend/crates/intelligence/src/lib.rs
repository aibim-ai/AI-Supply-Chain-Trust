//! Live intelligence fetchers — matches `intelligence.py` exactly.
//!
//! All external API calls (GitHub REST, OSV.dev, git clone) happen here.
//! No mocked responses in production — every call produces either real data
//! or an explicit `DataSourceError`.

#![deny(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

pub mod nvd;

const DEFAULT_MAX_ADVISORY_PAGES: usize = 100;
const DEFAULT_SECURITY_HISTORY_MAX_PAGES: usize = 1000;

fn last_page_from_link(link: &str) -> Option<i64> {
    link.split(',').find_map(|part| {
        if !part.contains("rel=\"last\"") {
            return None;
        }
        part.split(';').next().and_then(|url_part| {
            url_part
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .split('&')
                .find_map(|pair| pair.strip_prefix("page=")?.parse::<i64>().ok())
        })
    })
}

fn parse_github_tokens(github_token: Option<String>) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(value) = github_token {
        for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let token = token.trim();
            if !token.is_empty() && !tokens.iter().any(|existing| existing == token) {
                tokens.push(token.to_string());
            }
        }
    }
    tokens
}

// ---------------------------------------------------------------------------
// Security intelligence result (matches Python IntelligenceResult)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityIntelligence {
    pub fetched: bool,
    pub head_sha: Option<String>,
    pub fix_commits: Vec<FixCommit>,
    pub advisories: Vec<Value>,
    pub osv_vulns: Vec<Value>,
    pub cves: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nvd_cves: Vec<nvd::NvdCveEntry>,
    pub commit_count: i64,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_resolution: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixCommit {
    pub sha: String,
    pub subject: String,
    pub component: String,
    pub vuln_class: String,
    pub cwe: Vec<String>,
    pub severity: String,
    pub date: String,
    pub html_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_files: Vec<CommitFileEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_evidence_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_evidence_status: Option<String>,
    #[serde(default = "default_rule_based_decision_source")]
    pub decision_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_based_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_assisted_result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommitFileEvidence {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub additions: i64,
    #[serde(default)]
    pub deletions: i64,
    #[serde(default)]
    pub changes: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub touched_symbols: Vec<String>,
}

fn default_rule_based_decision_source() -> String {
    "rule_based".to_string()
}

// ---------------------------------------------------------------------------
// Client (matches Python fetch_* functions)
// ---------------------------------------------------------------------------

pub struct IntelligenceClient {
    client: Client,
    github_tokens: Vec<String>,
    github_token_cursor: Arc<AtomicUsize>,
    github_api_base: String,
    osv_api_base: String,
    timeout_seconds: u64,
    config: IntelligenceClientConfig,
    github_rate_limit: Arc<Mutex<GitHubRateLimitSnapshot>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ManifestIdentity {
    ecosystem: String,
    package_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct GitHubRateLimitSnapshot {
    pub limit: i64,
    pub remaining: i64,
    pub reset_at: u64,
    pub observed_at: u64,
}

#[derive(Clone)]
pub struct IntelligenceClientConfig {
    pub max_advisory_pages: usize,
    pub max_security_history_pages: usize,
    pub max_fix_commits: Option<usize>,
    pub github_timeout_seconds: u64,
    pub llm_commit_classification_enabled: bool,
    pub llm_ecosystem_resolution_enabled: bool,
    /// NVD credentials are never logged or serialized.
    pub nvd_api_key: Option<String>,
}

impl Default for IntelligenceClientConfig {
    fn default() -> Self {
        Self {
            max_advisory_pages: DEFAULT_MAX_ADVISORY_PAGES,
            max_security_history_pages: DEFAULT_SECURITY_HISTORY_MAX_PAGES,
            max_fix_commits: None,
            github_timeout_seconds: 20,
            llm_commit_classification_enabled: true,
            llm_ecosystem_resolution_enabled: true,
            nvd_api_key: None,
        }
    }
}

impl IntelligenceClient {
    pub fn new(github_token: Option<String>) -> Self {
        Self::with_config(github_token, IntelligenceClientConfig::default())
    }

    pub fn with_config(github_token: Option<String>, config: IntelligenceClientConfig) -> Self {
        let timeout_seconds = config.github_timeout_seconds.max(1);
        Self {
            client: Client::builder()
                .user_agent("ai-supply-chain-trust/0.2.0 (Rust)")
                .timeout(Duration::from_secs(timeout_seconds + 1))
                .build()
                .expect("reqwest client"),
            github_tokens: parse_github_tokens(github_token),
            github_token_cursor: Arc::new(AtomicUsize::new(0)),
            github_api_base: "https://api.github.com".into(),
            osv_api_base: "https://api.osv.dev".into(),
            timeout_seconds,
            config,
            github_rate_limit: Arc::new(Mutex::new(GitHubRateLimitSnapshot::default())),
        }
    }

    /// Clone the cheap reqwest handle, retaining the underlying connection pool.
    pub fn http_client(&self) -> Client {
        self.client.clone()
    }

    pub fn github_rate_limit_snapshot(&self) -> GitHubRateLimitSnapshot {
        *self.github_rate_limit.lock().unwrap()
    }

    pub fn github_background_budget_available(&self, foreground_reserve: i64) -> bool {
        let snapshot = self.github_rate_limit_snapshot();
        if snapshot.observed_at == 0 || unix_now_seconds() >= snapshot.reset_at {
            return true;
        }
        let proportional_reserve = (snapshot.limit / 10).max(1);
        let effective_reserve = foreground_reserve.max(0).min(proportional_reserve);
        snapshot.remaining > effective_reserve
    }

    // -----------------------------------------------------------------------
    // GitHub Security Advisories — paginated
    // -----------------------------------------------------------------------
    pub async fn fetch_github_advisories(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<Value>, ai_supply_chain_trust_models::DataSourceError> {
        let mut all = Vec::new();
        let max_pages = self.config.max_advisory_pages;
        for page in 1..=max_pages {
            let url = format!(
                "{}/repos/{}/{}/security-advisories?per_page=100&page={page}",
                self.github_api_base, owner, repo
            );
            let resp = match self.github_get(&url).await {
                Ok(r) => r,
                Err(e) => {
                    if page == 1 {
                        return Err(e);
                    }
                    warn!(page, "Advisory pagination stopped: {:?}", e);
                    break;
                }
            };
            let page_items: Vec<Value> = resp.json().await.map_err(|e| {
                warn!(error = %e, "Failed to parse GitHub advisories response");
                ai_supply_chain_trust_models::DataSourceError::GitHubTimeout
            })?;
            let count = page_items.len();
            all.extend(page_items);
            if count < 100 {
                break;
            }
        }
        info!(
            owner,
            repo,
            count = all.len(),
            "Fetched GitHub advisories (paginated)"
        );
        Ok(all)
    }

    // -----------------------------------------------------------------------
    // Security Commit History — paginated over the full configured history
    // -----------------------------------------------------------------------
    pub async fn fetch_security_history(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<FixCommit>, ai_supply_chain_trust_models::DataSourceError> {
        let slug = format!("{owner}/{repo}");
        let mut fix_commits = Vec::new();
        let mut total_scanned = 0i64;
        let mut skip_commit_detail_reason: Option<String> = None;
        let max_pages = self.config.max_security_history_pages;
        let max_fix_commits = self.config.max_fix_commits;

        for page in 1..=max_pages {
            let url = format!(
                "{}/repos/{}/{}/commits?per_page=100&page={page}",
                self.github_api_base, owner, repo
            );
            let resp = match self.github_get(&url).await {
                Ok(r) => r,
                Err(e) => {
                    if page == 1 {
                        return Err(e);
                    }
                    warn!(page, "Commit pagination stopped: {:?}", e);
                    break;
                }
            };
            let page_items: Vec<Value> = resp.json().await.map_err(|e| {
                warn!(error = %e, "Failed to parse commits response");
                ai_supply_chain_trust_models::DataSourceError::GitHubTimeout
            })?;
            let count = page_items.len();
            total_scanned += count as i64;
            for commit in &page_items {
                let message = commit
                    .get("commit")
                    .and_then(|c| c.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !looks_security_relevant(message) {
                    continue;
                }
                let sha = commit
                    .get("sha")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let html_url = format!("https://github.com/{slug}/{sha}");
                let date = commit
                    .get("commit")
                    .and_then(|c| c.get("author"))
                    .and_then(|a| a.get("date"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let subject = message.lines().next().unwrap_or("").to_string();
                let explicit_vulnerability_evidence = has_explicit_vulnerability_evidence(message);
                let (changed_files, component, file_evidence_status) =
                    if explicit_vulnerability_evidence {
                        (
                            Vec::new(),
                            "repository".to_string(),
                            "skipped_explicit_message_evidence".to_string(),
                        )
                    } else if let Some(reason) = skip_commit_detail_reason.as_deref() {
                        (Vec::new(), "repository".to_string(), reason.to_string())
                    } else if sha.is_empty() {
                        (
                            Vec::new(),
                            "repository".to_string(),
                            "missing_sha".to_string(),
                        )
                    } else {
                        match self.fetch_commit_detail(owner, repo, &sha).await {
                            Ok(detail) => {
                                let files = commit_file_evidence_from_detail(&detail);
                                let component = select_primary_component(&files);
                                let status = if files.is_empty() {
                                    "no_files".to_string()
                                } else {
                                    "fetched".to_string()
                                };
                                (files, component, status)
                            }
                            Err(
                                ai_supply_chain_trust_models::DataSourceError::GitHubRateLimited,
                            ) => {
                                let reason = "rate_limited".to_string();
                                skip_commit_detail_reason = Some(reason.clone());
                                (Vec::new(), "repository".to_string(), reason)
                            }
                            Err(err) => {
                                warn!(
                                    owner,
                                    repo,
                                    sha = %sha,
                                    error = ?err,
                                    "GitHub commit detail unavailable; file evidence marked unavailable"
                                );
                                (
                                    Vec::new(),
                                    "repository".to_string(),
                                    "unavailable".to_string(),
                                )
                            }
                        }
                    };
                if !should_keep_security_fix_commit(message, &changed_files) {
                    continue;
                }
                let vuln_class = classify_vuln_class_with_evidence(message, &changed_files);
                let cwe = classify_cwe_for_class(vuln_class);
                let severity = classify_severity_with_evidence(message, vuln_class, &changed_files);
                let rule_based_result = json!({
                    "vuln_class": vuln_class,
                    "severity": severity,
                    "cwe": cwe.clone(),
                    "security_relevant": true
                });
                let llm_assisted_result = llm_commit_classification(
                    self.config.llm_commit_classification_enabled,
                    &sha,
                    &subject,
                    date,
                    &html_url,
                    &rule_based_result,
                )
                .await;
                let decision_source = llm_assisted_result
                    .as_ref()
                    .and_then(|v| v.get("decision_source"))
                    .and_then(Value::as_str)
                    .unwrap_or("rule_based")
                    .to_string();

                fix_commits.push(FixCommit {
                    sha,
                    subject,
                    component,
                    vuln_class: vuln_class.to_string(),
                    cwe,
                    severity: severity.to_string(),
                    date: date.to_string(),
                    html_url,
                    changed_files,
                    file_evidence_source: Some("github_commit_detail".to_string()),
                    file_evidence_status: Some(file_evidence_status),
                    decision_source,
                    rule_based_result: Some(rule_based_result),
                    llm_assisted_result,
                });
                if max_fix_commits.is_some_and(|limit| fix_commits.len() >= limit) {
                    break;
                }
            }
            if count < 100 || max_fix_commits.is_some_and(|limit| fix_commits.len() >= limit) {
                break;
            }
        }
        info!(
            owner,
            repo,
            total = total_scanned,
            fix_count = fix_commits.len(),
            "Fetched security commits (paginated)"
        );
        Ok(fix_commits)
    }

    /// Fetch one immutable checkpoint unit for the progressive history worker.
    /// Classification/aggregation can consume the persisted raw pages later.
    pub async fn fetch_commit_history_page_raw(
        &self,
        owner: &str,
        repo: &str,
        page: usize,
    ) -> Result<Vec<Value>, ai_supply_chain_trust_models::DataSourceError> {
        let page = page.max(1);
        let url = format!(
            "{}/repos/{}/{}/commits?per_page=100&page={page}",
            self.github_api_base, owner, repo
        );
        let resp = self.github_get(&url).await?;
        resp.json().await.map_err(|error| {
            warn!(owner, repo, page, %error, "Failed to parse commit history page");
            ai_supply_chain_trust_models::DataSourceError::GitHubTimeout
        })
    }

    // -----------------------------------------------------------------------
    // OSV Batch Query
    // -----------------------------------------------------------------------
    pub async fn fetch_osv_vulns(
        &self,
        package_name: &str,
        ecosystem: &str,
    ) -> Result<Vec<Value>, ai_supply_chain_trust_models::DataSourceError> {
        let url = format!("{}/v1/querybatch", self.osv_api_base);
        let body = serde_json::json!({
            "queries": [{
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }]
        });
        let resp = timeout(
            Duration::from_secs(self.timeout_seconds),
            self.client.post(&url).json(&body).send(),
        )
        .await
        .map_err(|_| ai_supply_chain_trust_models::DataSourceError::OsvTimeout)?
        .map_err(|_| ai_supply_chain_trust_models::DataSourceError::OsvTimeout)?;

        let result: Value = resp.json().await.map_err(|e| {
            warn!(error = %e, "Failed to parse OSV response");
            ai_supply_chain_trust_models::DataSourceError::OsvTimeout
        })?;
        let vulns: Vec<Value> = result
            .get("results")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .flat_map(|r| {
                        r.get("vulns")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();

        info!(
            package_name,
            ecosystem,
            count = vulns.len(),
            "Fetched OSV vulns"
        );
        Ok(vulns)
    }

    pub async fn fetch_nvd_for_repo(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<nvd::NvdCveEntry>, ai_supply_chain_trust_models::DataSourceError> {
        let identity = self.resolve_manifest_identity(owner, repo).await;
        nvd::fetch_nvd_cves(
            &self.client,
            owner,
            repo,
            &identity.package_names,
            &identity.ecosystem,
            self.config.nvd_api_key.as_deref(),
        )
        .await
    }

    async fn resolve_manifest_identity(&self, owner: &str, repo: &str) -> ManifestIdentity {
        const MANIFESTS: [(&str, &str); 5] = [
            ("package.json", "npm"),
            ("Cargo.toml", "crates.io"),
            ("pyproject.toml", "PyPI"),
            ("composer.json", "Packagist"),
            ("go.mod", "Go"),
        ];
        let mut identity = ManifestIdentity::default();
        for (path, ecosystem) in MANIFESTS {
            let url = format!(
                "{}/repos/{}/{}/contents/{}",
                self.github_api_base, owner, repo, path
            );
            let Ok(response) = self.github_get(&url).await else {
                continue;
            };
            let Ok(payload) = response.json::<Value>().await else {
                continue;
            };
            let Some(encoded) = payload.get("content").and_then(Value::as_str) else {
                continue;
            };
            let compact = encoded
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>();
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(compact) else {
                continue;
            };
            let Ok(content) = String::from_utf8(bytes) else {
                continue;
            };
            if let Some(name) = package_name_from_manifest(path, &content) {
                identity.ecosystem = ecosystem.to_string();
                if !identity.package_names.contains(&name) {
                    identity.package_names.push(name);
                }
            }
        }
        identity
    }

    /// Fetches repository metadata to populate head_sha and commit_count.
    pub async fn fetch_repo_meta(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<(Option<String>, i64), ai_supply_chain_trust_models::DataSourceError> {
        let url = format!("{}/repos/{}/{}", self.github_api_base, owner, repo);
        let resp = self.github_get(&url).await?;
        let meta: Value = resp.json().await.unwrap_or_default();
        let default_branch = meta
            .get("default_branch")
            .and_then(Value::as_str)
            .unwrap_or("main");
        let (head_sha, commit_count) = self
            .fetch_default_branch_commit_meta(owner, repo, default_branch)
            .await
            .unwrap_or((None, 0));
        info!(
            owner,
            repo, default_branch, commit_count, "Fetched repo meta"
        );
        Ok((head_sha, commit_count))
    }

    /// Populate head metadata from a repository response already fetched by
    /// the orchestration layer. This avoids charging the same `/repos` request
    /// twice during a scan.
    pub async fn fetch_repo_meta_from_value(
        &self,
        owner: &str,
        repo: &str,
        meta: &Value,
    ) -> Result<(Option<String>, i64), ai_supply_chain_trust_models::DataSourceError> {
        let default_branch = meta
            .get("default_branch")
            .and_then(Value::as_str)
            .unwrap_or("main");
        self.fetch_default_branch_commit_meta(owner, repo, default_branch)
            .await
    }

    async fn fetch_default_branch_commit_meta(
        &self,
        owner: &str,
        repo: &str,
        default_branch: &str,
    ) -> Result<(Option<String>, i64), ai_supply_chain_trust_models::DataSourceError> {
        let url = format!(
            "{}/repos/{}/{}/commits?sha={}&per_page=1",
            self.github_api_base, owner, repo, default_branch
        );
        let resp = self.github_get(&url).await?;
        let commit_count = resp
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .and_then(last_page_from_link)
            .unwrap_or(1);
        let commits: Vec<Value> = resp.json().await.map_err(|e| {
            warn!(error = %e, "Failed to parse default branch commit response");
            ai_supply_chain_trust_models::DataSourceError::GitHubTimeout
        })?;
        let head_sha = commits
            .first()
            .and_then(|commit| commit.get("sha"))
            .and_then(Value::as_str)
            .map(String::from);
        Ok((head_sha, commit_count))
    }

    async fn fetch_commit_detail(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Value, ai_supply_chain_trust_models::DataSourceError> {
        let url = format!(
            "{}/repos/{}/{}/commits/{}",
            self.github_api_base, owner, repo, sha
        );
        let resp = self.github_get(&url).await?;
        resp.json().await.map_err(|e| {
            warn!(owner, repo, sha, error = %e, "Failed to parse commit detail response");
            ai_supply_chain_trust_models::DataSourceError::GitHubTimeout
        })
    }

    pub async fn fetch_commit_detail_raw(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Value, ai_supply_chain_trust_models::DataSourceError> {
        self.fetch_commit_detail(owner, repo, sha).await
    }

    // -----------------------------------------------------------------------
    // Full intel collection — each fetcher's error is recorded, not swallowed
    // -----------------------------------------------------------------------
    pub async fn collect_intel(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<SecurityIntelligence, ai_supply_chain_trust_models::DataSourceError> {
        self.collect_intel_inner(owner, repo, None).await
    }

    pub async fn collect_intel_with_repo_metadata(
        &self,
        owner: &str,
        repo: &str,
        repo_metadata: &Value,
    ) -> Result<SecurityIntelligence, ai_supply_chain_trust_models::DataSourceError> {
        self.collect_intel_inner(owner, repo, Some(repo_metadata))
            .await
    }

    /// Foreground intelligence excludes unbounded history and NVD enrichment.
    pub async fn collect_fast_intel_with_repo_metadata(
        &self,
        _owner: &str,
        repo: &str,
        _repo_metadata: &Value,
    ) -> Result<SecurityIntelligence, ai_supply_chain_trust_models::DataSourceError> {
        let rule_ecosystem = infer_ecosystem(repo);
        let rule_pkg = infer_package_name(repo);
        Ok(SecurityIntelligence {
            fetched: true,
            head_sha: None,
            fix_commits: Vec::new(),
            advisories: Vec::new(),
            osv_vulns: Vec::new(),
            cves: Vec::new(),
            nvd_cves: Vec::new(),
            commit_count: 0,
            errors: Vec::new(),
            ecosystem_resolution: Some(json!({
                "ecosystem": rule_ecosystem,
                "package_name": rule_pkg,
                "source": "rule",
                "mode": "fast"
            })),
        })
    }

    async fn collect_intel_inner(
        &self,
        owner: &str,
        repo: &str,
        repo_metadata: Option<&Value>,
    ) -> Result<SecurityIntelligence, ai_supply_chain_trust_models::DataSourceError> {
        self.collect_intel_inner_with_mode(owner, repo, repo_metadata, true)
            .await
    }

    async fn collect_intel_inner_with_mode(
        &self,
        owner: &str,
        repo: &str,
        repo_metadata: Option<&Value>,
        include_deferred: bool,
    ) -> Result<SecurityIntelligence, ai_supply_chain_trust_models::DataSourceError> {
        let mut errors: Vec<String> = Vec::new();

        let advisories = match self.fetch_github_advisories(owner, repo).await {
            Ok(a) => a,
            Err(e) => {
                errors.push(format!("advisories: {e:?}"));
                Vec::new()
            }
        };

        let fix_commits = if include_deferred {
            match self.fetch_security_history(owner, repo).await {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("commits: {e:?}"));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let rule_ecosystem = infer_ecosystem(repo);
        let rule_pkg = infer_package_name(repo);
        let ecosystem_resolution = llm_ecosystem_resolution(
            self.config.llm_ecosystem_resolution_enabled,
            owner,
            repo,
            &rule_ecosystem,
            &rule_pkg,
        )
        .await;
        let ecosystem = ecosystem_resolution
            .as_ref()
            .and_then(|v| v.get("ecosystem"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&rule_ecosystem)
            .to_string();
        let pkg = ecosystem_resolution
            .as_ref()
            .and_then(|v| v.get("package_name"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&rule_pkg)
            .to_string();
        let osv_vulns = match self.fetch_osv_vulns(&pkg, &ecosystem).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("osv: {e:?}"));
                Vec::new()
            }
        };

        let repo_meta_result = match repo_metadata {
            Some(metadata) => self.fetch_repo_meta_from_value(owner, repo, metadata).await,
            None => self.fetch_repo_meta(owner, repo).await,
        };
        let (head_sha, commit_count) = match repo_meta_result {
            Ok((sha, count)) => (sha, count),
            Err(e) => {
                errors.push(format!("repo_meta: {e:?}"));
                (None, 0)
            }
        };

        let mut cves: Vec<String> = advisories
            .iter()
            .filter_map(|a| a.get("cve_id").and_then(Value::as_str).map(String::from))
            .collect();

        for vuln in &osv_vulns {
            if let Some(aliases) = vuln.get("aliases").and_then(|v| v.as_array()) {
                for alias in aliases {
                    if let Some(id) = alias.as_str() {
                        if id.starts_with("CVE-") && !cves.contains(&id.to_string()) {
                            cves.push(id.to_string());
                        }
                    }
                }
            }
        }

        let nvd_cves = if include_deferred {
            let manifest_identity = self.resolve_manifest_identity(owner, repo).await;
            match nvd::fetch_nvd_cves(
                &self.client,
                owner,
                repo,
                &manifest_identity.package_names,
                &manifest_identity.ecosystem,
                self.config.nvd_api_key.as_deref(),
            )
            .await
            {
                Ok(nvd_entries) => {
                    for entry in &nvd_entries {
                        if !cves.contains(&entry.cve_id) {
                            cves.push(entry.cve_id.clone());
                        }
                    }
                    nvd_entries
                }
                Err(e) => {
                    errors.push(format!("nvd: {e:?}"));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let fetched = !advisories.is_empty()
            || !fix_commits.is_empty()
            || !osv_vulns.is_empty()
            || !cves.is_empty();

        if !errors.is_empty() {
            info!(
                owner,
                repo,
                error_count = errors.len(),
                "Intel collection completed with errors"
            );
        }

        Ok(SecurityIntelligence {
            fetched,
            head_sha,
            fix_commits,
            advisories,
            osv_vulns,
            cves,
            nvd_cves,
            commit_count,
            errors,
            ecosystem_resolution,
        })
    }

    async fn github_get(
        &self,
        url: &str,
    ) -> Result<reqwest::Response, ai_supply_chain_trust_models::DataSourceError> {
        let mut retries = 0;
        loop {
            let attempts = self.github_tokens.len() + 1;
            for attempt in 0..attempts {
                let mut req = self
                    .client
                    .get(url)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28");
                if let Some(token) = self.github_token_for_attempt(attempt) {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
                let resp = timeout(Duration::from_secs(self.timeout_seconds), req.send())
                    .await
                    .map_err(|_| ai_supply_chain_trust_models::DataSourceError::GitHubTimeout)?
                    .map_err(|_| ai_supply_chain_trust_models::DataSourceError::GitHubTimeout)?;

                self.observe_github_rate_limit(&resp);

                match resp.status().as_u16() {
                    200 => return Ok(resp),
                    401 => {
                        if attempt + 1 < attempts {
                            warn!(
                                url,
                                "GitHub token unauthorized; trying next configured token"
                            );
                            continue;
                        }
                        return Err(
                            ai_supply_chain_trust_models::DataSourceError::GitHubUnauthorized,
                        );
                    }
                    403 | 429 => {
                        let remaining = resp
                            .headers()
                            .get("x-ratelimit-remaining")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<i64>().ok())
                            .unwrap_or(0);
                        if attempt + 1 < attempts {
                            info!(
                                url,
                                remaining,
                                attempt,
                                tokens = attempts,
                                "GitHub token limited; trying next configured token"
                            );
                            continue;
                        }
                        if retries < 3 {
                            let wait = github_backoff_seconds(&resp, remaining).max(1);
                            info!(
                                url,
                                remaining,
                                wait,
                                retry = retries,
                                "All GitHub tokens limited; waiting before retry"
                            );
                            sleep(Duration::from_secs(wait + 1)).await;
                            retries += 1;
                            break;
                        }
                        return Err(
                            ai_supply_chain_trust_models::DataSourceError::GitHubRateLimited,
                        );
                    }
                    404 => {
                        return Err(
                            ai_supply_chain_trust_models::DataSourceError::GitHubRepoNotFound,
                        )
                    }
                    status => {
                        warn!(url, status, "Unexpected GitHub API response status");
                        return Err(ai_supply_chain_trust_models::DataSourceError::GitHubTimeout);
                    }
                }
            }
        }
    }

    fn next_github_token(&self) -> Option<&str> {
        if self.github_tokens.is_empty() {
            return None;
        }
        let index = self.github_token_cursor.fetch_add(1, Ordering::Relaxed);
        self.github_tokens
            .get(index % self.github_tokens.len())
            .map(String::as_str)
    }

    fn github_token_for_attempt(&self, attempt: usize) -> Option<&str> {
        if attempt >= self.github_tokens.len() {
            return None;
        }
        self.next_github_token()
    }

    fn observe_github_rate_limit(&self, response: &reqwest::Response) {
        let parse = |name| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<i64>().ok())
        };
        let Some(remaining) = parse("x-ratelimit-remaining") else {
            return;
        };
        let mut snapshot = self.github_rate_limit.lock().unwrap();
        snapshot.limit = parse("x-ratelimit-limit").unwrap_or(snapshot.limit);
        snapshot.remaining = remaining;
        snapshot.reset_at = parse("x-ratelimit-reset")
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(snapshot.reset_at);
        snapshot.observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        info!(
            limit = snapshot.limit,
            remaining = snapshot.remaining,
            reset_at = snapshot.reset_at,
            "GitHub rate-limit budget updated"
        );
    }
}

fn github_backoff_seconds(resp: &reqwest::Response, remaining: i64) -> u64 {
    if let Some(wait) = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        return wait.min(60);
    }
    if remaining == 0 {
        return resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|reset_at| github_reset_wait_seconds(reset_at, unix_now_seconds()))
            .unwrap_or(60)
            .clamp(1, 3600);
    }
    0
}

fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn github_reset_wait_seconds(reset_at: u64, now: u64) -> u64 {
    reset_at.saturating_sub(now)
}

/// Classify persisted list-page commits without issuing detail requests.
/// Only messages with explicit CVE/GHSA/CWE/security-vulnerability evidence
/// are retained; ambiguous candidates remain for a later detail-task pass.
pub fn security_candidate_shas(pages: &[Value]) -> Vec<String> {
    let mut shas = Vec::new();
    for commit in pages.iter().flat_map(|page| {
        page.get("commits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    }) {
        let message = commit
            .get("commit")
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let sha = commit.get("sha").and_then(Value::as_str).unwrap_or("");
        if looks_security_relevant(message)
            && !has_explicit_vulnerability_evidence(message)
            && !sha.is_empty()
            && !shas.iter().any(|existing| existing == sha)
        {
            shas.push(sha.to_string());
        }
    }
    shas
}

pub fn classify_persisted_commit_pages(owner: &str, repo: &str, pages: &[Value]) -> Vec<FixCommit> {
    classify_persisted_commit_pages_with_details(owner, repo, pages, &[])
}

pub fn classify_persisted_commit_pages_with_details(
    owner: &str,
    repo: &str,
    pages: &[Value],
    details: &[Value],
) -> Vec<FixCommit> {
    let mut fixes = Vec::new();
    for commit in pages.iter().flat_map(|page| {
        page.get("commits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    }) {
        let message = commit
            .get("commit")
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !looks_security_relevant(message) {
            continue;
        }
        let sha = commit
            .get("sha")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if sha.is_empty() || fixes.iter().any(|fix: &FixCommit| fix.sha == sha) {
            continue;
        }
        let detail = details
            .iter()
            .find(|detail| detail.get("sha").and_then(Value::as_str) == Some(sha.as_str()));
        let files = detail
            .map(commit_file_evidence_from_detail)
            .unwrap_or_default();
        if !should_keep_security_fix_commit(message, &files) {
            continue;
        }
        let vuln_class = classify_vuln_class_with_evidence(message, &files);
        let severity = classify_severity_with_evidence(message, vuln_class, &files);
        let cwe = classify_cwe_for_class(vuln_class);
        let component = select_primary_component(&files);
        let rule_based_result = json!({
            "vuln_class": vuln_class, "severity": severity,
            "cwe": cwe.clone(), "security_relevant": true
        });
        fixes.push(FixCommit {
            sha: sha.clone(),
            subject: message.lines().next().unwrap_or("").to_string(),
            component,
            vuln_class: vuln_class.to_string(),
            cwe,
            severity: severity.to_string(),
            date: commit
                .get("commit")
                .and_then(|value| value.get("author"))
                .and_then(|value| value.get("date"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            html_url: format!("https://github.com/{owner}/{repo}/commit/{sha}"),
            changed_files: files,
            file_evidence_source: Some(if detail.is_some() {
                "github_commit_detail".to_string()
            } else {
                "github_commit_list".to_string()
            }),
            file_evidence_status: Some(if detail.is_some() {
                "fetched".to_string()
            } else {
                "skipped_explicit_message_evidence".to_string()
            }),
            decision_source: "rule_based".to_string(),
            rule_based_result: Some(rule_based_result),
            llm_assisted_result: None,
        });
    }
    fixes
}

fn commit_file_evidence_from_detail(detail: &Value) -> Vec<CommitFileEvidence> {
    detail
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file.get("filename").and_then(Value::as_str)?.to_string();
            Some(CommitFileEvidence {
                path,
                status: file
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("modified")
                    .to_string(),
                additions: file.get("additions").and_then(Value::as_i64).unwrap_or(0),
                deletions: file.get("deletions").and_then(Value::as_i64).unwrap_or(0),
                changes: file.get("changes").and_then(Value::as_i64).unwrap_or(0),
                touched_symbols: file
                    .get("patch")
                    .and_then(Value::as_str)
                    .map(touched_symbols_from_patch)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn select_primary_component(files: &[CommitFileEvidence]) -> String {
    files
        .iter()
        .filter(|file| !file.path.trim().is_empty())
        .max_by_key(|file| {
            (
                source_path_score(&file.path),
                file.changes,
                file.additions + file.deletions,
            )
        })
        .map(|file| file.path.clone())
        .unwrap_or_else(|| "repository".to_string())
}

fn source_path_score(path: &str) -> i64 {
    let lower = path.to_ascii_lowercase();
    let mut score = 0;
    if lower.contains("/src/")
        || lower.starts_with("src/")
        || lower.contains("wolfcrypt/src/")
        || lower.contains("/lib/")
    {
        score += 40;
    }
    if lower.contains("ssl")
        || lower.contains("tls")
        || lower.contains("crypto")
        || lower.contains("cert")
        || lower.contains("auth")
    {
        score += 25;
    }
    if matches!(
        lower.rsplit('.').next(),
        Some("c")
            | Some("cc")
            | Some("cpp")
            | Some("h")
            | Some("hpp")
            | Some("rs")
            | Some("go")
            | Some("java")
            | Some("js")
            | Some("ts")
            | Some("py")
    ) {
        score += 20;
    }
    if lower.contains("/test")
        || lower.starts_with("test")
        || lower.contains("/doc")
        || lower.starts_with("doc")
        || lower.ends_with(".md")
        || lower.ends_with(".txt")
    {
        score -= 30;
    }
    score
}

fn should_keep_security_fix_commit(message: &str, files: &[CommitFileEvidence]) -> bool {
    if files.is_empty() {
        return has_explicit_vulnerability_evidence(message);
    }

    let all_auxiliary = files
        .iter()
        .all(|file| is_auxiliary_security_fix_path(&file.path));
    if all_auxiliary && !has_strong_auxiliary_vulnerability_evidence(message) {
        return false;
    }

    if has_explicit_vulnerability_evidence(message) {
        return true;
    }

    files
        .iter()
        .any(|file| !is_auxiliary_security_fix_path(&file.path))
}

fn has_explicit_vulnerability_evidence(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let normalized = lower.replace(['-', '_'], " ");
    let strong_terms = [
        "cve",
        "ghsa",
        "cwe",
        "vulnerability",
        "vulnerabilities",
        "command injection",
        "sql injection",
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "integer overflow",
        "use after free",
        "double free",
        "auth bypass",
        "authentication bypass",
        "authorization bypass",
        "remote code execution",
        "code execution",
        "arbitrary code",
        "memory corruption",
        "out of bounds",
        "race condition",
        "timing attack",
        "side channel",
        "privilege escalation",
        "information disclosure",
        "cross site scripting",
        "xss",
        "csrf",
        "ssrf",
        "path traversal",
        "directory traversal",
        "format string",
        "type confusion",
    ];

    strong_terms
        .iter()
        .any(|term| contains_evidence_term(&lower, &normalized, term))
}

fn has_strong_auxiliary_vulnerability_evidence(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let normalized = lower.replace(['-', '_'], " ");
    let strong_terms = [
        "cve",
        "ghsa",
        "cwe",
        "vulnerability",
        "vulnerabilities",
        "command injection",
        "sql injection",
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "integer overflow",
        "use after free",
        "double free",
        "auth bypass",
        "authentication bypass",
        "authorization bypass",
        "remote code execution",
        "code execution",
        "arbitrary code",
        "memory corruption",
        "out of bounds",
        "timing attack",
        "side channel",
        "privilege escalation",
        "information disclosure",
        "cross site scripting",
        "xss",
        "csrf",
        "ssrf",
        "path traversal",
        "directory traversal",
        "format string",
        "type confusion",
    ];

    strong_terms
        .iter()
        .any(|term| contains_evidence_term(&lower, &normalized, term))
}

fn contains_evidence_term(lower: &str, normalized: &str, term: &str) -> bool {
    if is_short_identifier_evidence_term(term) {
        return contains_ascii_token(lower, term) || contains_ascii_token(normalized, term);
    }

    lower.contains(term) || normalized.contains(term)
}

fn is_short_identifier_evidence_term(term: &str) -> bool {
    matches!(term, "cve" | "ghsa" | "cwe" | "xss" | "csrf" | "ssrf")
}

fn contains_ascii_token(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(idx, _)| {
        let before = haystack[..idx].chars().next_back();
        let after = haystack[idx + needle.len()..].chars().next();

        before.is_none_or(|ch| !ch.is_ascii_alphanumeric())
            && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
    })
}

fn is_auxiliary_security_fix_path(path: &str) -> bool {
    let lower = path.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    is_test_path(&lower)
        || is_ci_path(&lower)
        || is_build_config_path(&lower)
        || is_macro_registry_path(&lower)
        || is_doc_path(&lower)
        || is_content_data_path(&lower)
}

fn is_content_data_path(lower: &str) -> bool {
    let flat_data_file = lower.ends_with(".csv")
        || lower.ends_with(".tsv")
        || lower.ends_with(".jsonl")
        || lower.ends_with(".ndjson");
    let content_directory = lower.starts_with("data/")
        || lower.contains("/data/")
        || lower.starts_with("dataset/")
        || lower.starts_with("datasets/")
        || lower.contains("/dataset/")
        || lower.contains("/datasets/")
        || lower.starts_with("content/")
        || lower.contains("/content/")
        || lower.starts_with("prompts/")
        || lower.contains("/prompts/");
    let content_extension = lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".xml")
        || lower.ends_with(".parquet")
        || lower.ends_with(".arrow");

    flat_data_file || content_directory && content_extension
}

fn is_test_path(lower: &str) -> bool {
    lower.starts_with("test/")
        || lower.starts_with("tests/")
        || lower.starts_with("testing/")
        || lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.contains("/testing/")
        || lower.contains("/test_")
        || lower.contains("/test-")
        || lower.contains("_test.")
}

fn is_ci_path(lower: &str) -> bool {
    lower.starts_with(".github/")
        || lower.contains("/.github/")
        || lower.starts_with(".circleci/")
        || lower.contains("/.circleci/")
        || lower.starts_with(".azure-pipelines/")
        || lower.contains("/.azure-pipelines/")
        || lower.starts_with(".buildkite/")
        || lower.contains("/.buildkite/")
        || lower.starts_with(".gitlab-ci")
        || lower.starts_with(".travis")
}

fn is_build_config_path(lower: &str) -> bool {
    lower == "configure"
        || lower.ends_with("/configure")
        || lower == "configure.ac"
        || lower.ends_with("/configure.ac")
        || lower == "cmakelists.txt"
        || lower.ends_with("/cmakelists.txt")
        || lower.ends_with(".cmake")
        || lower.starts_with("cmake/")
        || lower.contains("/cmake/")
        || lower == "makefile"
        || lower.ends_with("/makefile")
        || lower.starts_with("makefile.")
        || lower.ends_with("/makefile.am")
        || lower.ends_with("/makefile.in")
        || lower.ends_with(".m4")
        || lower.ends_with(".mk")
        || lower.ends_with(".mak")
        || lower.ends_with(".sln")
        || lower.ends_with(".vcxproj")
        || lower.starts_with("build/")
        || lower.contains("/build/")
        || lower.starts_with("scripts/")
        || lower.contains("/scripts/")
}

fn is_macro_registry_path(lower: &str) -> bool {
    lower == ".wolfssl_known_macro_extras"
        || lower.ends_with("/.wolfssl_known_macro_extras")
        || lower.contains("known_macro")
        || lower.contains("known-macro")
}

fn is_doc_path(lower: &str) -> bool {
    lower.starts_with("doc/")
        || lower.starts_with("docs/")
        || lower.contains("/doc/")
        || lower.contains("/docs/")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower.ends_with(".adoc")
        || lower.ends_with(".txt")
}

fn touched_symbols_from_patch(patch: &str) -> Vec<String> {
    let mut symbols = Vec::new();
    for line in patch.lines() {
        if !line.starts_with("@@") {
            continue;
        }
        let Some((_, context)) = line.rsplit_once("@@") else {
            continue;
        };
        let symbol = normalize_hunk_symbol(context.trim());
        if !symbol.is_empty() && !symbols.contains(&symbol) {
            symbols.push(symbol);
        }
        if symbols.len() >= 12 {
            break;
        }
    }
    symbols
}

fn normalize_hunk_symbol(context: &str) -> String {
    let context = context
        .split('{')
        .next()
        .unwrap_or(context)
        .trim()
        .trim_start_matches('*')
        .trim();
    if context.is_empty() {
        return String::new();
    }
    if let Some(paren) = context.find('(') {
        return context[..paren]
            .split(|c: char| c.is_whitespace() || c == '*' || c == ':' || c == '&')
            .rfind(|part| !part.is_empty())
            .unwrap_or(context)
            .trim()
            .chars()
            .take(120)
            .collect();
    }
    context.chars().take(120).collect()
}

async fn llm_commit_classification(
    enabled: bool,
    sha: &str,
    subject: &str,
    date: &str,
    html_url: &str,
    rule_based_result: &Value,
) -> Option<Value> {
    if !enabled {
        return None;
    }
    let input = json!({
        "task": "vulnerability_classification",
        "rule_based_result": rule_based_result,
        "evidence": [{
            "id": "commit_1",
            "sha": sha,
            "subject": subject,
            "date": date,
            "html_url": html_url
        }]
    });
    match ai_supply_chain_trust_llm::tasks::classify_vulnerability(&input).await {
        Ok(value) => Some(value),
        Err(ai_supply_chain_trust_llm::guardrail::GuardrailError::Rejected(err)) => Some(
            ai_supply_chain_trust_llm::tasks::rejected_hallucination_decision_for(
                "vulnerability_classification",
                err,
                rule_based_result.clone(),
            ),
        ),
        Err(ai_supply_chain_trust_llm::guardrail::GuardrailError::Unavailable(err)) => {
            Some(ai_supply_chain_trust_llm::tasks::unavailable_decision_for(
                "vulnerability_classification",
                &err,
                rule_based_result.clone(),
            ))
        }
    }
}

async fn llm_ecosystem_resolution(
    enabled: bool,
    owner: &str,
    repo: &str,
    rule_ecosystem: &str,
    rule_pkg: &str,
) -> Option<Value> {
    if !enabled {
        return None;
    }
    let input = json!({
        "task": "ecosystem_resolution",
        "rule_based_result": {
            "ecosystem": rule_ecosystem,
            "package_name": rule_pkg
        },
        "evidence": [{
            "id": "repo_1",
            "owner": owner,
            "repo": repo,
            "package_name": rule_pkg,
            "ecosystem": rule_ecosystem
        }]
    });
    let rule_based_result = json!({"ecosystem": rule_ecosystem, "package_name": rule_pkg});
    match ai_supply_chain_trust_llm::tasks::resolve_ecosystem(&input).await {
        Ok(value) => Some(value),
        Err(ai_supply_chain_trust_llm::guardrail::GuardrailError::Rejected(err)) => Some(
            ai_supply_chain_trust_llm::tasks::rejected_hallucination_decision_for(
                "ecosystem_resolution",
                err,
                rule_based_result,
            ),
        ),
        Err(ai_supply_chain_trust_llm::guardrail::GuardrailError::Unavailable(err)) => {
            Some(ai_supply_chain_trust_llm::tasks::unavailable_decision_for(
                "ecosystem_resolution",
                &err,
                rule_based_result,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Classification helpers (match intelligence.py constants exactly)
// ---------------------------------------------------------------------------

pub(crate) fn looks_security_relevant(message: &str) -> bool {
    // Commit bodies routinely contain generated changelogs, scanner output,
    // linked issues, and CVE lists unrelated to the change.  Candidate
    // selection therefore uses the subject only.  Detail evidence is fetched
    // later for candidates that do not carry an advisory identifier.
    let lower = message.to_ascii_lowercase();
    let subject = lower.lines().next().unwrap_or("").trim();
    let remediation_terms = [
        "fix",
        "fixed",
        "fixes",
        "fixing",
        "patch",
        "patched",
        "mitigate",
        "mitigates",
        "harden",
        "hardening",
        "prevent",
        "prevents",
        "avoid",
        "remediate",
        "address",
        "resolve",
        "resolves",
        "block",
        "protect",
        "bump",
        "upgrade",
    ];
    let has_remediation = remediation_terms
        .iter()
        .any(|term| contains_ascii_token(subject, term));
    if !has_remediation {
        return false;
    }

    contains_advisory_identifier(subject)
        || contains_ascii_token(subject, "vulnerability")
        || contains_ascii_token(subject, "vulnerabilities")
        || contains_ascii_token(subject, "vulnerable")
        || contains_ascii_token(subject, "security")
        || has_high_confidence_vulnerability_phrase(subject)
        || contains_any(
            subject,
            &[
                "security fix",
                "security issue",
                "security hardening",
                "certificate validation",
                "certificate verification",
                "signature verification",
                "unauthorized access",
                "access control",
                "credential leak",
                "credential exposure",
                "secret leak",
                "secret exposure",
                "permission check",
                "input sanitization",
                "sanitize input",
                "escape input",
                "validate input",
            ],
        )
}

fn contains_advisory_identifier(text: &str) -> bool {
    ["cve", "ghsa", "cwe"]
        .iter()
        .any(|term| contains_ascii_token(text, term))
}

fn has_high_confidence_vulnerability_phrase(text: &str) -> bool {
    contains_any(
        text,
        &[
            "auth bypass",
            "authentication bypass",
            "authorization bypass",
            "remote code execution",
            "code execution",
            "arbitrary code",
            "command injection",
            "sql injection",
            "shell injection",
            "code injection",
            "template injection",
            "ldap injection",
            "prompt injection",
            "buffer overflow",
            "heap overflow",
            "use after free",
            "use-after-free",
            "double free",
            "memory corruption",
            "denial of service",
            "privilege escalation",
            "information disclosure",
            "cross-site scripting",
            "cross site scripting",
            "path traversal",
            "directory traversal",
            "timing attack",
            "side channel",
            "side-channel",
            "type confusion",
            "insecure deserialization",
        ],
    ) || ["rce", "xss", "csrf", "ssrf", "sqli"]
        .iter()
        .any(|term| contains_ascii_token(text, term))
}

#[cfg(test)]
pub(crate) fn classify_vuln_class(message: &str) -> &'static str {
    classify_vuln_class_with_evidence(message, &[])
}

fn classify_vuln_class_with_evidence(
    message: &str,
    changed_files: &[CommitFileEvidence],
) -> &'static str {
    let lower = message.to_ascii_lowercase();
    let evidence = vulnerability_evidence_text(message, changed_files);
    let code_patch = has_patch_stats(changed_files) && touches_source_file(changed_files);

    if is_security_control_improvement(&lower, changed_files) {
        return "Security Control Improvement";
    }
    if is_weak_aggregate_commit(&lower) {
        return "Security Fix";
    }

    if contains_any(
        &evidence,
        &[
            "signature verification",
            "signature validation",
            "verify signature",
            "verified signature",
            "signature bypass",
        ],
    ) || (contains_word(&evidence, "signature")
        && contains_any(
            &evidence,
            &["verify", "verification", "validate", "validation", "bypass"],
        ))
    {
        "Signature Verification Bypass"
    } else if contains_any(
        &evidence,
        &[
            "certificate validation",
            "certificate verification",
            "cert validation",
            "cert verification",
            "verify certificate",
            "hostname verification",
            "x509",
            "x.509",
        ],
    ) || (contains_any(&evidence, &["certificate", "cert"])
        && contains_any(
            &evidence,
            &[
                "verify",
                "verification",
                "validate",
                "validation",
                "hostname",
                "chain",
            ],
        ))
    {
        "Improper Certificate Validation"
    } else if contains_any(
        &evidence,
        &[
            "auth bypass",
            "authentication bypass",
            "authorization bypass",
            "unauthorized access",
            "access control bypass",
        ],
    ) {
        "Auth Bypass"
    } else if contains_ascii_token(&lower, "xss") || lower.contains("cross-site scripting") {
        "Cross-Site Scripting"
    } else if contains_ascii_token(&lower, "csrf") || lower.contains("cross-site request forgery") {
        "CSRF"
    } else if contains_ascii_token(&lower, "ssrf") || lower.contains("server-side request forgery")
    {
        "Server-Side Request Forgery"
    } else if lower.contains("denial of service") || contains_ascii_token(&lower, "dos") {
        "Denial of Service"
    } else if contains_any(
        &evidence,
        &[
            "command injection",
            "sql injection",
            "shell injection",
            "code injection",
            "template injection",
            "ldap injection",
            "prompt injection",
            "injection vulnerability",
        ],
    ) || contains_ascii_token(&lower, "sqli")
    {
        "Injection"
    } else if lower.contains("use after free")
        || lower.contains("use-after-free")
        || contains_word(&evidence, "uaf")
        || lower.contains("dangling")
    {
        "Use After Free"
    } else if lower.contains("double free") {
        "Double Free"
    } else if lower.contains("buffer overflow")
        || lower.contains("heap overflow")
        || lower.contains("stack overflow")
        || (lower.contains("overflow")
            && contains_any(&evidence, &["buffer", "buf", "memcpy", "strcpy"]))
    {
        "Buffer Overflow"
    } else if lower.contains("integer overflow")
        || lower.contains("integer wraparound")
        || lower.contains("integer underflow")
        || lower.contains("wraparound")
        || lower.contains("wrap around")
        || (lower.contains("overflow")
            && contains_any(&evidence, &["integer", "uint", "size_t", "length", "len"]))
    {
        "Integer Overflow"
    } else if lower.contains("out of bounds")
        || lower.contains("out-of-bounds")
        || contains_word(&evidence, "oob")
        || lower.contains("overread")
        || lower.contains("over-read")
        || (code_patch && lower.contains("bounds"))
    {
        "Out-of-Bounds Access"
    } else if lower.contains("null pointer") || lower.contains("null deref") {
        "NULL Pointer Dereference"
    } else if lower.contains("race condition") || lower.contains("toctou") {
        "Race Condition"
    } else if lower.contains("timing attack")
        || lower.contains("timing leak")
        || lower.contains("side channel")
        || lower.contains("side-channel")
        || lower.contains("constant time")
        || lower.contains("constant-time")
        || contains_any(&evidence, &["cache timing", "timing leak"])
    {
        "Timing/Side-Channel"
    } else if lower.contains("information disclosure")
        || contains_any(
            &evidence,
            &[
                "data leak",
                "secret leak",
                "credential leak",
                "token leak",
                "privacy leak",
                "sensitive information leak",
            ],
        )
    {
        "Information Disclosure"
    } else if contains_ascii_token(&lower, "rce")
        || lower.contains("arbitrary code")
        || lower.contains("code execution")
    {
        "Remote Code Execution"
    } else if lower.contains("privilege escalation") {
        "Privilege Escalation"
    } else if lower.contains("format string") {
        "Format String"
    } else if lower.contains("type confusion") {
        "Type Confusion"
    } else if lower.contains("deserial") {
        "Insecure Deserialization"
    } else if lower.contains("path traversal") || lower.contains("directory traversal") {
        "Path Traversal"
    } else {
        "Security Fix"
    }
}

#[cfg(test)]
pub(crate) fn classify_severity(message: &str) -> &'static str {
    let vuln_class = classify_vuln_class_with_evidence(message, &[]);
    classify_severity_with_evidence(message, vuln_class, &[])
}

fn classify_severity_with_evidence(
    message: &str,
    vuln_class: &str,
    changed_files: &[CommitFileEvidence],
) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if vuln_class == "Security Control Improvement" || is_weak_aggregate_commit(&lower) {
        return "medium";
    }
    let evidence = vulnerability_evidence_text(message, changed_files);
    if let Some(severity) = explicit_severity_from_text(&evidence) {
        return severity;
    }

    let code_patch = has_patch_stats(changed_files) && touches_source_file(changed_files);
    if matches!(
        vuln_class,
        "Auth Bypass"
            | "Buffer Overflow"
            | "Double Free"
            | "Format String"
            | "Improper Certificate Validation"
            | "Insecure Deserialization"
            | "Memory Corruption"
            | "Privilege Escalation"
            | "Remote Code Execution"
            | "Signature Verification Bypass"
            | "Use After Free"
    ) || (vuln_class == "Injection"
        && contains_any(
            &evidence,
            &["command injection", "code injection", "shell injection"],
        ))
    {
        "high"
    } else if vuln_class == "Integer Overflow" {
        if code_patch || contains_any(&evidence, &["length", "size", "bounds", "wraparound"]) {
            "high"
        } else {
            "medium"
        }
    } else if vuln_class == "Out-of-Bounds Access" {
        if code_patch {
            "high"
        } else {
            "medium"
        }
    } else if vuln_class == "Security Fix"
        && code_patch
        && contains_any(
            &evidence,
            &[
                "bypass",
                "code execution",
                "double free",
                "memory corruption",
                "overflow",
                "signature",
                "use after free",
                "use-after-free",
            ],
        )
    {
        "high"
    } else {
        "medium"
    }
}

fn explicit_severity_from_text(text: &str) -> Option<&'static str> {
    if contains_any(
        text,
        &[
            "severity:critical",
            "severity: critical",
            "severity=critical",
            "severity critical",
            "critical severity",
            "critical risk",
            "critical-risk",
            "cvss critical",
            "cvss: critical",
        ],
    ) {
        Some("critical")
    } else if contains_any(
        text,
        &[
            "severity:high",
            "severity: high",
            "severity=high",
            "severity high",
            "high severity",
            "high risk",
            "high-risk",
            "cvss high",
            "cvss: high",
        ],
    ) || contains_word(text, "high")
    {
        Some("high")
    } else if contains_any(
        text,
        &[
            "severity:medium",
            "severity: medium",
            "severity=medium",
            "severity:moderate",
            "severity: moderate",
            "severity=moderate",
            "severity medium",
            "severity moderate",
            "medium severity",
            "moderate severity",
            "medium risk",
            "moderate risk",
            "cvss medium",
            "cvss moderate",
        ],
    ) {
        Some("medium")
    } else if contains_any(
        text,
        &[
            "severity:low",
            "severity: low",
            "severity=low",
            "severity low",
            "low severity",
            "low risk",
            "low-risk",
            "low impact",
            "low-impact",
            "cvss low",
            "cvss: low",
        ],
    ) {
        Some("low")
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) fn classify_cwe(message: &str) -> Vec<String> {
    let class = classify_vuln_class(message);
    classify_cwe_for_class(class)
}

fn classify_cwe_for_class(class: &str) -> Vec<String> {
    match class {
        "Auth Bypass" => vec!["CWE-287".into()],
        "Improper Certificate Validation" => vec!["CWE-295".into()],
        "Signature Verification Bypass" => vec!["CWE-347".into()],
        "Security Control Improvement" => vec![],
        "Cross-Site Scripting" => vec!["CWE-79".into()],
        "CSRF" => vec!["CWE-352".into()],
        "Server-Side Request Forgery" => vec!["CWE-918".into()],
        "Denial of Service" => vec!["CWE-400".into()],
        "Injection" => vec!["CWE-74".into()],
        "Use After Free" => vec!["CWE-416".into()],
        "Double Free" => vec!["CWE-415".into()],
        "Buffer Overflow" => vec!["CWE-120".into()],
        "Integer Overflow" => vec!["CWE-190".into()],
        "Out-of-Bounds Access" => vec!["CWE-125".into()],
        "NULL Pointer Dereference" => vec!["CWE-476".into()],
        "Race Condition" => vec!["CWE-362".into()],
        "Information Disclosure" => vec!["CWE-200".into()],
        "Remote Code Execution" => vec!["CWE-94".into()],
        "Privilege Escalation" => vec!["CWE-269".into()],
        "Timing/Side-Channel" => vec!["CWE-385".into()],
        "Format String" => vec!["CWE-134".into()],
        "Type Confusion" => vec!["CWE-843".into()],
        "Insecure Deserialization" => vec!["CWE-502".into()],
        "Path Traversal" => vec!["CWE-22".into()],
        _ => vec![],
    }
}

fn vulnerability_evidence_text(message: &str, changed_files: &[CommitFileEvidence]) -> String {
    let mut evidence = message.to_ascii_lowercase();
    for file in changed_files {
        evidence.push(' ');
        evidence.push_str(&file.path.to_ascii_lowercase());
        for symbol in &file.touched_symbols {
            evidence.push(' ');
            evidence.push_str(&symbol.to_ascii_lowercase());
        }
    }
    evidence
}

fn is_weak_aggregate_commit(lower: &str) -> bool {
    let subject = lower.lines().next().unwrap_or("").trim();
    subject.starts_with("merge branch")
        || subject.starts_with("merge pull request")
        || subject.starts_with("[infra] merging")
        || subject.starts_with("chore:")
        || subject.starts_with("chore(")
}

fn is_security_control_improvement(lower: &str, changed_files: &[CommitFileEvidence]) -> bool {
    let subject = lower.lines().next().unwrap_or("").trim();
    let ci_or_scanner_subject = subject.starts_with("ci")
        || subject.starts_with("build")
        || subject.starts_with("chore(ci")
        || subject.contains("image-scan")
        || subject.contains("scorecard")
        || subject.contains("scanner");
    let scanner_terms = contains_any(
        lower,
        &[
            "add grype",
            "add osv-scan",
            "add scorecard",
            "image scan",
            "security scan",
            "scanner",
            "scan workflow",
        ],
    );
    let auxiliary_only = !changed_files.is_empty()
        && changed_files
            .iter()
            .all(|file| is_auxiliary_security_fix_path(&file.path));
    ci_or_scanner_subject
        && scanner_terms
        && (auxiliary_only || !touches_source_file(changed_files))
}

fn touches_source_file(changed_files: &[CommitFileEvidence]) -> bool {
    changed_files.iter().any(|file| {
        source_path_score(&file.path) > 0
            || file.path.ends_with(".c")
            || file.path.ends_with(".cc")
            || file.path.ends_with(".cpp")
            || file.path.ends_with(".h")
            || file.path.ends_with(".rs")
    })
}

fn has_patch_stats(changed_files: &[CommitFileEvidence]) -> bool {
    changed_files
        .iter()
        .any(|file| file.changes > 0 || file.additions > 0 || file.deletions > 0)
}

fn contains_any(text: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| text.contains(term))
}

fn contains_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let mut search_start = 0;
    while let Some(relative_start) = text[search_start..].find(word) {
        let start = search_start + relative_start;
        let end = start + word.len();
        let starts_on_boundary = start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric();
        let ends_on_boundary = end == text.len() || !text.as_bytes()[end].is_ascii_alphanumeric();
        if starts_on_boundary && ends_on_boundary {
            return true;
        }
        search_start = end;
    }
    false
}

fn package_name_from_manifest(path: &str, content: &str) -> Option<String> {
    let name = match path {
        "package.json" | "composer.json" => serde_json::from_str::<Value>(content)
            .ok()?
            .get("name")?
            .as_str()?
            .to_string(),
        "Cargo.toml" => toml::from_str::<toml::Value>(content)
            .ok()?
            .get("package")?
            .get("name")?
            .as_str()?
            .to_string(),
        "pyproject.toml" => {
            let document = toml::from_str::<toml::Value>(content).ok()?;
            document
                .get("project")
                .and_then(|project| project.get("name"))
                .and_then(toml::Value::as_str)
                .or_else(|| document.get("tool")?.get("poetry")?.get("name")?.as_str())?
                .to_string()
        }
        "go.mod" => content
            .lines()
            .find_map(|line| line.trim().strip_prefix("module "))?
            .trim()
            .to_string(),
        _ => return None,
    };
    let name = name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

fn infer_ecosystem(repo: &str) -> String {
    if repo.contains("npm") || repo.contains("node") {
        "npm".into()
    } else if repo.contains("pypi") || repo.ends_with(".py") {
        "PyPI".into()
    } else if repo.contains("crates") || repo.contains("rust") {
        "crates.io".into()
    } else {
        "GitHub Actions".into()
    }
}

fn infer_package_name(repo: &str) -> String {
    repo.split('/').next_back().unwrap_or(repo).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_package_identity_from_supported_manifests() {
        assert_eq!(
            package_name_from_manifest("package.json", r#"{"name":"@scope/raptor"}"#),
            Some("@scope/raptor".to_string())
        );
        assert_eq!(
            package_name_from_manifest("Cargo.toml", "[package]\nname = \"raptor-core\"\n"),
            Some("raptor-core".to_string())
        );
        assert_eq!(
            package_name_from_manifest("pyproject.toml", "[project]\nname = \"raptor-py\"\n"),
            Some("raptor-py".to_string())
        );
        assert_eq!(
            package_name_from_manifest("go.mod", "module github.com/acme/raptor-go\n\ngo 1.23\n"),
            Some("github.com/acme/raptor-go".to_string())
        );
    }

    #[test]
    fn security_relevant_messages_detected() {
        assert!(looks_security_relevant("fix: patch XSS vulnerability"));
        assert!(looks_security_relevant("Security: prevent auth bypass"));
        assert!(looks_security_relevant(
            "deps: upgrade lodash to fix CVE-2024-1234"
        ));
    }

    #[test]
    fn non_security_messages_ignored() {
        assert!(!looks_security_relevant("docs: update README"));
        assert!(!looks_security_relevant("chore: bump version to 2.0"));
        assert!(!looks_security_relevant("fix typo in README"));
    }

    #[test]
    fn security_candidate_matching_uses_semantic_boundaries() {
        assert!(!looks_security_relevant(
            "Add prompt: Unified Research and Source Analysis Prompt"
        ));
        assert!(!looks_security_relevant(
            "fix(images): reconcile mismatched image media types before send"
        ));
        assert!(!looks_security_relevant(
            "fix: remove unexpected force argument"
        ));
        assert!(!looks_security_relevant(
            "Update prompt: Android AI App Security Specialist Task"
        ));
        assert!(!looks_security_relevant(
            "feat: add authentication settings"
        ));
        assert!(!looks_security_relevant(
            "Fixes race condition in model training"
        ));
        assert!(!looks_security_relevant(
            "Fix NNX checkpoint axis out of bounds error"
        ));
        assert!(!looks_security_relevant(
            "Fix worker stack overflow by heap-allocating futures"
        ));
        assert!(!looks_security_relevant(
            "feat(rules): add cross-site scripting detector"
        ));
        assert!(!looks_security_relevant(
            "Import upstream tests for CVE-2024-0727"
        ));
        assert!(!looks_security_relevant(
            "feat: release model catalog\n\nfix CVE-2026-1234 in generated changelog"
        ));
        assert!(looks_security_relevant(
            "security: harden certificate validation"
        ));
        assert!(looks_security_relevant(
            "fix: prevent unauthorized access to private sessions"
        ));
        assert!(looks_security_relevant(
            "fix: prevent buffer overflow in archive parser"
        ));
        assert!(looks_security_relevant(
            "deps: bump protobuf for CVE-2026-41242"
        ));
    }

    #[test]
    fn replays_security_history_precision_corpus() {
        let corpus: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/security_history_precision.json"
        ))
        .expect("precision corpus should be valid JSON");

        for case in corpus {
            let message = case["message"].as_str().expect("message");
            let expected = case["expected"].as_bool().expect("expected");
            assert_eq!(
                looks_security_relevant(message),
                expected,
                "unexpected classification for {message:?}"
            );
        }
    }

    #[test]
    fn parses_last_page_from_github_link_header() {
        let link = r#"<https://api.github.com/repositories/123/commits?sha=main&per_page=1&page=2>; rel="next", <https://api.github.com/repositories/123/commits?sha=main&per_page=1&page=21314>; rel="last""#;
        assert_eq!(last_page_from_link(link), Some(21314));
    }

    #[test]
    fn persisted_pages_keep_only_explicit_security_commits() {
        let pages = vec![json!({"commits": [{
            "sha": "abc1234",
            "commit": {"message": "security: fix CVE-2026-1234 buffer overflow", "author": {"date": "2026-01-01T00:00:00Z"}}
        }, {
            "sha": "def5678",
            "commit": {"message": "fix flaky security test"}
        }]})];
        let fixes = classify_persisted_commit_pages("owner", "repo", &pages);
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].sha, "abc1234");
        assert_eq!(
            fixes[0].file_evidence_status.as_deref(),
            Some("skipped_explicit_message_evidence")
        );
    }

    #[test]
    fn persisted_candidate_uses_commit_detail_file_evidence() {
        let pages = vec![json!({"commits": [{
            "sha": "abc1234",
            "commit": {"message": "fix certificate validation bypass", "author": {"date": "2026-01-01T00:00:00Z"}}
        }]})];
        assert_eq!(security_candidate_shas(&pages), vec!["abc1234"]);
        let details = vec![json!({
            "sha": "abc1234",
            "files": [{"filename": "src/tls/verify.c", "status": "modified", "additions": 4, "deletions": 2, "changes": 6}]
        })];
        let fixes = classify_persisted_commit_pages_with_details("owner", "repo", &pages, &details);
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].file_evidence_status.as_deref(), Some("fetched"));
        assert_eq!(fixes[0].component, "src/tls/verify.c");
    }

    #[test]
    fn security_fix_commit_limit_is_unbounded_by_default() {
        assert_eq!(IntelligenceClientConfig::default().max_fix_commits, None);
    }

    #[test]
    fn background_budget_preserves_foreground_reserve() {
        let client = IntelligenceClient::new(None);
        {
            let mut budget = client.github_rate_limit.lock().unwrap();
            *budget = GitHubRateLimitSnapshot {
                limit: 5_000,
                remaining: 500,
                reset_at: unix_now_seconds() + 3600,
                observed_at: unix_now_seconds(),
            };
        }
        assert!(!client.github_background_budget_available(500));
        assert!(client.github_background_budget_available(499));
        {
            let mut budget = client.github_rate_limit.lock().unwrap();
            budget.reset_at = unix_now_seconds().saturating_sub(1);
        }
        assert!(client.github_background_budget_available(500));
    }

    #[test]
    fn background_budget_scales_reserve_for_anonymous_quota() {
        let client = IntelligenceClient::new(None);
        {
            let mut budget = client.github_rate_limit.lock().unwrap();
            *budget = GitHubRateLimitSnapshot {
                limit: 60,
                remaining: 58,
                reset_at: unix_now_seconds() + 3600,
                observed_at: unix_now_seconds(),
            };
        }

        assert!(client.github_background_budget_available(500));
        {
            let mut budget = client.github_rate_limit.lock().unwrap();
            budget.remaining = 6;
        }
        assert!(!client.github_background_budget_available(500));
    }

    #[test]
    fn intelligence_token_selection_prefers_credentials_then_anonymous() {
        let client = IntelligenceClient::new(Some("token-a,token-b".to_string()));

        assert_eq!(client.github_token_for_attempt(0), Some("token-a"));
        assert_eq!(client.github_token_for_attempt(1), Some("token-b"));
        assert_eq!(client.github_token_for_attempt(2), None);
    }

    #[test]
    fn security_fix_commit_limit_can_be_set_explicitly() {
        let config = IntelligenceClientConfig {
            max_fix_commits: Some(750),
            ..Default::default()
        };
        assert_eq!(config.max_fix_commits, Some(750));
    }

    #[tokio::test]
    async fn disabled_llm_tasks_short_circuit_without_credentials() {
        assert!(llm_commit_classification(
            false,
            "abcdef123456",
            "fix auth bypass",
            "2026-01-01T00:00:00Z",
            "https://github.com/example/repo/commit/abcdef123456",
            &json!({"severity": "high"}),
        )
        .await
        .is_none());
        assert!(
            llm_ecosystem_resolution(false, "example", "repo", "npm", "repo")
                .await
                .is_none()
        );
    }

    #[test]
    fn parses_commit_detail_file_evidence() {
        let detail = json!({
            "files": [{
                "filename": "src/ssl.c",
                "status": "modified",
                "additions": 12,
                "deletions": 3,
                "changes": 15,
                "patch": "@@ -10,7 +10,8 @@ int wolfSSL_accept(WOLFSSL* ssl)\n- old\n+ new"
            }]
        });

        let files = commit_file_evidence_from_detail(&detail);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/ssl.c");
        assert_eq!(files[0].changes, 15);
        assert_eq!(files[0].touched_symbols, vec!["wolfSSL_accept"]);
    }

    #[test]
    fn selects_source_security_file_as_primary_component() {
        let files = vec![
            CommitFileEvidence {
                path: "docs/security.md".to_string(),
                changes: 200,
                ..Default::default()
            },
            CommitFileEvidence {
                path: "wolfcrypt/src/asn.c".to_string(),
                changes: 10,
                ..Default::default()
            },
        ];

        assert_eq!(select_primary_component(&files), "wolfcrypt/src/asn.c");
    }

    #[test]
    fn selects_repository_without_file_evidence() {
        assert_eq!(select_primary_component(&[]), "repository");
    }

    #[test]
    fn keeps_explicit_vulnerability_commit_without_file_evidence() {
        assert!(should_keep_security_fix_commit(
            "Fix CVE-2026-12345 buffer overflow in parser",
            &[]
        ));
    }

    #[test]
    fn rejects_weak_security_commit_without_file_evidence() {
        assert!(!should_keep_security_fix_commit(
            "security: harden miscellaneous build settings",
            &[]
        ));
    }

    #[test]
    fn rejects_test_only_weak_security_commits() {
        let files = vec![file("tests/api/test_signature.c")];

        assert!(!should_keep_security_fix_commit(
            "tests: keep OQS_SIG_keypair() out of ExpectIntEQ",
            &files
        ));
    }

    #[test]
    fn rejects_test_only_guard_build_commits_without_vulnerability_evidence() {
        let files = vec![file("tests/api/test_aes.c")];

        assert!(!should_keep_security_fix_commit(
            "tests: guard Gmac/AesGcmSetExtIV tests for the self-test module\n\n\
             The CAVP self-test build failed to compile test_aes.c. \
             wc_AesGcmSetExtIV and wc_Gmac/wc_GmacVerify (test_wc_AesGmacArgMcdc) \
             are declared only under !WC_NO_RNG, so -Werror=implicit-function-declaration \
             aborted the build. FIPS builds are unaffected.",
            &files
        ));
    }

    #[test]
    fn rejects_ci_build_only_weak_security_commits() {
        let files = vec![
            file(".github/workflows/other-products.yml"),
            file(".github/scripts/parallel-make-check.py"),
        ];

        assert!(!should_keep_security_fix_commit(
            "Add workflows to check other wolfSSL products still build",
            &files
        ));
    }

    #[test]
    fn rejects_ci_test_race_conditions_without_product_vulnerability_evidence() {
        let files = vec![file(".github/workflows/hostap-vm.yml")];

        assert!(!should_keep_security_fix_commit(
            "Fix race conditions in hostap CI tests",
            &files
        ));
    }

    #[test]
    fn rejects_macro_registry_only_weak_security_commits() {
        let files = vec![file(".wolfssl_known_macro_extras")];

        assert!(!should_keep_security_fix_commit(
            "build: register HAVE_PQC in known-macro extras",
            &files
        ));
    }

    #[test]
    fn rejects_content_dataset_only_weak_security_commits() {
        let files = vec![file("prompts.csv"), file("content/prompts.jsonl")];

        assert!(!should_keep_security_fix_commit(
            "fix: correct security specialist prompt metadata",
            &files
        ));
        assert!(should_keep_security_fix_commit(
            "fix CVE-2026-1234 advisory metadata",
            &files
        ));
        assert!(!is_auxiliary_security_fix_path("src/data/validator.py"));
    }

    #[test]
    fn keeps_explicit_vulnerability_evidence_on_build_config_paths() {
        let files = vec![file("configure.ac")];

        assert!(should_keep_security_fix_commit(
            "Prevent command injection in includedir/libdir in configure.ac.",
            &files
        ));
    }

    #[test]
    fn keeps_actual_advisory_tokens_on_auxiliary_paths() {
        let files = vec![file(".github/workflows/security.yml")];

        assert!(should_keep_security_fix_commit(
            "ci: add regression check for CVE-2024-1234",
            &files
        ));
    }

    #[test]
    fn keeps_mixed_source_and_test_commits() {
        let files = vec![file("tests/api/test_tls.c"), file("src/tls.c")];

        assert!(should_keep_security_fix_commit(
            "fix: avoid certificate validation failure",
            &files
        ));
    }

    #[test]
    fn severity_low_requires_word_boundary() {
        assert_eq!(
            classify_severity("fix overflow in low-level parser"),
            "medium"
        );
        assert_eq!(classify_severity("low severity bounds hardening"), "low");
    }

    #[test]
    fn severity_uses_high_impact_class_and_file_evidence() {
        let tls_files = vec![file_with_symbols(
            "src/tls.c",
            &["TlsMessageProcess", "DoTls13HandShakeMsg"],
        )];
        assert_eq!(
            classify_severity_with_evidence(
                "fix RCE in TLS record parser",
                "Remote Code Execution",
                &tls_files
            ),
            "high"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "critical severity RCE in TLS record parser",
                "Remote Code Execution",
                &tls_files
            ),
            "critical"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "fix critical section handling in TLS state",
                "Security Fix",
                &tls_files
            ),
            "medium"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "fix buffer overflow while copying TLS record",
                "Buffer Overflow",
                &tls_files
            ),
            "high"
        );

        let crl_files = vec![file_with_symbols(
            "src/crl.c",
            &["test_wolfSSL_X509_CRL_reason_critical_boolean"],
        )];
        assert_eq!(
            classify_severity_with_evidence(
                "fixes from regression testing",
                "Improper Certificate Validation",
                &crl_files
            ),
            "high"
        );

        let session_files = vec![file_with_symbols(
            "src/internal.c",
            &["FreeSession", "wolfSSL_SESSION_free"],
        )];
        assert_eq!(
            classify_severity_with_evidence(
                "fix use-after-free in session cleanup",
                "Use After Free",
                &session_files
            ),
            "high"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "fix double free during certificate teardown",
                "Double Free",
                &session_files
            ),
            "high"
        );

        let auth_files = vec![file_with_symbols("src/ssl.c", &["CheckAuthFinished"])];
        assert_eq!(
            classify_severity_with_evidence(
                "fix authentication bypass in handshake",
                "Auth Bypass",
                &auth_files
            ),
            "high"
        );

        let cert_files = vec![file_with_symbols(
            "wolfcrypt/src/asn.c",
            &["wolfSSL_X509_verify_cert"],
        )];
        assert_eq!(
            classify_severity_with_evidence(
                "fix certificate validation for alternate chains",
                "Improper Certificate Validation",
                &cert_files
            ),
            "high"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "fix signature verification bypass in certificate parser",
                "Signature Verification Bypass",
                &cert_files
            ),
            "high"
        );

        let integer_files = vec![file_with_symbols("wolfcrypt/src/integer.c", &["mp_add"])];
        assert_eq!(
            classify_severity_with_evidence(
                "fix integer overflow in size calculation",
                "Integer Overflow",
                &integer_files
            ),
            "high"
        );
    }

    #[test]
    fn classifies_buffer_and_integer_overflow() {
        let buffer_files = vec![file_with_symbols("src/internal.c", &["GrowOutputBuffer"])];
        assert_eq!(
            classify_vuln_class_with_evidence(
                "fix overflow while copying TLS record",
                &buffer_files
            ),
            "Buffer Overflow"
        );

        let integer_files = vec![file_with_symbols("wolfcrypt/src/integer.c", &["mp_add"])];
        assert_eq!(
            classify_vuln_class_with_evidence("fix overflow in length calculation", &integer_files),
            "Integer Overflow"
        );
    }

    #[test]
    fn classifies_use_after_free_and_double_free() {
        assert_eq!(
            classify_vuln_class("fix use-after-free in session cleanup"),
            "Use After Free"
        );
        assert_eq!(
            classify_vuln_class("fix double free during certificate teardown"),
            "Double Free"
        );
    }

    #[test]
    fn vulnerability_classes_reject_generic_substrings_and_feature_terms() {
        assert_eq!(
            classify_vuln_class("Add Unified Research and Source Analysis Prompt"),
            "Security Fix"
        );
        assert_eq!(
            classify_vuln_class("fix authentication settings"),
            "Security Fix"
        );
        assert_eq!(
            classify_vuln_class("refactor dependency injection container"),
            "Security Fix"
        );
        assert_eq!(
            classify_vuln_class("fix memory leak in image cache"),
            "Security Fix"
        );
        assert_eq!(
            classify_vuln_class("fix RCE in archive parser"),
            "Remote Code Execution"
        );
        assert_eq!(
            classify_vuln_class("fix authentication bypass in login"),
            "Auth Bypass"
        );
    }

    #[test]
    fn classifies_certificate_validation_and_signature_verification() {
        let cert_files = vec![file_with_symbols(
            "wolfcrypt/src/asn.c",
            &["wolfSSL_X509_verify_cert"],
        )];
        assert_eq!(
            classify_vuln_class_with_evidence(
                "fix certificate validation for alternate chains",
                &cert_files
            ),
            "Improper Certificate Validation"
        );

        let signature_files = vec![file_with_symbols(
            "wolfcrypt/src/signature.c",
            &["CheckCertSignature"],
        )];
        assert_eq!(
            classify_vuln_class_with_evidence(
                "fix signature verification bypass in certificate parser",
                &signature_files
            ),
            "Signature Verification Bypass"
        );
        assert_eq!(
            classify_cwe("fix signature verification bypass"),
            vec!["CWE-347"]
        );
    }

    #[test]
    fn aggregate_and_scanner_commits_are_not_vulnerability_classes() {
        let ci_files = vec![CommitFileEvidence {
            path: ".github/workflows/image-scan.yml".into(),
            status: "added".into(),
            additions: 65,
            deletions: 0,
            changes: 65,
            touched_symbols: vec![],
        }];
        assert_eq!(
            classify_vuln_class_with_evidence(
                "ci(image-scan): add Grype image scan for OS + library CVEs",
                &ci_files
            ),
            "Security Control Improvement"
        );
        assert_eq!(
            classify_severity_with_evidence(
                "ci(image-scan): add Grype image scan for OS + library CVEs",
                "Security Control Improvement",
                &ci_files
            ),
            "medium"
        );

        let openssl_files = vec![CommitFileEvidence {
            path: "ext/openssl/openssl.c".into(),
            status: "modified".into(),
            additions: 2,
            deletions: 2,
            changes: 4,
            touched_symbols: vec![],
        }];
        assert_eq!(
            classify_vuln_class_with_evidence(
                "Merge branch 'PHP-8.5'\n\nFixing memory leak in openssl",
                &openssl_files
            ),
            "Security Fix"
        );
        assert_eq!(
            classify_vuln_class_with_evidence(
                "chore: litellm oss staging160626\n\nfix signature verification bypass",
                &openssl_files
            ),
            "Security Fix"
        );
    }

    #[test]
    fn classifies_out_of_bounds_from_bounds_patch_evidence() {
        let files = vec![file("src/tls.c")];

        assert_eq!(
            classify_vuln_class_with_evidence("fix bounds check in TLS parser", &files),
            "Out-of-Bounds Access"
        );
    }

    #[test]
    fn classifies_side_channel_and_timing() {
        assert_eq!(
            classify_vuln_class("harden constant-time comparison to prevent timing leak"),
            "Timing/Side-Channel"
        );
    }

    #[test]
    fn new_fix_commit_fields_default_for_old_reports() {
        let commit: FixCommit = serde_json::from_value(json!({
            "sha": "abc",
            "subject": "security fix",
            "component": "repository",
            "vuln_class": "Security Fix",
            "cwe": [],
            "severity": "medium",
            "date": "2026-01-01T00:00:00Z",
            "html_url": "https://github.com/example/repo/commit/abc"
        }))
        .expect("old FixCommit JSON should deserialize");

        assert!(commit.changed_files.is_empty());
        assert!(commit.file_evidence_source.is_none());
        assert!(commit.file_evidence_status.is_none());
        assert_eq!(commit.decision_source, "rule_based");
    }

    #[test]
    fn github_reset_wait_uses_full_reset_window() {
        assert_eq!(
            github_reset_wait_seconds(1_700_003_600, 1_700_000_000),
            3600
        );
        assert_eq!(github_reset_wait_seconds(1_700_000_000, 1_700_003_600), 0);
    }

    fn file(path: &str) -> CommitFileEvidence {
        CommitFileEvidence {
            path: path.to_string(),
            changes: 1,
            ..Default::default()
        }
    }

    fn file_with_symbols(path: &str, symbols: &[&str]) -> CommitFileEvidence {
        CommitFileEvidence {
            path: path.to_string(),
            changes: 1,
            touched_symbols: symbols.iter().map(|symbol| symbol.to_string()).collect(),
            ..Default::default()
        }
    }
}
