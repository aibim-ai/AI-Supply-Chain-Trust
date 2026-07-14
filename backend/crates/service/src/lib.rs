//! Service orchestration layer — matches `service.py`.
//! Coordinates evaluator, intelligence, security_context, and storage.

use ai_supply_chain_trust_evaluator::{evaluate_repository, EvidenceSources};
use ai_supply_chain_trust_intelligence::{IntelligenceClient, IntelligenceClientConfig};
use ai_supply_chain_trust_models::scanner::ScannerStatus;
use ai_supply_chain_trust_models::{EvaluationResult, ScannerRun};
use ai_supply_chain_trust_scoring::pillar_weight;
use ai_supply_chain_trust_security_context::{
    envelope_from_report, regression_contracts_from_report,
};
use ai_supply_chain_trust_storage::Database;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct Service {
    pub db: Arc<Database>,
    pub intel: IntelligenceClient,
    pub github: ai_supply_chain_trust_github_metadata::GitHubClient,
    pub github_token: Option<String>,
    owner_cache: RwLock<HashMap<String, (Instant, Value)>>,
    config: ServiceConfig,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub github_rate_limit_backoff_seconds: i64,
    pub github_foreground_reserve: i64,
    pub progressive_commit_detail_limit: usize,
    pub foreground_timeout_seconds: u64,
    pub nvd_task_timeout_seconds: u64,
    pub progressive_history_max_pages: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            github_rate_limit_backoff_seconds: 300,
            github_foreground_reserve: 500,
            progressive_commit_detail_limit: 25,
            foreground_timeout_seconds: 5,
            nvd_task_timeout_seconds: 90,
            progressive_history_max_pages: 10,
        }
    }
}

impl Service {
    pub fn new(db: Arc<Database>, github_token: Option<String>) -> Self {
        Self::with_config(
            db,
            github_token,
            IntelligenceClientConfig::default(),
            ServiceConfig::default(),
        )
    }

    pub fn with_intelligence_config(
        db: Arc<Database>,
        github_token: Option<String>,
        intelligence_config: IntelligenceClientConfig,
    ) -> Self {
        Self::with_config(
            db,
            github_token,
            intelligence_config,
            ServiceConfig::default(),
        )
    }

    pub fn with_config(
        db: Arc<Database>,
        github_token: Option<String>,
        intelligence_config: IntelligenceClientConfig,
        config: ServiceConfig,
    ) -> Self {
        let intel = IntelligenceClient::with_config(github_token.clone(), intelligence_config);
        let github = ai_supply_chain_trust_github_metadata::GitHubClient::with_client(
            intel.http_client(),
            github_token.clone(),
        );
        let primary_github_token = primary_github_token(github_token.as_deref());
        Self {
            db,
            intel,
            github,
            github_token: primary_github_token,
            owner_cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    // -----------------------------------------------------------------------
    // Run a trust scan
    // -----------------------------------------------------------------------
    pub async fn run_scan(&self, repo: &str) -> Result<Value, String> {
        self.run_scan_mode(repo, false)
            .await
            .map(|(report, _)| report)
    }

    pub async fn run_fast_scan(&self, repo: &str) -> Result<Value, String> {
        self.run_scan_mode(repo, true)
            .await
            .map(|(report, _)| report)
    }

    async fn run_fast_scan_with_id(&self, repo: &str) -> Result<(Value, i64), String> {
        self.run_scan_mode(repo, true).await
    }

    async fn run_scan_mode(&self, repo: &str, progressive: bool) -> Result<(Value, i64), String> {
        let scan_started = Instant::now();
        let (owner, name) = repo.split_once('/').unwrap_or((repo, ""));
        let today = Utc::now().date_naive();

        // 1. Fetch GitHub metadata
        let metadata_started = Instant::now();
        let metadata = self.fetch_repo_for_scan(owner, name, progressive).await?;
        tracing::info!(
            repo,
            stage = "github_repo_metadata",
            elapsed_ms = metadata_started.elapsed().as_millis() as u64,
            "Scan stage completed"
        );
        // Owner metadata and intelligence are independent after canonical repo
        // metadata is available, so overlap them without increasing per-source
        // fan-out beyond two requests.
        let enrichment_started = Instant::now();
        let (owner_result, intel_result) = if progressive {
            (
                Ok(json!({})),
                self.intel
                    .collect_fast_intel_with_repo_metadata(owner, name, &metadata)
                    .await,
            )
        } else {
            let owner_future = self.fetch_owner_cached(owner);
            let intel_future = self
                .intel
                .collect_intel_with_repo_metadata(owner, name, &metadata);
            tokio::join!(owner_future, intel_future)
        };
        tracing::info!(
            repo,
            stage = "owner_and_security_intelligence",
            elapsed_ms = enrichment_started.elapsed().as_millis() as u64,
            "Scan stage completed"
        );
        let owner_data = owner_result.unwrap_or(json!({}));

        let mut enriched = metadata.clone();
        if let Some(obj) = enriched.as_object_mut() {
            obj.insert("owner_details".into(), owner_data.clone());
            if let Some(owner_obj) = obj.get_mut("owner").and_then(Value::as_object_mut) {
                for key in ["created_at", "followers", "public_repos", "html_url"] {
                    if let Some(value) = owner_data.get(key) {
                        owner_obj.insert(key.to_string(), value.clone());
                    }
                }
            }
        }

        // 2. Collect security intelligence
        let intel_json = match &intel_result {
            Ok(r) => serde_json::to_value(r).unwrap_or(json!({})),
            Err(e) => {
                tracing::warn!(repo, error = %e, "Security intelligence fetch failed");
                return Err(format!("security intelligence fetch failed: {}", e.code()));
            }
        };
        if !progressive {
            if let Ok(intel) = &intel_result {
                if has_critical_security_intel_errors(&intel.errors) {
                    return Err(format!(
                        "critical security intelligence fetch failed: {}",
                        intel.errors.join("; ")
                    ));
                }
            }
        } else if let Ok(intel) = &intel_result {
            if has_critical_security_intel_errors(&intel.errors) {
                tracing::warn!(
                    repo,
                    errors = ?intel.errors,
                    "Progressive scan continuing with partial security intelligence"
                );
            }
        }
        let intel_ok = intel_result
            .as_ref()
            .map(|intel| intel.errors.is_empty())
            .unwrap_or(false);
        let intel_head_sha = intel_result.as_ref().ok().and_then(|r| r.head_sha.clone());

        // 3. Build evidence sources — enrich with external scanners
        let scanner_results: Option<Vec<ai_supply_chain_trust_scanner_runner::ScannerResult>> =
            None;

        let scanner_runs: Vec<ScannerRun> = scanner_results
            .as_ref()
            .map(|results| {
                results
                    .iter()
                    .map(|r| ScannerRun {
                        tool: r.tool.clone(),
                        status: match r.status.as_str() {
                            "ok" => ScannerStatus::Ok,
                            "skipped" => ScannerStatus::Skipped,
                            "failed" => ScannerStatus::Failed,
                            _ => ScannerStatus::Unavailable,
                        },
                        detail: r.detail.clone(),
                        impact: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let tool_outputs: std::collections::HashMap<String, Value> = scanner_results
            .as_ref()
            .map(|results| {
                results
                    .iter()
                    .filter_map(|r| r.output.clone().map(|o| (r.tool.clone(), o)))
                    .collect()
            })
            .unwrap_or_default();

        let evidence_sources = EvidenceSources {
            github_metadata: enriched.clone(),
            scorecard: tool_outputs.get("scorecard").cloned(),
            gitleaks: tool_outputs.get("gitleaks").cloned(),
            pip_audit: tool_outputs.get("pip-audit").cloned(),
            npm_audit: tool_outputs.get("npm-audit").cloned(),
            semgrep: tool_outputs.get("semgrep").cloned(),
            bandit: tool_outputs.get("bandit").cloned(),
            trivy: tool_outputs.get("trivy").cloned(),
            hf_metadata: None,
            artifact_root: None,
            tool_outputs,
            data_sources: vec!["github".into(), "github_advisories".into(), "osv".into()],
            scanner_runs,
        };

        // 4. Evaluate
        let evaluation_started = Instant::now();
        let mut result = evaluate_repository(repo, None, today, evidence_sources);
        apply_evidence_aware_decision(&mut result);

        // 5. Enrich with intel
        if let Some(metrics) = result.observed_metrics.as_object_mut() {
            let mut metadata_for_metrics = enriched.clone();
            if let Some(sha) = intel_head_sha.clone() {
                if let Some(obj) = metadata_for_metrics.as_object_mut() {
                    obj.insert("head_sha".into(), json!(sha));
                }
            }
            metrics.insert("metadata".into(), metadata_for_metrics);
            metrics.insert("repo_metadata".into(), metadata.clone());
            metrics.insert("owner_metadata".into(), owner_data);
            metrics.insert("security_intel".into(), intel_json);
            metrics.insert(
                "security_context_version".into(),
                json!(ai_repo_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION),
            );
            metrics.insert(
                "verification_status".into(),
                if progressive {
                    json!("enriching")
                } else if intel_ok {
                    json!("ok")
                } else {
                    json!("partial")
                },
            );
            metrics.insert(
                "scan_state".into(),
                if progressive {
                    json!("fast_ready")
                } else {
                    json!("complete")
                },
            );
            if let Some(sha) = intel_head_sha {
                metrics.insert("head_sha".into(), json!(sha));
            }
        }
        tracing::info!(
            repo,
            stage = "evaluation",
            elapsed_ms = evaluation_started.elapsed().as_millis() as u64,
            "Scan stage completed"
        );

        // 6. Persist
        let persistence_started = Instant::now();
        let report_json = serde_json::to_value(&result).map_err(|e| e.to_string())?;
        let evaluation_id = self
            .db
            .insert_report_async(&report_json)
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(
            repo,
            stage = "persistence",
            elapsed_ms = persistence_started.elapsed().as_millis() as u64,
            "Scan stage completed"
        );

        // 7. Publish event
        self.db
            .publish_trust_event(
                repo,
                if progressive {
                    "scan_fast_ready"
                } else {
                    "scan_complete"
                },
                &report_json,
            )
            .ok();

        tracing::info!(
            repo,
            elapsed_ms = scan_started.elapsed().as_millis() as u64,
            "Scan completed"
        );

        Ok((report_json, evaluation_id))
    }

    async fn fetch_owner_cached(&self, owner: &str) -> Result<Value, String> {
        const OWNER_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
        if let Some((stored_at, value)) = self.owner_cache.read().await.get(owner) {
            if stored_at.elapsed() < OWNER_CACHE_TTL {
                tracing::debug!(owner, cache = "hit", "GitHub owner metadata cache");
                return Ok(value.clone());
            }
        }

        tracing::debug!(owner, cache = "miss", "GitHub owner metadata cache");
        let value = self.github.fetch_owner(owner).await?;
        self.owner_cache
            .write()
            .await
            .insert(owner.to_string(), (Instant::now(), value.clone()));
        Ok(value)
    }

    async fn fetch_repo_cached(&self, owner: &str, repo: &str) -> Result<Value, String> {
        let cache_key = format!("github_repo:{owner}/{repo}");
        let cached = self
            .db
            .get_source_cache_entry(&cache_key)
            .map_err(|error| error.to_string())?;
        if let Some(entry) = cached.as_ref() {
            if entry["fresh"].as_bool() == Some(true) {
                tracing::info!(owner, repo, cache = "hit", "GitHub repo metadata cache");
                return Ok(entry["payload"].clone());
            }
        }
        let etag = cached.as_ref().and_then(|entry| entry["etag"].as_str());
        let last_modified = cached
            .as_ref()
            .and_then(|entry| entry["last_modified"].as_str());
        match self
            .github
            .fetch_repo_conditional(owner, repo, etag, last_modified)
            .await?
        {
            ai_supply_chain_trust_github_metadata::ConditionalJson::NotModified => {
                let payload = cached
                    .as_ref()
                    .map(|entry| entry["payload"].clone())
                    .ok_or("GitHub returned 304 without a cached payload")?;
                self.db
                    .put_source_cache(
                        &cache_key,
                        "github_repo",
                        &payload,
                        etag,
                        last_modified,
                        Some(300),
                    )
                    .map_err(|error| error.to_string())?;
                tracing::info!(
                    owner,
                    repo,
                    cache = "revalidated",
                    "GitHub repo metadata cache"
                );
                Ok(payload)
            }
            ai_supply_chain_trust_github_metadata::ConditionalJson::Modified {
                value,
                etag,
                last_modified,
            } => {
                self.db
                    .put_source_cache(
                        &cache_key,
                        "github_repo",
                        &value,
                        etag.as_deref(),
                        last_modified.as_deref(),
                        Some(300),
                    )
                    .map_err(|error| error.to_string())?;
                tracing::info!(owner, repo, cache = "miss", "GitHub repo metadata cache");
                Ok(value)
            }
        }
    }

    async fn fetch_repo_for_scan(
        &self,
        owner: &str,
        repo: &str,
        progressive: bool,
    ) -> Result<Value, String> {
        if !progressive {
            return self
                .fetch_repo_cached(owner, repo)
                .await
                .map_err(|error| format!("GitHub error: {error}"));
        }

        let deadline = Duration::from_secs(self.config.foreground_timeout_seconds.max(1));
        let stale = self.stale_repo_metadata(owner, repo);
        bounded_foreground_metadata(self.fetch_repo_cached(owner, repo), deadline, stale).await
    }

    fn stale_repo_metadata(&self, owner: &str, repo: &str) -> Option<Value> {
        let cache_key = format!("github_repo:{owner}/{repo}");
        let mut metadata = self
            .db
            .get_source_cache_entry(&cache_key)
            .ok()
            .flatten()
            .map(|entry| entry["payload"].clone())
            .filter(|payload| payload.is_object());
        if let Some(Value::Object(payload)) = metadata.as_mut() {
            payload.insert(
                "ai_supply_chain_trust_cache_state".to_string(),
                Value::String("stale".to_string()),
            );
        }
        metadata
    }

    // -----------------------------------------------------------------------
    // Get security context
    // -----------------------------------------------------------------------
    pub fn get_security_context(&self, repo: &str, base_url: &str) -> Value {
        let Some(report) = self.db.get_report(repo) else {
            return json!({
                "repo": repo,
                "status": "none",
                "message": "No evaluation exists for this repository. Run a scan first.",
                "summary": {"fixes": 0, "cves": 0, "top_severity": "unknown", "remediation_coverage": 0.0, "head_sha": "unknown", "generated_at": ""},
                "artifacts": {},
                "context": {},
                "leads": {}
            });
        };

        let scan_state = report
            .get("observed_metrics")
            .and_then(|metrics| metrics.get("scan_state"))
            .and_then(Value::as_str);
        if matches!(scan_state, Some("fast_ready") | Some("enriching")) {
            return json!({
                "repo": repo,
                "status": "enriching",
                "message": "Fast evaluation is ready; commit history and vulnerability evidence are still being enriched.",
                "scan_state": scan_state,
                "summary": {"fixes": 0, "cves": 0, "top_severity": "unknown", "remediation_coverage": 0.0,
                    "head_sha": report.get("observed_metrics").and_then(|m| m.get("head_sha")).cloned().unwrap_or(json!("unknown")),
                    "generated_at": report.get("evaluated_at").cloned().unwrap_or(json!(""))},
                "artifacts": {}, "context": {}, "leads": {}
            });
        }

        let envelope = envelope_from_report(&report, repo, base_url);
        let mut value =
            serde_json::to_value(&envelope).unwrap_or(json!({"error": "serialization_failed"}));
        let generated = regression_contracts_from_report(&report, repo);
        if let Some(contracts) = generated.as_array() {
            self.db.upsert_regression_contracts(repo, contracts).ok();
        }
        if let Ok(contracts) = self.db.regression_contracts(repo) {
            value["context"]["watchlist"] = json!(contracts);
        }
        value
    }

    pub fn regression_contracts(&self, repo: &str) -> Result<Value, anyhow::Error> {
        if let Some(report) = self.db.get_report(repo) {
            let generated = regression_contracts_from_report(&report, repo);
            if let Some(contracts) = generated.as_array() {
                self.db.upsert_regression_contracts(repo, contracts)?;
            }
        }
        let contracts = self.db.regression_contracts(repo)?;
        Ok(json!({"repo":repo,"count":contracts.len(),"contracts":contracts}))
    }

    pub fn regression_contract(&self, repo: &str, contract_id: &str) -> Option<Value> {
        self.regression_contracts(repo).ok()?;
        let contract = self.db.regression_contract(repo, contract_id)?;
        let events = self
            .db
            .regression_contract_events(repo, contract_id)
            .unwrap_or_default();
        Some(json!({"contract":contract,"events":events}))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_regression_contract(
        &self,
        repo: &str,
        contract_id: &str,
        expected_version: i64,
        to_state: &str,
        actor: &str,
        reason: &str,
        scope: &str,
        comment: Option<&str>,
        expires_at: Option<&str>,
    ) -> Result<Value, anyhow::Error> {
        const STATES: &[&str] = &[
            "candidate",
            "active",
            "verified",
            "suppressed",
            "retired",
            "invalidated",
        ];
        if !STATES.contains(&to_state) {
            anyhow::bail!("invalid lifecycle state");
        }
        if reason.trim().is_empty() || actor.trim().is_empty() {
            anyhow::bail!("actor and reason are required");
        }
        if to_state == "suppressed" && expires_at.is_none() {
            anyhow::bail!("suppression requires expires_at");
        }
        self.db.transition_regression_contract(
            repo,
            contract_id,
            expected_version,
            to_state,
            actor,
            reason,
            scope,
            comment,
            expires_at,
        )
    }

    pub fn assess_regressions(&self, repo: &str, input: &Value) -> Result<Value, anyhow::Error> {
        let mut report = self
            .db
            .get_report(repo)
            .ok_or_else(|| anyhow::anyhow!("repository report not found"))?;
        report["regression_assessment_input"] = input.clone();
        let contracts = regression_contracts_from_report(&report, repo);
        let rows = contracts.as_array().cloned().unwrap_or_default();
        self.db.upsert_regression_contracts(repo, &rows)?;
        let base_sha = input.get("base_sha").and_then(Value::as_str).unwrap_or("");
        let head_sha = input.get("head_sha").and_then(Value::as_str).unwrap_or("");
        for contract in &rows {
            if let (Some(id), Some(assessment)) = (
                contract.get("id").and_then(Value::as_str),
                contract.get("assessment"),
            ) {
                self.db
                    .insert_regression_assessment(repo, id, base_sha, head_sha, assessment)?;
            }
        }
        let conclusion = rows
            .iter()
            .filter_map(|contract| {
                contract
                    .pointer("/assessment/check_conclusion")
                    .and_then(Value::as_str)
            })
            .max_by_key(|value| match *value {
                "failure" => 4,
                "action_required" => 3,
                "neutral" => 2,
                _ => 1,
            })
            .unwrap_or("success");
        Ok(json!({
            "repo":repo,"base_sha":base_sha,"head_sha":head_sha,
            "check":{"name":"AI Supply Chain Trust Regression Watchlist","conclusion":conclusion,
                "idempotency_key":format!("regression-watchlist:{repo}:{head_sha}")},
            "contracts":rows
        }))
    }

    pub async fn assess_and_publish_regressions(
        &self,
        repo: &str,
        input: &Value,
    ) -> Result<Value, anyhow::Error> {
        let mut result = self.assess_regressions(repo, input)?;
        if input.get("publish_check").and_then(Value::as_bool) != Some(true) {
            return Ok(result);
        }
        let token = self
            .github_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("GitHub token is required to publish a check run"))?;
        let head_sha = input
            .get("head_sha")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("head_sha is required"))?;
        let conclusion = result
            .pointer("/check/conclusion")
            .and_then(Value::as_str)
            .unwrap_or("action_required");
        let contract_count = result
            .get("contracts")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let mut payload = json!({
            "name":"AI Supply Chain Trust Regression Watchlist",
            "head_sha":head_sha,
            "status":"completed",
            "conclusion":conclusion,
            "output":{
                "title":format!("Regression watchlist: {conclusion}"),
                "summary":format!("Evaluated {contract_count} evidence-backed regression contracts. See the AI Supply Chain Trust assessment for reason vectors and missing analysis.")
            }
        });
        let existing = self.db.regression_check_run(repo, head_sha);
        let (method, url) = if let Some(check_run_id) = existing {
            payload
                .as_object_mut()
                .map(|object| object.remove("head_sha"));
            (
                reqwest::Method::PATCH,
                format!("https://api.github.com/repos/{repo}/check-runs/{check_run_id}"),
            )
        } else {
            (
                reqwest::Method::POST,
                format!("https://api.github.com/repos/{repo}/check-runs"),
            )
        };
        let response = reqwest::Client::new()
            .request(method, url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "ai-supply-chain-trust/0.2.0")
            .json(&payload)
            .send()
            .await?;
        let status = response.status();
        let response_body: Value = response.json().await.unwrap_or(json!({}));
        if !status.is_success() {
            anyhow::bail!("GitHub check run publish failed with status {status}");
        }
        let check_run_id = response_body
            .get("id")
            .and_then(Value::as_i64)
            .or(existing)
            .ok_or_else(|| anyhow::anyhow!("GitHub check run response did not include id"))?;
        self.db
            .upsert_regression_check_run(repo, head_sha, check_run_id, conclusion)?;
        result["check"]["published"] = json!(true);
        result["check"]["check_run_id"] = json!(check_run_id);
        result["check"]["html_url"] = response_body
            .get("html_url")
            .cloned()
            .unwrap_or(Value::Null);
        Ok(result)
    }

    pub fn regression_assessments(
        &self,
        repo: &str,
        head_sha: &str,
    ) -> Result<Value, anyhow::Error> {
        let rows = self.db.regression_assessments(repo, head_sha)?;
        Ok(json!({"repo":repo,"head_sha":head_sha,"count":rows.len(),"assessments":rows}))
    }

    // -----------------------------------------------------------------------
    // Leaderboard
    // -----------------------------------------------------------------------
    pub fn leaderboard(&self, query: Option<&str>, limit: i64) -> Value {
        self.db.leaderboard(query, limit)
    }

    // -----------------------------------------------------------------------
    // Recent scans
    // -----------------------------------------------------------------------
    pub fn recent_scans(&self, limit: i64) -> Value {
        let rows = self.db.recent_scans(limit);
        json!({"count": rows.len(), "rows": rows})
    }

    // -----------------------------------------------------------------------
    // Get result
    // -----------------------------------------------------------------------
    pub fn get_result(&self, repo: &str) -> Option<Value> {
        self.db.get_report(repo)
    }

    // -----------------------------------------------------------------------
    // Metrics
    // -----------------------------------------------------------------------
    pub fn metrics(&self) -> Value {
        self.db.metrics()
    }

    // -----------------------------------------------------------------------
    // History
    // -----------------------------------------------------------------------
    pub fn get_history(&self, repo: &str) -> Vec<Value> {
        self.db.report_history(repo)
    }

    // -----------------------------------------------------------------------
    // Intel hits
    // -----------------------------------------------------------------------
    pub fn get_intel_hits(&self, repo: &str) -> Value {
        let report = self.db.get_report(repo);
        let intel = report
            .as_ref()
            .and_then(|r| r.get("observed_metrics"))
            .and_then(|m| m.get("security_intel"))
            .cloned()
            .unwrap_or(json!({}));
        json!({"repo": repo, "hits": intel})
    }

    // -----------------------------------------------------------------------
    // PIG (publisher identity graph) node
    // -----------------------------------------------------------------------
    pub fn get_pig_node(&self, account: &str) -> Value {
        let rows = self.db.recent_scans(1000);
        let owned: Vec<&Value> = rows
            .iter()
            .filter(|r| {
                r.get("repo")
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with(&format!("{account}/")))
                    .unwrap_or(false)
            })
            .collect();
        let score = if !owned.is_empty() {
            owned
                .iter()
                .map(|r| r.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0))
                .sum::<f64>()
                / owned.len() as f64
        } else {
            0.0
        };
        json!({"account": account, "repos_owned": owned.len(), "average_score": (score * 10.0).round() / 10.0, "risk_level": if score >= 70.0 { "low" } else if score >= 50.0 { "medium" } else { "high" }})
    }

    // -----------------------------------------------------------------------
    // Suggestions
    // -----------------------------------------------------------------------
    pub async fn suggest(&self, query: &str) -> Value {
        let query = query.trim();
        let rows = self.db.recent_scans(100);
        let db_matches: Vec<&Value> = rows
            .iter()
            .filter(|r| {
                r.get("repo")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase().contains(&query.to_lowercase()))
                    .unwrap_or(false)
            })
            .take(6)
            .collect();
        let mut candidates: Vec<Value> = db_matches
            .iter()
            .map(|r| {
                json!({
                    "repo": r.get("repo"),
                    "score": r.get("trust_score"),
                    "grade": r.get("grade"),
                    "status": r.get("status"),
                    "summary": r.get("summary"),
                    "source": "scanned"
                })
            })
            .collect();

        if query.len() >= 2 {
            match self.github_repository_search(query).await {
                Ok(remote) => {
                    for candidate in remote {
                        let repo = candidate
                            .get("repo")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_lowercase();
                        if repo.is_empty()
                            || candidates.iter().any(|existing| {
                                existing
                                    .get("repo")
                                    .and_then(Value::as_str)
                                    .map(|value| value.eq_ignore_ascii_case(&repo))
                                    .unwrap_or(false)
                            })
                        {
                            continue;
                        }
                        candidates.push(candidate);
                        if candidates.len() >= 6 {
                            break;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "GitHub repository search failed");
                }
            }
        }

        json!({"candidates": candidates})
    }

    async fn github_repository_search(&self, query: &str) -> Result<Vec<Value>, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()?;
        let mut request = client
            .get("https://api.github.com/search/repositories")
            .header("User-Agent", "ai-supply-chain-trust")
            .header("Accept", "application/vnd.github+json")
            .query(&[
                ("q", format!("{query} in:name,full_name")),
                ("sort", "stars".to_string()),
                ("order", "desc".to_string()),
                ("per_page", "6".to_string()),
            ]);
        if let Some(token) = &self.github_token {
            request = request.bearer_auth(token);
        }
        let payload: Value = request.send().await?.error_for_status()?.json().await?;
        let items = payload
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(items
            .into_iter()
            .filter_map(|item| {
                let repo = item.get("full_name")?.as_str()?.to_string();
                Some(json!({
                    "repo": repo,
                    "score": Value::Null,
                    "stars": item.get("stargazers_count").cloned().unwrap_or(Value::Null),
                    "description": item.get("description").cloned().unwrap_or(Value::Null),
                    "source": "github"
                }))
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // Discrepancy log — shows CVE divergence between pillars and context
    // -----------------------------------------------------------------------
    pub fn discrepancy_log(&self, repo: &str) -> Value {
        let report = self.db.get_report(repo);
        let context_cves = report
            .as_ref()
            .and_then(|r| r.get("observed_metrics"))
            .and_then(|m| m.get("security_intel"))
            .and_then(|s| s.get("cves"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let pillar_cves: Vec<Value> = report
            .as_ref()
            .and_then(|r| r.get("observed_metrics"))
            .and_then(|m| m.get("cve_count"))
            .map(|c| vec![c.clone()])
            .unwrap_or_default();

        let diff: Vec<String> = context_cves
            .iter()
            .filter_map(|c| c.as_str())
            .filter(|cve| !pillar_cves.iter().any(|p| p.as_str() == Some(cve)))
            .map(String::from)
            .collect();

        json!({
            "repo": repo,
            "pillar_cve_list": pillar_cves,
            "context_cve_list": context_cves,
            "cve_diff_count": diff.len(),
            "cve_divergence": diff
        })
    }

    // -----------------------------------------------------------------------
    // Storage consistency check — flags reports where pillar scores exist
    // but the linked context envelope is missing or stale
    // -----------------------------------------------------------------------
    pub fn storage_consistency_check(&self, limit: i64) -> Value {
        let rows = self.db.recent_scans(limit);
        let mut inconsistencies = Vec::new();

        for row in &rows {
            let repo = row.get("repo").and_then(Value::as_str).unwrap_or("");
            let report = self.db.get_report(repo);
            match report {
                Some(ref r) => {
                    let has_pillar_scores = r
                        .get("pillar_scores")
                        .and_then(|v| v.as_object())
                        .map(|o| !o.is_empty())
                        .unwrap_or(false);
                    let has_intel = r
                        .get("observed_metrics")
                        .and_then(|m| m.get("security_intel"))
                        .is_some();
                    if has_pillar_scores && !has_intel {
                        inconsistencies.push(json!({
                            "repo": repo,
                            "issue": "pillar_scores_present_but_context_intel_missing",
                            "evaluated_at": r.get("evaluated_at").cloned().unwrap_or(json!(null))
                        }));
                    }
                }
                None => {
                    inconsistencies.push(json!({
                        "repo": repo,
                        "issue": "scan_row_exists_but_report_not_found",
                    }));
                }
            }
        }

        json!({
            "scanned": rows.len(),
            "inconsistencies": inconsistencies.len(),
            "details": inconsistencies
        })
    }

    // -----------------------------------------------------------------------
    // Scoring versions
    // -----------------------------------------------------------------------
    pub fn get_scoring_versions(&self) -> Value {
        json!({"versions": [{"id": "2026-07-05-scap-8pillar-v1", "default": true}], "default": "2026-07-05-scap-8pillar-v1"})
    }

    // -----------------------------------------------------------------------
    // Queue operations
    // -----------------------------------------------------------------------
    pub fn pause_queue(&self, seconds: i64) -> Result<(), String> {
        self.db.pause_queue(seconds).map_err(|e| e.to_string())
    }
    pub fn resume_queue(&self) -> Result<(), String> {
        self.db.resume_queue().map_err(|e| e.to_string())
    }
    pub fn enqueue_rescan(&self, repo: &str, priority: i64) -> Result<i64, String> {
        self.db
            .enqueue_rescan_with_lane(repo, priority, "foreground")
            .map_err(|e| e.to_string())
    }
    pub fn enqueue_discovery(&self, repo: &str, priority: i64) -> Result<i64, String> {
        self.db
            .enqueue_rescan_with_lane(repo, priority, "background")
            .map_err(|e| e.to_string())
    }

    /// Queue reports produced by an older security-context classifier for a
    /// low-priority background rescan. Pending jobs are deduplicated by the
    /// storage layer, so this is safe to run on every worker restart.
    pub fn enqueue_stale_security_context_rescans(&self, limit: i64) -> Result<Value, String> {
        let rows = self.db.recent_scans(limit.clamp(1, 50_000));
        let mut stale_repos = Vec::new();
        let mut job_ids = Vec::new();

        for repo in rows
            .iter()
            .filter_map(|row| row.get("repo").and_then(Value::as_str))
        {
            let Some(report) = self.db.get_report(repo) else {
                continue;
            };
            let version = report
                .get("observed_metrics")
                .and_then(|metrics| metrics.get("security_context_version"))
                .and_then(Value::as_str);
            if version == Some(ai_repo_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION) {
                continue;
            }

            let job_id = self
                .db
                .enqueue_rescan_with_lane(repo, -100, "background")
                .map_err(|error| error.to_string())?;
            stale_repos.push(repo.to_string());
            job_ids.push(job_id);
        }

        Ok(json!({
            "examined": rows.len(),
            "stale": stale_repos.len(),
            "repos": stale_repos,
            "job_ids": job_ids,
            "target_version": ai_repo_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION
        }))
    }
    pub async fn run_progressive_scan(&self, repo: &str) -> Result<(i64, Value), String> {
        let job_id = self
            .db
            .create_scan_job_with_lane(repo, 100, "foreground")
            .map_err(|e| e.to_string())?;
        let result = self.run_fast_scan_with_id(repo).await;
        let error = result.as_ref().err().map(String::as_str);
        self.db
            .complete_scan_job(job_id, result.is_ok(), error)
            .map_err(|e| e.to_string())?;
        let (report, evaluation_id) = result?;
        self.schedule_progressive_evidence(job_id, evaluation_id)?;
        Ok((job_id, report))
    }

    fn schedule_progressive_evidence(&self, job_id: i64, evaluation_id: i64) -> Result<(), String> {
        self.db
            .enqueue_evidence_task(job_id, "github_history_page", "1", 20)
            .map_err(|e| e.to_string())?;
        self.db
            .enqueue_evidence_task(job_id, "nvd", "project", 10)
            .map_err(|e| e.to_string())?;
        self.db
            .enqueue_evidence_task(job_id, "finalize", &evaluation_id.to_string(), 0)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn run_next_queued_scan(&self) -> Result<bool, String> {
        let claimed = self.db.claim_next_scan_job().map_err(|e| e.to_string())?;
        self.run_claimed_scan(claimed).await
    }

    pub async fn run_next_foreground_scan(&self) -> Result<bool, String> {
        let claimed = self
            .db
            .claim_next_scan_job_for_lane("foreground")
            .map_err(|e| e.to_string())?;
        self.run_claimed_scan(claimed).await
    }

    async fn run_claimed_scan(&self, claimed: Option<(i64, String)>) -> Result<bool, String> {
        let Some((job_id, repo)) = claimed else {
            return Ok(false);
        };
        let result = self.run_fast_scan_with_id(&repo).await;
        if let Err(error) = &result {
            if is_github_rate_limited_error(error) {
                self.db.defer_scan_job(job_id, error).ok();
                return Err(format!("GitHub rate limited; deferred {repo}: {error}"));
            }
        }
        let error = result.as_ref().err().map(String::as_str);
        self.db
            .complete_scan_job(job_id, result.is_ok(), error)
            .ok();
        if let Ok((_, evaluation_id)) = &result {
            self.schedule_progressive_evidence(job_id, *evaluation_id)?;
        }
        result.map(|_| true)
    }

    /// Pull one durable 100-commit history page and chain the next page.
    pub async fn run_next_history_evidence(&self) -> Result<bool, String> {
        if !self
            .intel
            .github_background_budget_available(self.config.github_foreground_reserve)
        {
            tracing::info!(
                reserve = self.config.github_foreground_reserve,
                "GitHub history worker yielded to foreground reserve"
            );
            return Ok(false);
        }
        let Some(task) = self
            .db
            .claim_next_evidence_task("github_history_page", 120)
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let task_id = task["id"].as_i64().ok_or("evidence task missing id")?;
        let generation = task["attempts"]
            .as_i64()
            .ok_or("evidence task missing generation")?;
        let job_id = task["job_id"]
            .as_i64()
            .ok_or("evidence task missing job_id")?;
        let page = task["partition_key"]
            .as_str()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let repo = self
            .db
            .scan_job_repo(job_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan job {job_id} not found"))?;
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| format!("invalid repository {repo}"))?;

        match self
            .intel
            .fetch_commit_history_page_raw(owner, name, page)
            .await
        {
            Ok(commits) => {
                let count = commits.len();
                self.db
                    .complete_evidence_task(
                        task_id,
                        generation,
                        &json!({"repo": repo, "page": page, "count": count, "commits": commits}),
                    )
                    .map_err(|e| e.to_string())?;
                if count == 100 && page < self.config.progressive_history_max_pages {
                    self.db
                        .enqueue_evidence_task(
                            job_id,
                            "github_history_page",
                            &(page + 1).to_string(),
                            20,
                        )
                        .map_err(|e| e.to_string())?;
                } else {
                    self.schedule_commit_detail_evidence(job_id)?;
                }
                self.try_finalize_progressive(job_id).await?;
                Ok(true)
            }
            Err(error) => {
                let message = format!("{error:?}");
                self.db
                    .retry_evidence_task(task_id, generation, &message, 60)
                    .map_err(|e| e.to_string())?;
                Err(message)
            }
        }
    }

    fn schedule_commit_detail_evidence(&self, job_id: i64) -> Result<(), String> {
        let Some(pages) = self
            .db
            .completed_history_pages(job_id, self.config.progressive_history_max_pages)
            .map_err(|e| e.to_string())?
        else {
            return Ok(());
        };
        self.db
            .enqueue_evidence_task(job_id, "commit_detail_manifest", "candidates", 15)
            .map_err(|e| e.to_string())?;
        let mut candidates = ai_supply_chain_trust_intelligence::security_candidate_shas(&pages);
        candidates.truncate(self.config.progressive_commit_detail_limit);
        for sha in &candidates {
            self.db
                .enqueue_evidence_task(job_id, "commit_detail", sha, 15)
                .map_err(|e| e.to_string())?;
        }
        let manifest = self
            .db
            .claim_evidence_task_for_job(job_id, "commit_detail_manifest", 60)
            .map_err(|e| e.to_string())?
            .ok_or("commit detail manifest could not be claimed")?;
        let manifest_id = manifest["id"].as_i64().ok_or("manifest task missing id")?;
        let manifest_generation = manifest["attempts"]
            .as_i64()
            .ok_or("manifest task missing generation")?;
        self.db
            .complete_evidence_task(
                manifest_id,
                manifest_generation,
                &json!({"candidate_count": candidates.len(), "shas": candidates}),
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn run_next_commit_detail_evidence(&self) -> Result<bool, String> {
        if !self
            .intel
            .github_background_budget_available(self.config.github_foreground_reserve)
        {
            tracing::info!(
                reserve = self.config.github_foreground_reserve,
                "GitHub commit-detail worker yielded to foreground reserve"
            );
            return Ok(false);
        }
        let Some(task) = self
            .db
            .claim_next_evidence_task("commit_detail", 120)
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let task_id = task["id"].as_i64().ok_or("evidence task missing id")?;
        let generation = task["attempts"]
            .as_i64()
            .ok_or("evidence task missing generation")?;
        let job_id = task["job_id"]
            .as_i64()
            .ok_or("evidence task missing job_id")?;
        let sha = task["partition_key"]
            .as_str()
            .ok_or("commit detail task missing sha")?;
        let repo = self
            .db
            .scan_job_repo(job_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan job {job_id} not found"))?;
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| format!("invalid repository {repo}"))?;
        let cache_key = format!("github_commit_detail:{owner}/{name}:{sha}");
        if let Some(detail) = self
            .db
            .get_source_cache(&cache_key)
            .map_err(|e| e.to_string())?
        {
            tracing::info!(repo, sha, cache = "hit", "GitHub commit detail cache");
            self.db
                .complete_evidence_task(
                    task_id,
                    generation,
                    &json!({"repo": repo, "sha": sha, "detail": detail, "cache": "hit"}),
                )
                .map_err(|e| e.to_string())?;
            self.try_finalize_progressive(job_id).await?;
            return Ok(true);
        }
        tracing::info!(repo, sha, cache = "miss", "GitHub commit detail cache");
        match self.intel.fetch_commit_detail_raw(owner, name, sha).await {
            Ok(detail) => {
                self.db
                    .put_source_cache(
                        &cache_key,
                        "github_commit_detail",
                        &detail,
                        None,
                        None,
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                self.db
                    .complete_evidence_task(
                        task_id,
                        generation,
                        &json!({"repo": repo, "sha": sha, "detail": detail}),
                    )
                    .map_err(|e| e.to_string())?;
                self.try_finalize_progressive(job_id).await?;
                Ok(true)
            }
            Err(error) => {
                let message = format!("{error:?}");
                self.db
                    .retry_evidence_task(task_id, generation, &message, 60)
                    .map_err(|e| e.to_string())?;
                Err(message)
            }
        }
    }

    pub async fn run_next_nvd_evidence(&self) -> Result<bool, String> {
        let Some(task) = self
            .db
            .claim_next_evidence_task("nvd", 600)
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let task_id = task["id"].as_i64().ok_or("evidence task missing id")?;
        let generation = task["attempts"]
            .as_i64()
            .ok_or("evidence task missing generation")?;
        let job_id = task["job_id"]
            .as_i64()
            .ok_or("evidence task missing job_id")?;
        let repo = self
            .db
            .scan_job_repo(job_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan job {job_id} not found"))?;
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| format!("invalid repository {repo}"))?;

        let lookup = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.nvd_task_timeout_seconds),
            self.intel.fetch_nvd_for_repo(owner, name),
        )
        .await;
        match lookup {
            Err(_) => {
                let message = format!(
                    "NVD lookup exceeded {} seconds",
                    self.config.nvd_task_timeout_seconds
                );
                self.db
                    .retry_evidence_task(task_id, generation, &message, 30)
                    .map_err(|e| e.to_string())?;
                Err(message)
            }
            Ok(Ok(entries)) => {
                self.db
                    .complete_evidence_task(
                        task_id,
                        generation,
                        &json!({"repo": repo, "count": entries.len(), "cves": entries}),
                    )
                    .map_err(|e| e.to_string())?;
                self.try_finalize_progressive(job_id).await?;
                Ok(true)
            }
            Ok(Err(error)) => {
                let message = format!("{error:?}");
                self.db
                    .retry_evidence_task(task_id, generation, &message, 60)
                    .map_err(|e| e.to_string())?;
                Err(message)
            }
        }
    }

    /// Complete NVD work without a remote lookup when production has placed
    /// that source in degraded mode. This keeps progressive reports moving
    /// while preserving an explicit, auditable source status.
    pub async fn skip_next_nvd_evidence(&self, reason: &str) -> Result<bool, String> {
        let Some(task) = self
            .db
            .claim_next_evidence_task("nvd", 60)
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let task_id = task["id"].as_i64().ok_or("evidence task missing id")?;
        let generation = task["attempts"]
            .as_i64()
            .ok_or("evidence task missing generation")?;
        let job_id = task["job_id"]
            .as_i64()
            .ok_or("evidence task missing job_id")?;
        let repo = self
            .db
            .scan_job_repo(job_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan job {job_id} not found"))?;
        self.db
            .complete_evidence_task(
                task_id,
                generation,
                &json!({
                    "repo": repo,
                    "count": 0,
                    "cves": [],
                    "source_status": "disabled_memory_guard",
                    "reason": reason,
                }),
            )
            .map_err(|e| e.to_string())?;
        self.try_finalize_progressive(job_id).await?;
        Ok(true)
    }

    pub async fn run_pending_finalize_evidence(&self) -> Result<bool, String> {
        let job_ids = self
            .db
            .pending_finalize_job_ids(25)
            .map_err(|e| e.to_string())?;
        let mut finalized = false;
        for job_id in job_ids {
            finalized |= self.try_finalize_progressive(job_id).await?;
        }
        Ok(finalized)
    }

    async fn try_finalize_progressive(&self, job_id: i64) -> Result<bool, String> {
        let db = self.db.clone();
        let detail_limit = self.config.progressive_commit_detail_limit;
        let history_page_limit = self.config.progressive_history_max_pages;
        let Some(prepared) = tokio::task::spawn_blocking(move || {
            prepare_progressive_finalize(db, job_id, detail_limit, history_page_limit)
        })
        .await
        .map_err(|error| format!("finalize preparation task failed: {error}"))??
        else {
            return Ok(false);
        };
        let mut report = self
            .db
            .get_report_by_id_async(prepared.evaluation_id)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("bound evaluation {} not found", prepared.evaluation_id))?;
        if report.get("repo").and_then(Value::as_str) != Some(prepared.repo.as_str()) {
            return Err(format!(
                "bound evaluation {} repository mismatch",
                prepared.evaluation_id
            ));
        }
        if let Some(metrics) = report
            .get_mut("observed_metrics")
            .and_then(Value::as_object_mut)
        {
            let (history_head_sha, history_commit_count) =
                history_identity_from_pages(&prepared.history_pages);
            if let Some(intel) = metrics
                .get_mut("security_intel")
                .and_then(Value::as_object_mut)
            {
                intel.insert("fix_commits".into(), json!(prepared.fixes));
                intel.insert("nvd_cves".into(), json!(prepared.nvd_entries));
                intel.insert("commit_count".into(), json!(history_commit_count));
                if let Some(head_sha) = history_head_sha.as_deref() {
                    intel.insert("head_sha".into(), json!(head_sha));
                }
                let mut cves = intel
                    .get("cves")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for id in prepared
                    .nvd_entries
                    .iter()
                    .filter_map(|entry| entry.get("cve_id").and_then(Value::as_str))
                {
                    if !cves.iter().any(|existing| existing.as_str() == Some(id)) {
                        cves.push(json!(id));
                    }
                }
                intel.insert("cves".into(), Value::Array(cves));
            }
            if let Some(head_sha) = history_head_sha.as_deref() {
                metrics.insert("head_sha".into(), json!(head_sha));
                if let Some(metadata) = metrics.get_mut("metadata").and_then(Value::as_object_mut) {
                    metadata.insert("head_sha".into(), json!(head_sha));
                    metadata.insert("commit_count".into(), json!(history_commit_count));
                }
            }
            metrics.insert("verification_status".into(), json!("ok"));
            metrics.insert("scan_state".into(), json!("complete"));
        }
        self.db
            .insert_report_async(&report)
            .await
            .map_err(|e| e.to_string())?;
        self.db
            .publish_trust_event(&prepared.repo, "scan_complete", &report)
            .map_err(|e| e.to_string())?;
        self.db
            .complete_evidence_task(
                prepared.finalize_task_id,
                prepared.finalize_generation,
                &json!({"repo": prepared.repo, "status": "complete"}),
            )
            .map_err(|e| e.to_string())?;
        self.db
            .resolve_evidence_failure_alerts_for_repo(&prepared.repo)
            .map_err(|e| e.to_string())?;
        self.db
            .discard_unfinished_commit_detail_tasks(job_id)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
    pub fn queue_stats(&self) -> Value {
        let mut stats = self.db.queue_stats();
        if let Some(object) = stats.as_object_mut() {
            object.insert(
                "github_rate_limit".into(),
                serde_json::to_value(self.intel.github_rate_limit_snapshot())
                    .unwrap_or_else(|_| json!({})),
            );
            object.insert(
                "github_foreground_reserve".into(),
                json!(self.config.github_foreground_reserve),
            );
            object.insert(
                "progressive_commit_detail_limit".into(),
                json!(self.config.progressive_commit_detail_limit),
            );
        }
        stats
    }
    pub fn scan_jobs_recent(&self, limit: i64) -> Value {
        let jobs = self
            .db
            .scan_jobs_recent(limit)
            .into_iter()
            .map(sanitize_public_job)
            .collect::<Vec<_>>();
        json!({"count": jobs.len(), "jobs": jobs})
    }
    pub fn failure_alerts(&self, status: Option<&str>, limit: i64) -> Value {
        let alerts = self
            .db
            .failure_alerts(status, limit)
            .into_iter()
            .map(sanitize_public_failure_alert)
            .collect::<Vec<_>>();
        json!({
            "count": alerts.len(),
            "status": status.unwrap_or("open"),
            "counts": self.db.failure_alert_counts(),
            "alerts": alerts
        })
    }
    pub fn recover_transient_failures(&self, limit: i64) -> Result<Value, String> {
        let (scan_jobs, evidence_tasks) = self
            .db
            .recover_transient_failures(limit)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "scan_jobs_requeued": scan_jobs,
            "evidence_tasks_requeued": evidence_tasks
        }))
    }
    pub fn retry_failure_alert(&self, id: i64, priority: i64) -> Result<Option<Value>, String> {
        self.db
            .retry_failure_alert(id, priority)
            .map_err(|error| error.to_string())
    }
    pub fn acknowledge_failure_alert(&self, id: i64) -> Result<bool, String> {
        self.db
            .acknowledge_failure_alert(id)
            .map_err(|error| error.to_string())
    }
    pub async fn send_pending_failure_notifications(
        &self,
        webhook_url: &str,
        limit: i64,
    ) -> Result<usize, String> {
        self.db
            .backfill_failed_scan_job_alerts()
            .map_err(|error| error.to_string())?;
        let alerts = self.db.pending_failure_notifications(limit);
        if alerts.is_empty() {
            return Ok(0);
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .map_err(|error| error.to_string())?;
        let payload = failure_alert_digest_payload(&alerts);
        let result = client.post(webhook_url).json(&payload).send().await;
        match result {
            Ok(response) if response.status().is_success() => {
                for id in alerts.iter().filter_map(alert_id) {
                    self.db
                        .mark_failure_notification(id, "sent", None)
                        .map_err(|error| error.to_string())?;
                }
                Ok(alerts.len())
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let error = format!(
                    "webhook status {status}: {}",
                    truncate_slack_text(&body, 300)
                );
                for id in alerts.iter().filter_map(alert_id) {
                    self.db
                        .mark_failure_notification(id, "failed", Some(&error))
                        .map_err(|error| error.to_string())?;
                }
                Ok(0)
            }
            Err(error) => {
                let error = error.to_string();
                for id in alerts.iter().filter_map(alert_id) {
                    self.db
                        .mark_failure_notification(id, "failed", Some(&error))
                        .map_err(|error| error.to_string())?;
                }
                Ok(0)
            }
        }
    }
    pub fn record_audit(&self, event: &str, repo: Option<&str>, detail: &Value, ip: Option<&str>) {
        self.db.record_audit_event(event, repo, detail, ip).ok();
    }
}

struct PreparedProgressiveFinalize {
    finalize_task_id: i64,
    finalize_generation: i64,
    repo: String,
    evaluation_id: i64,
    fixes: Vec<ai_supply_chain_trust_intelligence::FixCommit>,
    nvd_entries: Vec<Value>,
    history_pages: Vec<Value>,
}

fn history_identity_from_pages(pages: &[Value]) -> (Option<String>, usize) {
    let head_sha = pages
        .iter()
        .find(|page| page.get("page").and_then(Value::as_u64) == Some(1))
        .and_then(|page| page.get("commits").and_then(Value::as_array))
        .and_then(|commits| commits.first())
        .and_then(|commit| commit.get("sha").and_then(Value::as_str))
        .filter(|sha| !sha.is_empty())
        .map(String::from);
    let commit_count = pages
        .iter()
        .filter_map(|page| page.get("count").and_then(Value::as_u64))
        .sum::<u64>() as usize;
    (head_sha, commit_count)
}

fn prepare_progressive_finalize(
    db: Arc<Database>,
    job_id: i64,
    detail_limit: usize,
    history_page_limit: usize,
) -> Result<Option<PreparedProgressiveFinalize>, String> {
    let Some(bundle) = db
        .completed_progressive_evidence(job_id, detail_limit, history_page_limit)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let Some(finalize_task) = db
        .claim_evidence_task_for_job(job_id, "finalize", 120)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let finalize_task_id = finalize_task["id"]
        .as_i64()
        .ok_or("finalize task missing id")?;
    let finalize_generation = finalize_task["attempts"]
        .as_i64()
        .ok_or("finalize task missing generation")?;
    let repo = db
        .scan_job_repo(job_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("scan job {job_id} not found"))?;
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| format!("invalid repository {repo}"))?;
    let evaluation_id = finalize_task["partition_key"]
        .as_str()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or("finalize task missing bound evaluation id")?;
    let pages = bundle["history_pages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let details = bundle["commit_details"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let fixes = ai_supply_chain_trust_intelligence::classify_persisted_commit_pages_with_details(
        owner, name, &pages, &details,
    );
    let nvd_entries = bundle["nvd"]["cves"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(Some(PreparedProgressiveFinalize {
        finalize_task_id,
        finalize_generation,
        repo,
        evaluation_id,
        fixes,
        nvd_entries,
        history_pages: pages,
    }))
}

fn alert_id(alert: &Value) -> Option<i64> {
    alert.get("id").and_then(Value::as_i64)
}

fn failure_alert_digest_payload(alerts: &[Value]) -> Value {
    let mut lines = vec![format!(
        "AI Supply Chain Trust failures: {} scan job alert(s)",
        alerts.len()
    )];
    lines.extend(
        alerts
            .iter()
            .enumerate()
            .map(|(index, alert)| failure_alert_digest_line(index + 1, alert)),
    );
    json!({ "text": lines.join("\n\n") })
}

fn failure_alert_digest_line(index: usize, alert: &Value) -> String {
    let repo = alert
        .get("repo")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let title = alert
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Failure alert");
    let error = truncate_slack_text(
        alert.get("error").and_then(Value::as_str).unwrap_or(""),
        1800,
    );
    let source_kind = alert
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let source_id = alert.get("source_id").and_then(Value::as_i64).unwrap_or(0);
    let attempts = alert.get("attempts").and_then(Value::as_i64).unwrap_or(0);
    let max_attempts = alert
        .get("max_attempts")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let first_seen_at = alert
        .get("first_seen_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let last_seen_at = alert
        .get("last_seen_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!(
        "{index}. {repo} - {title}\nSource: {source_kind} #{source_id}; attempts: {attempts}/{max_attempts}; first: {first_seen_at}; last: {last_seen_at}\nError: {error}"
    )
}

fn truncate_slack_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn primary_github_token(tokens: Option<&str>) -> Option<String> {
    tokens.and_then(|value| {
        value
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(str::trim)
            .find(|token| !token.is_empty())
            .map(str::to_string)
    })
}

fn sanitize_public_job(mut job: Value) -> Value {
    if let Some(object) = job.as_object_mut() {
        object.remove("last_error");
    }
    job
}

fn sanitize_public_failure_alert(mut alert: Value) -> Value {
    if let Some(object) = alert.as_object_mut() {
        object.remove("error");
        object.remove("notification_error");
    }
    alert
}

fn has_critical_security_intel_errors(errors: &[String]) -> bool {
    errors.iter().any(|error| {
        error.starts_with("advisories:")
            || error.starts_with("commits:")
            || error.starts_with("repo_meta:")
    })
}

fn is_github_rate_limited_error(error: &str) -> bool {
    error.contains("GitHubRateLimited") || error.contains("github_rate_limited")
}

async fn bounded_foreground_metadata<F>(
    fetch: F,
    deadline: Duration,
    stale: Option<Value>,
) -> Result<Value, String>
where
    F: Future<Output = Result<Value, String>>,
{
    match tokio::time::timeout(deadline, fetch).await {
        Ok(Ok(metadata)) => Ok(metadata),
        Ok(Err(error)) => {
            stale.ok_or_else(|| format!("GitHub foreground metadata failed: {error}"))
        }
        Err(_) => stale.ok_or_else(|| {
            format!(
                "GitHub foreground metadata timed out after {}ms",
                deadline.as_millis()
            )
        }),
    }
}

fn apply_evidence_aware_decision(result: &mut EvaluationResult) {
    let mut total_weight = 0.0;
    let mut covered_weight = 0.0;
    let mut missing = Vec::new();
    let mut reasons = Vec::new();

    for (key, pillar) in &result.pillar_scores {
        let weight = pillar_weight(key);
        if weight <= 0.0 {
            continue;
        }
        total_weight += weight;
        if pillar.applicable && pillar.unavailable.is_empty() {
            covered_weight += weight;
        } else {
            for item in &pillar.unavailable {
                missing.push(format!("{}: {}", pillar.name, item));
            }
            if !pillar.applicable && pillar.unavailable.is_empty() {
                missing.push(format!("{}: evidence unavailable", pillar.name));
            }
        }
        for concern in pillar.concerns.iter().take(2) {
            reasons.push(format!("{}: {}", pillar.name, concern));
        }
    }

    let coverage = if total_weight > 0.0 {
        (covered_weight / total_weight).clamp(0.0, 1.0)
    } else {
        0.0
    };
    missing.sort();
    missing.dedup();
    reasons.sort();
    reasons.dedup();
    reasons.truncate(6);

    let has_policy_block = !result.critical_flags.is_empty();
    if !has_policy_block {
        if coverage < 0.50 {
            result.verdict = "Insufficient evidence for approval".into();
            result.action = "Complete missing evidence before approval".into();
        } else if coverage < 0.75 && matches!(result.grade.to_string().as_str(), "A" | "B") {
            result.verdict = "Review with missing evidence".into();
            result.action = "Complete missing evidence before approval".into();
        }
    }

    let confidence = if has_policy_block {
        "policy_block"
    } else if coverage >= 0.85 {
        "high"
    } else if coverage >= 0.65 {
        "medium"
    } else {
        "low"
    };
    if missing.is_empty() {
        reasons.push("Required evidence sources are available.".into());
    } else {
        reasons.push(format!(
            "{} evidence gap(s) affect confidence.",
            missing.len()
        ));
    }

    result.evidence_coverage = (coverage * 100.0).round() / 100.0;
    result.confidence = confidence.into();
    result.missing_evidence = missing.clone();
    result.decision_reasons = reasons.clone();
    result.trust_decision = json!({
        "score": (result.trust_score * 10.0).round() / 10.0,
        "grade": result.grade.to_string(),
        "label": result.verdict,
        "action": result.action,
        "confidence": confidence,
        "evidence_coverage": result.evidence_coverage,
        "missing_evidence": missing,
        "reasons": reasons,
        "policy_block": has_policy_block
    });

    if let Some(metrics) = result.observed_metrics.as_object_mut() {
        metrics.insert("evidence_coverage".into(), json!(result.evidence_coverage));
        metrics.insert("confidence".into(), json!(confidence));
        metrics.insert("missing_evidence".into(), json!(result.missing_evidence));
        metrics.insert("decision_reasons".into(), json!(result.decision_reasons));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progressive_history_supplies_verified_head_identity() {
        let pages = vec![
            json!({"page": 2, "count": 2, "commits": [{"sha": "later-page"}]}),
            json!({"page": 1, "count": 100, "commits": [{"sha": "abc123"}]}),
        ];

        assert_eq!(
            history_identity_from_pages(&pages),
            (Some("abc123".to_string()), 102)
        );
    }
    use ai_supply_chain_trust_models::{Grade, PillarResult};
    use chrono::NaiveDate;
    use std::collections::HashMap;

    fn make_report(repo: &str) -> Value {
        json!({
            "repo": repo,
            "evaluated_at": "2026-07-09",
            "trust_score": 85.0,
            "grade": "A",
            "verdict": "Safe",
            "action": "Use",
            "next_review_date": "2026-10-07",
            "coverage": "5/7",
            "critical_flags": [],
            "pillar_scores": {"publisher_credibility": {"name":"Publisher","normalized":80.0,"evidence":[],"concerns":[]}},
            "scanner_runs": [{"tool":"github-metadata-rust","status":"ok","detail":"ok"}],
            "observed_metrics": {
                "security_context_version": "2026-07-14-history-precision-v2",
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "metadata": {"default_branch": "main", "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "commit_count": 100}
            },
            "scoring_version": "2026-07-05-scap-8pillar-v1"
        })
    }

    fn cached_metadata(repo: &str) -> Value {
        let (owner, name) = repo.split_once('/').unwrap();
        json!({
            "id": 42,
            "name": name,
            "full_name": repo,
            "default_branch": "main",
            "stargazers_count": 10,
            "forks_count": 2,
            "open_issues_count": 1,
            "watchers_count": 10,
            "archived": false,
            "disabled": false,
            "fork": false,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2026-07-12T00:00:00Z",
            "pushed_at": "2026-07-12T00:00:00Z",
            "license": {"spdx_id": "MIT"},
            "owner": {"login": owner, "type": "Organization"}
        })
    }

    fn seed_metadata_cache(db: &Database, repo: &str) {
        db.put_source_cache(
            &format!("github_repo:{repo}"),
            "github_repo",
            &cached_metadata(repo),
            Some("test-etag"),
            None,
            Some(300),
        )
        .unwrap();
    }

    #[test]
    fn service_leaderboard_works() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db.clone(), None);
        db.insert_report(&make_report("test/repo")).unwrap();
        let lb = svc.leaderboard(None, 10);
        assert_eq!(lb["count"].as_i64().unwrap(), 1);
    }

    #[test]
    fn service_security_context_no_report_returns_none() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db, None);
        let ctx = svc.get_security_context("nonexistent/repo", "https://example.com");
        assert_eq!(ctx["status"], "none");
    }

    #[test]
    fn service_security_context_with_report_returns_ready() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db.clone(), None);
        db.insert_report(&make_report("owner/repo")).unwrap();
        let ctx = svc.get_security_context("owner/repo", "https://example.com");
        let status = ctx["status"].as_str().unwrap();
        assert!(
            status == "ready" || status == "error",
            "Expected ready or error, got {status}"
        );
    }

    #[test]
    fn service_security_context_exposes_progress_until_evidence_complete() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db.clone(), None);
        let mut report = make_report("owner/repo");
        report["observed_metrics"]["scan_state"] = json!("fast_ready");
        report["observed_metrics"]["verification_status"] = json!("enriching");
        db.insert_report(&report).unwrap();

        let context = svc.get_security_context("owner/repo", "https://example.com");
        assert_eq!(context["status"], json!("enriching"));
        assert_eq!(context["scan_state"], json!("fast_ready"));
    }

    #[test]
    fn stale_security_contexts_are_requeued_in_the_background() {
        let db = Arc::new(ai_repo_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db.clone(), None);
        let current = make_report("owner/current");
        let mut stale = make_report("owner/stale");
        stale["observed_metrics"]["security_context_version"] = json!("legacy-v1");
        db.insert_report(&current).unwrap();
        db.insert_report(&stale).unwrap();

        let result = svc.enqueue_stale_security_context_rescans(100).unwrap();

        assert_eq!(result["examined"], json!(2));
        assert_eq!(result["stale"], json!(1));
        assert_eq!(result["repos"], json!(["owner/stale"]));
        let jobs = db.scan_jobs_recent(10);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0]["repo"], json!("owner/stale"));
        assert_eq!(jobs[0]["lane"], json!("background"));
        assert_eq!(jobs[0]["priority"], json!(-100));
    }

    #[test]
    fn public_job_and_failure_responses_hide_error_details() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        let svc = Service::new(db.clone(), None);
        let job_id = db.create_scan_job("owner/repo", 10).unwrap();
        db.complete_scan_job(job_id, false, Some("repo_meta: GitHubTimeout"))
            .unwrap();

        let raw_jobs = db.scan_jobs_recent(1);
        assert_eq!(raw_jobs[0]["last_error"], json!("repo_meta: GitHubTimeout"));
        let public_jobs = svc.scan_jobs_recent(1);
        assert!(public_jobs["jobs"][0].get("last_error").is_none());

        let raw_alerts = db.failure_alerts(Some("open"), 10);
        assert_eq!(raw_alerts[0]["error"], json!("repo_meta: GitHubTimeout"));
        let public_alerts = svc.failure_alerts(Some("open"), 10);
        assert!(public_alerts["alerts"][0].get("error").is_none());
        assert!(public_alerts["alerts"][0]
            .get("notification_error")
            .is_none());
    }

    #[test]
    fn failure_alert_digest_payload_is_slack_compatible_and_detailed() {
        let alert = json!({
            "id": 1,
            "source_kind": "scan_job",
            "source_id": 36,
            "repo": "openclaw/openclaw",
            "title": "Scan job failed",
            "error": "advisories: GitHubTimeout",
            "attempts": 1,
            "max_attempts": 1,
            "first_seen_at": "2026-07-11 14:20:35",
            "last_seen_at": "2026-07-11 14:20:35"
        });

        let payload = failure_alert_digest_payload(&[alert]);
        let text = payload["text"].as_str().unwrap_or("");
        assert!(text.contains("AI Supply Chain Trust failures: 1 scan job alert(s)"));
        assert!(text.contains("1. openclaw/openclaw - Scan job failed"));
        assert!(text.contains("Source: scan_job #36; attempts: 1/1"));
        assert!(text.contains("Error: advisories: GitHubTimeout"));
        assert!(payload.get("blocks").is_none());
        assert!(payload.get("alert").is_none());
    }

    #[test]
    fn critical_security_intel_errors_fail_loudly() {
        assert!(has_critical_security_intel_errors(&[
            "commits: GitHubRateLimited".to_string()
        ]));
        assert!(has_critical_security_intel_errors(&[
            "advisories: GitHubRateLimited".to_string()
        ]));
        assert!(has_critical_security_intel_errors(&[
            "repo_meta: GitHubRateLimited".to_string()
        ]));
        assert!(!has_critical_security_intel_errors(&[
            "nvd: NvdTimeout".to_string(),
            "osv: OsvTimeout".to_string()
        ]));
    }

    #[test]
    fn github_rate_limit_errors_trigger_queue_backoff() {
        assert!(is_github_rate_limited_error(
            "critical security intelligence fetch failed: commits: GitHubRateLimited"
        ));
        assert!(is_github_rate_limited_error("github_rate_limited"));
        assert!(!is_github_rate_limited_error("NvdTimeout"));
    }

    #[tokio::test]
    async fn foreground_metadata_deadline_is_bounded() {
        let started = Instant::now();
        let result = bounded_foreground_metadata(
            std::future::pending::<Result<Value, String>>(),
            Duration::from_millis(20),
            None,
        )
        .await;

        assert!(result.unwrap_err().contains("timed out after 20ms"));
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn foreground_metadata_uses_stale_cache_after_timeout() {
        let stale = cached_metadata("owner/repo");
        let result = bounded_foreground_metadata(
            std::future::pending::<Result<Value, String>>(),
            Duration::from_millis(10),
            Some(stale.clone()),
        )
        .await
        .unwrap();

        assert_eq!(result, stale);
    }

    #[test]
    fn stale_metadata_is_explicitly_marked() {
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
        seed_metadata_cache(&db, "owner/repo");
        let service = Service::new(db, None);

        let metadata = service.stale_repo_metadata("owner", "repo").unwrap();

        assert_eq!(
            metadata["ai_supply_chain_trust_cache_state"],
            json!("stale")
        );
    }

    #[tokio::test]
    async fn fast_scan_from_cache_meets_local_latency_budget() {
        let db = Arc::new(Database::open_memory().unwrap());
        seed_metadata_cache(&db, "owner/repo");
        let service = Service::new(db.clone(), None);
        let started = Instant::now();

        let report = service.run_fast_scan("owner/repo").await.unwrap();

        assert_eq!(report["observed_metrics"]["scan_state"], "fast_ready");
        assert!(db.get_report("owner/repo").is_some());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "cached fast scan took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn foreground_jobs_can_complete_concurrently() {
        let db = Arc::new(Database::open_memory().unwrap());
        for repo in ["owner/one", "owner/two", "owner/three"] {
            seed_metadata_cache(&db, repo);
            db.create_scan_job_with_lane(repo, 100, "foreground")
                .unwrap();
        }
        let service = Arc::new(Service::new(db.clone(), None));

        let (one, two, three) = tokio::join!(
            service.run_next_queued_scan(),
            service.run_next_queued_scan(),
            service.run_next_queued_scan()
        );

        assert_eq!(
            [one, two, three].into_iter().filter_map(Result::ok).count(),
            3
        );
        let jobs = db.scan_jobs_recent(10);
        assert_eq!(
            jobs.iter()
                .filter(|job| job["status"] == json!("completed"))
                .count(),
            3
        );
        assert_eq!(db.queue_stats()["queued"], json!(0));
    }

    #[test]
    fn evidence_aware_decision_downgrades_low_coverage_approval() {
        let mut pillars = HashMap::new();
        pillars.insert(
            "publisher_credibility".to_string(),
            PillarResult::new("publisher_credibility", "Publisher Credibility")
                .with_score(20.0, 20.0),
        );
        pillars.insert(
            "repo_health".to_string(),
            PillarResult::new("repo_health", "Repository Health").with_score(15.0, 15.0),
        );
        pillars.insert(
            "openssf_scorecard".to_string(),
            PillarResult::new("openssf_scorecard", "OpenSSF Scorecard")
                .with_score(0.0, 25.0)
                .with_applicable(false)
                .with_unavailable(vec!["Scorecard data not available.".into()]),
        );
        pillars.insert(
            "code_safety".to_string(),
            PillarResult::new("code_safety", "Code Safety")
                .with_score(0.0, 15.0)
                .with_applicable(false)
                .with_unavailable(vec!["Code safety scanner data not available.".into()]),
        );

        let mut result = EvaluationResult::new(
            "owner/repo",
            NaiveDate::from_ymd_opt(2026, 7, 11).unwrap(),
            72.0,
            Grade::B,
            "Review with known gaps",
            "Review missing evidence and document known gaps",
            NaiveDate::from_ymd_opt(2026, 10, 9).unwrap(),
            pillars,
            vec![],
            vec![],
        );
        apply_evidence_aware_decision(&mut result);

        assert_eq!(result.confidence, "low");
        assert_eq!(result.verdict, "Insufficient evidence for approval");
        assert!(result.evidence_coverage < 0.5);
        assert_eq!(result.missing_evidence.len(), 2);
        assert_eq!(
            result.trust_decision["label"],
            json!("Insufficient evidence for approval")
        );
    }
}
