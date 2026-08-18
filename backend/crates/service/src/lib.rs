//! Service orchestration layer — matches `service.py`.
//! Coordinates evaluator, intelligence, security_context, and storage.

use ai_supply_chain_trust_evaluator::{evaluate_repository, EvidenceSources};
use ai_supply_chain_trust_intelligence::{IntelligenceClient, IntelligenceClientConfig};
use ai_supply_chain_trust_models::scanner::ScannerStatus;
use ai_supply_chain_trust_models::{EvaluationResult, Finding, Grade, ScannerRun, Severity};
use ai_supply_chain_trust_scanner_runner::{
    CheckoutOptions, ScannerResult, ScannerRunner, SourceCheckout,
};
use ai_supply_chain_trust_scoring::{evidence_anchored_score, pillar_weight};
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
    scanner_checkout: ScannerCheckoutConfig,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub github_rate_limit_backoff_seconds: i64,
    pub github_foreground_reserve: i64,
    pub progressive_commit_detail_limit: usize,
    pub foreground_timeout_seconds: u64,
    pub nvd_task_timeout_seconds: u64,
    pub progressive_history_max_pages: usize,
    pub scanner_enabled: bool,
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
            scanner_enabled: true,
        }
    }
}

/// Bounds for the opt-in repository checkout used by scanners that need a
/// working tree (everything except Scorecard, which queries GitHub directly).
///
/// This is a separate config object rather than three more `ServiceConfig`
/// fields so that adding it does not force every `ServiceConfig { .. }` literal
/// in the workspace to change; `Service` reads it from the environment by
/// default, so an operator can enable checkouts without a code change.
#[derive(Debug, Clone)]
pub struct ScannerCheckoutConfig {
    /// **Off by default.** Cloning arbitrary public repositories onto the
    /// production host has real disk and security implications, so enabling it
    /// is an explicit operator decision
    /// (`AI_SUPPLY_CHAIN_TRUST_SCANNER_SOURCE_CHECKOUT=1`), never a side effect
    /// of a scan. While off, source-requiring scanners report `no_source` and
    /// say so plainly instead of implying the repository had nothing to find.
    pub enabled: bool,
    /// Wall-clock limit for a single `git clone --depth 1`.
    pub timeout_seconds: u64,
    /// Hard cap on checkout size; larger clones are deleted, not scanned.
    pub max_bytes: u64,
}

impl Default for ScannerCheckoutConfig {
    fn default() -> Self {
        let bounds = CheckoutOptions::default();
        Self {
            enabled: scanner_source_checkout_from_env(),
            timeout_seconds: checkout_bound_from_env(
                "AI_SUPPLY_CHAIN_TRUST_SCANNER_CHECKOUT_TIMEOUT_SECONDS",
                bounds.timeout_seconds,
            ),
            max_bytes: checkout_bound_from_env(
                "AI_SUPPLY_CHAIN_TRUST_SCANNER_CHECKOUT_MAX_BYTES",
                bounds.max_bytes,
            ),
        }
    }
}

/// Reads a positive checkout bound from the environment, falling back to the
/// compiled default when the variable is unset, unparseable, or zero.
///
/// These are tunable without a rebuild because enabling checkouts makes them
/// operationally relevant: the size cap is enforced *after* `git clone` returns,
/// so it bounds what is retained and handed to a scanner, while the timeout is
/// what actually bounds peak disk usage during the clone.
fn checkout_bound_from_env(name: &str, default: u64) -> u64 {
    parse_checkout_bound(std::env::var(name).ok().as_deref(), default)
}

/// Pure parsing half of [`checkout_bound_from_env`], kept separate so it can be
/// tested without mutating process-global environment state.
fn parse_checkout_bound(raw: Option<&str>, default: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Reads the opt-in source-checkout flag from the environment. The default is
/// `false` whenever the variable is unset or not explicitly truthy.
pub fn scanner_source_checkout_from_env() -> bool {
    std::env::var("AI_SUPPLY_CHAIN_TRUST_SCANNER_SOURCE_CHECKOUT")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on" | "enabled"
            )
        })
        .unwrap_or(false)
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
            scanner_checkout: ScannerCheckoutConfig::default(),
        }
    }

    /// Override the repository-checkout bounds (see [`ScannerCheckoutConfig`]).
    pub fn with_scanner_checkout_config(mut self, checkout: ScannerCheckoutConfig) -> Self {
        self.scanner_checkout = checkout;
        self
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
        merge_owner_into_metadata(&mut enriched, &owner_data);

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
        let scanner_evidence = if progressive {
            ScannerEvidence::default()
        } else {
            self.collect_scanner_evidence(repo).await
        };
        let mut scanner_runs = scanner_evidence.runs;
        let mut tool_outputs = scanner_evidence.outputs;
        let dependency_intelligence = intel_result
            .as_ref()
            .ok()
            .and_then(|intel| intel.dependency_intelligence.clone());
        if let Some(dependency) = dependency_intelligence.as_ref() {
            let status = match dependency.status.as_str() {
                "fetched" if dependency.errors.is_empty() => ScannerStatus::Ok,
                "fetched" => ScannerStatus::Partial,
                "skipped_fast_scan" => ScannerStatus::Skipped,
                _ => ScannerStatus::Unavailable,
            };
            scanner_runs.push(ScannerRun {
                tool: "github-sbom-osv".to_string(),
                status,
                detail: format!(
                    "status={}; packages={}; queried={}; malicious_matches={}; errors={}",
                    dependency.status,
                    dependency.packages_in_sbom,
                    dependency.packages_queried,
                    dependency.malicious_package_matches.len(),
                    dependency.errors.len(),
                ),
                impact: None,
            });
            tool_outputs.insert(
                "github-sbom-osv".to_string(),
                serde_json::to_value(dependency)
                    .unwrap_or_else(|_| json!({"status": "serialization_error"})),
            );
        }

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
            data_sources: vec![
                "github".into(),
                "github_advisories".into(),
                "osv".into(),
                "github_dependency_graph".into(),
            ],
            scanner_runs,
        };

        // 4. Evaluate
        let evaluation_started = Instant::now();
        let mut result = evaluate_repository(repo, None, today, evidence_sources);
        apply_evidence_aware_decision(&mut result);
        apply_dependency_malware_override(&mut result, dependency_intelligence.as_ref());

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
                json!(ai_supply_chain_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION),
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
        let report_json = report_json_from_result(&result)?;
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

    /// Owner metadata for the finalize pass. A failed lookup degrades to `{}`
    /// and is never allowed to fail the finalize: the publisher pillars simply
    /// score the way they did before, and the rest of the enrichment stands.
    async fn fetch_owner_for_finalize(&self, repo: &str) -> Value {
        let owner = repo.split('/').next().unwrap_or_default();
        if owner.is_empty() {
            return json!({});
        }
        match self.fetch_owner_cached(owner).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(repo, error, "Finalize owner metadata fetch failed");
                json!({})
            }
        }
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
        let metadata = if !progressive {
            self.fetch_repo_cached(owner, repo)
                .await
                .map_err(|error| format!("GitHub error: {error}"))?
        } else {
            let deadline = Duration::from_secs(self.config.foreground_timeout_seconds.max(1));
            let stale = self.stale_repo_metadata(owner, repo);
            bounded_foreground_metadata(self.fetch_repo_cached(owner, repo), deadline, stale)
                .await?
        };

        ensure_public_repository(&metadata)?;
        Ok(metadata)
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

    async fn collect_scanner_evidence(&self, repo: &str) -> ScannerEvidence {
        if !self.config.scanner_enabled {
            return ScannerEvidence::default();
        }
        let repo_url = format!("https://github.com/{repo}");
        let mut runner = ScannerRunner::new(&repo_url);
        if let Some(token) = self.github_token.as_deref() {
            runner = runner.with_github_token(token);
        }

        // Opt-in only. `checkout` owns the temporary directory: it is removed
        // when this scope ends, on every path including a scanner panic.
        let checkout = self.checkout_source(&repo_url).await;
        if let Some(checkout) = checkout.as_ref() {
            runner = runner.with_source(checkout.path().to_string_lossy().into_owned());
        }
        let evidence = scanner_evidence_from_results(runner.run_all().await);
        drop(checkout);
        evidence
    }

    /// Shallow-clone the repository when the operator has explicitly enabled
    /// source checkouts. A failed clone is never fatal — the scanners that
    /// needed it report `no_source` and the scan continues.
    async fn checkout_source(&self, repo_url: &str) -> Option<SourceCheckout> {
        if !self.scanner_checkout.enabled {
            return None;
        }
        let options = CheckoutOptions {
            timeout_seconds: self.scanner_checkout.timeout_seconds,
            max_bytes: self.scanner_checkout.max_bytes,
            ..CheckoutOptions::default()
        };
        match SourceCheckout::shallow_clone(repo_url, &options).await {
            Ok(checkout) => Some(checkout),
            Err(error) => {
                tracing::warn!(repo_url, %error, "Scanner source checkout failed");
                None
            }
        }
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

    pub fn enqueue_rescan_with_capacity(
        &self,
        repo: &str,
        priority: i64,
        max_queued: usize,
    ) -> Result<Option<i64>, String> {
        self.db
            .enqueue_rescan_with_capacity(repo, priority, max_queued)
            .map_err(|e| e.to_string())
    }
    pub fn enqueue_discovery(&self, repo: &str, priority: i64) -> Result<i64, String> {
        self.db
            .enqueue_rescan_with_lane(repo, priority, "background")
            .map_err(|e| e.to_string())
    }

    pub fn enqueue_discovery_with_capacity(
        &self,
        repo: &str,
        priority: i64,
        max_queued: usize,
    ) -> Result<Option<i64>, String> {
        self.db
            .enqueue_rescan_with_capacity(repo, priority, max_queued)
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
            if version
                == Some(ai_supply_chain_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION)
            {
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
            "target_version": ai_supply_chain_trust_security_context::LIVE_SECURITY_CONTEXT_VERSION
        }))
    }
    /// Re-queue every repository in the public inventory, regardless of the
    /// security-context version its stored report carries.
    ///
    /// A scoring or pipeline fix does not rewrite stored reports, so correcting
    /// published verdicts requires scanning each repository again. The existing
    /// version-keyed sweep above cannot do that job on its own: bumping
    /// `LIVE_SECURITY_CONTEXT_VERSION` is also rule 2 of the evidence gate, so it
    /// invalidates every stored context at once and each repository page reads as
    /// "evidence missing" until its rescan lands. This enqueues the same work
    /// without invalidating anything, so pages keep serving their current context
    /// and flip to corrected data as their own scan completes.
    ///
    /// Jobs go to the background lane at the lowest priority so a visitor's own
    /// scan is never queued behind this sweep.
    pub fn enqueue_full_inventory_rescan(&self, limit: i64) -> Result<Value, String> {
        let rows = self.db.recent_scans(limit.clamp(1, 50_000));
        let mut queued = Vec::new();
        let mut failed = Vec::new();

        for repo in rows
            .iter()
            .filter_map(|row| row.get("repo").and_then(Value::as_str))
        {
            match self.db.enqueue_rescan_with_lane(repo, -100, "background") {
                // A repository already sitting in the queue is not an error: the
                // sweep is meant to be safe to run twice.
                Ok(job_id) => queued.push(json!({"repo": repo, "job_id": job_id})),
                Err(error) => failed.push(json!({"repo": repo, "error": error.to_string()})),
            }
        }

        Ok(json!({
            "examined": rows.len(),
            "queued": queued.len(),
            "failed": failed.len(),
            "jobs": queued,
            "errors": failed
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
        // The real scanner evidence and the publisher metadata are both inputs
        // to the re-evaluation below, and they are independent of each other.
        let (scanner_evidence, owner_data) = tokio::join!(
            self.collect_scanner_evidence(&prepared.repo),
            self.fetch_owner_for_finalize(&prepared.repo)
        );
        // Keep the runs recorded by the fast pass for sources that do not
        // re-run at finalize (notably the GitHub SBOM/OSV dependency check),
        // instead of overwriting the whole list with the scanner-only results.
        let scanner_runs = merged_scanner_runs(&report, scanner_evidence.runs);
        report["scanner_runs"] = serde_json::to_value(&scanner_runs)
            .map_err(|error| format!("scanner result serialization failed: {error}"))?;
        if let Some(metrics) = report
            .get_mut("observed_metrics")
            .and_then(Value::as_object_mut)
        {
            metrics.insert("scanner_outputs".into(), json!(scanner_evidence.outputs));
            // Owner metadata is skipped by the progressive pass, which is why
            // `owner_metadata` was `{}` on every stored report. It is merged
            // here — before the re-evaluation — so the publisher pillars can
            // read `metadata.owner.created_at` / `.public_repos`.
            metrics.insert("owner_metadata".into(), owner_data.clone());
            if let Some(metadata) = metrics.get_mut("metadata") {
                merge_owner_into_metadata(metadata, &owner_data);
            }
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
        // Score the report against the evidence that now exists. Without this
        // the fast pass's empty-evidence scores are what production ships,
        // while the real evidence sits unused in the same document.
        rescore_finalized_report(
            &mut report,
            &prepared.repo,
            scanner_evidence.outputs,
            scanner_runs,
        );
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

/// Top-level report keys owned by the evaluation. A key absent from a fresh
/// evaluation is *removed* rather than left behind: `missing_evidence`,
/// `critical_flags` and friends are skipped when empty during serialization, so
/// a plain "copy the keys that exist" merge would strand stale values from the
/// empty-evidence pass on the finalized report.
const RESCORED_REPORT_KEYS: &[&str] = &[
    "trust_score",
    "evidence_anchored_score",
    "grade",
    "verdict",
    "action",
    "evidence_coverage",
    "confidence",
    "missing_evidence",
    "decision_reasons",
    "trust_decision",
    "next_review_date",
    "pillar_scores",
    "critical_flags",
    "override_applied",
    "coverage",
    "scorecard_raw",
    "data_sources",
    "scoring_version",
];

/// `observed_metrics` keys produced by the progressive pipeline rather than by
/// the evaluator. A re-evaluation must never overwrite these — they carry the
/// commit history, NVD, dependency and verification state that finalize spent
/// the whole job collecting.
const PRESERVED_OBSERVED_METRICS_KEYS: &[&str] = &[
    "metadata",
    "repo_metadata",
    "owner_metadata",
    "security_intel",
    "security_context_version",
    "verification_status",
    "scan_state",
    "head_sha",
    "scanner_outputs",
];

/// Re-run the evaluation against the evidence finalize has gathered and merge
/// the scored fields back into the enriched report.
///
/// Merging into the existing report (rather than rebuilding it from the new
/// evaluation) is deliberate: everything the progressive pipeline computed —
/// `security_intel`, `metadata`, `owner_metadata`, `head_sha`,
/// `verification_status`, `scan_state` — must survive untouched.
///
/// A report without usable metadata keeps its existing scores: re-evaluating
/// against nothing would replace one wrong answer with another.
fn rescore_finalized_report(
    report: &mut Value,
    repo: &str,
    mut tool_outputs: HashMap<String, Value>,
    scanner_runs: Vec<ScannerRun>,
) {
    let Some(metadata) = finalize_metadata(report) else {
        tracing::warn!(
            repo,
            "Finalize skipped re-evaluation: report carries no repository metadata"
        );
        return;
    };
    let today = report
        .get("evaluated_at")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<chrono::NaiveDate>().ok())
        .unwrap_or_else(|| Utc::now().date_naive());

    let dependency = report
        .pointer("/observed_metrics/security_intel/dependency_intelligence")
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<ai_supply_chain_trust_intelligence::DependencyIntelligence>(
                value,
            )
            .ok()
        });
    if let Some(dependency) = dependency.as_ref() {
        if let Ok(value) = serde_json::to_value(dependency) {
            tool_outputs.insert("github-sbom-osv".to_string(), value);
        }
    }

    let evidence_sources = EvidenceSources {
        github_metadata: metadata,
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
        data_sources: vec![
            "github".into(),
            "github_advisories".into(),
            "osv".into(),
            "github_dependency_graph".into(),
        ],
        scanner_runs,
    };

    // Same post-processing chain as `run_scan_mode`, in the same order, so the
    // fast and finalized paths cannot drift apart.
    let mut result = evaluate_repository(repo, None, today, evidence_sources);
    apply_evidence_aware_decision(&mut result);
    apply_dependency_malware_override(&mut result, dependency.as_ref());

    let rescored = match report_json_from_result(&result) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(repo, error, "Finalize re-evaluation serialization failed");
            return;
        }
    };
    merge_rescored_report(report, rescored);
    tracing::info!(
        repo,
        trust_score = result.trust_score,
        evidence_coverage = result.evidence_coverage,
        confidence = %result.confidence,
        "Finalize re-evaluated the report against collected evidence"
    );
}

/// Repository metadata to evaluate against: the enriched copy finalize just
/// updated, falling back to the raw GitHub payload.
fn finalize_metadata(report: &Value) -> Option<Value> {
    report
        .pointer("/observed_metrics/metadata")
        .filter(|value| value.is_object())
        .or_else(|| {
            report
                .pointer("/observed_metrics/repo_metadata")
                .filter(|value| value.is_object())
        })
        .cloned()
}

fn merge_rescored_report(report: &mut Value, rescored: Value) {
    let Some(target) = report.as_object_mut() else {
        return;
    };
    let Some(source) = rescored.as_object() else {
        return;
    };
    for key in RESCORED_REPORT_KEYS {
        match source.get(*key) {
            Some(value) => {
                target.insert((*key).to_string(), value.clone());
            }
            None => {
                target.remove(*key);
            }
        }
    }
    // The evaluator's own `observed_metrics` only ever carries decision fields;
    // everything the progressive pipeline stored there stays as it is.
    let (Some(Value::Object(fresh)), Some(Value::Object(metrics))) = (
        source.get("observed_metrics"),
        target.get_mut("observed_metrics"),
    ) else {
        return;
    };
    for (key, value) in fresh {
        if PRESERVED_OBSERVED_METRICS_KEYS.contains(&key.as_str()) {
            continue;
        }
        metrics.insert(key.clone(), value.clone());
    }
}

/// Fresh scanner runs first, then any run from the stored report whose tool did
/// not re-run at finalize, so nothing recorded by the fast pass is dropped.
fn merged_scanner_runs(report: &Value, fresh: Vec<ScannerRun>) -> Vec<ScannerRun> {
    let fresh_tools: Vec<String> = fresh.iter().map(|run| run.tool.clone()).collect();
    let mut runs = fresh;
    let existing = report
        .get("scanner_runs")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<ScannerRun>>(value).ok())
        .unwrap_or_default();
    for run in existing {
        if !fresh_tools.contains(&run.tool) {
            runs.push(run);
        }
    }
    runs
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

/// Fold owner metadata into repository metadata the way the pillars expect.
///
/// The full owner blob lands on `owner_details`, but the publisher pillars read
/// `metadata.owner.created_at` and `metadata.owner.public_repos`, so the
/// account-age and identity-graph signals are copied onto the nested `owner`
/// object as well. Without this second step the publisher pillars see nothing —
/// and the brand-new-account auto-fail can never fire.
fn merge_owner_into_metadata(metadata: &mut Value, owner_data: &Value) {
    let Some(object) = metadata.as_object_mut() else {
        return;
    };
    object.insert("owner_details".into(), owner_data.clone());
    let Some(owner_object) = object.get_mut("owner").and_then(Value::as_object_mut) else {
        return;
    };
    for key in ["created_at", "followers", "public_repos", "html_url"] {
        if let Some(value) = owner_data.get(key) {
            owner_object.insert(key.to_string(), value.clone());
        }
    }
}

/// Serialize an evaluation into its stored report shape.
///
/// `evidence_anchored_score` is surfaced at the top level here because
/// `EvaluationResult` (a frozen model this crate does not own) has no field for
/// it; `apply_evidence_aware_decision` already places the same value inside
/// `trust_decision` and `observed_metrics`.
fn report_json_from_result(result: &EvaluationResult) -> Result<Value, String> {
    let mut report = serde_json::to_value(result).map_err(|error| error.to_string())?;
    if let Some(object) = report.as_object_mut() {
        object.insert(
            "evidence_anchored_score".into(),
            json!(rounded_anchored_score(&result.pillar_scores)),
        );
    }
    Ok(report)
}

fn rounded_anchored_score(
    pillars: &HashMap<String, ai_supply_chain_trust_models::PillarResult>,
) -> f64 {
    (evidence_anchored_score(pillars) * 10.0).round() / 10.0
}

#[derive(Default)]
struct ScannerEvidence {
    runs: Vec<ScannerRun>,
    outputs: HashMap<String, Value>,
}

fn scanner_evidence_from_results(results: Vec<ScannerResult>) -> ScannerEvidence {
    let runs = results
        .iter()
        .map(|result| ScannerRun {
            tool: result.tool.clone(),
            // The runner distinguishes more states than the persisted enum can
            // hold, so the mapping is chosen to keep the operator-facing
            // meaning intact: a tool we never installed and a repository we
            // never checked out are things *we* failed to provide
            // (`unavailable`), while an ecosystem the repository genuinely does
            // not use is a real skip. The precise reason survives in `detail`.
            status: match result.status.as_str() {
                "ok" => ScannerStatus::Ok,
                "not_applicable" | "skipped" => ScannerStatus::Skipped,
                "failed" => ScannerStatus::Failed,
                "partial" => ScannerStatus::Partial,
                "not_installed" | "no_source" => ScannerStatus::Unavailable,
                _ => ScannerStatus::Unavailable,
            },
            detail: result.detail.clone(),
            impact: None,
        })
        .collect();
    let outputs = results
        .into_iter()
        .filter_map(|result| result.output.map(|output| (result.tool, output)))
        .collect();
    ScannerEvidence { runs, outputs }
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

fn ensure_public_repository(metadata: &Value) -> Result<(), String> {
    if metadata.get("private").and_then(Value::as_bool) == Some(false) {
        return Ok(());
    }

    Err("repository is not public".to_string())
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

    // `trust_score` divides by the *applicable* weight only, so a repository can
    // be awarded 100.0/grade A for scoring perfectly on the 47% of the model we
    // managed to measure. The anchored score divides by the full 100 weight, so
    // unmeasured evidence earns nothing and the number cannot contradict
    // `evidence_coverage`. It is additive reporting: `trust_score` and the
    // grading it feeds are untouched.
    let anchored_score = rounded_anchored_score(&result.pillar_scores);

    result.trust_decision = json!({
        "score": (result.trust_score * 10.0).round() / 10.0,
        "evidence_anchored_score": anchored_score,
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
        metrics.insert("evidence_anchored_score".into(), json!(anchored_score));
    }
}

fn apply_dependency_malware_override(
    result: &mut EvaluationResult,
    dependency: Option<&ai_supply_chain_trust_intelligence::DependencyIntelligence>,
) {
    let Some(dependency) = dependency else {
        return;
    };
    if dependency.malicious_package_matches.is_empty() {
        return;
    }

    let matches = dependency
        .malicious_package_matches
        .iter()
        .take(5)
        .map(|entry| format!("{} ({})", entry.purl, entry.id))
        .collect::<Vec<_>>()
        .join(", ");
    result.critical_flags.push(Finding::new(
        "supply_chain",
        Severity::Critical,
        format!("OpenSSF malicious-package record matched: {matches}"),
    ));
    result.grade = Grade::F;
    result.verdict = "Do not approve: malicious dependency evidence".to_string();
    result.action = "Remove or replace the matched dependency, then rescan".to_string();
    result.override_applied = true;
    result
        .decision_reasons
        .push("GitHub dependency SBOM matched an OpenSSF malicious-package record".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_bounds_fall_back_to_the_compiled_default() {
        // Unset, blank, unparseable, negative and zero must all keep the
        // compiled bound rather than silently disabling the cap: a max_bytes of
        // 0 would reject every checkout, and a timeout of 0 would abort every
        // clone instantly.
        for raw in [
            None,
            Some(""),
            Some("   "),
            Some("lots"),
            Some("-1"),
            Some("0"),
        ] {
            assert_eq!(parse_checkout_bound(raw, 4096), 4096, "raw={raw:?}");
        }
    }

    #[test]
    fn checkout_bounds_accept_operator_overrides() {
        assert_eq!(parse_checkout_bound(Some("268435456"), 4096), 268_435_456);
        assert_eq!(parse_checkout_bound(Some(" 90 "), 120), 90);
    }

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

    #[test]
    fn scanner_results_are_mapped_to_evidence_without_promoting_failures() {
        let evidence = scanner_evidence_from_results(vec![
            ScannerResult {
                tool: "scorecard".into(),
                status: "ok".into(),
                detail: "Scorecard score: 8.0/10".into(),
                output: Some(json!({"score": 8.0})),
                duration_ms: 10,
            },
            ScannerResult {
                tool: "semgrep".into(),
                status: "not_installed".into(),
                detail: "semgrep was not run: the 'semgrep' binary is not installed".into(),
                output: None,
                duration_ms: 0,
            },
            ScannerResult {
                tool: "gitleaks".into(),
                status: "no_source".into(),
                detail: "gitleaks was not run: source checkout is disabled".into(),
                output: None,
                duration_ms: 0,
            },
            ScannerResult {
                tool: "pip-audit".into(),
                status: "not_applicable".into(),
                detail: "pip-audit does not apply: no Python manifest".into(),
                output: None,
                duration_ms: 0,
            },
        ]);

        assert_eq!(evidence.runs.len(), 4);
        assert_eq!(evidence.runs[0].status, ScannerStatus::Ok);
        // Deployment gaps stay `unavailable`...
        assert_eq!(evidence.runs[1].status, ScannerStatus::Unavailable);
        assert_eq!(evidence.runs[2].status, ScannerStatus::Unavailable);
        // ...and only a genuinely inapplicable ecosystem is a skip.
        assert_eq!(evidence.runs[3].status, ScannerStatus::Skipped);
        assert!(evidence.runs[1].detail.contains("not installed"));
        assert!(evidence.runs[2].detail.contains("checkout"));
        assert_eq!(evidence.outputs["scorecard"]["score"], json!(8.0));
        assert!(!evidence.outputs.contains_key("semgrep"));
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
            "private": false,
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
        let db = Arc::new(ai_supply_chain_trust_storage::Database::open_memory().unwrap());
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

    #[test]
    fn private_or_ambiguous_repository_metadata_is_rejected() {
        assert!(ensure_public_repository(&json!({"private": false})).is_ok());
        assert_eq!(
            ensure_public_repository(&json!({"private": true})).unwrap_err(),
            "repository is not public"
        );
        assert_eq!(
            ensure_public_repository(&json!({"visibility": "public"})).unwrap_err(),
            "repository is not public"
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
    async fn private_cached_metadata_never_creates_a_report() {
        let db = Arc::new(Database::open_memory().unwrap());
        let mut private_metadata = cached_metadata("owner/private-repo");
        private_metadata["private"] = json!(true);
        db.put_source_cache(
            "github_repo:owner/private-repo",
            "github_repo",
            &private_metadata,
            None,
            None,
            Some(300),
        )
        .unwrap();
        let service = Service::new(db.clone(), None);

        assert_eq!(
            service
                .run_fast_scan("owner/private-repo")
                .await
                .unwrap_err(),
            "repository is not public"
        );
        assert!(db.get_report("owner/private-repo").is_none());
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

    fn evidence_from(metadata: &Value, tool_outputs: HashMap<String, Value>) -> EvidenceSources {
        EvidenceSources {
            github_metadata: metadata.clone(),
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
            data_sources: vec!["github".into()],
            scanner_runs: vec![],
        }
    }

    /// A report shaped exactly like the progressive fast pass leaves it:
    /// scored against empty scanner evidence, with the enrichment keys the
    /// finalize pass later fills in.
    fn fast_pass_report(repo: &str) -> Value {
        let metadata = cached_metadata(repo);
        let mut result = evaluate_repository(
            repo,
            None,
            NaiveDate::from_ymd_opt(2026, 8, 18).unwrap(),
            evidence_from(&metadata, HashMap::new()),
        );
        apply_evidence_aware_decision(&mut result);
        let mut report = report_json_from_result(&result).unwrap();
        let metrics = report["observed_metrics"].as_object_mut().unwrap();
        metrics.insert("metadata".into(), metadata.clone());
        metrics.insert("repo_metadata".into(), metadata);
        metrics.insert("owner_metadata".into(), json!({}));
        metrics.insert(
            "security_intel".into(),
            json!({"commit_count": 120, "head_sha": "abc123", "fix_commits": [{"sha": "abc123"}], "nvd_cves": []}),
        );
        metrics.insert("head_sha".into(), json!("abc123"));
        metrics.insert("security_context_version".into(), json!("test-version"));
        metrics.insert("verification_status".into(), json!("ok"));
        metrics.insert("scan_state".into(), json!("complete"));
        report["scanner_runs"] = json!([{
            "tool": "github-sbom-osv", "status": "ok", "detail": "status=fetched"
        }]);
        report
    }

    #[test]
    fn finalize_rescoring_scores_the_evidence_the_fast_pass_never_saw() {
        let mut report = fast_pass_report("owner/repo");

        // Baseline: the production shape — four of eight pillars inapplicable.
        assert_eq!(report["evidence_coverage"], json!(0.47));
        assert_eq!(report["confidence"], json!("low"));
        assert_eq!(
            report["pillar_scores"]["openssf_scorecard"]["applicable"],
            json!(false)
        );

        let outputs = HashMap::from([(
            "scorecard".to_string(),
            json!({"score": 8.5, "date": "2026-08-18", "checks": []}),
        )]);
        rescore_finalized_report(
            &mut report,
            "owner/repo",
            outputs,
            vec![ScannerRun {
                tool: "scorecard".into(),
                status: ScannerStatus::Ok,
                detail: "Scorecard score: 8.5/10".into(),
                impact: None,
            }],
        );

        assert_eq!(
            report["pillar_scores"]["openssf_scorecard"]["applicable"],
            json!(true)
        );
        assert_eq!(report["evidence_coverage"], json!(0.72));
        assert_eq!(report["confidence"], json!("medium"));
        assert_eq!(report["trust_decision"]["confidence"], json!("medium"));
        assert_eq!(
            report["observed_metrics"]["confidence"],
            json!("medium"),
            "observed_metrics must track the re-evaluated decision"
        );
    }

    #[test]
    fn finalize_rescoring_preserves_every_progressive_enrichment_key() {
        let mut report = fast_pass_report("owner/repo");
        let intel = report["observed_metrics"]["security_intel"].clone();

        rescore_finalized_report(&mut report, "owner/repo", HashMap::new(), vec![]);

        let metrics = &report["observed_metrics"];
        assert_eq!(metrics["security_intel"], intel);
        assert_eq!(metrics["head_sha"], json!("abc123"));
        assert_eq!(metrics["security_context_version"], json!("test-version"));
        assert_eq!(metrics["verification_status"], json!("ok"));
        assert_eq!(metrics["scan_state"], json!("complete"));
        assert_eq!(metrics["repo_metadata"]["full_name"], json!("owner/repo"));
        assert_eq!(metrics["metadata"]["default_branch"], json!("main"));
        assert!(metrics.get("owner_metadata").is_some());
    }

    #[test]
    fn finalize_rescoring_drops_stale_scored_fields_instead_of_stranding_them() {
        let mut report = fast_pass_report("owner/repo");
        // Serialization skips these when empty, so a "copy present keys" merge
        // would leave the empty-evidence values behind forever.
        report["missing_evidence"] = json!(["OpenSSF Scorecard: stale gap"]);
        report["critical_flags"] =
            json!([{"category": "stale", "severity": "critical", "message": "stale"}]);

        let outputs =
            HashMap::from([("scorecard".to_string(), json!({"score": 9.0, "checks": []}))]);
        rescore_finalized_report(&mut report, "owner/repo", outputs, vec![]);

        assert!(
            !report["missing_evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some("OpenSSF Scorecard: stale gap")),
            "stale evidence gaps must not survive re-evaluation"
        );
        assert_eq!(report["critical_flags"], json!([]));
    }

    #[test]
    fn finalize_rescoring_keeps_existing_scores_without_metadata() {
        let mut report = fast_pass_report("owner/repo");
        report["observed_metrics"]["metadata"] = json!(null);
        report["observed_metrics"]["repo_metadata"] = json!(null);
        let before = report.clone();

        rescore_finalized_report(&mut report, "owner/repo", HashMap::new(), vec![]);

        assert_eq!(report, before);
    }

    #[test]
    fn finalize_keeps_scanner_runs_that_do_not_rerun() {
        let report = json!({"scanner_runs": [
            {"tool": "github-sbom-osv", "status": "ok", "detail": "status=fetched"},
            {"tool": "scorecard", "status": "unavailable", "detail": "stale"}
        ]});

        let merged = merged_scanner_runs(
            &report,
            vec![ScannerRun {
                tool: "scorecard".into(),
                status: ScannerStatus::Ok,
                detail: "Scorecard score: 8.5/10".into(),
                impact: None,
            }],
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].tool, "scorecard");
        assert_eq!(merged[0].status, ScannerStatus::Ok);
        assert_eq!(merged[1].tool, "github-sbom-osv");
    }

    #[test]
    fn owner_metadata_reaches_the_nested_owner_object_the_pillars_read() {
        let mut metadata = cached_metadata("owner/repo");
        merge_owner_into_metadata(
            &mut metadata,
            &json!({
                "created_at": "2015-01-01T00:00:00Z",
                "followers": 900,
                "public_repos": 42,
                "html_url": "https://github.com/owner"
            }),
        );

        assert_eq!(
            metadata["owner"]["created_at"],
            json!("2015-01-01T00:00:00Z")
        );
        assert_eq!(metadata["owner"]["public_repos"], json!(42));
        assert_eq!(metadata["owner_details"]["followers"], json!(900));
    }

    #[tokio::test]
    async fn progressive_finalize_fetches_owner_metadata_and_rescores() {
        let db = Arc::new(Database::open_memory().unwrap());
        seed_metadata_cache(&db, "owner/repo");
        let service = Service::with_config(
            db.clone(),
            None,
            IntelligenceClientConfig::default(),
            ServiceConfig {
                // Keep the test hermetic: no scanner subprocesses, no clones.
                scanner_enabled: false,
                ..ServiceConfig::default()
            },
        )
        .with_scanner_checkout_config(ScannerCheckoutConfig {
            enabled: false,
            ..ScannerCheckoutConfig::default()
        });
        service.owner_cache.write().await.insert(
            "owner".to_string(),
            (
                Instant::now(),
                json!({
                    "login": "owner",
                    "created_at": "2015-01-01T00:00:00Z",
                    "followers": 900,
                    "public_repos": 42,
                    "html_url": "https://github.com/owner"
                }),
            ),
        );

        let (job_id, fast_report) = service.run_progressive_scan("owner/repo").await.unwrap();
        assert_eq!(fast_report["observed_metrics"]["owner_metadata"], json!({}));
        assert_eq!(fast_report["observed_metrics"]["scan_state"], "fast_ready");

        complete_progressive_evidence(&db, job_id);
        assert!(service.try_finalize_progressive(job_id).await.unwrap());

        let finalized = db.get_report("owner/repo").unwrap();
        let metrics = &finalized["observed_metrics"];
        assert_eq!(metrics["owner_metadata"]["public_repos"], json!(42));
        assert_eq!(
            metrics["metadata"]["owner"]["created_at"],
            json!("2015-01-01T00:00:00Z"),
            "publisher pillars read metadata.owner.created_at"
        );
        assert_eq!(metrics["scan_state"], json!("complete"));
        assert_eq!(metrics["verification_status"], json!("ok"));
        assert!(finalized["evidence_anchored_score"].is_number());
        assert!(
            !finalized["pillar_scores"]["publisher_credibility"]["concerns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value
                    .as_str()
                    .is_some_and(|text| text.contains("creation timestamp unavailable"))),
            "publisher credibility must no longer report missing owner metadata"
        );
    }

    /// Drive the progressive evidence queue to the state finalize waits for.
    fn complete_progressive_evidence(db: &Database, job_id: i64) {
        let history = db
            .claim_next_evidence_task("github_history_page", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(
            history["id"].as_i64().unwrap(),
            history["attempts"].as_i64().unwrap(),
            // Digit-free fake SHA on purpose: scripts/security_independence_guard.sh
            // rejects a repository slug sharing a line with a commit metric and a
            // multi-digit number, to stop repo-specific results being hardcoded.
            &json!({"repo": "owner/repo", "page": 1, "count": 1, "commits": [{"sha": "abcdef"}]}),
        )
        .unwrap();
        let nvd = db.claim_next_evidence_task("nvd", 60).unwrap().unwrap();
        db.complete_evidence_task(
            nvd["id"].as_i64().unwrap(),
            nvd["attempts"].as_i64().unwrap(),
            &json!({"repo": "owner/repo", "count": 0, "cves": []}),
        )
        .unwrap();
        db.enqueue_evidence_task(job_id, "commit_detail_manifest", "candidates", 15)
            .unwrap();
        let manifest = db
            .claim_evidence_task_for_job(job_id, "commit_detail_manifest", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(
            manifest["id"].as_i64().unwrap(),
            manifest["attempts"].as_i64().unwrap(),
            &json!({"repo": "owner/repo", "shas": []}),
        )
        .unwrap();
    }

    #[test]
    fn evidence_anchored_score_is_published_next_to_the_frozen_score() {
        let mut pillars = HashMap::new();
        pillars.insert(
            "publisher_credibility".to_string(),
            PillarResult::new("publisher_credibility", "Publisher Credibility")
                .with_score(20.0, 20.0),
        );
        pillars.insert(
            "openssf_scorecard".to_string(),
            PillarResult::new("openssf_scorecard", "OpenSSF Scorecard")
                .with_score(0.0, 25.0)
                .with_applicable(false)
                .with_unavailable(vec!["Scorecard data not available.".into()]),
        );

        let mut result = EvaluationResult::new(
            "owner/repo",
            NaiveDate::from_ymd_opt(2026, 8, 18).unwrap(),
            100.0,
            Grade::A,
            "Approved",
            "Use",
            NaiveDate::from_ymd_opt(2026, 11, 16).unwrap(),
            pillars,
            vec![],
            vec![],
        );
        apply_evidence_aware_decision(&mut result);
        let report = report_json_from_result(&result).unwrap();

        // The frozen contract is untouched...
        assert_eq!(report["trust_score"], json!(100.0));
        // ...while the anchored score refuses to award unmeasured evidence.
        assert_eq!(report["evidence_anchored_score"], json!(20.0));
        assert_eq!(
            report["trust_decision"]["evidence_anchored_score"],
            json!(20.0)
        );
        assert_eq!(
            report["observed_metrics"]["evidence_anchored_score"],
            json!(20.0)
        );
    }

    #[test]
    fn malicious_dependency_evidence_forces_an_explicit_rejection() {
        let mut result = EvaluationResult::new(
            "owner/repo",
            NaiveDate::from_ymd_opt(2026, 7, 30).unwrap(),
            90.0,
            Grade::A,
            "Approved",
            "Use",
            NaiveDate::from_ymd_opt(2026, 10, 28).unwrap(),
            HashMap::new(),
            vec![],
            vec![],
        );
        let dependency = ai_supply_chain_trust_intelligence::DependencyIntelligence {
            status: "fetched".to_string(),
            malicious_package_matches: vec![
                ai_supply_chain_trust_intelligence::DependencyOsvMatch {
                    purl: "pkg:npm/example-malware@1.0.0".to_string(),
                    id: "MAL-2026-0001".to_string(),
                    modified: None,
                },
            ],
            ..Default::default()
        };

        apply_dependency_malware_override(&mut result, Some(&dependency));

        assert_eq!(result.grade, Grade::F);
        assert!(result.override_applied);
        assert!(result.verdict.contains("malicious dependency"));
        assert!(result.critical_flags[0].message.contains("MAL-2026-0001"));
    }
}
