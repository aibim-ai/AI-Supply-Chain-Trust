#![recursion_limit = "256"]
//! HTTP server — axum. Graceful shutdown, DB health, SSE, MCP, rate limiting.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_supply_chain_trust_auth::verify_bearer_token;
use ai_supply_chain_trust_intelligence::IntelligenceClientConfig;
use ai_supply_chain_trust_service::{Service, ServiceConfig};
use ai_supply_chain_trust_storage::Database;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Json, Response,
    },
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<Service>,
    pub base_url: String,
    worker_token: Option<String>,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    feedback_limiter: Arc<Mutex<RateLimiter>>,
    scan_permits: Arc<Semaphore>,
    sse_permits: Arc<Semaphore>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_required",
            message: "Unauthorized".into(),
        }
    }

    fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "Too many feedback submissions; please try again later".into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "unavailable",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": self.message, "code": self.code})),
        )
            .into_response()
    }
}

#[derive(Clone)]
pub(crate) struct RateLimiter {
    hits: HashMap<String, Vec<Instant>>,
    max_hits: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_hits: usize, window_secs: u64) -> Self {
        Self {
            hits: HashMap::new(),
            max_hits,
            window: Duration::from_secs(window_secs),
        }
    }

    fn check(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let entries = self.hits.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() >= self.max_hits {
            return false;
        }
        entries.push(now);
        true
    }

    fn check_repo(&mut self, repo: &str) -> bool {
        let normalized = normalize_repo_key(repo);
        self.check(&normalized)
    }
}

fn normalize_repo_key(repo: &str) -> String {
    let trimmed = repo.trim().trim_end_matches('/');
    let path = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .or_else(|| trimmed.strip_prefix("github.com/"))
        .unwrap_or(trimmed)
        .trim_end_matches(".git");
    path.to_ascii_lowercase()
}

fn validate_repo(repo: &str) -> Result<String, ApiError> {
    let normalized = normalize_repo_key(repo);
    let mut parts = normalized.split('/');
    let valid = matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(name), None)
        if valid_github_owner(owner) && valid_github_repo(name));
    if valid {
        Ok(normalized)
    } else {
        Err(ApiError::bad_request("repo must be owner/repository"))
    }
}

fn valid_github_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_github_repo(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn acquire_permit(
    pool: &Arc<Semaphore>,
    message: &'static str,
) -> Result<OwnedSemaphorePermit, ApiError> {
    pool.clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::unavailable(message))
}

/// Startup-time configuration validator. Logs warnings for missing
/// optional config; only fails on truly critical missing configuration.
pub fn validate_startup_config() -> anyhow::Result<()> {
    let checks: Vec<(&str, &str, bool)> = vec![
        (
            "allowed_origins",
            "AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS",
            std::env::var("AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS").is_ok(),
        ),
        (
            "JWT secret",
            "JWT_SECRET",
            std::env::var("JWT_SECRET").is_ok(),
        ),
        (
            "worker token",
            "AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN",
            std::env::var("AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN").is_ok(),
        ),
    ];

    let mut warnings = Vec::new();
    for (name, var, present) in &checks {
        if !present {
            warnings.push(format!("{name} (env {var}) is not configured"));
        }
    }

    if !warnings.is_empty() {
        warn!(
            "Startup config warnings (non-fatal):\n  - {}",
            warnings.join("\n  - ")
        );
    } else {
        info!("Startup config validation passed");
    }

    Ok(())
}

pub async fn serve(
    host: &str,
    port: u16,
    db_path: String,
    github_token: Option<String>,
    base_url: String,
) -> anyhow::Result<()> {
    validate_startup_config()?;

    let pg_url = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty());
    let db = if let Some(ref url) = pg_url {
        info!("Using PostgreSQL backend");
        Arc::new(Database::open_with_pg(&db_path, url).await?)
    } else {
        Arc::new(Database::open(&db_path)?)
    };
    let github_tokens = github_tokens_from_env(github_token);
    let discovery_token = github_tokens
        .as_deref()
        .and_then(|tokens| {
            tokens
                .split(',')
                .map(str::trim)
                .find(|token| !token.is_empty())
        })
        .map(str::to_string);
    let service = Arc::new(Service::with_config(
        db.clone(),
        github_tokens,
        intelligence_config_from_env(),
        service_config_from_env(),
    ));
    let worker_service = service.clone();
    let state = AppState {
        service,
        base_url: base_url.clone(),
        worker_token: std::env::var("AI_SUPPLY_CHAIN_TRUST_WORKER_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 86400))),
        feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
        scan_permits: Arc::new(Semaphore::new(4)),
        sse_permits: Arc::new(Semaphore::new(100)),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/api", get(api_index))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/health", get(api_health))
        .route("/api/v1/healthz", get(api_healthz))
        .route("/api/v1/context/:owner/:repo", get(get_context))
        .route("/api/v1/context", axum::routing::post(create_context))
        .route(
            "/api/v1/repos/:owner/:repo/regression-contracts",
            get(regression_contracts_handler),
        )
        .route(
            "/api/v1/repos/:owner/:repo/regression-contracts/:contract_id",
            get(regression_contract_handler),
        )
        .route(
            "/api/v1/repos/:owner/:repo/regression-contracts/:contract_id/transitions",
            axum::routing::post(regression_transition_handler),
        )
        .route(
            "/api/v1/repos/:owner/:repo/regression-assessments",
            axum::routing::post(regression_assessment_handler),
        )
        .route(
            "/api/v1/repos/:owner/:repo/regression-assessments/:head_sha",
            get(regression_assessments_handler),
        )
        .route("/api/v1/scan", axum::routing::post(scan))
        .route(
            "/api/v1/feedback",
            axum::routing::post(feedback_handler).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/api/v1/leaderboard", get(leaderboard))
        .route("/api/v1/recent-scans", get(recent_scans))
        .route("/api/v1/result", get(result))
        .route("/api/v1/history", get(history))
        .route("/api/v1/intel/hits", get(intel_hits))
        .route("/api/v1/pig", get(pig_node))
        .route("/api/v1/suggest", get(suggest))
        .route("/api/v1/scoring/versions", get(scoring_versions))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/metrics/prometheus", get(prometheus_metrics))
        .route("/api/v1/events", get(events_sse))
        .route("/api/v1/jobs", get(jobs_handler))
        .route("/api/v1/queue/stats", get(queue_stats_handler))
        .route("/api/v1/ops/failures", get(failure_alerts_handler))
        .route(
            "/api/v1/ops/failures/:id/retry",
            axum::routing::post(failure_retry_handler),
        )
        .route(
            "/api/v1/ops/failures/:id/ack",
            axum::routing::post(failure_ack_handler),
        )
        .route(
            "/api/v1/queue/pause",
            axum::routing::post(queue_pause_handler),
        )
        .route(
            "/api/v1/queue/resume",
            axum::routing::post(queue_resume_handler),
        )
        .route(
            "/api/v1/queue/rescan",
            axum::routing::post(queue_rescan_handler),
        )
        .route("/api/v1/admin/discrepancy", get(discrepancy_handler))
        .route("/api/v1/admin/consistency", get(consistency_handler))
        .route("/sitemap.xml", get(sitemap_xml))
        .route("/r/*path", get(security_context_artifact))
        .route("/mcp", get(mcp_info).post(mcp_handler))
        .fallback_service(get(serve_static))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from((host.parse::<std::net::Ipv4Addr>()?, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Server listening");
    maybe_start_queue_worker(worker_service, discovery_token);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shut down gracefully");
    Ok(())
}

fn service_config_from_env() -> ServiceConfig {
    ServiceConfig {
        github_rate_limit_backoff_seconds: std::env::var(
            "AI_SUPPLY_CHAIN_TRUST_GITHUB_RATE_LIMIT_BACKOFF_SECONDS",
        )
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &i64| *value > 0)
        .unwrap_or_else(|| ServiceConfig::default().github_rate_limit_backoff_seconds),
        github_foreground_reserve: std::env::var("AI_SUPPLY_CHAIN_TRUST_GITHUB_FOREGROUND_RESERVE")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &i64| *value >= 0)
            .unwrap_or_else(|| ServiceConfig::default().github_foreground_reserve),
        progressive_commit_detail_limit: std::env::var(
            "AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_COMMIT_DETAIL_LIMIT",
        )
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &usize| *value > 0)
        .unwrap_or_else(|| ServiceConfig::default().progressive_commit_detail_limit),
        foreground_timeout_seconds: std::env::var(
            "AI_SUPPLY_CHAIN_TRUST_FOREGROUND_TIMEOUT_SECONDS",
        )
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &u64| *value > 0)
        .unwrap_or_else(|| ServiceConfig::default().foreground_timeout_seconds),
        nvd_task_timeout_seconds: std::env::var("AI_SUPPLY_CHAIN_TRUST_NVD_TASK_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &u64| *value > 0)
            .unwrap_or_else(|| ServiceConfig::default().nvd_task_timeout_seconds),
        progressive_history_max_pages: std::env::var(
            "AI_SUPPLY_CHAIN_TRUST_PROGRESSIVE_HISTORY_MAX_PAGES",
        )
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &usize| *value > 0)
        .unwrap_or_else(|| ServiceConfig::default().progressive_history_max_pages),
    }
}

fn github_tokens_from_env(github_token: Option<String>) -> Option<String> {
    let mut values = Vec::new();
    if let Some(token) = github_token.filter(|value| !value.trim().is_empty()) {
        values.push(token);
    }
    if let Ok(tokens) = std::env::var("GITHUB_TOKENS") {
        if !tokens.trim().is_empty() {
            values.push(tokens);
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

fn intelligence_config_from_env() -> IntelligenceClientConfig {
    let limit = |name, default| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &usize| *value > 0)
            .unwrap_or(default)
    };
    let timeout_seconds = std::env::var("AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &u64| *value > 0)
        .unwrap_or(120);
    IntelligenceClientConfig {
        max_advisory_pages: limit("AI_SUPPLY_CHAIN_TRUST_GITHUB_ADVISORY_MAX_PAGES", 100),
        max_security_history_pages: limit("AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_PAGES", 1000),
        max_fix_commits: std::env::var("AI_SUPPLY_CHAIN_TRUST_SECURITY_HISTORY_MAX_FIX_COMMITS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &usize| *value > 0),
        github_timeout_seconds: timeout_seconds,
        llm_commit_classification_enabled: !env_flag(
            "AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_COMMIT_CLASSIFICATION",
        ),
        llm_ecosystem_resolution_enabled: !env_flag(
            "AI_SUPPLY_CHAIN_TRUST_DISABLE_LLM_ECOSYSTEM_RESOLUTION",
        ),
        nvd_api_key: std::env::var("NVD_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty()),
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u64_allow_zero(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn maybe_start_queue_worker(service: Arc<Service>, discovery_token: Option<String>) {
    let worker_role = std::env::var("AI_SUPPLY_CHAIN_TRUST_WORKER_ROLE")
        .unwrap_or_else(|_| "general".to_string())
        .to_ascii_lowercase();
    let worker_start_delay_secs =
        env_u64_allow_zero("AI_SUPPLY_CHAIN_TRUST_WORKER_START_DELAY_SECONDS", 0);
    let evidence_interval_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_INTERVAL_SECONDS", 1);
    info!(worker_role, "Background worker role selected");
    if !env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON") {
        info!("Background workers disabled because AI_SUPPLY_CHAIN_TRUST_DAEMON is not enabled");
        return;
    }
    if worker_role == "nvd" {
        start_nvd_worker_pool(
            service,
            worker_start_delay_secs,
            evidence_interval_secs,
            "enabled",
        );
        return;
    }

    let nvd_service = service.clone();
    let detail_service = service.clone();
    let finalize_service = service.clone();
    let notification_service = service.clone();
    let recovery_service = service.clone();
    let stale_context_service = service.clone();
    let recovery_interval_secs = env_u64(
        "AI_SUPPLY_CHAIN_TRUST_FAILURE_RECOVERY_INTERVAL_SECONDS",
        600,
    );
    tokio::spawn(async move {
        if worker_start_delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
        }
        match stale_context_service.enqueue_stale_security_context_rescans(50_000) {
            Ok(result) => info!(%result, "Stale security contexts queued for precision rescan"),
            Err(error) => warn!(%error, "Failed to queue stale security-context rescans"),
        }
    });
    tokio::spawn(async move {
        if worker_start_delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(recovery_interval_secs));
        loop {
            tick.tick().await;
            match recovery_service.recover_transient_failures(200) {
                Ok(result)
                    if result["scan_jobs_requeued"].as_u64().unwrap_or(0) > 0
                        || result["evidence_tasks_requeued"].as_u64().unwrap_or(0) > 0 =>
                {
                    info!(%result, "Transient failures automatically requeued")
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "Transient failure recovery failed"),
            }
        }
    });
    if let Ok(webhook_url) = std::env::var("AI_SUPPLY_CHAIN_TRUST_ALERT_WEBHOOK_URL") {
        if !webhook_url.trim().is_empty() {
            let webhook_url = webhook_url.trim().to_string();
            let interval_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_ALERT_INTERVAL_SECONDS", 60);
            tokio::spawn(async move {
                if worker_start_delay_secs > 0 {
                    tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
                }
                let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
                loop {
                    tick.tick().await;
                    match notification_service
                        .send_pending_failure_notifications(&webhook_url, 20)
                        .await
                    {
                        Ok(sent) if sent > 0 => {
                            info!(sent, "Failure alert webhook notifications sent")
                        }
                        Ok(_) => {}
                        Err(error) => warn!(%error, "Failure alert webhook notification failed"),
                    }
                }
            });
        }
    }
    if env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON") {
        let interval_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_DAEMON_QUEUE_INTERVAL", 10);
        let max_concurrent =
            env_usize("AI_SUPPLY_CHAIN_TRUST_DAEMON_MAX_CONCURRENT", 1).clamp(1, 20);
        let general_workers = if max_concurrent > 1 {
            max_concurrent - 1
        } else {
            1
        };
        info!(
            interval_secs,
            max_concurrent, general_workers, "Queue worker pool starting"
        );
        for worker_id in 0..general_workers {
            let service = service.clone();
            tokio::spawn(async move {
                if worker_start_delay_secs > 0 {
                    tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
                }
                info!(worker_id, "Queue worker started");
                loop {
                    match service.run_next_queued_scan().await {
                        Ok(true) => tokio::task::yield_now().await,
                        Ok(false) => {
                            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                        }
                        Err(error) => {
                            warn!(worker_id, %error, "Queued scan failed");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                }
            });
        }
        if max_concurrent > 1 {
            let service = service.clone();
            tokio::spawn(async move {
                if worker_start_delay_secs > 0 {
                    tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
                }
                info!("Reserved foreground queue worker started");
                loop {
                    match service.run_next_foreground_scan().await {
                        Ok(true) => tokio::task::yield_now().await,
                        Ok(false) => tokio::time::sleep(Duration::from_secs(interval_secs)).await,
                        Err(error) => {
                            warn!(%error, "Reserved foreground scan failed");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                }
            });
        }
    }
    start_discovery_worker(service.clone(), discovery_token, worker_start_delay_secs);
    let history_batch = env_usize("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_BATCH", 1).clamp(1, 20);
    let history_concurrency =
        env_usize("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_HISTORY_CONCURRENCY", 4).clamp(1, 20);
    info!(
        history_concurrency,
        history_batch, evidence_interval_secs, "GitHub history worker pool starting"
    );
    for history_worker_id in 0..history_concurrency {
        let evidence_service = service.clone();
        tokio::spawn(async move {
            if worker_start_delay_secs > 0 {
                tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(evidence_interval_secs));
            loop {
                tick.tick().await;
                for _ in 0..history_batch {
                    match evidence_service.run_next_history_evidence().await {
                        Ok(true) => continue,
                        Ok(false) => break,
                        Err(error) => {
                            warn!(history_worker_id, %error, source = "github_history_page", "Evidence task failed");
                            break;
                        }
                    }
                }
            }
        });
    }
    let nvd_mode = std::env::var("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_MODE").unwrap_or_else(|_| {
        if matches!(
            std::env::var("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_ENABLED")
                .ok()
                .as_deref(),
            Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO")
        ) {
            "skip".to_string()
        } else {
            "enabled".to_string()
        }
    });
    start_nvd_worker_pool(
        nvd_service,
        worker_start_delay_secs,
        evidence_interval_secs,
        &nvd_mode,
    );
    let detail_batch = env_usize("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_DETAIL_BATCH", 2).clamp(1, 50);
    tokio::spawn(async move {
        if worker_start_delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(evidence_interval_secs));
        loop {
            tick.tick().await;
            for _ in 0..detail_batch {
                match detail_service.run_next_commit_detail_evidence().await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(error) => {
                        warn!(%error, source = "commit_detail", "Evidence task failed");
                        break;
                    }
                }
            }
        }
    });
    let finalize_concurrency =
        env_usize("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_FINALIZE_CONCURRENCY", 2).clamp(1, 8);
    info!(
        finalize_concurrency,
        "Evidence finalize worker pool starting"
    );
    for finalize_worker_id in 0..finalize_concurrency {
        let finalize_service = finalize_service.clone();
        tokio::spawn(async move {
            if worker_start_delay_secs > 0 {
                tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(evidence_interval_secs));
            loop {
                tick.tick().await;
                match finalize_service.run_pending_finalize_evidence().await {
                    Ok(true) | Ok(false) => {}
                    Err(error) => {
                        warn!(finalize_worker_id, %error, source = "finalize", "Evidence finalize failed")
                    }
                }
            }
        });
    }
}

fn start_nvd_worker_pool(
    service: Arc<Service>,
    worker_start_delay_secs: u64,
    evidence_interval_secs: u64,
    mode: &str,
) {
    let mode = mode.to_ascii_lowercase();
    if mode == "off" {
        info!(
            nvd_mode = mode,
            "NVD evidence worker disabled for this role"
        );
        return;
    }
    let nvd_concurrency =
        env_usize("AI_SUPPLY_CHAIN_TRUST_EVIDENCE_NVD_CONCURRENCY", 1).clamp(1, 4);
    info!(
        nvd_concurrency,
        nvd_mode = mode,
        "NVD evidence worker pool starting"
    );
    for nvd_worker_id in 0..nvd_concurrency {
        let nvd_service = service.clone();
        let mode = mode.clone();
        tokio::spawn(async move {
            if worker_start_delay_secs > 0 {
                tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(evidence_interval_secs));
            loop {
                tick.tick().await;
                let result = if mode == "enabled" {
                    nvd_service.run_next_nvd_evidence().await
                } else {
                    nvd_service
                        .skip_next_nvd_evidence("NVD source is in degraded mode")
                        .await
                };
                match result {
                    Ok(true) | Ok(false) => {}
                    Err(error) => {
                        warn!(nvd_worker_id, %error, source = "nvd", "Evidence task failed")
                    }
                }
            }
        });
    }
}

fn start_discovery_worker(
    service: Arc<Service>,
    github_token: Option<String>,
    worker_start_delay_secs: u64,
) {
    let interval_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVERY_INTERVAL", 86_400);
    let limit = env_usize("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_LIMIT", 10).clamp(1, 100);
    let min_stars =
        env_u64_allow_zero("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_MIN_STARS", 500) as i64;
    let pushed_days = env_u64("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_DAYS", 7).clamp(1, 365);
    info!(
        interval_secs,
        limit, min_stars, "Repository discovery worker starting"
    );
    tokio::spawn(async move {
        if worker_start_delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
        }
        let timeout_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS", 20);
        let mut client = ai_supply_chain_trust_discovery::DiscoveryClient::with_timeout(
            github_token,
            timeout_secs,
        );
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            tick.tick().await;
            // The scan pipeline accepts canonical GitHub owner/repo identifiers.
            // Registry/model discovery remains available to the CLI, but those
            // identifiers must not be fed into this queue.
            let pushed_since = (chrono::Utc::now() - chrono::Duration::days(pushed_days as i64))
                .format("%Y-%m-%d")
                .to_string();
            let cycle_started = std::time::Instant::now();
            let discovered = client
                .discover_github_recent(limit as i64, min_stars, &pushed_since)
                .await;
            let discovered_count = discovered.len();
            let candidates = discovery_candidates(discovered, min_stars);
            let candidate_count = candidates.len();
            let mut queued = 0usize;
            let mut existing = 0usize;
            let mut failures = 0usize;
            for candidate in candidates {
                if service.get_result(&candidate.repo).is_some() {
                    existing += 1;
                    continue;
                }
                match service.enqueue_discovery(&candidate.repo, 0) {
                    Ok(_) => queued += 1,
                    Err(error) => {
                        failures += 1;
                        warn!(repo = %candidate.repo, %error, "Discovered repository could not be queued")
                    }
                }
            }
            info!(
                discovered = discovered_count,
                candidates = candidate_count,
                existing,
                queued,
                failures,
                elapsed_ms = cycle_started.elapsed().as_millis() as u64,
                "Repository discovery cycle completed"
            );
        }
    });
}

fn discovery_candidates(
    discovered: Vec<ai_supply_chain_trust_discovery::DiscoveredRepo>,
    min_stars: i64,
) -> Vec<ai_supply_chain_trust_discovery::DiscoveredRepo> {
    discovered
        .into_iter()
        .filter(|candidate| candidate.source.starts_with("github:"))
        .filter(|candidate| candidate.stars >= min_stars)
        .filter(|candidate| {
            let mut parts = candidate.repo.split('/');
            matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repo), None) if !owner.is_empty() && !repo.is_empty())
        })
        .collect()
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl-c") };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
    info!("Shutdown signal received");
}

fn verify_token(header: Option<&str>, expected_digest: &str) -> bool {
    if let Some(bearer) = header.and_then(|h| h.strip_prefix("Bearer ")) {
        verify_bearer_token(bearer, expected_digest)
    } else {
        false
    }
}

fn require_worker_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = state.worker_token.as_deref() else {
        return Err(ApiError::unauthorized());
    };
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    if verify_token(auth_header, token) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

// ---- Handlers ----

async fn health() -> &'static str {
    "healthy\n"
}

async fn healthz(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let metrics = state.service.metrics();
    let scans = metrics
        .get("scans_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1);
    if scans < 0 {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        Ok(Json(
            json!({"status":"ok","db":"connected","scans_total":scans}),
        ))
    }
}

async fn api_health() -> Json<Value> {
    Json(json!({"status":"ok","role":"rust"}))
}

async fn api_healthz(State(state): State<AppState>) -> Json<Value> {
    let m = state.service.metrics();
    Json(
        json!({"status":"ok","db":"connected","scans_total":m.get("scans_total").cloned().unwrap_or(json!(0))}),
    )
}
async fn api_index() -> Json<Value> {
    Json(json!({
        "service": "ai-supply-chain-trust",
        "version": "2.0.0-rust",
        "description": "Ready-to-use security context for public repositories: fixed-risk history, disclosed intelligence, recurring weak spots, and variant leads.",
        "access": "public repositories only. Free, no auth. Results are public.",
        "auth": "none (public, rate-limited per IP)",
        "base_url": "https://ai-supply-chain-trust.aibim.ai",
        "docs": "https://ai-supply-chain-trust.aibim.ai/api/v1/openapi.json",
        "artifacts": {
            "security_context_json": "/r/{owner}/{repo}.json",
            "security_context_md": "/r/{owner}/{repo}.md",
            "vulnerability_leads_json": "/r/{owner}/{repo}.leads.json",
            "vulnerability_leads_md": "/r/{owner}/{repo}.leads.md"
        },
        "endpoints": [
            {"method": "GET", "path": "/health", "summary": "Health check"},
            {"method": "GET", "path": "/api/v1/health", "summary": "JSON health"},
            {"method": "GET", "path": "/api/v1/healthz", "summary": "JSON DB health"},
            {"method": "GET", "path": "/api/v1/openapi.json", "summary": "OpenAPI 3.1.0 schema"},
            {"method": "GET", "path": "/api/v1/context/{owner}/{repo}", "summary": "Get security context envelope", "query": {"wait": "seconds (0-30, optional)"}},
            {"method": "POST", "path": "/api/v1/context", "summary": "Create/refresh context", "body": {"repo": "owner/name"}},
            {"method": "POST", "path": "/api/v1/scan", "summary": "Run trust scan", "body": {"repo": "owner/name"}},
            {"method": "POST", "path": "/api/v1/feedback", "summary": "Send product feedback", "body": {"category": "bug|data|idea|other", "message": "text", "repo": "owner/name (optional)", "page": "/path"}},
            {"method": "GET", "path": "/api/v1/leaderboard", "summary": "Leaderboard", "query": {"q": "search", "limit": "int"}},
            {"method": "GET", "path": "/api/v1/recent-scans", "summary": "Recent scans"},
            {"method": "GET", "path": "/api/v1/result", "summary": "Get result", "query": {"repo": "owner/name"}},
            {"method": "GET", "path": "/api/v1/history", "summary": "Report history", "query": {"repo": "owner/name"}},
            {"method": "GET", "path": "/api/v1/intel/hits", "summary": "Intelligence hits", "query": {"repo": "owner/name"}},
            {"method": "GET", "path": "/api/v1/pig", "summary": "Publisher identity", "query": {"account": "name"}},
            {"method": "GET", "path": "/api/v1/suggest", "summary": "Repo suggestions", "query": {"q": "search"}},
            {"method": "GET", "path": "/api/v1/scoring/versions", "summary": "Scoring versions"},
            {"method": "GET", "path": "/api/v1/metrics", "summary": "JSON metrics"},
            {"method": "GET", "path": "/api/v1/metrics/prometheus", "summary": "Prometheus metrics"},
            {"method": "GET", "path": "/api/v1/events", "summary": "SSE event stream"},
            {"method": "GET", "path": "/api/v1/jobs", "summary": "Recent scan jobs"},
            {"method": "GET", "path": "/api/v1/queue/stats", "summary": "Queue stats"},
            {"method": "GET", "path": "/api/v1/ops/failures", "summary": "Open failure inbox", "query": {"status": "open|acknowledged|resolved|all", "limit": "int"}},
            {"method": "POST", "path": "/api/v1/ops/failures/{id}/retry", "summary": "Retry failed scan or evidence work", "body": {"priority": "int"}},
            {"method": "POST", "path": "/api/v1/ops/failures/{id}/ack", "summary": "Acknowledge an open failure"},
            {"method": "POST", "path": "/api/v1/queue/pause", "summary": "Pause queue", "body": {"seconds": "int"}},
            {"method": "POST", "path": "/api/v1/queue/resume", "summary": "Resume queue"},
            {"method": "POST", "path": "/api/v1/queue/rescan", "summary": "Enqueue rescan", "body": {"repo": "owner/name", "priority": "int"}},
            {"method": "GET", "path": "/api/v1/admin/discrepancy", "summary": "CVE discrepancy diagnostics", "query": {"repo": "owner/name"}},
            {"method": "GET", "path": "/api/v1/admin/consistency", "summary": "Storage consistency diagnostics", "query": {"limit": "int"}},
            {"method": "GET", "path": "/r/{owner}/{repo}.json", "summary": "Security context JSON"},
            {"method": "GET", "path": "/r/{owner}/{repo}.md", "summary": "Security context Markdown"},
            {"method": "GET", "path": "/r/{owner}/{repo}.leads.json", "summary": "Vulnerability leads JSON"},
            {"method": "GET", "path": "/r/{owner}/{repo}.leads.md", "summary": "Vulnerability leads Markdown"},
        ],
        "tools": [
            {"name": "get_security_context", "description": "Get generated security context for a repository"},
            {"name": "get_vulnerability_leads", "description": "Get vulnerability variant-analysis leads"},
            {"name": "create_security_context", "description": "Create or refresh security context for a repo"}
        ]
    }))
}

pub fn openapi_schema() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "AI Supply Chain Trust API", "version": "2.0.0", "description": "Free repository trust and supply-chain scanner API"},
        "servers": [{"url": "https://ai-supply-chain-trust.aibim.ai"}],
        "paths": {
            "/health": {"get": {"summary": "Health check", "responses": {"200": {"description": "OK"}}}},
            "/api/v1/health": {"get": {"summary": "JSON health", "responses": {"200": {"description": "OK"}}}},
            "/api/v1/healthz": {"get": {"summary": "JSON DB health", "responses": {"200": {"description": "OK"}}}},
            "/api/v1/openapi.json": {"get": {"summary": "OpenAPI schema", "responses": {"200": {"description": "OpenAPI 3.1.0 schema"}}}},
            "/api/v1/context/{owner}/{repo}": {"get": {"summary": "Get security context", "parameters": [{"name":"owner","in":"path","required":true,"schema":{"type":"string"}},{"name":"repo","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Security context envelope"}}}},
            "/api/v1/context": {"post": {"summary": "Create/refresh context", "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"repo":{"type":"string"}}}}}},"responses":{"200":{"description":"Context created"}}}},
            "/api/v1/repos/{owner}/{repo}/regression-contracts": {"get": {"summary":"List evidence-backed regression contracts","responses":{"200":{"description":"Regression contracts"}}}},
            "/api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}": {"get": {"summary":"Get contract and lifecycle events","responses":{"200":{"description":"Regression contract"}}}},
            "/api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}/transitions": {"post": {"summary":"Transition contract lifecycle (authenticated)","responses":{"200":{"description":"Updated contract"},"409":{"description":"Version conflict"}}}},
            "/api/v1/repos/{owner}/{repo}/regression-assessments": {"post": {"summary":"Assess base/head diff and persist immutable results (authenticated)","responses":{"200":{"description":"PR check assessment"}}}},
            "/api/v1/repos/{owner}/{repo}/regression-assessments/{head_sha}": {"get": {"summary":"Get immutable assessments for a head SHA","responses":{"200":{"description":"Assessments"}}}},
            "/api/v1/scan": {"post": {"summary": "Run trust scan", "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"repo":{"type":"string"}}}}}},"responses":{"200":{"description":"Scan result"}}}},
            "/api/v1/feedback": {"post": {"summary": "Send product feedback", "requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["category","message","page"],"properties":{"category":{"type":"string","enum":["bug","data","idea","other"]},"message":{"type":"string","minLength":10,"maxLength":2000},"repo":{"type":"string"},"page":{"type":"string"}}}}}},"responses":{"202":{"description":"Feedback accepted"},"429":{"description":"Rate limited"}}}},
            "/api/v1/leaderboard": {"get": {"summary": "Leaderboard", "parameters":[{"name":"q","in":"query","schema":{"type":"string"}},{"name":"limit","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"Leaderboard rows"}}}},
            "/api/v1/recent-scans": {"get": {"summary": "Recent scans", "responses":{"200":{"description":"Recent scan rows"}}}},
            "/api/v1/result": {"get": {"summary": "Get result", "parameters":[{"name":"repo","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Evaluation result"}}}},
            "/api/v1/history": {"get": {"summary": "Report history", "parameters":[{"name":"repo","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Report history rows"}}}},
            "/api/v1/intel/hits": {"get": {"summary": "Security intelligence hits", "parameters":[{"name":"repo","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Security intelligence payload"}}}},
            "/api/v1/pig": {"get": {"summary": "Publisher identity graph node", "parameters":[{"name":"account","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Publisher identity summary"}}}},
            "/api/v1/suggest": {"get": {"summary": "Repository suggestions", "parameters":[{"name":"q","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Suggestion candidates"}}}},
            "/api/v1/scoring/versions": {"get": {"summary": "Scoring versions", "responses":{"200":{"description":"Available scoring versions"}}}},
            "/api/v1/metrics": {"get": {"summary": "JSON metrics", "responses":{"200":{"description":"Service metrics"}}}},
            "/api/v1/metrics/prometheus": {"get": {"summary": "Prometheus metrics", "responses":{"200":{"content":{"text/plain":{}}}}}},
            "/api/v1/events": {"get": {"summary": "SSE event stream", "responses":{"200":{"content":{"text/event-stream":{}}}}}},
            "/api/v1/jobs": {"get": {"summary": "Recent scan jobs", "parameters":[{"name":"limit","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"Recent scan jobs"}}}},
            "/api/v1/queue/stats": {"get": {"summary": "Queue stats", "responses":{"200":{"description":"Queue statistics"}}}},
            "/api/v1/ops/failures": {"get": {"summary": "Open failure inbox", "parameters":[{"name":"status","in":"query","schema":{"type":"string","enum":["open","acknowledged","resolved","all"]}},{"name":"limit","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"Failure alerts"}}}},
            "/api/v1/ops/failures/{id}/retry": {"post": {"summary": "Retry failed scan or evidence work", "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"priority":{"type":"integer"}}}}}},"responses":{"200":{"description":"Failure retry queued"}}}},
            "/api/v1/ops/failures/{id}/ack": {"post": {"summary": "Acknowledge an open failure", "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{"200":{"description":"Failure acknowledged"}}}},
            "/api/v1/queue/pause": {"post": {"summary": "Pause queue", "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"seconds":{"type":"integer"}}}}}},"responses":{"200":{"description":"Queue paused"}}}},
            "/api/v1/queue/resume": {"post": {"summary": "Resume queue", "responses":{"200":{"description":"Queue resumed"}}}},
            "/api/v1/queue/rescan": {"post": {"summary": "Enqueue rescan", "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"repo":{"type":"string"},"priority":{"type":"integer"}},"required":["repo"]}}}},"responses":{"200":{"description":"Job queued"}}}},
            "/api/v1/admin/discrepancy": {"get": {"summary": "CVE discrepancy diagnostics", "parameters":[{"name":"repo","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"Discrepancy diagnostics"}}}},
            "/api/v1/admin/consistency": {"get": {"summary": "Storage consistency diagnostics", "parameters":[{"name":"limit","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"Storage consistency diagnostics"}}}},
            "/r/{owner}/{repo}.json": {"get": {"summary": "Security context JSON artifact"}},
            "/r/{owner}/{repo}.md": {"get": {"summary": "Security context Markdown artifact"}},
            "/r/{owner}/{repo}.leads.json": {"get": {"summary": "Vulnerability leads JSON artifact"}},
            "/r/{owner}/{repo}.leads.md": {"get": {"summary": "Vulnerability leads Markdown artifact"}},
            "/mcp": {"post": {"summary": "MCP JSON-RPC endpoint", "requestBody":{"content":{"application/json":{}}},"responses":{"200":{"description":"JSON-RPC response"}}}}
        }
    })
}

async fn openapi() -> Json<Value> {
    Json(openapi_schema())
}

#[derive(Deserialize)]
struct CtxParams {
    wait: Option<i64>,
}

async fn get_context(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(p): Query<CtxParams>,
) -> Json<Value> {
    let _wait = p.wait.unwrap_or(0).min(60);
    let repo = validate_repo(&format!("{owner}/{repo}"))
        .unwrap_or_else(|_| normalize_repo_key(&format!("{owner}/{repo}")));
    Json(state.service.get_security_context(&repo, &state.base_url))
}

async fn regression_contracts_handler(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(&format!("{owner}/{repo}"))?;
    state
        .service
        .regression_contracts(&repo)
        .map(Json)
        .map_err(ApiError::internal)
}

async fn regression_contract_handler(
    State(state): State<AppState>,
    Path((owner, repo, contract_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(&format!("{owner}/{repo}"))?;
    state
        .service
        .regression_contract(&repo, &contract_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("regression contract not found"))
}

#[derive(Deserialize)]
struct RegressionTransitionBody {
    expected_version: i64,
    to_state: String,
    actor: String,
    reason: String,
    scope: Option<String>,
    comment: Option<String>,
    expires_at: Option<String>,
}

async fn regression_transition_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, contract_id)): Path<(String, String, String)>,
    axum::extract::Json(body): axum::extract::Json<RegressionTransitionBody>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    let repo = validate_repo(&format!("{owner}/{repo}"))?;
    state
        .service
        .transition_regression_contract(
            &repo,
            &contract_id,
            body.expected_version,
            &body.to_state,
            &body.actor,
            &body.reason,
            body.scope.as_deref().unwrap_or("contract"),
            body.comment.as_deref(),
            body.expires_at.as_deref(),
        )
        .map(Json)
        .map_err(|error| {
            if error.to_string().contains("version_conflict") {
                ApiError {
                    status: StatusCode::CONFLICT,
                    code: "version_conflict",
                    message: error.to_string(),
                }
            } else {
                ApiError::bad_request(error.to_string())
            }
        })
}

async fn regression_assessment_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    let repo = validate_repo(&format!("{owner}/{repo}"))?;
    state
        .service
        .assess_and_publish_regressions(&repo, &body)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn regression_assessments_handler(
    State(state): State<AppState>,
    Path((owner, repo, head_sha)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(&format!("{owner}/{repo}"))?;
    state
        .service
        .regression_assessments(&repo, &head_sha)
        .map(Json)
        .map_err(ApiError::internal)
}

#[derive(Deserialize)]
struct CreateCtxBody {
    repo: String,
}
async fn create_context(
    State(state): State<AppState>,
    axum::extract::Json(b): axum::extract::Json<CreateCtxBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let repo = validate_repo(&b.repo).map_err(|error| {
        (
            error.status,
            Json(json!({"error": error.message, "code": error.code})),
        )
    })?;
    let mut ctx = state.service.get_security_context(&repo, &state.base_url);
    let status = ctx.get("status").and_then(Value::as_str).unwrap_or("");
    if status == "ready" {
        if let Some(obj) = ctx.as_object_mut() {
            obj.insert("created".into(), json!(false));
        }
        return Ok(Json(ctx));
    }

    {
        let mut rl = state.rate_limiter.lock().await;
        if !rl.check_repo(&repo) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"rate_limited","code":"post_rate_limit"})),
            ));
        }
    }

    let _permit = acquire_permit(&state.scan_permits, "Scan capacity is currently full").map_err(
        |error| {
            (
                error.status,
                Json(json!({"error":error.message,"code":error.code})),
            )
        },
    )?;

    state
        .service
        .run_progressive_scan(&repo)
        .await
        .map_err(|error| public_scan_failure(&repo, error))?;
    ctx = state.service.get_security_context(&repo, &state.base_url);
    if let Some(obj) = ctx.as_object_mut() {
        obj.insert("created".into(), json!(true));
    }
    Ok(Json(ctx))
}

#[derive(Deserialize)]
struct FeedbackBody {
    category: String,
    message: String,
    #[serde(default)]
    repo: Option<String>,
    page: String,
    #[serde(default)]
    website: String,
}

async fn feedback_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<FeedbackBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    validate_feedback_origin(&state.base_url, &headers)?;
    if !body.website.trim().is_empty() {
        return Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))));
    }

    let category = body.category.trim().to_ascii_lowercase();
    if !matches!(category.as_str(), "bug" | "data" | "idea" | "other") {
        return Err(ApiError::bad_request("Invalid feedback category"));
    }
    let message = body.message.trim();
    if !(10..=2000).contains(&message.chars().count()) || message.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "Feedback must be between 10 and 2000 characters",
        ));
    }
    let page = body.page.trim();
    if !page.starts_with('/') || page.len() > 500 || page.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Invalid feedback page"));
    }
    let repo = body
        .repo
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(validate_repo)
        .transpose()?;

    let client_key = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 64)
        .unwrap_or("unknown");
    {
        let mut limiter = state.feedback_limiter.lock().await;
        if !limiter.check(client_key) {
            return Err(ApiError::too_many_requests());
        }
    }

    let webhook = std::env::var("AI_SUPPLY_CHAIN_TRUST_FEEDBACK_WEBHOOK_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("AI_SUPPLY_CHAIN_TRUST_ALERT_WEBHOOK_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| ApiError::unavailable("Feedback delivery is not configured"))?;
    if !webhook.starts_with("https://hooks.slack.com/services/") {
        warn!("Rejected non-Slack feedback webhook configuration");
        return Err(ApiError::unavailable("Feedback delivery is not configured"));
    }

    let metadata = match repo {
        Some(repo) => format!("Category: {category} · Repository: {repo} · Page: {page}"),
        None => format!("Category: {category} · Page: {page}"),
    };
    let payload = json!({
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "AI Supply Chain Trust feedback"}},
            {"type": "section", "text": {"type": "plain_text", "text": message}},
            {"type": "context", "elements": [{"type": "plain_text", "text": metadata}]}
        ]
    });
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| ApiError::unavailable("Feedback delivery is temporarily unavailable"))?
        .post(webhook)
        .json(&payload)
        .send()
        .await
        .map_err(|error| {
            warn!(%error, "Feedback Slack delivery failed");
            ApiError::unavailable("Feedback delivery is temporarily unavailable")
        })?;
    if !response.status().is_success() {
        warn!(status = %response.status(), "Feedback Slack delivery was rejected");
        return Err(ApiError::unavailable(
            "Feedback delivery is temporarily unavailable",
        ));
    }

    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}

fn validate_feedback_origin(base_url: &str, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Feedback origin is required"))?;
    if origin.trim_end_matches('/') != base_url.trim_end_matches('/') {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "invalid_origin",
            message: "Feedback origin is not allowed".into(),
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct ScanBody {
    repo: String,
}

async fn scan(
    State(state): State<AppState>,
    axum::extract::Json(body): axum::extract::Json<ScanBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let repo = validate_repo(&body.repo).map_err(|error| {
        (
            error.status,
            Json(json!({"error": error.message, "code": error.code})),
        )
    })?;
    {
        let mut rl = state.rate_limiter.lock().await;
        if !rl.check_repo(&repo) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"rate_limited","code":"post_rate_limit"})),
            ));
        }
    }
    let _permit = acquire_permit(&state.scan_permits, "Scan capacity is currently full").map_err(
        |error| {
            (
                error.status,
                Json(json!({"error":error.message,"code":error.code})),
            )
        },
    )?;
    match state.service.run_progressive_scan(&repo).await {
        Ok((job_id, r)) => Ok(Json(
            json!({"repo":repo,"job_id":job_id,"status":"enriching","report":r}),
        )),
        Err(error) => Err(public_scan_failure(&repo, error)),
    }
}

fn public_scan_failure(repo: &str, error: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    warn!(repo, %error, "Interactive scan failed");
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": "Scan could not be completed",
            "code": "scan_failed"
        })),
    )
}

#[derive(Deserialize)]
struct LbQuery {
    q: Option<String>,
    limit: Option<i64>,
}
async fn leaderboard(State(state): State<AppState>, Query(p): Query<LbQuery>) -> Json<Value> {
    Json(
        state
            .service
            .leaderboard(p.q.as_deref(), p.limit.unwrap_or(20)),
    )
}

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<i64>,
}
async fn recent_scans(State(state): State<AppState>, Query(p): Query<RecentQuery>) -> Json<Value> {
    Json(state.service.recent_scans(p.limit.unwrap_or(20)))
}

#[derive(Deserialize)]
struct ResultQuery {
    repo: Option<String>,
}
async fn result(
    State(state): State<AppState>,
    Query(p): Query<ResultQuery>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .get_result(&validate_repo(
            &p.repo
                .ok_or_else(|| ApiError::bad_request("repo is required"))?,
        )?)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("repository result not found"))
}

async fn metrics(State(state): State<AppState>) -> Json<Value> {
    let mut metrics = state.service.metrics();
    if let Some(object) = metrics.as_object_mut() {
        object.insert(
            "llm_runtime".into(),
            ai_supply_chain_trust_llm::runtime_telemetry_snapshot(),
        );
    }
    Json(metrics)
}

#[derive(Deserialize)]
struct HistoryQuery {
    repo: Option<String>,
}
async fn history(
    State(state): State<AppState>,
    Query(p): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(
        &p.repo
            .ok_or_else(|| ApiError::bad_request("repo is required"))?,
    )?;
    Ok(Json(json!(state.service.get_history(&repo))))
}

#[derive(Deserialize)]
struct IntelQuery {
    repo: Option<String>,
}
async fn intel_hits(
    State(state): State<AppState>,
    Query(p): Query<IntelQuery>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(
        &p.repo
            .ok_or_else(|| ApiError::bad_request("repo is required"))?,
    )?;
    Ok(Json(state.service.get_intel_hits(&repo)))
}

#[derive(Deserialize)]
struct PigQuery {
    account: Option<String>,
}
async fn pig_node(
    State(state): State<AppState>,
    Query(p): Query<PigQuery>,
) -> Result<Json<Value>, StatusCode> {
    let account = p.account.ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(state.service.get_pig_node(&account)))
}

#[derive(Deserialize)]
struct SuggestQuery {
    q: Option<String>,
}
async fn suggest(
    State(state): State<AppState>,
    Query(p): Query<SuggestQuery>,
) -> Result<Json<Value>, StatusCode> {
    let q = p.q.ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(state.service.suggest(&q).await))
}

async fn scoring_versions(State(state): State<AppState>) -> Json<Value> {
    Json(state.service.get_scoring_versions())
}

async fn queue_stats_handler(State(state): State<AppState>) -> Json<Value> {
    Json(state.service.queue_stats())
}

async fn jobs_handler(State(state): State<AppState>, Query(p): Query<RecentQuery>) -> Json<Value> {
    Json(state.service.scan_jobs_recent(p.limit.unwrap_or(50)))
}

#[derive(Deserialize)]
struct FailureQuery {
    status: Option<String>,
    limit: Option<i64>,
}

async fn failure_alerts_handler(
    State(state): State<AppState>,
    Query(p): Query<FailureQuery>,
) -> Json<Value> {
    Json(
        state
            .service
            .failure_alerts(p.status.as_deref(), p.limit.unwrap_or(50)),
    )
}

#[derive(Deserialize)]
struct FailureRetryBody {
    priority: Option<i64>,
}

async fn failure_retry_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<axum::extract::Json<FailureRetryBody>>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    let priority = body.map(|body| body.priority.unwrap_or(100)).unwrap_or(100);
    match state.service.retry_failure_alert(id, priority) {
        Ok(Some(value)) => Ok(Json(value)),
        Ok(None) => Err(ApiError::not_found("failure alert not found")),
        Err(error) => Err(ApiError::internal(error)),
    }
}

async fn failure_ack_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    match state.service.acknowledge_failure_alert(id) {
        Ok(true) => Ok(Json(json!({"status":"acknowledged","id":id}))),
        Ok(false) => Err(ApiError::not_found("open failure alert not found")),
        Err(error) => Err(ApiError::internal(error)),
    }
}

const SITEMAP_REPOSITORY_LIMIT: usize = 500;

async fn sitemap_xml(State(state): State<AppState>) -> Response {
    let base = state.base_url.trim_end_matches('/');
    let recent = state.service.recent_scans(SITEMAP_REPOSITORY_LIMIT as i64);
    let core_pages = [
        ("/", "1.0", "daily"),
        ("/contexts", "0.9", "daily"),
        ("/leaderboard", "0.8", "daily"),
        ("/about", "0.6", "monthly"),
        ("/editorial-policy", "0.6", "monthly"),
        ("/privacy", "0.5", "monthly"),
    ];

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#,
    );
    for (path, priority, changefreq) in core_pages {
        append_sitemap_url(
            &mut xml,
            &format!("{base}{path}"),
            None,
            priority,
            changefreq,
        );
    }

    let mut seen_repositories = std::collections::BTreeSet::new();
    if let Some(rows) = recent.get("rows").and_then(Value::as_array) {
        for row in rows.iter().take(SITEMAP_REPOSITORY_LIMIT) {
            if let Some(repo) = row.get("repo").and_then(Value::as_str) {
                let repo = repo.trim_matches('/');
                if !repo.is_empty()
                    && repo.contains('/')
                    && seen_repositories.insert(repo.to_ascii_lowercase())
                {
                    let lastmod = row
                        .get("evaluated_at")
                        .and_then(Value::as_str)
                        .filter(|value| is_w3c_date(value));
                    append_sitemap_url(
                        &mut xml,
                        &format!("{base}/r/{repo}"),
                        lastmod,
                        "0.7",
                        "weekly",
                    );
                }
            }
        }
    }
    xml.push_str("</urlset>\n");

    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

fn append_sitemap_url(
    xml: &mut String,
    url: &str,
    lastmod: Option<&str>,
    priority: &str,
    changefreq: &str,
) {
    xml.push_str("  <url>\n    <loc>");
    xml.push_str(&xml_escape(url));
    xml.push_str("</loc>\n");
    if let Some(lastmod) = lastmod {
        xml.push_str("    <lastmod>");
        xml.push_str(lastmod);
        xml.push_str("</lastmod>\n");
    }
    xml.push_str("    <changefreq>");
    xml.push_str(changefreq);
    xml.push_str("</changefreq>\n    <priority>");
    xml.push_str(priority);
    xml.push_str("</priority>\n  </url>\n");
}

fn is_w3c_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Deserialize)]
struct PauseBody {
    seconds: i64,
}
async fn queue_pause_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(b): axum::extract::Json<PauseBody>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    state.service.pause_queue(b.seconds).ok();
    Ok(Json(json!({"status":"paused","seconds":b.seconds})))
}
async fn queue_resume_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    state.service.resume_queue().ok();
    Ok(Json(json!({"status":"resumed"})))
}

#[derive(Deserialize)]
struct RescanBody {
    repo: String,
    priority: Option<i64>,
}
async fn queue_rescan_handler(
    State(state): State<AppState>,
    axum::extract::Json(b): axum::extract::Json<RescanBody>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(&b.repo)?;
    {
        let mut limiter = state.rate_limiter.lock().await;
        if !limiter.check_repo(&repo) {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                message: "Too many rescan requests; please try again later".into(),
            });
        }
    }
    let priority = b.priority.unwrap_or(0).clamp(-100, 100);
    match state.service.enqueue_rescan(&repo, priority) {
        Ok(job_id) => Ok(Json(json!({"status":"queued", "job_id": job_id}))),
        Err(error) => Err(ApiError::internal(error)),
    }
}

#[derive(Deserialize)]
struct DiscrepancyQuery {
    repo: Option<String>,
}
async fn discrepancy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DiscrepancyQuery>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    let repo = q.repo.unwrap_or_default();
    Ok(Json(state.service.discrepancy_log(&repo)))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    limit: Option<i64>,
}
async fn consistency_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsistencyQuery>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    Ok(Json(
        state
            .service
            .storage_consistency_check(q.limit.unwrap_or(100)),
    ))
}

async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    require_worker_token(&state, &headers)?;
    let m = state.service.metrics();
    let runtime = ai_supply_chain_trust_llm::runtime_telemetry_snapshot();
    let scans = m.get("scans_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let unique = m.get("unique_repos").and_then(|v| v.as_i64()).unwrap_or(0);
    let llm_total = m
        .get("llm_decisions_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let llm_rejected = m
        .get("llm_hallucination_rejections_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let llm_rejection_rate = m
        .get("llm_hallucination_rejection_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let llm_rate_limited = m
        .get("llm_rate_limited_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let llm_model_missing = m
        .get("llm_model_missing_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let llm_latency_average_ms = m
        .get("llm_latency_average_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let llm_latency_samples = m
        .get("llm_latency_samples_total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mut text = format!(
        "# HELP ai_supply_chain_trust_scans_total Total evaluations\n# TYPE ai_supply_chain_trust_scans_total counter\nai_supply_chain_trust_scans_total {scans}\n# HELP ai_supply_chain_trust_unique_repos Unique repositories\n# TYPE ai_supply_chain_trust_unique_repos gauge\nai_supply_chain_trust_unique_repos {unique}\n# HELP ai_supply_chain_trust_llm_decisions_total LLM decision records by source/model/task\n# TYPE ai_supply_chain_trust_llm_decisions_total counter\nai_supply_chain_trust_llm_decisions_total {llm_total}\n# HELP ai_supply_chain_trust_llm_hallucination_rejections_total LLM outputs rejected by deterministic fact checking\n# TYPE ai_supply_chain_trust_llm_hallucination_rejections_total counter\nai_supply_chain_trust_llm_hallucination_rejections_total {llm_rejected}\n# HELP ai_supply_chain_trust_llm_hallucination_rejection_rate Rejected LLM decisions divided by total LLM decisions\n# TYPE ai_supply_chain_trust_llm_hallucination_rejection_rate gauge\nai_supply_chain_trust_llm_hallucination_rejection_rate {llm_rejection_rate}\n# HELP ai_supply_chain_trust_llm_rate_limited_total LLM outcomes caused by upstream HTTP 429\n# TYPE ai_supply_chain_trust_llm_rate_limited_total counter\nai_supply_chain_trust_llm_rate_limited_total {llm_rate_limited}\n# HELP ai_supply_chain_trust_llm_model_missing_total LLM decision records without model metadata\n# TYPE ai_supply_chain_trust_llm_model_missing_total gauge\nai_supply_chain_trust_llm_model_missing_total {llm_model_missing}\n# HELP ai_supply_chain_trust_llm_latency_average_ms Average latency of persisted LLM outcomes with latency data\n# TYPE ai_supply_chain_trust_llm_latency_average_ms gauge\nai_supply_chain_trust_llm_latency_average_ms {llm_latency_average_ms}\n# HELP ai_supply_chain_trust_llm_latency_samples_total Persisted LLM outcomes with latency data\n# TYPE ai_supply_chain_trust_llm_latency_samples_total counter\nai_supply_chain_trust_llm_latency_samples_total {llm_latency_samples}\n"
    );
    let runtime_calls = runtime
        .get("calls_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let runtime_successes = runtime
        .get("successes_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let runtime_failures = runtime
        .get("failures_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let runtime_latency = runtime
        .get("latency_average_ms")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    text.push_str(&format!(
        "# HELP ai_supply_chain_trust_llm_runtime_calls_total Exact OpenRouter HTTP attempts in the current process\n# TYPE ai_supply_chain_trust_llm_runtime_calls_total counter\nai_supply_chain_trust_llm_runtime_calls_total {runtime_calls}\n# HELP ai_supply_chain_trust_llm_runtime_successes_total Successful schema-shaped OpenRouter responses in the current process\n# TYPE ai_supply_chain_trust_llm_runtime_successes_total counter\nai_supply_chain_trust_llm_runtime_successes_total {runtime_successes}\n# HELP ai_supply_chain_trust_llm_runtime_failures_total Failed OpenRouter attempts in the current process\n# TYPE ai_supply_chain_trust_llm_runtime_failures_total counter\nai_supply_chain_trust_llm_runtime_failures_total {runtime_failures}\n# HELP ai_supply_chain_trust_llm_runtime_latency_average_ms Average OpenRouter HTTP attempt latency in the current process\n# TYPE ai_supply_chain_trust_llm_runtime_latency_average_ms gauge\nai_supply_chain_trust_llm_runtime_latency_average_ms {runtime_latency}\n"
    ));
    if let Some(outcomes) = runtime
        .get("by_task_model_outcome")
        .and_then(Value::as_array)
    {
        for item in outcomes {
            let Some(count) = item.get("count").and_then(Value::as_u64) else {
                continue;
            };
            let model = prometheus_label_value(item.get("model").and_then(Value::as_str));
            let task = prometheus_label_value(item.get("task").and_then(Value::as_str));
            let outcome = prometheus_label_value(item.get("outcome").and_then(Value::as_str));
            text.push_str(&format!(
                "ai_supply_chain_trust_llm_runtime_calls_total{{model=\"{model}\",task=\"{task}\",outcome=\"{outcome}\"}} {count}\n"
            ));
        }
    }
    if let Some(items) = m
        .get("llm_decisions_by_model_task")
        .and_then(Value::as_object)
    {
        for item in items.values() {
            let Some(count) = item.get("count").and_then(Value::as_i64) else {
                continue;
            };
            let model = prometheus_label_value(item.get("model").and_then(Value::as_str));
            let task = prometheus_label_value(item.get("task").and_then(Value::as_str));
            let decision_source =
                prometheus_label_value(item.get("decision_source").and_then(Value::as_str));
            text.push_str(&format!(
                "ai_supply_chain_trust_llm_decisions_total{{model=\"{model}\",task=\"{task}\",decision_source=\"{decision_source}\"}} {count}\n"
            ));
        }
    }
    Ok(axum::response::Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(text))
        .unwrap())
}

fn prometheus_label_value(value: Option<&str>) -> String {
    value
        .unwrap_or("unknown")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn serve_static(req: axum::http::Request<axum::body::Body>) -> axum::response::Response {
    let request_path = req.uri().path();
    if request_path == "/free-tools" || request_path.starts_with("/free-tools/") {
        let suffix = request_path.strip_prefix("/free-tools").unwrap_or_default();
        let mut location = if suffix.is_empty() {
            "/".to_string()
        } else {
            suffix.to_string()
        };
        if let Some(query) = req.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        return axum::response::Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, location)
            .body(axum::body::Body::empty())
            .unwrap();
    }
    let path = request_path.trim_start_matches('/');
    if !is_safe_static_path(path) {
        return axum::response::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from("bad request"))
            .unwrap();
    }
    let web_dir = frontend_web_dir();
    let requested_path =
        std::path::Path::new(&web_dir).join(if path.is_empty() { "index.html" } else { path });
    let file_path = if requested_path.exists() && requested_path.is_file() {
        requested_path
    } else if path.is_empty() || std::path::Path::new(path).extension().is_none() {
        std::path::Path::new(&web_dir).join("index.html")
    } else {
        requested_path
    };

    if file_path.exists() && file_path.is_file() {
        let content = tokio::fs::read(&file_path).await.unwrap_or_default();
        let mime = mime_guess::from_path(&file_path).first_or_octet_stream();
        let file_name = file_path.file_name().and_then(|v| v.to_str());
        let is_bundled_asset = path.starts_with("assets/js/") || path.starts_with("assets/css/");
        let cache_control = if file_name == Some("index.html") {
            "no-cache, no-store, must-revalidate"
        } else if is_bundled_asset {
            "no-cache, must-revalidate"
        } else {
            "public, max-age=3600"
        };
        axum::response::Response::builder()
            .header("Content-Type", mime.as_ref())
            .header("Cache-Control", cache_control)
            .body(axum::body::Body::from(content))
            .unwrap()
    } else {
        axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap()
    }
}

fn is_safe_static_path(path: &str) -> bool {
    !std::path::Path::new(path).components().any(|component| {
        !matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    })
}

fn frontend_web_dir() -> String {
    if let Ok(path) = std::env::var("AI_SUPPLY_CHAIN_TRUST_WEB_DIR") {
        return path;
    }
    let local = std::path::Path::new("frontend/web");
    if local.join("index.html").exists() {
        return local.to_string_lossy().to_string();
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../frontend/web")
        .to_string_lossy()
        .to_string()
}

// ---- SSE events ----

async fn events_sse(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let permit = acquire_permit(
        &state.sse_permits,
        "Event stream capacity is currently full",
    )?;
    let requested_cursor = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    let db = state.service.db.clone();
    let mut cursor = requested_cursor.unwrap_or_else(|| db.latest_trust_event_id());
    let stream = async_stream::stream! {
        let _permit = permit;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            for event in db.trust_events_after(cursor, 100) {
                if let Some(id) = event.get("id").and_then(Value::as_i64) {
                    cursor = id;
                    yield Ok(Event::default().id(id.to_string()).data(event.to_string()));
                }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ---- MCP endpoint ----

#[derive(Deserialize)]
struct McpConfigQuery {
    client: Option<String>,
}

async fn mcp_info(Query(query): Query<McpConfigQuery>, headers: HeaderMap) -> Response {
    let client = normalize_mcp_client(query.client.as_deref());
    let endpoint = mcp_endpoint_from_headers(&headers);
    let accepts_html = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/html"));
    if accepts_html {
        return Html(mcp_config_html(client)).into_response();
    }

    Json(json!({
        "client": client,
        "endpoint": endpoint,
        "config": mcp_config_for_client(client, &endpoint),
    }))
    .into_response()
}

fn normalize_mcp_client(client: Option<&str>) -> &'static str {
    match client.unwrap_or("cursor").to_ascii_lowercase().as_str() {
        "codex" => "codex",
        "claude" => "claude",
        "vscode" | "vs-code" | "vs_code" => "vscode",
        "other" => "other",
        _ => "cursor",
    }
}

fn mcp_endpoint_from_headers(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("127.0.0.1:8000");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| {
            if host.starts_with("127.0.0.1") || host.starts_with("localhost") {
                "http"
            } else {
                "https"
            }
        });
    format!("{proto}://{host}/mcp")
}

fn mcp_config_for_client(client: &str, endpoint: &str) -> Value {
    match client {
        "codex" => json!(format!("codex mcp add securitycontext {endpoint}")),
        "claude" => json!(format!(
            "claude mcp add --transport http securitycontext {endpoint}"
        )),
        "vscode" => json!({"servers":{"securitycontext":{"url":endpoint,"type":"http"}}}),
        _ => json!({"mcpServers":{"securitycontext":{"url":endpoint}}}),
    }
}

fn mcp_config_html(initial_client: &str) -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Supply Chain Trust MCP</title>
  <style>
    :root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#171717;background:#fafafa}
    body{margin:0;display:grid;min-height:100vh;place-items:center;padding:24px}
    main{width:min(100%,760px);display:grid;gap:18px}
    h1{margin:0;font-size:28px;letter-spacing:0}
    p{margin:0;color:#666}
    label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#666;font-weight:700}
    select,button{min-height:42px;border:1px solid #d4d4d4;border-radius:8px;background:#fff;color:#171717;padding:0 12px;font-weight:700}
    pre{margin:0;overflow:auto;white-space:pre-wrap;word-break:break-word;border:1px solid #d4d4d4;border-radius:10px;background:#fff;padding:16px;line-height:1.45}
    .row{display:flex;gap:10px;align-items:end;flex-wrap:wrap}
    .field{display:grid;gap:6px}
    code{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  </style>
</head>
<body>
  <main>
    <div>
      <h1>AI Supply Chain Trust MCP</h1>
      <p>Select your agent and copy the matching MCP configuration.</p>
    </div>
    <div class="row">
      <div class="field">
        <label for="client">Client</label>
        <select id="client">
          <option value="cursor">Cursor</option>
          <option value="codex">Codex</option>
          <option value="claude">Claude</option>
          <option value="vscode">VS Code</option>
          <option value="other">Other</option>
        </select>
      </div>
      <button id="copy" type="button">Copy</button>
    </div>
    <pre><code id="config"></code></pre>
  </main>
  <script>
    const endpoint = location.origin + "/mcp";
    const client = document.getElementById("client");
    const config = document.getElementById("config");
    const initialClient = "{initial_client}";
    const snippets = {
      cursor: () => JSON.stringify({mcpServers:{securitycontext:{url:endpoint}}}, null, 2),
      other: () => JSON.stringify({mcpServers:{securitycontext:{url:endpoint}}}, null, 2),
      codex: () => "codex mcp add securitycontext " + endpoint,
      claude: () => "claude mcp add --transport http securitycontext " + endpoint,
      vscode: () => JSON.stringify({servers:{securitycontext:{url:endpoint,type:"http"}}}, null, 2)
    };
    function render(){ config.textContent = snippets[client.value](); }
    client.value = snippets[initialClient] ? initialClient : "cursor";
    client.addEventListener("change", render);
    document.getElementById("copy").addEventListener("click", () => navigator.clipboard.writeText(config.textContent));
    render();
  </script>
</body>
</html>"#
    .replace("{initial_client}", initial_client)
}

async fn mcp_handler(
    State(state): State<AppState>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Json<Value> {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let params = body.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "initialize" => {
            json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"ai-supply-chain-trust","version":"2.0.0"}})
        }
        "tools/list" => json!({"tools":[
            {"name":"get_security_context","description":"Get generated security context for a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string","description":"owner/repo"}},"required":["repo"]}},
            {"name":"get_vulnerability_leads","description":"Get variant-analysis leads","inputSchema":{"type":"object","properties":{"repo":{"type":"string","description":"owner/repo"}},"required":["repo"]}},
            {"name":"create_security_context","description":"Create or refresh security context","inputSchema":{"type":"object","properties":{"repo":{"type":"string","description":"owner/repo"}},"required":["repo"]}}
        ]}),
        "tools/call" => {
            let tool = params.get("name").and_then(Value::as_str).unwrap_or("");
            let empty_args = json!({});
            let args = params.get("arguments").unwrap_or(&empty_args);
            let repo = args.get("repo").and_then(Value::as_str).unwrap_or("");

            match tool {
                "get_security_context" => match validate_repo(repo) {
                    Ok(repo) => {
                        let ctx = state.service.get_security_context(&repo, &state.base_url);
                        json!({"content":[{"type":"text","text":serde_json::to_string(&ctx).unwrap_or_default()}],"structuredContent":ctx})
                    }
                    Err(_) => {
                        json!({"isError":true,"content":[{"type":"text","text":"Invalid repository; expected owner/repository"}]})
                    }
                },
                "get_vulnerability_leads" => match validate_repo(repo) {
                    Ok(repo) => {
                        let ctx = state.service.get_security_context(&repo, &state.base_url);
                        let leads = ctx.get("leads").cloned().unwrap_or(json!([]));
                        json!({"content":[{"type":"text","text":serde_json::to_string(&leads).unwrap_or_default()}],"structuredContent":leads})
                    }
                    Err(_) => {
                        json!({"isError":true,"content":[{"type":"text","text":"Invalid repository; expected owner/repository"}]})
                    }
                },
                "create_security_context" => {
                    let Ok(repo) = validate_repo(repo) else {
                        return Json(
                            json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"Invalid repository; expected owner/repository"}]}}),
                        );
                    };
                    let permit =
                        acquire_permit(&state.scan_permits, "Scan capacity is currently full");
                    if permit.is_err() {
                        return Json(
                            json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"Scan capacity is currently full"}]}}),
                        );
                    }
                    let _permit = permit.expect("checked permit");
                    let mut ctx = state.service.get_security_context(&repo, &state.base_url);
                    if ctx.get("status").and_then(Value::as_str) != Some("ready") {
                        match state.service.run_progressive_scan(&repo).await {
                            Ok(_) => {
                                ctx = state.service.get_security_context(&repo, &state.base_url);
                                if let Some(obj) = ctx.as_object_mut() {
                                    obj.insert("created".into(), json!(true));
                                }
                            }
                            Err(error) => {
                                ctx = json!({"repo": repo, "status": "error", "error": error});
                            }
                        }
                    } else if let Some(obj) = ctx.as_object_mut() {
                        obj.insert("created".into(), json!(false));
                    }
                    json!({"content":[{"type":"text","text":format!("Security context for {repo}")}],"structuredContent":ctx})
                }
                _ => json!({"error":{"code":-32601,"message":format!("Unknown tool: {tool}")}}),
            }
        }
        _ => json!({"error":{"code":-32601,"message":format!("Unknown method: {method}")}}),
    };

    Json(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

// ---- Artifact handlers ----

async fn security_context_artifact(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> axum::response::Response {
    let path = path.trim_matches('/');
    let (repo, format) = if let Some(repo) = path.strip_suffix(".leads.json") {
        (repo, "leads_json")
    } else if let Some(repo) = path.strip_suffix(".json") {
        (repo, "context_json")
    } else if let Some(repo) = path.strip_suffix(".md") {
        (repo, "markdown")
    } else {
        (path, "html")
    };

    if repo.split('/').count() != 2 {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap();
    }

    if format == "html" {
        let req = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        return serve_static(req).await;
    }

    let ctx = state.service.get_security_context(repo, &state.base_url);
    match format {
        "context_json" => axum::response::Response::builder()
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&ctx.get("context").cloned().unwrap_or(json!({})))
                    .unwrap_or_default(),
            ))
            .unwrap(),
        "leads_json" => axum::response::Response::builder()
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&ctx.get("leads").cloned().unwrap_or(json!({})))
                    .unwrap_or_default(),
            ))
            .unwrap(),
        "markdown" => {
            let md = format!(
                "# Security Context: {}\n\n```json\n{}\n```\n",
                repo,
                serde_json::to_string_pretty(&ctx).unwrap_or_default()
            );
            axum::response::Response::builder()
                .header("Content-Type", "text/markdown")
                .body(axum::body::Body::from(md))
                .unwrap()
        }
        _ => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body;
    use axum::body::Body;
    use axum::http::Request;
    use axum::response::Response;
    use tokio_stream::StreamExt;

    async fn response_text(response: Response) -> String {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).expect("utf8 response")
    }

    #[tokio::test]
    async fn health_returns_ok() {
        assert_eq!(health().await, "healthy\n");
    }

    #[test]
    fn public_scan_failure_hides_upstream_diagnostics() {
        let (status, payload) = public_scan_failure(
            "owner/repo",
            "GitHubTimeout https://api.github.com/repos/owner/repo?token=secret",
        );

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(payload.0["code"], json!("scan_failed"));
        assert_eq!(payload.0["error"], json!("Scan could not be completed"));
        let serialized = payload.0.to_string();
        assert!(!serialized.contains("GitHub"));
        assert!(!serialized.contains("secret"));
    }

    #[tokio::test]
    async fn sse_stream_delivers_events_persisted_after_connection() {
        let db = Arc::new(Database::open_memory().unwrap());
        let service = Arc::new(Service::new(db.clone(), None));
        let state = AppState {
            service,
            base_url: "http://localhost".to_string(),
            worker_token: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let response = events_sse(State(state), HeaderMap::new())
            .await
            .into_response();
        db.publish_trust_event("owner/repo", "scan_complete", &json!({"score": 81}))
            .unwrap();

        let mut body = response.into_body().into_data_stream();
        let chunk = tokio::time::timeout(Duration::from_secs(2), body.next())
            .await
            .expect("SSE event deadline")
            .expect("SSE body chunk")
            .expect("SSE body result");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("event_type"));
        assert!(text.contains("scan_complete"));
        assert!(text.contains("owner/repo"));
        assert!(text.contains("\"score\":81"));
    }

    #[test]
    fn repository_validation_accepts_canonical_github_forms() {
        assert_eq!(validate_repo("drupal/drupal").unwrap(), "drupal/drupal");
        assert_eq!(
            validate_repo("r1z4x/OWASPAttackSimulator").unwrap(),
            "r1z4x/owaspattacksimulator"
        );
        assert_eq!(
            validate_repo("https://github.com/drupal/drupal.git").unwrap(),
            "drupal/drupal"
        );
    }

    #[test]
    fn repository_validation_rejects_partial_or_ambiguous_input() {
        assert_eq!(
            validate_repo("drupal").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            validate_repo("owner/repo/extra").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        for malicious in [
            "owner/repo?ref=other",
            "owner/repo#fragment",
            "owner%2frepo/target",
            "owner/repo\\child",
            "https://attacker.example/owner/repo",
            "https://user@github.com/owner/repo",
            "-owner/repo",
            "owner/..",
        ] {
            assert_eq!(
                validate_repo(malicious).unwrap_err().status,
                StatusCode::BAD_REQUEST,
                "accepted malicious repository identity: {malicious}"
            );
        }
    }

    #[test]
    fn work_admission_rejects_capacity_overflow() {
        let pool = Arc::new(Semaphore::new(1));
        let permit = acquire_permit(&pool, "full").expect("first permit");
        let error = acquire_permit(&pool, "full").unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        drop(permit);
        assert!(acquire_permit(&pool, "full").is_ok());
    }

    #[test]
    fn feedback_origin_must_match_public_base_url() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            "https://ai-supply-chain-trust.aibim.ai".parse().unwrap(),
        );
        assert!(
            validate_feedback_origin("https://ai-supply-chain-trust.aibim.ai/", &headers).is_ok()
        );

        headers.insert(header::ORIGIN, "https://attacker.example".parse().unwrap());
        assert_eq!(
            validate_feedback_origin("https://ai-supply-chain-trust.aibim.ai", &headers)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn feedback_rate_limiter_enforces_short_window() {
        let mut limiter = RateLimiter::new(3, 600);
        assert!(limiter.check("203.0.113.9"));
        assert!(limiter.check("203.0.113.9"));
        assert!(limiter.check("203.0.113.9"));
        assert!(!limiter.check("203.0.113.9"));
        assert!(limiter.check("203.0.113.10"));
    }

    #[tokio::test]
    async fn openapi_covers_browser_client_endpoints() {
        let schema = openapi().await.0;
        let paths = schema["paths"].as_object().expect("OpenAPI paths");
        for path in [
            "/api/v1/context",
            "/api/v1/context/{owner}/{repo}",
            "/api/v1/repos/{owner}/{repo}/regression-contracts",
            "/api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}",
            "/api/v1/repos/{owner}/{repo}/regression-contracts/{contract_id}/transitions",
            "/api/v1/repos/{owner}/{repo}/regression-assessments",
            "/api/v1/repos/{owner}/{repo}/regression-assessments/{head_sha}",
            "/api/v1/scan",
            "/api/v1/feedback",
            "/api/v1/recent-scans",
            "/api/v1/jobs",
            "/api/v1/queue/stats",
            "/api/v1/queue/rescan",
            "/api/v1/leaderboard",
            "/api/v1/result",
            "/api/v1/history",
            "/api/v1/intel/hits",
            "/r/{owner}/{repo}.json",
            "/r/{owner}/{repo}.md",
            "/r/{owner}/{repo}.leads.json",
            "/r/{owner}/{repo}.leads.md",
        ] {
            assert!(paths.contains_key(path), "Missing browser API path {path}");
        }
    }

    #[tokio::test]
    async fn root_serves_frontend_shell() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = serve_static(req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("/assets/css/design-system.css"));
        assert!(text.contains("AI Supply Chain Trust"));
        assert!(!text.contains("Rust v2.0"));
    }

    #[tokio::test]
    async fn extensionless_frontend_routes_serve_shell() {
        let req = Request::builder()
            .uri("/leaderboard")
            .body(Body::empty())
            .unwrap();
        let response = serve_static(req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("/assets/js/app.js"));
    }

    #[tokio::test]
    async fn legacy_free_tools_routes_redirect_to_canonical_root_paths() {
        let req = Request::builder()
            .uri("/free-tools/r/owner/repo?scan=queued")
            .body(Body::empty())
            .unwrap();
        let response = serve_static(req).await;

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/r/owner/repo?scan=queued"
        );
    }

    #[tokio::test]
    async fn static_routes_reject_parent_directory_traversal() {
        let req = Request::builder()
            .uri("/../Cargo.toml")
            .body(Body::empty())
            .unwrap();
        let response = serve_static(req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn security_context_html_route_serves_frontend_shell() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = AppState {
            service: Arc::new(Service::new(db, None)),
            base_url: "http://localhost".to_string(),
            worker_token: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let response =
            security_context_artifact(State(state), Path("wolfssl/wolfssl".to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("app-header"));
        assert!(text.contains("/assets/js/app.js"));
        assert!(!text.contains("<body><section class=\"securitycontext-page\">"));
    }

    #[tokio::test]
    async fn mcp_browser_request_serves_config_page() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        let response = mcp_info(Query(McpConfigQuery { client: None }), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("AI Supply Chain Trust MCP"));
        assert!(text.contains("mcpServers"));
        assert!(text.contains("securitycontext"));
    }

    #[tokio::test]
    async fn mcp_client_query_serves_matching_config() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:8000".parse().unwrap());

        let response = mcp_info(
            Query(McpConfigQuery {
                client: Some("codex".to_string()),
            }),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("codex mcp add securitycontext http://127.0.0.1:8000/mcp"));
    }

    #[tokio::test]
    async fn sitemap_serves_xml_with_static_entries() {
        let db = Arc::new(Database::open_memory().unwrap());
        db.insert_report(&json!({
            "repo": "wolfssl/wolfssl",
            "evaluated_at": "2026-07-11",
            "trust_score": 75.0,
            "grade": "B",
            "verdict": "Review with known gaps",
            "action": "Review",
            "next_review_date": "2026-10-09",
            "coverage": "3/7",
            "critical_flags": [],
            "pillar_scores": {},
            "scanner_runs": [],
            "observed_metrics": {"security_intel": {"fix_commits": [], "cves": [], "errors": []}},
            "scoring_version": "v1"
        }))
        .unwrap();
        let state = AppState {
            service: Arc::new(Service::new(db, None)),
            base_url: "https://example.test".to_string(),
            worker_token: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let response = sitemap_xml(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("<urlset"));
        assert!(text.contains("<loc>https://example.test/</loc>"));
        assert!(text.contains("<loc>https://example.test/contexts</loc>"));
        assert!(text.contains("<loc>https://example.test/r/wolfssl/wolfssl</loc>"));
        assert!(text.contains("<lastmod>2026-07-11</lastmod>"));
        assert!(text.contains("<priority>1.0</priority>"));
        assert!(!text.contains("/free-tools"));
        assert!(!text.contains("https://example.test/mcp"));
        assert!(!text.contains("https://example.test/recent-scans"));
    }

    #[tokio::test]
    async fn sitemap_prioritizes_core_pages_and_limits_repository_inventory() {
        let db = Arc::new(Database::open_memory().unwrap());
        for index in 0..=SITEMAP_REPOSITORY_LIMIT {
            db.insert_report(&json!({
                "repo": format!("owner/repo-{index}"),
                "evaluated_at": "2026-07-14",
                "trust_score": 75.0,
                "grade": "B",
                "verdict": "Review",
                "action": "Review",
                "next_review_date": "2026-10-12",
                "coverage": "3/7",
                "critical_flags": [],
                "pillar_scores": {},
                "scanner_runs": [],
                "observed_metrics": {},
                "scoring_version": "v1"
            }))
            .unwrap();
        }
        let state = AppState {
            service: Arc::new(Service::new(db, None)),
            base_url: "https://example.test".to_string(),
            worker_token: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let text = response_text(sitemap_xml(State(state)).await).await;

        assert_eq!(
            text.matches("  <url>\n").count(),
            SITEMAP_REPOSITORY_LIMIT + 6
        );
        assert!(
            text.find("<loc>https://example.test/</loc>").unwrap()
                < text
                    .find("<loc>https://example.test/r/owner/repo-500</loc>")
                    .unwrap()
        );
        assert!(text.contains("/r/owner/repo-500"));
        assert!(!text.contains("/r/owner/repo-0</loc>"));
    }
}
