#![recursion_limit = "256"]
//! HTTP server — axum. Graceful shutdown, DB health, SSE, MCP, rate limiting.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_supply_chain_trust_auth::verify_bearer_token;
use ai_supply_chain_trust_intelligence::IntelligenceClientConfig;
use ai_supply_chain_trust_service::{Service, ServiceConfig};
use ai_supply_chain_trust_storage::{Database, DiscoveryCandidateRecord, DiscoveryCycleCompletion};
use axum::{
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
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
use url::Url;

mod seo;

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<Service>,
    pub base_url: String,
    worker_token: Option<String>,
    discovery_token_configured: bool,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    max_queued_scans: usize,
    feedback_limiter: Arc<Mutex<RateLimiter>>,
    scan_permits: Arc<Semaphore>,
    sse_permits: Arc<Semaphore>,
}

fn max_queued_scans() -> usize {
    std::env::var("AI_SUPPLY_CHAIN_TRUST_MAX_QUEUED_SCANS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
}

fn parse_allowed_origins(value: &str) -> anyhow::Result<Vec<HeaderValue>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            if origin == "*" {
                anyhow::bail!("wildcard allowed origins are not permitted");
            }
            let parsed = Url::parse(origin)
                .map_err(|error| anyhow::anyhow!("invalid allowed origin {origin:?}: {error}"))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                anyhow::bail!(
                    "allowed origin must be an http(s) origin without credentials or path"
                );
            }
            let canonical = parsed.origin().ascii_serialization();
            if canonical == "null" || origin.trim_end_matches('/') != canonical {
                anyhow::bail!("allowed origin must be a canonical http(s) origin");
            }
            HeaderValue::from_str(&canonical)
                .map_err(|error| anyhow::anyhow!("invalid allowed origin {origin:?}: {error}"))
        })
        .collect()
}

fn cors_layer() -> anyhow::Result<CorsLayer> {
    let origins = std::env::var("AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS")
        .ok()
        .map(|value| parse_allowed_origins(&value))
        .transpose()?
        .unwrap_or_default();
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    if origins.is_empty() {
        Ok(layer)
    } else {
        Ok(layer.allow_origin(origins))
    }
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

    fn check_requester(&mut self, requester: &str) -> bool {
        self.check(&format!("requester:{requester}"))
    }
}

fn trusted_proxy_ips() -> HashSet<IpAddr> {
    std::env::var("AI_SUPPLY_CHAIN_TRUST_TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect()
}

fn requester_key(peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    requester_key_with_trusted_proxies(peer, headers, &trusted_proxy_ips())
}

fn requester_key_with_trusted_proxies(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &HashSet<IpAddr>,
) -> String {
    let Some(peer) = peer else {
        return "unknown".into();
    };
    let peer_ip = peer.ip();
    if trusted_proxies.contains(&peer_ip) {
        let forwarded_ip = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .find_map(|value| value.parse::<IpAddr>().ok())
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<IpAddr>().ok())
            });
        if let Some(forwarded_ip) = forwarded_ip {
            return format!("ip:{forwarded_ip}");
        }
    }
    format!("ip:{peer_ip}")
}

fn admit_request(limiter: &mut RateLimiter, repo: &str, requester: &str) -> bool {
    limiter.check_requester(requester) && limiter.check_repo(repo)
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
            std::env::var("AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS")
                .ok()
                .is_some_and(|value| !value.trim().is_empty()),
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
        discovery_token_configured: discovery_token.is_some(),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 86400))),
        max_queued_scans: max_queued_scans(),
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
        .route("/api/v1/discovery/cycles", get(discovery_cycles_handler))
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
        .route(
            "/api/v1/ops/requeue-all",
            axum::routing::post(requeue_all_handler),
        )
        .route("/api/v1/admin/discrepancy", get(discrepancy_handler))
        .route("/api/v1/admin/consistency", get(consistency_handler))
        .route("/sitemap.xml", get(sitemap_xml))
        .route("/r/*path", get(security_context_artifact))
        .route("/mcp", get(mcp_info).post(mcp_handler))
        .fallback(get(serve_frontend))
        .layer(cors_layer()?)
        .with_state(state);

    let addr = SocketAddr::from((host.parse::<std::net::Ipv4Addr>()?, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Server listening");
    maybe_start_queue_worker(worker_service, discovery_token);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server shut down gracefully");
    Ok(())
}

// The struct update below is redundant *today* — that is the point: it keeps a
// new field in `crates/service` from breaking this crate's build.
#[allow(clippy::needless_update)]
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
        scanner_enabled: !matches!(
            std::env::var("AI_SUPPLY_CHAIN_TRUST_SCANNER_MODE")
                .unwrap_or_else(|_| "sync".into())
                .to_ascii_lowercase()
                .as_str(),
            "off" | "disabled" | "none"
        ),
        // Every field above is env-overridable; a new field added in
        // `crates/service` must not break this crate's build.
        ..ServiceConfig::default()
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
    if env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISABLE_DISCOVERY") {
        warn!("Repository discovery worker disabled by configuration");
        return;
    }
    let Some(github_token) = configured_discovery_token(github_token) else {
        warn!("Repository discovery worker disabled because no GitHub token is configured");
        return;
    };
    let interval_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVERY_INTERVAL", 86_400);
    let config = DiscoveryWorkerConfig {
        limit: env_usize("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_LIMIT", 10).clamp(1, 100),
        min_stars: env_u64_allow_zero("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_MIN_STARS", 5) as i64,
        created_days: env_u64("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_DAYS", 7).clamp(1, 365),
        daily_budget: env_usize("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVERY_DAILY_BUDGET", 50)
            .clamp(1, 10_000),
        queue_capacity: max_queued_scans(),
        topics: configured_discovery_topics(
            std::env::var("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVERY_TOPICS")
                .ok()
                .as_deref(),
        ),
    };
    info!(
        interval_secs,
        limit = config.limit,
        min_stars = config.min_stars,
        daily_budget = config.daily_budget,
        queue_capacity = config.queue_capacity,
        topics = ?config.topics,
        "Repository discovery worker starting"
    );
    tokio::spawn(async move {
        if worker_start_delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(worker_start_delay_secs)).await;
        }
        let timeout_secs = env_u64("AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS", 20);
        let mut client = ai_supply_chain_trust_discovery::DiscoveryClient::with_timeout(
            Some(github_token),
            timeout_secs,
        );
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            tick.tick().await;
            run_discovery_cycle(&service, &mut client, &config).await;
        }
    });
}

#[derive(Clone, Debug)]
struct DiscoveryWorkerConfig {
    limit: usize,
    min_stars: i64,
    created_days: u64,
    daily_budget: usize,
    queue_capacity: usize,
    topics: Vec<String>,
}

async fn run_discovery_cycle(
    service: &Arc<Service>,
    client: &mut ai_supply_chain_trust_discovery::DiscoveryClient,
    config: &DiscoveryWorkerConfig,
) {
    // The scan pipeline accepts canonical GitHub owner/repo identifiers.
    // Registry/model discovery remains available to the CLI, but those
    // identifiers must not be fed into this queue.
    let created_since = (chrono::Utc::now() - chrono::Duration::days(config.created_days as i64))
        .format("%Y-%m-%d")
        .to_string();
    let cycle_started = std::time::Instant::now();
    let cycle_id = service
        .db
        .start_discovery_cycle(
            "github_created",
            &json!({
                "limit": config.limit,
                "min_stars": config.min_stars,
                "created_since": created_since,
                "token_configured": client.has_github_token(),
                "daily_queue_budget": config.daily_budget,
                "queue_capacity": config.queue_capacity,
                "topics": config.topics,
            }),
        )
        .ok();
    let discovered = client
        .discover_github_recent_with_topics(
            config.limit as i64,
            config.min_stars,
            &created_since,
            &config.topics,
        )
        .await;
    let discovered_count = discovered.len();
    let candidates = discovery_candidate_decisions(discovered, config.min_stars);
    let candidate_count = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .count();
    let already_queued_today = service.db.discovery_queued_today("github_created").max(0) as usize;
    let remaining_daily_budget = config.daily_budget.saturating_sub(already_queued_today);
    let mut queued = 0usize;
    let mut existing = 0usize;
    let mut failures = 0usize;
    let mut admitted_this_cycle = 0usize;
    for candidate in candidates {
        if !candidate.eligible {
            record_discovery_candidate(
                service,
                cycle_id,
                &candidate.candidate,
                "rejected",
                candidate.reason.as_deref(),
                None,
            );
            continue;
        }
        if admitted_this_cycle >= config.limit {
            record_discovery_candidate(
                service,
                cycle_id,
                &candidate.candidate,
                "skipped",
                Some("cycle_candidate_limit_exhausted"),
                None,
            );
            continue;
        }
        admitted_this_cycle += 1;
        if queued >= remaining_daily_budget {
            record_discovery_candidate(
                service,
                cycle_id,
                &candidate.candidate,
                "skipped",
                Some("daily_queue_budget_exhausted"),
                None,
            );
            continue;
        }
        if service.get_result(&candidate.candidate.repo).is_some() {
            existing += 1;
            record_discovery_candidate(
                service,
                cycle_id,
                &candidate.candidate,
                "already_scanned",
                Some("a persisted report already exists"),
                None,
            );
            continue;
        }
        match service.enqueue_discovery_with_capacity(
            &candidate.candidate.repo,
            0,
            config.queue_capacity,
        ) {
            Ok(Some(job_id)) => {
                queued += 1;
                record_discovery_candidate(
                    service,
                    cycle_id,
                    &candidate.candidate,
                    "queued",
                    None,
                    Some(job_id),
                );
            }
            Ok(None) => {
                record_discovery_candidate(
                    service,
                    cycle_id,
                    &candidate.candidate,
                    "skipped",
                    Some("queue_capacity_exhausted"),
                    None,
                );
            }
            Err(error) => {
                failures += 1;
                record_discovery_candidate(
                    service,
                    cycle_id,
                    &candidate.candidate,
                    "queue_failed",
                    Some(&error),
                    None,
                );
                warn!(repo = %candidate.candidate.repo, %error, "Discovered repository could not be queued")
            }
        }
    }
    if let Some(cycle_id) = cycle_id {
        service
            .db
            .complete_discovery_cycle(DiscoveryCycleCompletion {
                cycle_id,
                discovered_count,
                eligible_count: candidate_count,
                queued_count: queued,
                existing_count: existing,
                failure_count: failures,
                error: None,
            })
            .ok();
    }
    info!(
        discovered = discovered_count,
        candidates = candidate_count,
        daily_budget = config.daily_budget,
        already_queued_today,
        existing,
        queued,
        failures,
        elapsed_ms = cycle_started.elapsed().as_millis() as u64,
        "Repository discovery cycle completed"
    );
}

fn configured_discovery_token(token: Option<String>) -> Option<String> {
    token.filter(|value| !value.trim().is_empty())
}

fn configured_discovery_topics(value: Option<&str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let topics = value
        .into_iter()
        .flat_map(|topics| topics.split(','))
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|topic| {
            !topic.is_empty()
                && topic.len() <= 50
                && !topic.starts_with('-')
                && !topic.ends_with('-')
                && topic
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .filter(|topic| seen.insert(topic.clone()))
        .take(20)
        .collect::<Vec<_>>();
    if topics.is_empty() {
        ai_supply_chain_trust_discovery::default_github_topics()
    } else {
        topics
    }
}

struct DiscoveryCandidateDecision {
    candidate: ai_supply_chain_trust_discovery::DiscoveredRepo,
    eligible: bool,
    reason: Option<String>,
}

fn record_discovery_candidate(
    service: &Service,
    cycle_id: Option<i64>,
    candidate: &ai_supply_chain_trust_discovery::DiscoveredRepo,
    disposition: &str,
    reason: Option<&str>,
    scan_job_id: Option<i64>,
) {
    if let Some(cycle_id) = cycle_id {
        service
            .db
            .record_discovery_candidate(DiscoveryCandidateRecord {
                cycle_id,
                repo: &candidate.repo,
                source: &candidate.source,
                stars: candidate.stars,
                description: &candidate.description,
                disposition,
                reason,
                scan_job_id,
            })
            .ok();
    }
}

#[cfg(test)]
fn discovery_candidates(
    discovered: Vec<ai_supply_chain_trust_discovery::DiscoveredRepo>,
    min_stars: i64,
) -> Vec<ai_supply_chain_trust_discovery::DiscoveredRepo> {
    discovery_candidate_decisions(discovered, min_stars)
        .into_iter()
        .filter(|candidate| candidate.eligible)
        .map(|candidate| candidate.candidate)
        .collect()
}

fn discovery_candidate_decisions(
    discovered: Vec<ai_supply_chain_trust_discovery::DiscoveredRepo>,
    min_stars: i64,
) -> Vec<DiscoveryCandidateDecision> {
    let mut seen = HashSet::new();
    discovered
        .into_iter()
        .map(|candidate| {
            let reason = if !candidate.source.starts_with("github:") {
                Some("source_is_not_github".to_string())
            } else if candidate.stars < min_stars {
                Some("below_minimum_stars".to_string())
            } else {
            let mut parts = candidate.repo.split('/');
                if !matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repo), None) if !owner.is_empty() && !repo.is_empty()) {
                    Some("invalid_github_repository".to_string())
                } else if !seen.insert(candidate.repo.to_ascii_lowercase()) {
                    Some("duplicate_repository".to_string())
                } else {
                    None
                }
            };
            DiscoveryCandidateDecision {
                candidate,
                eligible: reason.is_none(),
                reason,
            }
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
    if state.service.db.health_check().await.is_err() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let metrics = state.service.metrics();
    let scans = metrics
        .get("scans_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1);
    let discovery_requires_token = env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON")
        && !env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISABLE_DISCOVERY");
    if scans < 0 || (discovery_requires_token && !state.discovery_token_configured) {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        Ok(Json(json!({
            "status":"ok",
            "db":"connected",
            "storage_backend": state.service.db.backend(),
            "scans_total":scans,
            "discovery": {
                "enabled": discovery_requires_token,
                "github_token_configured": state.discovery_token_configured
            }
        })))
    }
}

async fn api_health() -> Json<Value> {
    Json(json!({"status":"ok","role":"rust"}))
}

async fn api_healthz(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    if state.service.db.health_check().await.is_err() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let discovery_requires_token = env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON")
        && !env_flag("AI_SUPPLY_CHAIN_TRUST_DAEMON_DISABLE_DISCOVERY");
    if discovery_requires_token && !state.discovery_token_configured {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let m = state.service.metrics();
    Ok(Json(json!({
        "status":"ok",
        "db":"connected",
        "storage_backend": state.service.db.backend(),
        "scans_total":m.get("scans_total").cloned().unwrap_or(json!(0)),
        "discovery_token_configured": state.discovery_token_configured
    })))
}
async fn api_index(State(state): State<AppState>) -> Json<Value> {
    Json(api_index_payload(&state.base_url))
}

fn api_index_payload(base_url: &str) -> Value {
    let base_url = base_url.trim_end_matches('/');
    json!({
        "service": "ai-supply-chain-trust",
        "version": "2.0.0-rust",
        "description": "Ready-to-use security context for public repositories: fixed-risk history, disclosed intelligence, recurring weak spots, and variant leads.",
        "access": "public repositories only. Free, no auth. Results are public.",
        "auth": "none (public; selected creation routes use repository-keyed request limits; rescan queue is bounded)",
        "base_url": base_url,
        "docs": format!("{base_url}/api/v1/openapi.json"),
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
            {"method": "GET", "path": "/api/v1/discovery/cycles", "summary": "Recent repository discovery cycles", "query": {"limit": "int"}},
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
    })
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
            "/api/v1/discovery/cycles": {"get": {"summary": "Recent repository discovery cycles", "parameters":[{"name":"limit","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"Discovery cycle audit records"}}}},
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
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
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
        let requester = requester_key(peer.map(|ConnectInfo(peer)| peer), &headers);
        let mut rl = state.rate_limiter.lock().await;
        if !admit_request(&mut rl, &repo, &requester) {
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
    peer: Option<ConnectInfo<SocketAddr>>,
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

    let client_key = requester_key(peer.map(|ConnectInfo(peer)| peer), &headers);
    {
        let mut limiter = state.feedback_limiter.lock().await;
        if !limiter.check(&client_key) {
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
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<ScanBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let repo = validate_repo(&body.repo).map_err(|error| {
        (
            error.status,
            Json(json!({"error": error.message, "code": error.code})),
        )
    })?;
    {
        let requester = requester_key(peer.map(|ConnectInfo(peer)| peer), &headers);
        let mut rl = state.rate_limiter.lock().await;
        if !admit_request(&mut rl, &repo, &requester) {
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
    Ok(Json(with_aligned_suggest_scores(
        state.service.suggest(&q).await,
    )))
}

/// `/api/v1/recent-scans`, `/api/v1/leaderboard` and `/api/v1/result` all
/// publish the trust score as `trust_score`; suggestions published it only as
/// `score`. Publish both: `trust_score` is the aligned name, `score` stays for
/// existing clients (`frontend/src/lib/repository-search.js` reads either).
fn with_aligned_suggest_scores(mut payload: Value) -> Value {
    if let Some(candidates) = payload.get_mut("candidates").and_then(Value::as_array_mut) {
        for candidate in candidates {
            let score = candidate.get("score").cloned().unwrap_or(Value::Null);
            if let Some(candidate) = candidate.as_object_mut() {
                candidate.entry("trust_score").or_insert(score);
            }
        }
    }
    payload
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

async fn discovery_cycles_handler(
    State(state): State<AppState>,
    Query(p): Query<RecentQuery>,
) -> Json<Value> {
    Json(json!({"cycles": state.service.db.discovery_cycles_recent(p.limit.unwrap_or(20))}))
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

/// One sitemap file may carry 50,000 URLs (and 50 MB uncompressed) per the
/// sitemap protocol. Six of those are the core pages, so the repository
/// inventory gets the rest. Crossing this ceiling means splitting into a
/// sitemap index of several files — see the handoff note in the module docs
/// for `sitemap_xml`; at ~385 repositories that is still far away.
const SITEMAP_URL_LIMIT: usize = 50_000;
const SITEMAP_REPOSITORY_LIMIT: usize = SITEMAP_URL_LIMIT - SITEMAP_CORE_PAGES.len();

/// `(path, priority, changefreq)` for the pages that are not repositories.
const SITEMAP_CORE_PAGES: [(&str, &str, &str); 6] = [
    ("/", "1.0", "daily"),
    ("/contexts", "0.9", "daily"),
    ("/leaderboard", "0.8", "daily"),
    ("/about", "0.6", "monthly"),
    ("/editorial-policy", "0.6", "monthly"),
    ("/privacy", "0.5", "monthly"),
];

/// The editorial pages only change when their copy changes, so they carry a
/// pinned date instead of pretending to change with every scan. Bump this when
/// `/about`, `/editorial-policy` or `/privacy` are edited.
const EDITORIAL_PAGES_LASTMOD: &str = "2026-07-30";

async fn sitemap_xml(State(state): State<AppState>) -> Response {
    let base = state.base_url.trim_end_matches('/');
    let recent = state.service.recent_scans(SITEMAP_REPOSITORY_LIMIT as i64);
    let rows = recent.get("rows").and_then(Value::as_array);

    // The listing pages change whenever a scan lands, so their <lastmod> is the
    // newest evaluation we publish.
    let newest_evaluation = rows
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("evaluated_at").and_then(Value::as_str))
        .filter(|value| is_w3c_date(value))
        .max()
        .map(str::to_string);

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#,
    );
    for (path, priority, changefreq) in SITEMAP_CORE_PAGES {
        let lastmod = if changefreq == "daily" {
            newest_evaluation.as_deref()
        } else {
            Some(EDITORIAL_PAGES_LASTMOD)
        };
        append_sitemap_url(
            &mut xml,
            &format!("{base}{path}"),
            lastmod,
            priority,
            changefreq,
        );
    }

    let mut seen_repositories = std::collections::BTreeSet::new();
    if let Some(rows) = rows {
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
#[derive(Deserialize)]
struct RequeueAllBody {
    limit: Option<i64>,
}

/// Re-queue the whole public inventory. Worker-token protected and deliberately
/// exempt from the public per-requester rescan limit, which exists to stop an
/// anonymous visitor flooding the queue and makes a fleet-wide sweep impossible
/// through `/api/v1/queue/rescan` (10 requests per requester per day).
async fn requeue_all_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<axum::extract::Json<RequeueAllBody>>,
) -> Result<Json<Value>, ApiError> {
    require_worker_token(&state, &headers)?;
    let limit = body
        .and_then(|axum::extract::Json(body)| body.limit)
        .unwrap_or(50_000);
    state
        .service
        .enqueue_full_inventory_rescan(limit)
        .map(Json)
        .map_err(ApiError::internal)
}

async fn queue_rescan_handler(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    axum::extract::Json(b): axum::extract::Json<RescanBody>,
) -> Result<Json<Value>, ApiError> {
    let repo = validate_repo(&b.repo)?;
    let priority = b.priority.unwrap_or(0).clamp(-100, 100);
    {
        let requester = requester_key(peer.map(|ConnectInfo(peer)| peer), &headers);
        let mut limiter = state.rate_limiter.lock().await;
        if !admit_request(&mut limiter, &repo, &requester) {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                message: "Too many rescan requests; please try again later".into(),
            });
        }
    }
    match state
        .service
        .enqueue_rescan_with_capacity(&repo, priority, state.max_queued_scans)
    {
        Ok(Some(job_id)) => Ok(Json(json!({"status":"queued", "job_id": job_id}))),
        Ok(None) => Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "queue_full",
            message: "Scan queue is at capacity; please try again later".into(),
        }),
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
    let discovery_cycles = m
        .get("discovery_cycles_total")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let discovery_cycles_failed = m
        .get("discovery_cycles_failed")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let discovery_candidates = m
        .get("discovery_candidates_total")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let discovery_queued_today = m
        .get("discovery_queued_today")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let mut text = format!(
        "# HELP ai_supply_chain_trust_scans_total Total evaluations\n# TYPE ai_supply_chain_trust_scans_total counter\nai_supply_chain_trust_scans_total {scans}\n# HELP ai_supply_chain_trust_unique_repos Unique repositories\n# TYPE ai_supply_chain_trust_unique_repos gauge\nai_supply_chain_trust_unique_repos {unique}\n# HELP ai_supply_chain_trust_llm_decisions_total LLM decision records by source/model/task\n# TYPE ai_supply_chain_trust_llm_decisions_total counter\nai_supply_chain_trust_llm_decisions_total {llm_total}\n# HELP ai_supply_chain_trust_llm_hallucination_rejections_total LLM outputs rejected by deterministic fact checking\n# TYPE ai_supply_chain_trust_llm_hallucination_rejections_total counter\nai_supply_chain_trust_llm_hallucination_rejections_total {llm_rejected}\n# HELP ai_supply_chain_trust_llm_hallucination_rejection_rate Rejected LLM decisions divided by total LLM decisions\n# TYPE ai_supply_chain_trust_llm_hallucination_rejection_rate gauge\nai_supply_chain_trust_llm_hallucination_rejection_rate {llm_rejection_rate}\n# HELP ai_supply_chain_trust_llm_rate_limited_total LLM outcomes caused by upstream HTTP 429\n# TYPE ai_supply_chain_trust_llm_rate_limited_total counter\nai_supply_chain_trust_llm_rate_limited_total {llm_rate_limited}\n# HELP ai_supply_chain_trust_llm_model_missing_total LLM decision records without model metadata\n# TYPE ai_supply_chain_trust_llm_model_missing_total gauge\nai_supply_chain_trust_llm_model_missing_total {llm_model_missing}\n# HELP ai_supply_chain_trust_llm_latency_average_ms Average latency of persisted LLM outcomes with latency data\n# TYPE ai_supply_chain_trust_llm_latency_average_ms gauge\nai_supply_chain_trust_llm_latency_average_ms {llm_latency_average_ms}\n# HELP ai_supply_chain_trust_llm_latency_samples_total Persisted LLM outcomes with latency data\n# TYPE ai_supply_chain_trust_llm_latency_samples_total counter\nai_supply_chain_trust_llm_latency_samples_total {llm_latency_samples}\n"
    );
    text.push_str(&format!(
        "# HELP ai_supply_chain_trust_discovery_cycles_total Completed and failed discovery cycles\n# TYPE ai_supply_chain_trust_discovery_cycles_total counter\nai_supply_chain_trust_discovery_cycles_total {discovery_cycles}\n# HELP ai_supply_chain_trust_discovery_cycles_failed Total discovery cycles marked failed\n# TYPE ai_supply_chain_trust_discovery_cycles_failed counter\nai_supply_chain_trust_discovery_cycles_failed {discovery_cycles_failed}\n# HELP ai_supply_chain_trust_discovery_candidates_total Candidate records retained for auditability\n# TYPE ai_supply_chain_trust_discovery_candidates_total counter\nai_supply_chain_trust_discovery_candidates_total {discovery_candidates}\n"
    ));
    text.push_str(&format!(
        "# HELP ai_supply_chain_trust_discovery_queued_today Discovery queue admissions since UTC midnight\n# TYPE ai_supply_chain_trust_discovery_queued_today gauge\nai_supply_chain_trust_discovery_queued_today {discovery_queued_today}\n"
    ));
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

/// SPA fallback: serves the frontend shell with server-rendered route metadata.
///
/// Real files (bundles, icons, `robots.txt`, …) and the legacy `/free-tools`
/// redirects keep going through [`serve_static`] untouched.
async fn serve_frontend(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    if !is_spa_document_path(&path) || static_file_exists(&path) {
        return serve_static(req).await;
    }
    let headers = req.headers().clone();
    render_spa_document(&state, &headers, &path, query.as_deref()).await
}

fn is_spa_document_path(path: &str) -> bool {
    if path == "/free-tools" || path.starts_with("/free-tools/") {
        return false;
    }
    let trimmed = path.trim_start_matches('/');
    if !is_safe_static_path(trimmed) {
        return false;
    }
    trimmed.is_empty() || std::path::Path::new(trimmed).extension().is_none()
}

fn static_file_exists(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() || !is_safe_static_path(trimmed) {
        return false;
    }
    let candidate = std::path::Path::new(&frontend_web_dir()).join(trimmed);
    candidate.is_file()
}

async fn render_spa_document(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    query: Option<&str>,
) -> axum::response::Response {
    let Some(shell) = read_frontend_shell().await else {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap();
    };
    let route = seo::resolve_route(path, query);
    let origin = request_origin(headers, &state.base_url);
    let report = seo::route_repository(&route).and_then(|repo| state.service.get_result(repo));
    let document = seo::render_document(&shell, &route, &origin, report.as_ref());

    axum::response::Response::builder()
        .header("Content-Type", "text/html")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(axum::body::Body::from(document))
        .unwrap()
}

async fn read_frontend_shell() -> Option<String> {
    let path = std::path::Path::new(&frontend_web_dir()).join("index.html");
    tokio::fs::read_to_string(path).await.ok()
}

/// Absolute origin for canonical/OG URLs, taken from the request so dev,
/// preview and production each describe themselves. Falls back to the
/// configured public base URL when the forwarded host is absent or not a
/// plausible host (headers are attacker-controlled).
fn request_origin(headers: &HeaderMap, base_url: &str) -> String {
    let fallback = base_url.trim_end_matches('/').to_string();
    let header_value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let Some(host) = header_value("x-forwarded-host")
        .or_else(|| header_value(header::HOST.as_str()))
        .filter(|host| is_plausible_host(host))
    else {
        return fallback;
    };
    let scheme = header_value("x-forwarded-proto")
        .filter(|scheme| *scheme == "http" || *scheme == "https")
        .map(str::to_string)
        .unwrap_or_else(|| {
            let host_only = host.split(':').next().unwrap_or(host);
            if matches!(host_only, "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]")
                || fallback.starts_with("http://")
            {
                "http".to_string()
            } else {
                "https".to_string()
            }
        });
    format!("{scheme}://{host}")
}

fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':' | '[' | ']')
        })
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
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
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
                    {
                        let requester = requester_key(peer.map(|ConnectInfo(peer)| peer), &headers);
                        let mut limiter = state.rate_limiter.lock().await;
                        if !admit_request(&mut limiter, &repo, &requester) {
                            return Json(
                                json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"Too many requests for this repository; please try again later"}]}}),
                            );
                        }
                    }
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
    headers: HeaderMap,
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
        // The SPA shell, described for *this* repository rather than for "/".
        return render_spa_document(&state, &headers, &format!("/r/{repo}"), None).await;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_stream::StreamExt;

    async fn response_text(response: Response) -> String {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).expect("utf8 response")
    }

    async fn github_discovery_server() -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut raw = vec![0; 8192];
            let read = socket.read(&mut raw).await.unwrap();
            let request = String::from_utf8_lossy(&raw[..read]).to_string();
            let body = json!({"items": [{
                "full_name": "owner/mock-repo",
                "stargazers_count": 7,
                "description": "deterministic worker fixture"
            }]})
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        assert_eq!(health().await, "healthy\n");
    }

    #[tokio::test]
    async fn readiness_checks_storage_and_reports_backend() {
        let state = AppState {
            service: Arc::new(Service::new(
                Arc::new(Database::open_memory().unwrap()),
                None,
            )),
            base_url: "http://localhost".to_string(),
            worker_token: None,
            discovery_token_configured: true,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 100,
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let response = healthz(State(state.clone())).await.expect("ready response");
        assert_eq!(response.0["storage_backend"], json!("sqlite"));
        assert_eq!(response.0["status"], json!("ok"));

        let api_response = api_healthz(State(state)).await.expect("API ready response");
        assert_eq!(api_response.0["storage_backend"], json!("sqlite"));
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
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 100,
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
    fn discovery_candidates_keep_unique_valid_github_repositories() {
        use ai_supply_chain_trust_discovery::DiscoveredRepo;

        let candidates = discovery_candidates(
            vec![
                DiscoveredRepo {
                    repo: "Owner/Repo".into(),
                    source: "github:topic:llm".into(),
                    stars: 5,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "owner/repo".into(),
                    source: "github:topic:ai-agent".into(),
                    stars: 8,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "pypi:not-a-github-repo".into(),
                    source: "pypi:search:llm".into(),
                    stars: 99,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "owner/low-star".into(),
                    source: "github:topic:llm".into(),
                    stars: 4,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "owner/repo/extra".into(),
                    source: "github:topic:llm".into(),
                    stars: 99,
                    description: String::new(),
                },
            ],
            5,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].repo, "Owner/Repo");
    }

    #[test]
    fn discovery_candidate_decisions_keep_every_rejection_reason() {
        use ai_supply_chain_trust_discovery::DiscoveredRepo;

        let decisions = discovery_candidate_decisions(
            vec![
                DiscoveredRepo {
                    repo: "owner/accepted".into(),
                    source: "github:topic:llm".into(),
                    stars: 5,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "owner/accepted".into(),
                    source: "github:topic:ai".into(),
                    stars: 5,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "owner/low".into(),
                    source: "github:topic:llm".into(),
                    stars: 4,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "not-a-repo".into(),
                    source: "github:topic:llm".into(),
                    stars: 8,
                    description: String::new(),
                },
                DiscoveredRepo {
                    repo: "pypi:package".into(),
                    source: "pypi:search".into(),
                    stars: 8,
                    description: String::new(),
                },
            ],
            5,
        );

        assert_eq!(decisions.iter().filter(|entry| entry.eligible).count(), 1);
        assert_eq!(decisions[1].reason.as_deref(), Some("duplicate_repository"));
        assert_eq!(decisions[2].reason.as_deref(), Some("below_minimum_stars"));
        assert_eq!(
            decisions[3].reason.as_deref(),
            Some("invalid_github_repository")
        );
        assert_eq!(decisions[4].reason.as_deref(), Some("source_is_not_github"));
    }

    #[test]
    fn discovery_requires_a_non_empty_github_token() {
        assert_eq!(configured_discovery_token(None), None);
        assert_eq!(configured_discovery_token(Some("  ".into())), None);
        assert_eq!(
            configured_discovery_token(Some("github-token".into())),
            Some("github-token".into())
        );
    }

    #[test]
    fn discovery_topics_are_bounded_deduplicated_and_query_safe() {
        assert_eq!(
            configured_discovery_topics(Some("LLM, ai-agent, llm, invalid/topic, -bad, valid-2")),
            vec!["llm", "ai-agent", "valid-2"]
        );
        assert_eq!(
            configured_discovery_topics(Some("bad topic")),
            ai_supply_chain_trust_discovery::default_github_topics()
        );
    }

    #[tokio::test]
    async fn discovery_cycle_persists_mocked_github_candidate_and_queue_job() {
        let (github_base, request) = github_discovery_server().await;
        let db = Arc::new(Database::open_memory().unwrap());
        let service = Arc::new(Service::new(db.clone(), None));
        let mut client = ai_supply_chain_trust_discovery::DiscoveryClient::with_timeout(
            Some("test-token".into()),
            2,
        )
        .with_github_api_base(github_base);
        let config = DiscoveryWorkerConfig {
            limit: 1,
            min_stars: 5,
            created_days: 7,
            daily_budget: 1,
            queue_capacity: 10,
            topics: vec!["mock-topic".into()],
        };

        run_discovery_cycle(&service, &mut client, &config).await;

        let request = request.await.unwrap();
        assert!(request.starts_with("GET /search/repositories?"));
        assert!(request.contains("topic:mock-topic"));
        assert!(
            request.contains("stars:%3E=5") || request.contains("stars:>=5"),
            "unexpected GitHub search request: {request}"
        );

        let cycles = db.discovery_cycles_recent(1);
        assert_eq!(cycles[0]["status"], json!("completed"));
        assert_eq!(cycles[0]["discovered_count"], json!(1));
        assert_eq!(cycles[0]["eligible_count"], json!(1));
        assert_eq!(cycles[0]["queued_count"], json!(1));
        assert_eq!(cycles[0]["config"]["topics"], json!(["mock-topic"]));
        assert_eq!(db.scan_jobs_recent(1)[0]["repo"], json!("owner/mock-repo"));
    }

    #[tokio::test]
    async fn requeue_all_requires_the_worker_token_and_skips_the_public_limit() {
        // The public rescan limit is 10 per requester per day, so a fleet-wide
        // sweep is impossible through /api/v1/queue/rescan. This route exists to
        // do that job, which makes its auth the only thing between an anonymous
        // caller and the entire scan queue.
        let db = Arc::new(Database::open_memory().unwrap());
        for repo in ["a/one", "b/two", "c/three"] {
            db.insert_report(&json!({
                "repo": repo, "evaluated_at": "2026-08-01", "trust_score": 50.0,
                "grade": "C", "verdict": "v", "action": "a", "next_review_date": "2026-09-01",
                "coverage": "", "critical_flags": [], "pillar_scores": {},
                "scanner_runs": [], "observed_metrics": {}, "scoring_version": "v1"
            }))
            .unwrap();
        }
        let mut state = test_state(db, "https://example.test");

        // No token configured: the route must stay shut rather than open.
        let closed = requeue_all_handler(State(state.clone()), HeaderMap::new(), None)
            .await
            .expect_err("must reject when no worker token is configured");
        assert_eq!(closed.status, StatusCode::UNAUTHORIZED);

        state.worker_token =
            Some("6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf".into());

        let anonymous = requeue_all_handler(State(state.clone()), HeaderMap::new(), None)
            .await
            .expect_err("must reject an unauthenticated caller");
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

        let mut wrong = HeaderMap::new();
        wrong.insert("authorization", HeaderValue::from_static("Bearer nope"));
        let rejected = requeue_all_handler(State(state.clone()), wrong, None)
            .await
            .expect_err("must reject a wrong token");
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer worker-secret"),
        );
        let response = requeue_all_handler(State(state), headers, None)
            .await
            .expect("a valid worker token should be accepted");
        assert_eq!(response.0["examined"], json!(3));
        assert_eq!(response.0["queued"], json!(3));
        assert_eq!(response.0["failed"], json!(0));
    }

    #[tokio::test]
    async fn rescan_queue_rejects_new_jobs_at_capacity() {
        let db = Arc::new(Database::open_memory().unwrap());
        let service = Arc::new(Service::new(db, None));
        service.enqueue_rescan("first/repo", 0).unwrap();
        let state = AppState {
            service,
            base_url: "http://localhost".to_string(),
            worker_token: None,
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 1,
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let error = queue_rescan_handler(
            State(state),
            None,
            HeaderMap::new(),
            axum::extract::Json(RescanBody {
                repo: "second/repo".to_string(),
                priority: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "queue_full");
    }

    #[tokio::test]
    async fn mcp_context_creation_uses_repository_rate_limit() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = AppState {
            service: Arc::new(Service::new(db, None)),
            base_url: "http://localhost".to_string(),
            worker_token: None,
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1, 60))),
            max_queued_scans: 100,
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };
        assert!(state.rate_limiter.lock().await.check_repo("owner/repo"));

        let response = mcp_handler(
            State(state),
            None,
            HeaderMap::new(),
            axum::extract::Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "create_security_context",
                    "arguments": {"repo": "owner/repo"}
                }
            })),
        )
        .await;

        assert_eq!(response.0["result"]["isError"], json!(true));
        assert_eq!(
            response.0["result"]["content"][0]["text"],
            json!("Too many requests for this repository; please try again later")
        );
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

    #[test]
    fn requester_identity_accepts_forwarded_ip_only_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.9, 192.0.2.4".parse().unwrap(),
        );
        headers.insert("x-real-ip", "203.0.113.7".parse().unwrap());
        let peer = "192.0.2.10:443".parse().unwrap();

        assert_eq!(
            requester_key_with_trusted_proxies(Some(peer), &headers, &HashSet::new()),
            "ip:192.0.2.10"
        );
        assert_eq!(
            requester_key_with_trusted_proxies(
                Some(peer),
                &headers,
                &["192.0.2.10".parse().unwrap()].into_iter().collect(),
            ),
            "ip:198.51.100.9"
        );
    }

    #[test]
    fn requester_admission_limits_repository_rotation() {
        let mut limiter = RateLimiter::new(2, 60);
        assert!(admit_request(&mut limiter, "owner/one", "ip:198.51.100.9"));
        assert!(admit_request(&mut limiter, "owner/two", "ip:198.51.100.9"));
        assert!(!admit_request(
            &mut limiter,
            "owner/three",
            "ip:198.51.100.9"
        ));
    }

    #[test]
    fn allowed_origins_parser_accepts_csv_and_rejects_invalid_headers() {
        let origins = parse_allowed_origins("https://app.example, https://admin.example").unwrap();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0], "https://app.example");
        assert_eq!(origins[1], "https://admin.example");
        assert!(parse_allowed_origins("*").is_err());
        assert!(parse_allowed_origins("null").is_err());
        assert!(parse_allowed_origins("https://app.example/path").is_err());
        assert!(parse_allowed_origins("https://user@app.example").is_err());
        assert!(parse_allowed_origins("https://app.example\ninvalid").is_err());
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

    #[test]
    fn api_index_describes_actual_admission_controls() {
        let index = api_index_payload("https://example.test");
        let auth = index["auth"].as_str().expect("auth description");
        assert!(auth.contains("repository-keyed"));
        assert!(!auth.contains("per IP"));
        assert_eq!(index["base_url"], "https://example.test");
        assert_eq!(index["docs"], "https://example.test/api/v1/openapi.json");
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
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 100,
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        };

        let response = security_context_artifact(
            State(state),
            Path("wolfssl/wolfssl".to_string()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(text.contains("app-header"));
        assert!(text.contains("/assets/js/app.js"));
        assert!(!text.contains("<body><section class=\"securitycontext-page\">"));
    }

    fn test_state(db: Arc<Database>, base_url: &str) -> AppState {
        AppState {
            service: Arc::new(Service::new(db, None)),
            base_url: base_url.to_string(),
            worker_token: None,
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 100,
            feedback_limiter: Arc::new(Mutex::new(RateLimiter::new(3, 600))),
            scan_permits: Arc::new(Semaphore::new(4)),
            sse_permits: Arc::new(Semaphore::new(100)),
        }
    }

    async fn spa_document(state: &AppState, uri: &str) -> String {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let response = serve_frontend(State(state.clone()), req).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        response_text(response).await
    }

    /// Counts raw occurrences in the response body: a DOM parser would tolerate
    /// the duplicate `<title>`/description that the shipped shell carries, and
    /// duplicates are exactly what breaks crawlers.
    fn assert_single_managed_tags(document: &str, route: &str) {
        let occurrences = |needle: &str| document.matches(needle).count();
        assert_eq!(occurrences("<title"), 1, "duplicate <title> on {route}");
        assert_eq!(occurrences("</title>"), 1, "duplicate </title> on {route}");
        assert_eq!(
            occurrences("name=\"description\""),
            1,
            "duplicate description on {route}"
        );
        assert_eq!(
            occurrences("rel=\"canonical\""),
            1,
            "duplicate canonical on {route}"
        );
        for identity in [
            "og:title",
            "og:description",
            "og:url",
            "og:type",
            "og:site_name",
            "twitter:card",
            "twitter:title",
            "twitter:description",
        ] {
            assert_eq!(occurrences(identity), 1, "duplicate {identity} on {route}");
        }
        assert!(
            occurrences("application/ld+json") <= 1,
            "more than one JSON-LD block on {route}"
        );
        assert!(
            !document.contains("<!--SSR_HEAD-->"),
            "placeholder left on {route}"
        );
        assert!(
            !document.contains("Agent-ready security context for public software repositories."),
            "shipped generic description survived on {route}"
        );
        assert!(
            !document.contains("<title>AI Supply Chain Trust</title>"),
            "shipped generic title survived on {route}"
        );
    }

    /// The served shell (`frontend/web/index.html`) already carries a generic
    /// `<title>` and description *before* the placeholder, so injection has to
    /// replace them rather than append beside them.
    #[tokio::test]
    async fn every_spa_route_serves_one_of_each_managed_seo_tag() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        for route in [
            "/",
            "/contexts",
            "/leaderboard",
            "/result",
            "/result?repo=ollama%2Follama",
            "/about",
            "/editorial-policy",
            "/privacy",
            "/r/ollama/ollama",
            "/definitely-not-a-route",
        ] {
            let document = spa_document(&state, route).await;
            assert_single_managed_tags(&document, route);
            assert!(document.contains("/assets/js/app.js"), "{route}");
        }
    }

    #[tokio::test]
    async fn spa_routes_publish_distinct_titles_and_canonicals() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        let home = spa_document(&state, "/").await;
        assert!(home
            .contains("<title>AI Supply Chain Trust — public repository security context</title>"));
        assert!(home.contains("<link rel=\"canonical\" href=\"https://example.test/\" />"));
        assert!(home.contains("content=\"website\""));
        assert_eq!(home.matches("application/ld+json").count(), 1);
        assert!(home.contains("\"@id\":\"https://example.test/#website\""));
        assert!(home.contains("\"@id\":\"https://example.test/#organization\""));

        let leaderboard = spa_document(&state, "/leaderboard").await;
        assert!(leaderboard
            .contains("<title>Repository trust leaderboard | AI Supply Chain Trust</title>"));
        assert!(leaderboard.contains("href=\"https://example.test/leaderboard\""));
        assert_eq!(leaderboard.matches("application/ld+json").count(), 0);

        let privacy = spa_document(&state, "/privacy").await;
        assert!(privacy.contains("<title>Privacy | AI Supply Chain Trust</title>"));
        assert!(privacy.contains("href=\"https://example.test/privacy\""));

        let result = spa_document(&state, "/result?repo=ollama%2Follama").await;
        assert!(result.contains("href=\"https://example.test/result?repo=ollama%2Follama\""));
    }

    #[tokio::test]
    async fn only_the_not_found_route_publishes_robots() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        let missing = spa_document(&state, "/definitely-not-a-route").await;
        assert_eq!(missing.matches("name=\"robots\"").count(), 1);
        assert!(missing.contains("content=\"noindex, follow\""));

        for route in ["/", "/contexts", "/about", "/r/ollama/ollama"] {
            let document = spa_document(&state, route).await;
            assert_eq!(
                document.matches("robots").count(),
                0,
                "robots leaked onto {route}"
            );
        }
    }

    #[tokio::test]
    async fn repository_route_publishes_the_stored_report() {
        let db = Arc::new(Database::open_memory().unwrap());
        db.insert_report(&json!({
            "repo": "ollama/ollama",
            "evaluated_at": "2026-07-11",
            "trust_score": 74.6,
            "grade": "B",
            "verdict": "Review with known gaps",
            "action": "Complete missing evidence before approval",
            "next_review_date": "2026-10-09",
            "coverage": "5/7",
            "critical_flags": [],
            "pillar_scores": {},
            "scanner_runs": [],
            "observed_metrics": {},
            "scoring_version": "v1"
        }))
        .unwrap();
        let state = test_state(db, "https://example.test");

        // Both the `/r/*path` artifact route and the SPA fallback describe it.
        let via_artifact = response_text(
            security_context_artifact(
                State(state.clone()),
                Path("ollama/ollama".to_string()),
                HeaderMap::new(),
            )
            .await,
        )
        .await;
        let via_fallback = spa_document(&state, "/r/ollama/ollama").await;

        for document in [&via_artifact, &via_fallback] {
            assert_single_managed_tags(document, "/r/ollama/ollama");
            assert!(document.contains(
                "<title>ollama/ollama — trust grade B 75/100 | AI Supply Chain Trust</title>"
            ));
            assert!(document.contains("content=\"article\""));
            assert!(document
                .contains("Review with known gaps (trust grade B 75/100) — evidence-backed"));
            assert!(document.contains("\"@type\":\"SoftwareSourceCode\""));
            assert_eq!(document.matches("application/ld+json").count(), 1);
            // Crawlable stub instead of an empty <div id="root">.
            assert!(document.contains("<h1>ollama/ollama security context</h1>"));
            assert!(!document.contains("<!--SSR_MAIN-->"));
            assert!(!document.contains("<div id=\"root\"></div>"));
        }
    }

    #[tokio::test]
    async fn unscanned_repository_degrades_to_generic_metadata() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        let document = spa_document(&state, "/r/unknown/repository").await;

        assert_single_managed_tags(&document, "/r/unknown/repository");
        assert!(document.contains(
            "<title>unknown/repository security context | AI Supply Chain Trust</title>"
        ));
        assert!(document.contains(
            "Evidence-backed security context for the public GitHub repository unknown/repository"
        ));
        assert!(!document.contains("/100"));
        assert!(!document.contains("undefined"));
    }

    /// A repository slug is untrusted URL input; so is the Host header.
    #[tokio::test]
    async fn hostile_repository_paths_cannot_inject_markup() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        for hostile in [
            "/r/owner/repo%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/r/owner/%3C%2Ftitle%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/result?repo=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        ] {
            let document = spa_document(&state, hostile).await;
            assert_single_managed_tags(&document, hostile);
            assert!(!document.contains("<script>alert"), "{document}");
            assert!(!document.contains("<img"), "{document}");
            assert!(!document.contains("\"><script"), "{document}");
            assert!(!document.contains("</title><"), "{document}");
            // Whatever survives does so only as escaped text.
            assert!(
                document.contains("&lt;") || document.contains("%3C") || document.contains("%253C"),
                "{document}"
            );
        }
    }

    #[tokio::test]
    async fn absolute_urls_follow_the_request_host() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://production.test");

        let forwarded = Request::builder()
            .uri("/contexts")
            .header(header::HOST, "internal:8000")
            .header("x-forwarded-host", "preview.example.test")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        let document = response_text(serve_frontend(State(state.clone()), forwarded).await).await;
        assert!(document.contains("href=\"https://preview.example.test/contexts\""));

        let local = Request::builder()
            .uri("/contexts")
            .header(header::HOST, "localhost:5173")
            .body(Body::empty())
            .unwrap();
        let document = response_text(serve_frontend(State(state.clone()), local).await).await;
        assert!(document.contains("href=\"http://localhost:5173/contexts\""));

        // A hostile Host header falls back to the configured base URL.
        let spoofed = Request::builder()
            .uri("/contexts")
            .header(header::HOST, "evil.test/\"><script>alert(1)</script>")
            .body(Body::empty())
            .unwrap();
        let document = response_text(serve_frontend(State(state), spoofed).await).await;
        assert!(document.contains("href=\"https://production.test/contexts\""));
        assert!(!document.contains("<script>alert"));
    }

    #[tokio::test]
    async fn static_assets_still_bypass_the_seo_layer() {
        let db = Arc::new(Database::open_memory().unwrap());
        let state = test_state(db, "https://example.test");

        let req = Request::builder()
            .uri("/robots.txt")
            .body(Body::empty())
            .unwrap();
        let response = serve_frontend(State(state.clone()), req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(!text.contains("<title>"));

        let redirect = Request::builder()
            .uri("/free-tools/r/owner/repo")
            .body(Body::empty())
            .unwrap();
        let response = serve_frontend(State(state.clone()), redirect).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);

        let traversal = Request::builder()
            .uri("/../Cargo.toml")
            .body(Body::empty())
            .unwrap();
        let response = serve_frontend(State(state), traversal).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn suggestions_publish_the_aligned_score_field() {
        let payload = with_aligned_suggest_scores(json!({
            "candidates": [
                {"repo": "owner/scanned", "score": 74.5, "source": "scanned"},
                {"repo": "owner/remote", "score": Value::Null, "source": "github"}
            ]
        }));

        let candidates = payload["candidates"].as_array().unwrap();
        assert_eq!(candidates[0]["trust_score"], json!(74.5));
        assert_eq!(candidates[0]["score"], json!(74.5), "legacy field kept");
        assert_eq!(candidates[1]["trust_score"], Value::Null);
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
            discovery_token_configured: false,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
            max_queued_scans: 100,
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

    /// The sitemap protocol allows 50,000 URLs per file. Anything smaller
    /// silently truncates the repository inventory, which is the whole reason
    /// this page exists.
    #[test]
    fn sitemap_limit_matches_the_sitemap_protocol() {
        assert_eq!(SITEMAP_URL_LIMIT, 50_000);
        assert_eq!(
            SITEMAP_REPOSITORY_LIMIT + SITEMAP_CORE_PAGES.len(),
            SITEMAP_URL_LIMIT
        );
    }

    #[tokio::test]
    async fn sitemap_publishes_every_repository_and_dates_the_core_pages() {
        let db = Arc::new(Database::open_memory().unwrap());
        for index in 0..25 {
            // Every repository is rescanned, so a row window over `evaluations`
            // would cover only a fraction of them.
            for round in 0..4 {
                db.insert_report(&json!({
                    "repo": format!("owner/repo-{index}"),
                    "evaluated_at": format!("2026-07-{:02}", 10 + round),
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
        }
        let state = test_state(db, "https://example.test");

        let text = response_text(sitemap_xml(State(state)).await).await;

        assert_eq!(
            text.matches("  <url>\n").count(),
            25 + SITEMAP_CORE_PAGES.len(),
            "every tracked repository must be published"
        );
        for index in 0..25 {
            assert!(
                text.contains(&format!(
                    "<loc>https://example.test/r/owner/repo-{index}</loc>"
                )),
                "missing repository {index}"
            );
        }
        assert!(
            text.find("<loc>https://example.test/</loc>").unwrap()
                < text
                    .find("<loc>https://example.test/r/owner/repo-0</loc>")
                    .unwrap()
        );
        // All six core pages carry a <lastmod>.
        let core_section = &text[..text.find("/r/owner/").unwrap()];
        assert_eq!(core_section.matches("<lastmod>").count(), 6);
        assert!(core_section.contains("<lastmod>2026-07-13</lastmod>"));
        assert!(core_section.contains(&format!("<lastmod>{EDITORIAL_PAGES_LASTMOD}</lastmod>")));
    }
}
