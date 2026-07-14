use std::collections::{BTreeMap, HashMap};
use std::env;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tracing::{info, warn};

const OPENROUTER_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_PRIMARY: &str = "openai/gpt-4.1-mini";
const DEFAULT_SECONDARY: &str = "google/gemini-2.5-flash";

#[derive(Debug, Error)]
pub enum LlmUnavailableError {
    #[error("OPENROUTER_API_KEY is required for LLM decisions")]
    MissingApiKey,
    #[error("OpenRouter request failed: {0}")]
    Request(String),
    #[error("OpenRouter returned HTTP {status}: {message}")]
    HttpStatus {
        status: u16,
        message: String,
        retry_after_seconds: Option<u64>,
    },
    #[error("OpenRouter response was not valid JSON: {0}")]
    InvalidJson(String),
    #[error("OpenRouter daily quota exhausted")]
    QuotaExhausted,
    #[error("OpenRouter circuit is open for model {model}")]
    CircuitOpen { model: String },
    #[error("LLM request budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("invalid LLM configuration: {0}")]
    InvalidConfig(String),
}

impl LlmUnavailableError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::MissingApiKey => "missing_api_key",
            Self::Request(_) => "network_error",
            Self::HttpStatus { status: 429, .. } => "rate_limited",
            Self::HttpStatus { status, .. } if *status >= 500 => "upstream_error",
            Self::HttpStatus { .. } => "http_error",
            Self::InvalidJson(_) => "invalid_json",
            Self::QuotaExhausted => "local_quota_exhausted",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::BudgetExceeded(_) => "budget_exhausted",
            Self::InvalidConfig(_) => "configuration_error",
        }
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Request(_)
                | Self::HttpStatus {
                    status: 408 | 429,
                    ..
                }
                | Self::HttpStatus {
                    status: 500..=599,
                    ..
                }
        )
    }
}

#[derive(Debug, Clone)]
pub struct LlmClientConfig {
    pub api_key: String,
    pub endpoint_url: String,
    pub primary_model: String,
    pub secondary_model: Option<String>,
    pub timeout: Duration,
    pub max_retries: usize,
    pub requests_per_minute: u32,
    pub requests_per_day: u32,
    pub retry_base_delay: Duration,
    pub retry_max_delay: Duration,
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown: Duration,
    pub max_input_bytes: usize,
    pub fallback_max_total_attempts: usize,
    pub fallback_max_total_latency: Duration,
    pub require_non_free_model: bool,
}

impl LlmClientConfig {
    pub fn from_env() -> Result<Self, LlmUnavailableError> {
        let api_key =
            env::var("OPENROUTER_API_KEY").map_err(|_| LlmUnavailableError::MissingApiKey)?;
        let primary_model =
            env::var("OPENROUTER_MODEL_PRIMARY").unwrap_or_else(|_| DEFAULT_PRIMARY.to_string());
        let timeout = env::var("OPENROUTER_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(20);
        let max_retries = env::var("OPENROUTER_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2);
        let env_u32 = |name: &str, default| {
            env::var(name)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(default)
        };
        let env_u64 = |name: &str, default| {
            env::var(name)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(default)
        };
        let env_usize = |name: &str, default| {
            env::var(name)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(default)
        };
        let env_bool = |name: &str, default| match env::var(name).ok().as_deref() {
            Some("1" | "true" | "TRUE" | "yes" | "YES") => true,
            Some("0" | "false" | "FALSE" | "no" | "NO") => false,
            _ => default,
        };
        Ok(Self {
            api_key,
            endpoint_url: env::var("OPENROUTER_URL").unwrap_or_else(|_| OPENROUTER_URL.to_string()),
            primary_model,
            secondary_model: env::var("OPENROUTER_MODEL_SECONDARY")
                .ok()
                .filter(|model| !model.trim().is_empty())
                .or_else(|| Some(DEFAULT_SECONDARY.to_string())),
            timeout: Duration::from_secs(timeout),
            max_retries,
            requests_per_minute: env_u32("OPENROUTER_REQUESTS_PER_MINUTE", 20),
            requests_per_day: env_u32("OPENROUTER_REQUESTS_PER_DAY", 200),
            retry_base_delay: Duration::from_millis(env_u64("OPENROUTER_RETRY_BASE_DELAY_MS", 250)),
            retry_max_delay: Duration::from_millis(env_u64(
                "OPENROUTER_RETRY_MAX_DELAY_MS",
                10_000,
            )),
            circuit_failure_threshold: env_u32("OPENROUTER_CIRCUIT_FAILURE_THRESHOLD", 3),
            circuit_cooldown: Duration::from_secs(env_u64(
                "OPENROUTER_CIRCUIT_COOLDOWN_SECONDS",
                60,
            )),
            max_input_bytes: env_usize("OPENROUTER_MAX_INPUT_BYTES", 65_536),
            fallback_max_total_attempts: env_usize("OPENROUTER_FALLBACK_MAX_TOTAL_ATTEMPTS", 4),
            fallback_max_total_latency: Duration::from_millis(env_u64(
                "OPENROUTER_FALLBACK_MAX_TOTAL_LATENCY_MS",
                30_000,
            )),
            require_non_free_model: env_bool("OPENROUTER_REQUIRE_NON_FREE_MODEL", false),
        })
    }
}

#[derive(Debug)]
struct TokenBucket {
    minute_tokens: f64,
    day_tokens: u32,
    minute_capacity: f64,
    minute_refill_per_second: f64,
    last_refill: Instant,
    day_started: chrono::NaiveDate,
    day_capacity: u32,
}

impl TokenBucket {
    fn new(per_minute: u32, per_day: u32) -> Self {
        Self {
            minute_tokens: per_minute as f64,
            day_tokens: per_day,
            minute_capacity: per_minute as f64,
            minute_refill_per_second: per_minute as f64 / 60.0,
            last_refill: Instant::now(),
            day_started: chrono::Utc::now().date_naive(),
            day_capacity: per_day,
        }
    }

    async fn acquire(&mut self) -> Result<(), LlmUnavailableError> {
        let today = chrono::Utc::now().date_naive();
        if today != self.day_started {
            self.day_started = today;
            self.day_tokens = self.day_capacity;
        }
        if self.day_tokens == 0 {
            return Err(LlmUnavailableError::QuotaExhausted);
        }
        loop {
            let elapsed = self.last_refill.elapsed().as_secs_f64();
            self.minute_tokens = (self.minute_tokens + elapsed * self.minute_refill_per_second)
                .min(self.minute_capacity);
            self.last_refill = Instant::now();
            if self.minute_tokens >= 1.0 {
                self.minute_tokens -= 1.0;
                self.day_tokens -= 1;
                info!(
                    day_remaining = self.day_tokens,
                    minute_tokens = self.minute_tokens,
                    "OpenRouter local quota token acquired"
                );
                return Ok(());
            }
            sleep(Duration::from_millis(250)).await;
        }
    }
}

#[derive(Debug, Default)]
struct ModelCircuit {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct CircuitBreaker {
    models: HashMap<String, ModelCircuit>,
}

impl CircuitBreaker {
    fn allow(&mut self, model: &str, cooldown: Duration) -> bool {
        let circuit = self.models.entry(model.to_string()).or_default();
        match circuit.opened_at {
            Some(opened_at) if opened_at.elapsed() < cooldown => false,
            Some(_) => {
                *circuit = ModelCircuit::default();
                true
            }
            None => true,
        }
    }

    fn success(&mut self, model: &str) {
        self.models.remove(model);
    }

    fn failure(&mut self, model: &str, threshold: u32) {
        let circuit = self.models.entry(model.to_string()).or_default();
        circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
        if threshold > 0 && circuit.consecutive_failures >= threshold {
            circuit.opened_at = Some(Instant::now());
        }
    }
}

#[derive(Debug)]
pub struct LlmCallResult {
    pub output: Value,
    pub model: String,
    pub latency_ms: u64,
    pub attempts: usize,
}

struct RouteFailure {
    error: LlmUnavailableError,
    attempts: usize,
}

#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    config: LlmClientConfig,
    limiter: Arc<Mutex<TokenBucket>>,
    circuits: Arc<Mutex<CircuitBreaker>>,
}

static SHARED_CLIENT: OnceLock<LlmClient> = OnceLock::new();
static RUNTIME_TELEMETRY: OnceLock<std::sync::Mutex<RuntimeTelemetry>> = OnceLock::new();

#[derive(Default)]
struct RuntimeTelemetry {
    calls_total: u64,
    successes_total: u64,
    failures_total: u64,
    rate_limited_total: u64,
    latency_total_ms: u64,
    by_task_model_outcome: BTreeMap<(String, String, String), u64>,
}

fn observe_runtime_call(task: &str, model: &str, outcome: &str, latency_ms: u64) {
    let telemetry = RUNTIME_TELEMETRY.get_or_init(Default::default);
    let mut telemetry = telemetry.lock().unwrap_or_else(|error| error.into_inner());
    telemetry.calls_total = telemetry.calls_total.saturating_add(1);
    telemetry.latency_total_ms = telemetry.latency_total_ms.saturating_add(latency_ms);
    if outcome == "success" {
        telemetry.successes_total = telemetry.successes_total.saturating_add(1);
    } else {
        telemetry.failures_total = telemetry.failures_total.saturating_add(1);
    }
    if outcome == "rate_limited" {
        telemetry.rate_limited_total = telemetry.rate_limited_total.saturating_add(1);
    }
    *telemetry
        .by_task_model_outcome
        .entry((task.to_string(), model.to_string(), outcome.to_string()))
        .or_insert(0) += 1;
}

pub fn runtime_telemetry_snapshot() -> Value {
    let telemetry = RUNTIME_TELEMETRY.get_or_init(Default::default);
    let telemetry = telemetry.lock().unwrap_or_else(|error| error.into_inner());
    let outcomes = telemetry
        .by_task_model_outcome
        .iter()
        .map(|((task, model, outcome), count)| {
            json!({"task": task, "model": model, "outcome": outcome, "count": count})
        })
        .collect::<Vec<_>>();
    let average_latency_ms = if telemetry.calls_total == 0 {
        0.0
    } else {
        telemetry.latency_total_ms as f64 / telemetry.calls_total as f64
    };
    json!({
        "calls_total": telemetry.calls_total,
        "successes_total": telemetry.successes_total,
        "failures_total": telemetry.failures_total,
        "rate_limited_total": telemetry.rate_limited_total,
        "latency_average_ms": average_latency_ms,
        "by_task_model_outcome": outcomes
    })
}

impl LlmClient {
    pub fn from_env() -> Result<Self, LlmUnavailableError> {
        Self::new(LlmClientConfig::from_env()?)
    }

    /// Returns the single process-wide client so all tasks share quota and circuit state.
    pub fn shared_from_env() -> Result<Self, LlmUnavailableError> {
        if let Some(client) = SHARED_CLIENT.get() {
            return Ok(client.clone());
        }
        let client = Self::from_env()?;
        let _ = SHARED_CLIENT.set(client);
        Ok(SHARED_CLIENT
            .get()
            .expect("shared LLM client initialized")
            .clone())
    }

    pub fn new(config: LlmClientConfig) -> Result<Self, LlmUnavailableError> {
        if config.requests_per_minute == 0 || config.fallback_max_total_attempts == 0 {
            return Err(LlmUnavailableError::BudgetExceeded(
                "requests-per-minute and total-attempt budgets must be greater than zero".into(),
            ));
        }
        if config.require_non_free_model
            && std::iter::once(config.primary_model.as_str())
                .chain(config.secondary_model.as_deref())
                .any(|model| model.ends_with(":free"))
        {
            return Err(LlmUnavailableError::InvalidConfig(
                "free model routes are forbidden; configure a quota-controlled model".into(),
            ));
        }
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent("ai-supply-chain-trust/0.2.0 OpenRouter")
            .build()
            .map_err(|e| LlmUnavailableError::Request(e.to_string()))?;
        Ok(Self {
            limiter: Arc::new(Mutex::new(TokenBucket::new(
                config.requests_per_minute,
                config.requests_per_day,
            ))),
            circuits: Arc::new(Mutex::new(CircuitBreaker::default())),
            client,
            config,
        })
    }

    pub async fn chat_json_schema(
        &self,
        task: &str,
        system_prompt: &str,
        input: &Value,
        output_schema: &Value,
    ) -> Result<LlmCallResult, LlmUnavailableError> {
        let input_size = serde_json::to_vec(input).unwrap_or_default().len();
        if input_size > self.config.max_input_bytes {
            return Err(LlmUnavailableError::BudgetExceeded(format!(
                "input is {input_size} bytes; maximum is {}",
                self.config.max_input_bytes
            )));
        }
        let operation_started = Instant::now();
        let mut attempts_used = 0usize;
        let mut models = vec![self.config.primary_model.as_str()];
        if let Some(secondary) = self.config.secondary_model.as_deref() {
            if secondary != self.config.primary_model {
                models.push(secondary);
            }
        }
        let mut last_error = None;
        for model in models {
            let attempts_remaining = self
                .config
                .fallback_max_total_attempts
                .saturating_sub(attempts_used);
            if attempts_remaining == 0
                || operation_started.elapsed() >= self.config.fallback_max_total_latency
            {
                warn!(task, attempts_used, "LLM fallback budget exhausted");
                break;
            }
            if !self
                .circuits
                .lock()
                .await
                .allow(model, self.config.circuit_cooldown)
            {
                last_error = Some(LlmUnavailableError::CircuitOpen {
                    model: model.to_string(),
                });
                continue;
            }
            let latency_remaining = self
                .config
                .fallback_max_total_latency
                .saturating_sub(operation_started.elapsed());
            let route = tokio::time::timeout(
                latency_remaining,
                self.chat_json_schema_once(
                    task,
                    model,
                    system_prompt,
                    input,
                    output_schema,
                    self.config
                        .max_retries
                        .min(attempts_remaining.saturating_sub(1)),
                ),
            )
            .await;
            match route {
                Err(_) => {
                    last_error = Some(LlmUnavailableError::BudgetExceeded(format!(
                        "total latency exceeded {} ms",
                        self.config.fallback_max_total_latency.as_millis()
                    )));
                    break;
                }
                Ok(Ok((output, latency_ms, attempts))) => {
                    attempts_used = attempts_used.saturating_add(attempts);
                    self.circuits.lock().await.success(model);
                    return Ok(LlmCallResult {
                        output,
                        model: model.to_string(),
                        latency_ms,
                        attempts: attempts_used,
                    });
                }
                Ok(Err(failure)) => {
                    attempts_used = attempts_used.saturating_add(failure.attempts);
                    let err = failure.error;
                    let retryable = err.is_retryable();
                    if retryable {
                        self.circuits
                            .lock()
                            .await
                            .failure(model, self.config.circuit_failure_threshold);
                    }
                    warn!(task, model, error_type = err.category(), error = %err, "LLM model route unavailable");
                    if !retryable {
                        return Err(err);
                    }
                    last_error = Some(err);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| LlmUnavailableError::Request("no model configured".into())))
    }

    async fn chat_json_schema_once(
        &self,
        task: &str,
        model: &str,
        system_prompt: &str,
        input: &Value,
        output_schema: &Value,
        max_retries: usize,
    ) -> Result<(Value, u64, usize), RouteFailure> {
        let call_started = Instant::now();
        for attempt in 0..=max_retries {
            self.limiter
                .lock()
                .await
                .acquire()
                .await
                .map_err(|error| RouteFailure {
                    error,
                    attempts: attempt,
                })?;
            let started = Instant::now();
            let body = json!({
                "model": model,
                "temperature": 0,
                "top_p": 1,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": serde_json::to_string(input).unwrap_or_else(|_| "{}".into())}
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": task,
                        "strict": true,
                        "schema": output_schema
                    }
                }
            });
            let response = self
                .client
                .post(&self.config.endpoint_url)
                .bearer_auth(&self.config.api_key)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await;
            let latency_ms = started.elapsed().as_millis() as u64;
            match response {
                Ok(resp) if resp.status().is_success() => {
                    let mut body = Vec::new();
                    let mut stream = resp.bytes_stream();
                    let mut read_error = None;
                    while let Some(chunk) = stream.next().await {
                        match chunk {
                            Ok(chunk) if body.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                                body.extend_from_slice(&chunk);
                            }
                            Ok(_) => {
                                read_error = Some("response exceeds 1 MiB limit".to_string());
                                break;
                            }
                            Err(error) => {
                                read_error = Some(error.to_string());
                                break;
                            }
                        }
                    }
                    let raw: Value = match read_error
                        .map(Err)
                        .unwrap_or_else(|| serde_json::from_slice(&body).map_err(|e| e.to_string()))
                    {
                        Ok(raw) => raw,
                        Err(error) => {
                            observe_runtime_call(task, model, "invalid_json", latency_ms);
                            return Err(RouteFailure {
                                error: LlmUnavailableError::InvalidJson(error),
                                attempts: attempt + 1,
                            });
                        }
                    };
                    let usage = raw.get("usage").cloned().unwrap_or(Value::Null);
                    info!(task, model, latency_ms, usage = %usage, "OpenRouter call completed");
                    let Some(content) = raw
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|a| a.first())
                        .and_then(|c| c.get("message"))
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                    else {
                        observe_runtime_call(task, model, "invalid_json", latency_ms);
                        return Err(RouteFailure {
                            error: LlmUnavailableError::InvalidJson(
                                "missing choices[0].message.content".into(),
                            ),
                            attempts: attempt + 1,
                        });
                    };
                    let output = match serde_json::from_str(content) {
                        Ok(output) => output,
                        Err(error) => {
                            observe_runtime_call(task, model, "invalid_json", latency_ms);
                            return Err(RouteFailure {
                                error: LlmUnavailableError::InvalidJson(error.to_string()),
                                attempts: attempt + 1,
                            });
                        }
                    };
                    observe_runtime_call(task, model, "success", latency_ms);
                    return Ok((
                        output,
                        call_started.elapsed().as_millis() as u64,
                        attempt + 1,
                    ));
                }
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after_seconds = parse_retry_after(resp.headers().get("retry-after"));
                    let text = resp.text().await.unwrap_or_default();
                    warn!(task, model, attempt, status = %status, latency_ms, "OpenRouter call failed");
                    let error = LlmUnavailableError::HttpStatus {
                        status: status.as_u16(),
                        message: text,
                        retry_after_seconds,
                    };
                    observe_runtime_call(task, model, error.category(), latency_ms);
                    if attempt == max_retries || !error.is_retryable() {
                        return Err(RouteFailure {
                            error,
                            attempts: attempt + 1,
                        });
                    }
                    sleep(self.retry_delay(attempt, retry_after_seconds)).await;
                }
                Err(err) => {
                    observe_runtime_call(task, model, "network_error", latency_ms);
                    warn!(task, model, attempt, latency_ms, error = %err, "OpenRouter call errored");
                    if attempt == max_retries {
                        return Err(RouteFailure {
                            error: LlmUnavailableError::Request(err.to_string()),
                            attempts: attempt + 1,
                        });
                    }
                    sleep(self.retry_delay(attempt, None)).await;
                }
            }
        }
        Err(RouteFailure {
            error: LlmUnavailableError::Request("retry loop exhausted".into()),
            attempts: max_retries + 1,
        })
    }

    fn retry_delay(&self, attempt: usize, retry_after_seconds: Option<u64>) -> Duration {
        if let Some(seconds) = retry_after_seconds {
            return Duration::from_secs(seconds).min(self.config.retry_max_delay);
        }
        let exponential = self
            .config
            .retry_base_delay
            .saturating_mul(2u32.saturating_pow(attempt as u32));
        let jitter_ceiling = (exponential.as_millis() as u64 / 4).max(1);
        let jitter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64
            % jitter_ceiling;
        (exponential + Duration::from_millis(jitter)).min(self.config.retry_max_delay)
    }
}

fn parse_retry_after(value: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    let value = value?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse() {
        return Some(seconds);
    }
    let deadline = chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %H:%M:%S GMT")
        .ok()?
        .and_utc();
    Some(
        deadline
            .signed_duration_since(chrono::Utc::now())
            .num_seconds()
            .max(0) as u64,
    )
}

pub fn input_hash(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn config(endpoint_url: String) -> LlmClientConfig {
        LlmClientConfig {
            api_key: "test-key".into(),
            endpoint_url,
            primary_model: "test/model".into(),
            secondary_model: None,
            timeout: Duration::from_secs(1),
            max_retries: 0,
            requests_per_minute: 10,
            requests_per_day: 10,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(10),
            circuit_failure_threshold: 3,
            circuit_cooldown: Duration::from_secs(1),
            max_input_bytes: 65_536,
            fallback_max_total_attempts: 4,
            fallback_max_total_latency: Duration::from_secs(5),
            require_non_free_model: false,
        }
    }

    async fn mock_response(status: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}/chat/completions")
    }

    async fn mock_responses(responses: Vec<(&str, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responses = responses
            .into_iter()
            .map(|(status, body)| (status.to_string(), body))
            .collect::<Vec<_>>();
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 8192];
                let _ = socket.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        format!("http://{address}/chat/completions")
    }

    async fn delayed_response(delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let _ = socket.read(&mut request).await.unwrap();
            sleep(delay).await;
            let body = json!({
                "choices": [{"message": {"content": "{\"status\":\"ok\"}"}}]
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        format!("http://{address}/chat/completions")
    }

    #[tokio::test]
    async fn structured_chat_parses_inner_json_and_reports_model() {
        let body = json!({
            "choices": [{"message": {"content": "{\"status\":\"ok\"}"}}],
            "usage": {"total_tokens": 7}
        })
        .to_string();
        let endpoint = mock_response("200 OK", &body).await;
        let client = LlmClient::new(config(endpoint)).unwrap();

        let response = client
            .chat_json_schema("decision", "evidence only", &json!({}), &json!({}))
            .await
            .unwrap();

        assert_eq!(response.output, json!({"status": "ok"}));
        assert_eq!(response.model, "test/model");
        assert_eq!(response.attempts, 1);
        let telemetry = runtime_telemetry_snapshot();
        assert!(telemetry["calls_total"]
            .as_u64()
            .is_some_and(|value| value >= 1));
        assert!(telemetry["by_task_model_outcome"].is_array());
    }

    #[tokio::test]
    async fn structured_chat_classifies_invalid_json_and_http_failure() {
        let endpoint = mock_response("200 OK", "not-json").await;
        let client = LlmClient::new(config(endpoint)).unwrap();
        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::InvalidJson(_))
        ));

        let endpoint = mock_response("503 Service Unavailable", "busy").await;
        let client = LlmClient::new(config(endpoint)).unwrap();
        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::HttpStatus { status: 503, .. })
        ));
    }

    #[tokio::test]
    async fn local_daily_quota_fails_before_network_and_hash_is_stable() {
        let mut client_config = config("http://127.0.0.1:1/unreachable".into());
        client_config.requests_per_day = 0;
        let client = LlmClient::new(client_config).unwrap();

        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::QuotaExhausted)
        ));
        assert_eq!(input_hash(&json!({"a": 1})), input_hash(&json!({"a": 1})));
        assert_ne!(input_hash(&json!({"a": 1})), input_hash(&json!({"a": 2})));
    }

    #[tokio::test]
    async fn daily_quota_resets_to_configured_capacity() {
        let client = LlmClient::new(config("http://127.0.0.1:1/unreachable".into())).unwrap();
        let mut limiter = client.limiter.lock().await;
        limiter.day_tokens = 0;
        limiter.day_started = chrono::Utc::now().date_naive() - chrono::Days::new(1);
        limiter.acquire().await.unwrap();
        assert_eq!(limiter.day_tokens, 9);
    }

    #[tokio::test]
    async fn permanent_http_errors_are_not_retried() {
        let endpoint = mock_response("401 Unauthorized", "bad key").await;
        let mut client_config = config(endpoint);
        client_config.max_retries = 3;
        let client = LlmClient::new(client_config).unwrap();

        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::HttpStatus { status: 401, .. })
        ));
    }

    #[tokio::test]
    async fn secondary_model_is_used_when_primary_route_is_rate_limited() {
        let success = json!({
            "choices": [{"message": {"content": "{\"status\":\"ok\"}"}}]
        })
        .to_string();
        let endpoint = mock_responses(vec![
            ("429 Too Many Requests", "busy".into()),
            ("200 OK", success),
        ])
        .await;
        let mut client_config = config(endpoint);
        client_config.secondary_model = Some("backup/model".into());
        let client = LlmClient::new(client_config).unwrap();

        let response = client
            .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
            .await
            .unwrap();

        assert_eq!(response.model, "backup/model");
        assert_eq!(response.output, json!({"status": "ok"}));
    }

    #[tokio::test]
    async fn total_attempt_budget_prevents_unbounded_secondary_fallback() {
        let endpoint = mock_response("429 Too Many Requests", "busy").await;
        let mut client_config = config(endpoint);
        client_config.secondary_model = Some("backup/model".into());
        client_config.fallback_max_total_attempts = 1;
        let client = LlmClient::new(client_config).unwrap();

        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::HttpStatus { status: 429, .. })
        ));
    }

    #[tokio::test]
    async fn total_latency_budget_cancels_a_slow_route() {
        let endpoint = delayed_response(Duration::from_millis(100)).await;
        let mut client_config = config(endpoint);
        client_config.fallback_max_total_latency = Duration::from_millis(5);
        let client = LlmClient::new(client_config).unwrap();

        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({}), &json!({}))
                .await,
            Err(LlmUnavailableError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn circuit_opens_at_threshold_and_recovers_after_cooldown() {
        let mut breaker = CircuitBreaker::default();
        breaker.failure("model", 2);
        assert!(breaker.allow("model", Duration::from_secs(1)));
        breaker.failure("model", 2);
        assert!(!breaker.allow("model", Duration::from_secs(1)));
        assert!(breaker.allow("model", Duration::ZERO));
    }

    #[test]
    fn retry_after_and_error_categories_are_structured() {
        let value = reqwest::header::HeaderValue::from_static("7");
        assert_eq!(parse_retry_after(Some(&value)), Some(7));
        let deadline = chrono::Utc::now() + chrono::Duration::seconds(10);
        let value = reqwest::header::HeaderValue::from_str(
            &deadline.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        )
        .unwrap();
        assert!(parse_retry_after(Some(&value)).is_some_and(|seconds| (8..=10).contains(&seconds)));
        let error = LlmUnavailableError::HttpStatus {
            status: 429,
            message: "busy".into(),
            retry_after_seconds: Some(7),
        };
        assert_eq!(error.category(), "rate_limited");
        assert_eq!(error.http_status(), Some(429));
    }

    #[tokio::test]
    async fn input_cost_budget_is_enforced_before_network() {
        let mut client_config = config("http://127.0.0.1:1/unreachable".into());
        client_config.max_input_bytes = 4;
        let client = LlmClient::new(client_config).unwrap();

        assert!(matches!(
            client
                .chat_json_schema("decision", "prompt", &json!({"too": "large"}), &json!({}))
                .await,
            Err(LlmUnavailableError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn production_policy_can_reject_free_model_routes() {
        let mut client_config = config("http://127.0.0.1:1/unreachable".into());
        client_config.primary_model = "google/gemma-4-31b-it:free".into();
        client_config.require_non_free_model = true;
        assert!(matches!(
            LlmClient::new(client_config),
            Err(LlmUnavailableError::InvalidConfig(_))
        ));
    }
}
