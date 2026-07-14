//! GitHub metadata fetcher — matches github_metadata.py

use reqwest::Client;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub struct GitHubClient {
    client: Client,
    tokens: Vec<String>,
    token_cursor: Arc<AtomicUsize>,
    base: String,
}

pub enum ConditionalJson {
    NotModified,
    Modified {
        value: Value,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        let client = Client::builder()
            .user_agent("ai-supply-chain-trust/0.2.0")
            .timeout(Duration::from_secs(20))
            .build()
            .expect("reqwest client");
        Self::with_client(client, token)
    }

    /// Reuse a process-wide HTTP transport so DNS, TLS and connection pools are
    /// shared by metadata and intelligence requests.
    pub fn with_client(client: Client, token: Option<String>) -> Self {
        Self {
            client,
            tokens: parse_github_tokens(token),
            token_cursor: Arc::new(AtomicUsize::new(0)),
            base: "https://api.github.com".into(),
        }
    }

    pub async fn fetch_repo(&self, owner: &str, repo: &str) -> Result<Value, String> {
        let url = format!("{}/repos/{}/{}", self.base, owner, repo);
        self.get_json(&url).await
    }

    pub async fn fetch_repo_conditional(
        &self,
        owner: &str,
        repo: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<ConditionalJson, String> {
        let url = format!("{}/repos/{}/{}", self.base, owner, repo);
        let attempts = self.tokens.len() + 1;
        for attempt in 0..attempts {
            let token = self.token_for_attempt(attempt);
            let resp = self
                .send_with_transport_retries(&url, || {
                    let mut req = self
                        .client
                        .get(&url)
                        .header("Accept", "application/vnd.github+json")
                        .header("X-GitHub-Api-Version", "2022-11-28");
                    if let Some(token) = token {
                        req = req.header("Authorization", format!("Bearer {token}"));
                    }
                    if let Some(value) = etag {
                        req = req.header("If-None-Match", value);
                    }
                    if let Some(value) = last_modified {
                        req = req.header("If-Modified-Since", value);
                    }
                    req
                })
                .await?;
            if resp.status().as_u16() == 304 {
                return Ok(ConditionalJson::NotModified);
            }
            let status = resp.status();
            if !status.is_success() {
                let error = github_status_error(status.as_u16());
                if matches!(status.as_u16(), 401 | 403 | 429) && attempt + 1 < attempts {
                    tracing::info!(
                        url,
                        status = status.as_u16(),
                        "GitHub metadata token failed; trying next configured token"
                    );
                    continue;
                }
                return Err(error);
            }
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .map(String::from);
            let last_modified = resp
                .headers()
                .get("last-modified")
                .and_then(|value| value.to_str().ok())
                .map(String::from);
            let value = resp.json().await.map_err(|error| error.to_string())?;
            return Ok(ConditionalJson::Modified {
                value,
                etag,
                last_modified,
            });
        }
        Err("GitHubRateLimited".to_string())
    }

    pub async fn fetch_owner(&self, login: &str) -> Result<Value, String> {
        let url = format!("{}/users/{}", self.base, login);
        self.get_json(&url).await
    }

    pub async fn fetch_releases(&self, owner: &str, repo: &str) -> Result<Value, String> {
        let url = format!(
            "{}/repos/{}/{}/releases?per_page=100",
            self.base, owner, repo
        );
        self.get_json(&url).await
    }

    async fn get_json(&self, url: &str) -> Result<Value, String> {
        let attempts = self.tokens.len() + 1;
        for attempt in 0..attempts {
            let token = self.token_for_attempt(attempt);
            let resp = self
                .send_with_transport_retries(url, || {
                    let mut req = self
                        .client
                        .get(url)
                        .header("Accept", "application/vnd.github+json")
                        .header("X-GitHub-Api-Version", "2022-11-28");
                    if let Some(token) = token {
                        req = req.header("Authorization", format!("Bearer {token}"));
                    }
                    req
                })
                .await?;
            let status = resp.status();
            let remaining = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown");
            tracing::debug!(url, %status, remaining, "GitHub metadata response");
            if !status.is_success() {
                let error = github_status_error(status.as_u16());
                if matches!(status.as_u16(), 401 | 403 | 429) && attempt + 1 < attempts {
                    tracing::info!(
                        url,
                        status = status.as_u16(),
                        remaining,
                        "GitHub metadata token failed; trying next configured token"
                    );
                    continue;
                }
                return Err(error);
            }
            let body: Value = resp.json().await.map_err(|e| e.to_string())?;
            return Ok(body);
        }
        Err("GitHubRateLimited".to_string())
    }

    async fn send_with_transport_retries<F>(
        &self,
        url: &str,
        mut build: F,
    ) -> Result<reqwest::Response, String>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        let mut last_error = None;
        for attempt in 0..7 {
            match build().send().await {
                Ok(resp) => return Ok(resp),
                Err(error) => {
                    let classified = github_transport_error(&error);
                    tracing::warn!(
                        url,
                        attempt = attempt + 1,
                        error = %classified,
                        "GitHub metadata transport request failed"
                    );
                    last_error = Some(classified);
                    if attempt < 6 {
                        let delay_ms = 500u64 * 2u64.pow(attempt as u32).min(16000);
                        sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| "GitHubTransport".to_string()))
    }

    fn token_for_attempt(&self, attempt: usize) -> Option<&str> {
        if attempt >= self.tokens.len() {
            return None;
        }
        self.next_token()
    }

    fn next_token(&self) -> Option<&str> {
        if self.tokens.is_empty() {
            return None;
        }
        let index = self.token_cursor.fetch_add(1, Ordering::Relaxed);
        self.tokens
            .get(index % self.tokens.len())
            .map(String::as_str)
    }
}

fn github_transport_error(error: &reqwest::Error) -> String {
    let prefix = if error.is_timeout() {
        "GitHubTimeout"
    } else if error.is_connect() {
        "GitHubConnect"
    } else {
        "GitHubTransport"
    };
    format!("{prefix}: {error}")
}

fn parse_github_tokens(token: Option<String>) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(value) = token {
        for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let token = token.trim();
            if !token.is_empty() && !tokens.iter().any(|existing| existing == token) {
                tokens.push(token.to_string());
            }
        }
    }
    tokens
}

fn github_status_error(status: u16) -> String {
    match status {
        401 => "GitHubUnauthorized".to_string(),
        403 | 429 => "GitHubRateLimited".to_string(),
        404 => "GitHubRepoNotFound".to_string(),
        code => format!("GitHubHttpStatus({code})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_parser_deduplicates_all_supported_separators() {
        let tokens = parse_github_tokens(Some("token-a, token-b;token-a\ntoken-c".to_string()));
        assert_eq!(tokens, vec!["token-a", "token-b", "token-c"]);
        assert!(parse_github_tokens(None).is_empty());
    }

    #[test]
    fn token_selection_prefers_credentials_then_falls_back_anonymous() {
        let client = GitHubClient::new(Some("token-a,token-b".to_string()));
        assert_eq!(client.token_for_attempt(0), Some("token-a"));
        assert_eq!(client.token_for_attempt(1), Some("token-b"));
        assert_eq!(client.token_for_attempt(2), None);
    }

    #[test]
    fn status_codes_map_to_stable_error_contracts() {
        assert_eq!(github_status_error(401), "GitHubUnauthorized");
        assert_eq!(github_status_error(403), "GitHubRateLimited");
        assert_eq!(github_status_error(429), "GitHubRateLimited");
        assert_eq!(github_status_error(404), "GitHubRepoNotFound");
        assert_eq!(github_status_error(502), "GitHubHttpStatus(502)");
    }
}
