//! Multi-source AI repo discovery — matches `discovery.py`.
//! Discovers repositories from GitHub Search, Trending, PyPI, npm, HuggingFace.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRepo {
    pub repo: String,
    pub source: String,
    pub stars: i64,
    pub description: String,
}

pub struct DiscoveryClient {
    client: Client,
    github_token: Option<String>,
    github_api_base: String,
    pypi_base: String,
    huggingface_api_base: String,
    last_call: Option<Instant>,
    min_interval: Duration,
}

impl DiscoveryClient {
    pub fn new(github_token: Option<String>) -> Self {
        Self::with_timeout(github_token, 20)
    }

    pub fn with_timeout(github_token: Option<String>, timeout_secs: u64) -> Self {
        Self {
            client: Client::builder()
                .user_agent("ai-supply-chain-trust/2.0")
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .unwrap(),
            github_token,
            github_api_base: "https://api.github.com".into(),
            pypi_base: "https://pypi.org".into(),
            huggingface_api_base: "https://huggingface.co".into(),
            last_call: None,
            min_interval: Duration::from_secs(2), // rate-limit safety
        }
    }

    async fn throttle(&mut self) {
        if let Some(last) = self.last_call {
            let elapsed = last.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
        }
        self.last_call = Some(Instant::now());
    }

    // -------------------------------------------------------------------
    // GitHub Search — AI/ML repos by topic
    // -------------------------------------------------------------------
    pub async fn discover_github(&mut self, per_query: i64) -> Vec<DiscoveredRepo> {
        self.discover_github_matching(per_query, "stars:>10", "stars")
            .await
    }

    pub async fn discover_github_recent(
        &mut self,
        per_query: i64,
        min_stars: i64,
        pushed_since: &str,
    ) -> Vec<DiscoveredRepo> {
        let qualifiers = format!("stars:>{}+pushed:>={pushed_since}", min_stars.max(0));
        self.discover_github_matching(per_query, &qualifiers, "updated")
            .await
    }

    async fn discover_github_matching(
        &mut self,
        per_query: i64,
        qualifiers: &str,
        sort: &str,
    ) -> Vec<DiscoveredRepo> {
        let topics = [
            "machine-learning",
            "deep-learning",
            "llm",
            "mcp-server",
            "ai-agent",
            "transformers",
            "neural-network",
            "security-scanner",
        ];
        let mut repos = Vec::new();

        for topic in &topics {
            self.throttle().await;
            let url = format!(
                "{}/search/repositories?q=topic:{topic}+{qualifiers}&sort={sort}&order=desc&per_page={per_query}",
                self.github_api_base
            );
            match self.github_get(&url).await {
                Ok(body) => {
                    if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                        for item in items {
                            let full_name =
                                item.get("full_name").and_then(Value::as_str).unwrap_or("");
                            let stars = item
                                .get("stargazers_count")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            let desc = item
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            repos.push(DiscoveredRepo {
                                repo: full_name.to_string(),
                                source: format!("github:topic:{topic}"),
                                stars,
                                description: desc.to_string(),
                            });
                        }
                    }
                }
                Err(error) => warn!(topic, %error, "GitHub discovery query failed"),
            }
        }
        info!("GitHub discovery: {} repos", repos.len());
        repos
    }

    // -------------------------------------------------------------------
    // PyPI — AI/ML packages
    // -------------------------------------------------------------------
    pub async fn discover_pypi(&self) -> Vec<DiscoveredRepo> {
        let mut repos = Vec::new();
        let terms = ["llm", "transformers", "pytorch", "tensorflow"];
        for term in &terms {
            let url = format!("{}/search/?q={term}", self.pypi_base);
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(html) = resp.text().await {
                        // Extract package names from HTML (simplified)
                        for line in html.lines() {
                            if line.contains("package-snippet__name") {
                                let name = line
                                    .split('>')
                                    .nth(1)
                                    .unwrap_or("")
                                    .split('<')
                                    .next()
                                    .unwrap_or("");
                                if !name.is_empty() {
                                    repos.push(DiscoveredRepo {
                                        repo: format!("pypi:{name}"),
                                        source: format!("pypi:search:{term}"),
                                        stars: 0,
                                        description: String::new(),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        info!("PyPI discovery: {} packages", repos.len());
        repos
    }

    // -------------------------------------------------------------------
    // HuggingFace — trending models
    // -------------------------------------------------------------------
    pub async fn discover_huggingface(&self, limit: i64) -> Vec<DiscoveredRepo> {
        let url = format!(
            "{}/api/models?sort=downloads&direction=-1&limit={limit}",
            self.huggingface_api_base
        );
        let mut repos = Vec::new();
        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(models) = resp.json::<Vec<Value>>().await {
                for model in models {
                    let id = model.get("id").and_then(Value::as_str).unwrap_or("");
                    let downloads = model.get("downloads").and_then(|v| v.as_i64()).unwrap_or(0);
                    repos.push(DiscoveredRepo {
                        repo: format!("hf:{id}"),
                        source: "huggingface:trending".into(),
                        stars: downloads,
                        description: String::new(),
                    });
                }
            }
        }
        info!("HF discovery: {} models", repos.len());
        repos
    }

    // -------------------------------------------------------------------
    // All sources combined
    // -------------------------------------------------------------------
    pub async fn discover_all(&mut self, limit_per_source: i64) -> Vec<DiscoveredRepo> {
        let mut all = Vec::new();
        all.extend(self.discover_github(limit_per_source).await);
        all.extend(self.discover_pypi().await);
        all.extend(self.discover_huggingface(limit_per_source).await);
        all.sort_by_key(|a| std::cmp::Reverse(a.stars));
        all.dedup_by(|a, b| a.repo == b.repo);
        all
    }

    async fn github_get(&self, url: &str) -> Result<Value, anyhow::Error> {
        let mut req = self
            .client
            .get(url)
            .header("Accept", "application/vnd.github+json");
        if let Some(ref t) = self.github_token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        Ok(req.send().await?.error_for_status()?.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn discovered_repo_serialization() {
        let r = DiscoveredRepo {
            repo: "owner/name".into(),
            source: "github:topic:ai".into(),
            stars: 100,
            description: "An AI repo".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("owner/name"));
    }

    async fn discovery_server(request_count: usize) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        tokio::spawn(async move {
            for _ in 0..request_count {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut raw = vec![0; 8192];
                let read = socket.read(&mut raw).await.unwrap();
                let request = String::from_utf8_lossy(&raw[..read]).to_string();
                captured.lock().unwrap().push(request.clone());
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (content_type, body) = if path.starts_with("/search/repositories") {
                    (
                        "application/json",
                        json!({"items": [{
                            "full_name": "owner/github-repo",
                            "stargazers_count": 90,
                            "description": "GitHub result"
                        }]})
                        .to_string(),
                    )
                } else if path.starts_with("/search/") {
                    (
                        "text/html",
                        "<span class=\"package-snippet__name\">local-package</span>".into(),
                    )
                } else {
                    (
                        "application/json",
                        json!([{"id": "owner/model", "downloads": 120}]).to_string(),
                    )
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}"), requests)
    }

    #[tokio::test]
    async fn all_sources_are_combined_sorted_deduped_and_authenticated() {
        let (base, requests) = discovery_server(13).await;
        let mut client = DiscoveryClient::with_timeout(Some("test-token".into()), 1);
        client.github_api_base = base.clone();
        client.pypi_base = base.clone();
        client.huggingface_api_base = base;
        client.min_interval = Duration::ZERO;

        let repos = client.discover_all(1).await;

        assert_eq!(repos[0].repo, "hf:owner/model");
        assert_eq!(repos[1].repo, "owner/github-repo");
        assert_eq!(repos[2].repo, "pypi:local-package");
        assert_eq!(repos.len(), 3);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 13);
        assert!(requests
            .iter()
            .filter(|request| request.contains("/search/repositories"))
            .all(|request| request.contains("authorization: Bearer test-token")));
    }

    #[tokio::test]
    async fn recent_github_discovery_applies_freshness_and_star_filters() {
        let (base, requests) = discovery_server(8).await;
        let mut client = DiscoveryClient::with_timeout(None, 1);
        client.github_api_base = base;
        client.min_interval = Duration::ZERO;

        let repos = client.discover_github_recent(1, 500, "2026-07-06").await;

        assert_eq!(repos.len(), 8);
        let requests = requests.lock().unwrap();
        assert!(
            requests.iter().all(|request| {
                request.contains("stars:")
                    && request.contains("pushed:")
                    && request.contains("2026-07-06")
                    && request.contains("sort=updated")
            }),
            "captured requests: {requests:#?}"
        );
    }
}
