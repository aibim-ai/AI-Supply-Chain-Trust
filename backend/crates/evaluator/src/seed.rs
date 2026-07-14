//! Seed data — ONLY compiled with #[cfg(feature = "seed-data")].
//! NEVER included in production builds.

use serde_json::json;

pub const SEED_REPOS: &[&str] = &[
    "microsoft/onnxruntime",
    "huggingface/transformers",
    "langchain-ai/langchain",
    "ggerganov/llama.cpp",
];

pub fn seed_metadata(repo: &str) -> serde_json::Value {
    match repo {
        "microsoft/onnxruntime" => json!({
            "full_name": "microsoft/onnxruntime", "stargazers_count": 15000,
            "forks_count": 3500, "open_issues_count": 200,
            "pushed_at": "2026-06-01T00:00:00Z",
            "license": {"spdx_id": "MIT"}, "archived": false, "disabled": false,
            "owner": {"login": "microsoft", "type": "Organization", "created_at": "2010-01-01T00:00:00Z"}
        }),
        "huggingface/transformers" => json!({
            "full_name": "huggingface/transformers", "stargazers_count": 140000,
            "forks_count": 28000, "open_issues_count": 500,
            "pushed_at": "2026-07-01T00:00:00Z",
            "license": {"spdx_id": "Apache-2.0"}, "archived": false, "disabled": false,
            "owner": {"login": "huggingface", "type": "Organization", "created_at": "2016-01-01T00:00:00Z"}
        }),
        _ => json!({
            "full_name": repo, "stargazers_count": 100, "forks_count": 20,
            "open_issues_count": 5, "pushed_at": "2026-06-15T00:00:00Z",
            "license": {"spdx_id": "MIT"}, "archived": false, "disabled": false,
            "owner": {"login": "unknown", "type": "User", "created_at": "2020-01-01T00:00:00Z"}
        }),
    }
}
