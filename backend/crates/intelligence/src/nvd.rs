//! NVD (National Vulnerability Database) CVE fetcher.
//! Queries the NVD REST API 2.0 for CVEs matching a project keyword.
//!
//! API: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={term}
//! Rate limit: 5 requests per 30 seconds without API key, 50 with key.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use tokio::time::sleep;
use tracing::{info, warn};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_PAGE_SIZE: usize = 250;
const NVD_MAX_PAGES: usize = 4;
const NVD_RATE_DELAY_MS: u64 = 6100;
const NVD_KEYED_RATE_DELAY_MS: u64 = 650;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NvdCveEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub published: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attribution_terms: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_url: String,
}

/// Fetch CVEs from NVD matching repo/package aliases and keep only records
/// whose description explicitly names one of those aliases.
pub async fn fetch_nvd_cves(
    client: &Client,
    owner: &str,
    repo: &str,
    package_names: &[String],
    ecosystem: &str,
    api_key: Option<&str>,
) -> Result<Vec<NvdCveEntry>, ai_supply_chain_trust_models::DataSourceError> {
    let aliases = project_aliases(package_names, repo);
    if aliases.is_empty() {
        warn!(
            owner,
            repo, "NVD lookup skipped: no manifest-derived package identity"
        );
        return Ok(Vec::new());
    }
    let search_terms = aliases.clone();
    let mut all_cves: Vec<NvdCveEntry> = Vec::new();

    for term in &search_terms {
        let encoded_term =
            url::form_urlencoded::byte_serialize(term.as_bytes()).collect::<String>();
        for page in 0..NVD_MAX_PAGES {
            let start_index = page * NVD_PAGE_SIZE;
            // NVD's 2,000-record default can contain very large configuration
            // trees. Bounded pages keep peak memory predictable in the worker.
            let url = format!(
                "{NVD_API_BASE}?keywordSearch={encoded_term}&resultsPerPage={NVD_PAGE_SIZE}&startIndex={start_index}"
            );

            let mut request = client
                .get(&url)
                .header("User-Agent", "ai-supply-chain-trust/0.2.0")
                .timeout(Duration::from_secs(60));
            if let Some(key) = api_key {
                request = request.header("apiKey", key);
            }
            let resp = match request.send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(term, error = %e, "NVD request failed");
                    break;
                }
            };

            if resp.status().as_u16() == 403 || resp.status().as_u16() == 429 {
                warn!(
                    term,
                    status = resp.status().as_u16(),
                    "NVD rate limited; deferring task"
                );
                return Err(ai_supply_chain_trust_models::DataSourceError::NvdRateLimited);
            }

            let mut body: Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(term, error = %e, "NVD response parse failed");
                    break;
                }
            };
            let total_results = body
                .get("totalResults")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            // Move the array out instead of cloning the full CVE payload.
            let vulnerabilities = body
                .get_mut("vulnerabilities")
                .and_then(Value::as_array_mut)
                .map(std::mem::take)
                .unwrap_or_default();
            let returned = vulnerabilities.len();
            if returned == 0 {
                break;
            }

            for vuln in &vulnerabilities {
                let cve_obj = vuln.get("cve").unwrap_or(vuln);
                let cve_id = cve_obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if cve_id.is_empty() || all_cves.iter().any(|entry| entry.cve_id == cve_id) {
                    continue;
                }

                let description = cve_obj
                    .get("descriptions")
                    .and_then(|d| d.as_array())
                    .and_then(|a| {
                        a.iter()
                            .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                    })
                    .and_then(|d| d.get("value").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let attribution_terms = matching_aliases(description, &aliases);
                if attribution_terms.is_empty() || !cpe_matches_project(cve_obj, &aliases) {
                    continue;
                }

                let (severity, cvss_score) = extract_cvss(cve_obj);
                let published = cve_obj
                    .get("published")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                all_cves.push(NvdCveEntry {
                    cve_id: cve_id.to_string(),
                    description: description.to_string(),
                    severity,
                    cvss_score,
                    published: published.to_string(),
                    source: "nvd".to_string(),
                    attribution_terms,
                    source_url: format!("https://nvd.nist.gov/vuln/detail/{cve_id}"),
                });
            }

            if start_index + returned >= total_results {
                break;
            }
            let delay_ms = if api_key.is_some() {
                NVD_KEYED_RATE_DELAY_MS
            } else {
                NVD_RATE_DELAY_MS
            };
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    info!(
        owner,
        repo,
        ecosystem,
        package_names = ?package_names,
        aliases = ?aliases,
        count = all_cves.len(),
        "NVD CVE fetch complete"
    );

    Ok(all_cves)
}

fn project_aliases(package_names: &[String], repo: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for raw in package_names {
        let normalized = raw
            .split('/')
            .next_back()
            .unwrap_or(raw)
            .trim()
            .trim_end_matches(".git")
            .to_ascii_lowercase();
        add_alias(&mut aliases, &normalized);
        if let Some(stripped) = normalized.strip_suffix("-src") {
            add_alias(&mut aliases, stripped);
        }
        if let Some(stripped) = normalized.strip_suffix("_src") {
            add_alias(&mut aliases, stripped);
        }
    }
    // Source repositories commonly have no package manifest at their root
    // (FFmpeg, PHP and wolfSSL are notable examples). The repository slug is
    // still a useful identity only when the strict CPE product check below can
    // independently confirm it. Avoid generic slugs that would create noisy
    // NVD keyword searches.
    if aliases.is_empty() {
        let repo_name = repo
            .split('/')
            .next_back()
            .unwrap_or(repo)
            .trim()
            .trim_end_matches(".git")
            .to_ascii_lowercase();
        if is_specific_repo_alias(&repo_name) {
            add_alias(&mut aliases, &repo_name);
            if let Some(stripped) = repo_name.strip_suffix("-src") {
                add_alias(&mut aliases, stripped);
            }
            if let Some(stripped) = repo_name.strip_suffix("_src") {
                add_alias(&mut aliases, stripped);
            }
        }
    }
    if aliases.iter().any(|alias| alias == "wolfssl") {
        add_alias(&mut aliases, "wolfcrypt");
        add_alias(&mut aliases, "cyassl");
    }
    aliases
}

fn is_specific_repo_alias(alias: &str) -> bool {
    alias.len() >= 4
        && !matches!(
            alias,
            "app"
                | "application"
                | "backend"
                | "client"
                | "core"
                | "framework"
                | "frontend"
                | "library"
                | "platform"
                | "project"
                | "repo"
                | "repository"
                | "server"
                | "source"
        )
}

fn add_alias(aliases: &mut Vec<String>, alias: &str) {
    let alias = alias.trim().to_ascii_lowercase();
    if alias.len() >= 3 && !aliases.iter().any(|existing| existing == &alias) {
        aliases.push(alias);
    }
}

fn matching_aliases(description: &str, aliases: &[String]) -> Vec<String> {
    let lower = description.to_ascii_lowercase();
    aliases
        .iter()
        .filter(|alias| contains_alias(&lower, alias))
        .cloned()
        .collect()
}

fn cpe_matches_project(cve: &Value, aliases: &[String]) -> bool {
    let wanted = aliases
        .iter()
        .map(|alias| normalize_product(alias))
        .collect::<Vec<_>>();
    let mut criteria = Vec::new();
    collect_cpe_criteria(cve.get("configurations"), &mut criteria);
    criteria.into_iter().any(|criterion| {
        let parts = criterion.split(':').collect::<Vec<_>>();
        let product = parts.get(4).copied().unwrap_or_default();
        let decoded = url::form_urlencoded::parse(product.as_bytes())
            .map(|(key, value)| format!("{key}{value}"))
            .collect::<String>();
        let normalized = normalize_product(&decoded);
        !normalized.is_empty() && wanted.iter().any(|alias| alias == &normalized)
    })
}

fn collect_cpe_criteria(value: Option<&Value>, output: &mut Vec<String>) {
    match value {
        Some(Value::Array(values)) => {
            for value in values {
                collect_cpe_criteria(Some(value), output);
            }
        }
        Some(Value::Object(map)) => {
            if let Some(criteria) = map.get("criteria").and_then(Value::as_str) {
                output.push(criteria.to_ascii_lowercase());
            }
            for value in map.values() {
                collect_cpe_criteria(Some(value), output);
            }
        }
        _ => {}
    }
}

fn normalize_product(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_alias(lower: &str, alias: &str) -> bool {
    if alias.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return lower.match_indices(alias).any(|(idx, _)| {
            let before = lower[..idx].chars().next_back();
            let after = lower[idx + alias.len()..].chars().next();
            before.is_none_or(|ch| !ch.is_ascii_alphanumeric())
                && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
        });
    }
    lower.contains(alias)
}

fn extract_cvss(cve: &Value) -> (String, Option<f64>) {
    let metrics = cve.get("metrics");
    if let Some(cvss31) = metrics
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let base_score = cvss31
            .get("cvssData")
            .and_then(|c| c.get("baseScore"))
            .and_then(|v| v.as_f64());
        let severity = cvss31
            .get("cvssData")
            .and_then(|c| c.get("baseSeverity"))
            .and_then(|v| v.as_str())
            .unwrap_or("MEDIUM");
        return (severity.to_ascii_lowercase(), base_score);
    }
    if let Some(cvss30) = metrics
        .and_then(|m| m.get("cvssMetricV30"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let base_score = cvss30
            .get("cvssData")
            .and_then(|c| c.get("baseScore"))
            .and_then(|v| v.as_f64());
        let severity = cvss30
            .get("cvssData")
            .and_then(|c| c.get("baseSeverity"))
            .and_then(|v| v.as_str())
            .unwrap_or("MEDIUM");
        return (severity.to_ascii_lowercase(), base_score);
    }
    if let Some(cvss2) = metrics
        .and_then(|m| m.get("cvssMetricV2"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let base_score = cvss2
            .get("cvssData")
            .and_then(|c| c.get("baseScore"))
            .and_then(|v| v.as_f64());
        let severity = match base_score {
            Some(score) if score >= 7.0 => "high",
            Some(score) if score >= 4.0 => "medium",
            Some(_) => "low",
            None => "unknown",
        };
        return (severity.to_string(), base_score);
    }
    ("medium".to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wolfssl_aliases_include_historical_product_names() {
        let aliases = project_aliases(&["wolfssl".to_string()], "wolfssl");

        assert!(aliases.contains(&"wolfssl".to_string()));
        assert!(aliases.contains(&"wolfcrypt".to_string()));
        assert!(aliases.contains(&"cyassl".to_string()));
    }

    #[test]
    fn nvd_attribution_requires_repo_alias_in_description() {
        let aliases = project_aliases(&["wolfssl".to_string()], "wolfssl");

        assert_eq!(
            matching_aliases("wolfSSL before 5.7.2 has a TLS parsing issue.", &aliases),
            vec!["wolfssl".to_string()]
        );
        assert_eq!(
            matching_aliases("wolfCrypt before 5.7.2 has an ASN.1 issue.", &aliases),
            vec!["wolfcrypt".to_string()]
        );
        assert!(matching_aliases("wolfMQTT before 1.19 has an issue.", &aliases).is_empty());
        assert!(matching_aliases("OpenSSL before 3.0 has an issue.", &aliases).is_empty());
    }

    #[test]
    fn php_src_aliases_include_php_product_name() {
        let aliases = project_aliases(&["php-src".to_string()], "php-src");

        assert!(aliases.contains(&"php-src".to_string()));
        assert!(aliases.contains(&"php".to_string()));
        assert_eq!(
            matching_aliases("In PHP before 8.3.1, parsing may fail.", &aliases),
            vec!["php".to_string()]
        );
    }

    #[test]
    fn raptor_name_does_not_match_unrelated_cpe_products() {
        let aliases = project_aliases(&["raptor".to_string()], "raptor");
        let firewall = serde_json::json!({
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:symantec:raptor_firewall:6.5.3:*:*:*:*:*:*:*"
            }]}]}]
        });
        let gfx = serde_json::json!({
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:tech_source:raptor_gfx:*:*:*:*:*:*:*:*"
            }]}]}]
        });

        assert!(!cpe_matches_project(&firewall, &aliases));
        assert!(!cpe_matches_project(&gfx, &aliases));
    }

    #[test]
    fn exact_manifest_package_and_cpe_product_match_is_accepted() {
        let aliases = project_aliases(&["wolfssl".to_string()], "wolfssl");
        let cve = serde_json::json!({
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:wolfssl:wolfssl:5.7.0:*:*:*:*:*:*:*"
            }]}]}]
        });

        assert!(cpe_matches_project(&cve, &aliases));
    }

    #[test]
    fn source_repo_slug_is_used_when_manifest_identity_is_missing() {
        assert_eq!(
            project_aliases(&[], "php/php-src"),
            vec!["php-src".to_string(), "php".to_string()]
        );
        let wolfssl = project_aliases(&[], "wolfssl/wolfssl");
        assert!(wolfssl.contains(&"wolfssl".to_string()));
        assert!(wolfssl.contains(&"wolfcrypt".to_string()));
        assert!(wolfssl.contains(&"cyassl".to_string()));
    }

    #[test]
    fn generic_repo_slug_is_not_used_as_nvd_identity() {
        assert!(project_aliases(&[], "example/server").is_empty());
    }
}
