//! AI Supply Chain Trust — Rust-native binary entrypoint.
//! Dispatches to all CLI subcommands (serve, eval, discover, etc.)

use ai_supply_chain_trust_cli::{Cli, Command};
use clap::Parser;
use serde_json::json;

fn discovery_timeout_seconds() -> u64 {
    std::env::var("AI_SUPPLY_CHAIN_TRUST_GITHUB_TIMEOUT_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &u64| *v > 0)
        .unwrap_or(120)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("ai_supply_chain_trust=info,tower_http=warn")
            }),
        )
        .init();

    let cli = Cli::parse();
    let db_path = cli.db_path.clone();
    let token = cli.token.clone();
    let web_dir = cli.web_dir.clone();
    if std::env::var("AI_SUPPLY_CHAIN_TRUST_WEB_DIR").is_err() {
        std::env::set_var("AI_SUPPLY_CHAIN_TRUST_WEB_DIR", &web_dir);
    }

    let base_url = cli
        .base_url
        .unwrap_or_else(|| "http://localhost:8000".to_string());

    match cli.command {
        Command::Serve(args) => {
            let url = base_url.clone();
            tracing::info!(host = %args.host, port = args.port, role = %args.role, "Starting server");

            match args.role.as_str() {
                "api" | "all" => {
                    ai_supply_chain_trust_server_new::serve(
                        &args.host, args.port, db_path, token, url,
                    )
                    .await?;
                }
                "web" => {
                    eprintln!("Web-only mode: serving static files. Use 'all' for API+Web.");
                    ai_supply_chain_trust_server_new::serve(
                        &args.host, args.port, db_path, token, url,
                    )
                    .await?;
                }
                _ => {
                    eprintln!("Unknown role: {}. Valid: api, web, all", args.role);
                    std::process::exit(1);
                }
            }
        }

        Command::Eval(args) => {
            println!("Evaluating {}...", args.repo);
            let service = make_service(&db_path, token).await?;
            match service.run_scan(&args.repo).await {
                Ok(report) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        let score = report
                            .get("trust_score")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let grade = report.get("grade").and_then(|v| v.as_str()).unwrap_or("-");
                        let verdict = report.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
                        println!(
                            "{:<20} {:>6.0}/100  {:<2}  {}",
                            args.repo, score, grade, verdict
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Discover(args) => {
            println!(
                "Discovering repos (limit_per_source={}, max_total={})...",
                args.limit_per_source, args.max_total
            );
            let mut client = ai_supply_chain_trust_discovery::DiscoveryClient::with_timeout(
                token,
                discovery_timeout_seconds(),
            );
            let repos = client.discover_all(args.limit_per_source).await;
            println!("Found {} repos:", repos.len());
            for (i, r) in repos.iter().take(args.max_total as usize).enumerate() {
                println!(
                    "  {:3}. {:40} ★{:>6}  [{}]",
                    i + 1,
                    r.repo,
                    r.stars,
                    r.source
                );
            }

            if !args.no_score {
                println!("\nScoring discovered repos...");
                let service = make_service(&db_path, None).await?;
                for r in repos.iter().take(args.max_total as usize) {
                    if args.skip_existing && service.get_result(&r.repo).is_some() {
                        continue;
                    }
                    match service.run_scan(&r.repo).await {
                        Ok(report) => {
                            let score = report
                                .get("trust_score")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            println!("  {:40} {:>6.0}/100", r.repo, score);
                        }
                        Err(e) => eprintln!("  {:40} ERROR: {}", r.repo, e),
                    }
                }
            }
        }

        Command::Leaderboard(args) => {
            let service = make_service(&db_path, token).await?;
            let lb = service.leaderboard(args.query.as_deref(), args.limit);
            if let Some(rows) = lb.get("rows").and_then(|v| v.as_array()) {
                for r in rows {
                    let repo = r.get("repo").and_then(|v| v.as_str()).unwrap_or("");
                    let score = r.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let grade = r.get("grade").and_then(|v| v.as_str()).unwrap_or("-");
                    let verdict = r.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
                    println!("{repo:<40} {score:>6.0}/100  {grade:<2}  {verdict}");
                }
            }
        }

        Command::SecurityContext(args) => {
            let service = make_service(&db_path, token).await?;
            let ctx = service.get_security_context(&args.repo, "http://localhost:8000");
            if args.format == "markdown" {
                let md = format!(
                    "# Security Context: {}\n\n```json\n{}\n```\n",
                    args.repo,
                    serde_json::to_string_pretty(&ctx)?
                );
                println!("{md}");
            } else {
                println!("{}", serde_json::to_string_pretty(&ctx)?);
            }
        }

        Command::Scan(args) => {
            let repo_url = args.repo.unwrap_or_else(|| ".".into());
            let runner = if let Some(path) = args.path {
                ai_supply_chain_trust_scanner_runner::ScannerRunner::new(&repo_url)
                    .with_source(&path)
            } else {
                ai_supply_chain_trust_scanner_runner::ScannerRunner::new(&repo_url)
            };
            println!("Running scanners on {repo_url}...");
            let results = runner.run_all().await;
            for r in &results {
                let status = if r.status == "ok" {
                    "✅"
                } else if r.status == "skipped" {
                    "⏭️"
                } else {
                    "❌"
                };
                println!("  {} {:<15} {}", status, r.tool, r.detail);
            }
        }

        Command::Api => {
            println!(
                r#"{{"service":"ai-supply-chain-trust","version":"2.0.0-rust","endpoints":["/api/v1/scan","/api/v1/context/{{owner}}/{{repo}}","/api/v1/leaderboard","/api/v1/recent-scans","/api/v1/result","/api/v1/metrics","/api/v1/health","/api"]}}"#
            );
        }

        Command::Openapi => {
            println!(
                "{}",
                serde_json::to_string_pretty(&ai_supply_chain_trust_server_new::openapi_schema())?
            );
        }

        Command::Reevaluate(args) => {
            let service = make_service(&db_path, token).await?;
            println!("Re-evaluating {}...", args.repo);
            match service.run_scan(&args.repo).await {
                Ok(report) => println!("{}", serde_json::to_string_pretty(&report)?),
                Err(e) => eprintln!("Error: {e}"),
            }
        }

        Command::History(args) => {
            let service = make_service(&db_path, token).await?;
            let history = service.get_history(&args.repo);
            println!("{}", serde_json::to_string_pretty(&json!(history))?);
        }

        Command::Doctor => {
            println!("Tool availability:");
            for tool in &[
                "git",
                "scorecard",
                "gitleaks",
                "pip-audit",
                "npm",
                "semgrep",
                "bandit",
                "trivy",
                "cargo",
            ] {
                let found = std::process::Command::new("which")
                    .arg(tool)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                println!("  {:15} {}", tool, if found { "✅" } else { "❌" });
            }
        }

        Command::Netcheck(args) => {
            run_netcheck(&args.url, args.github_token_from_env).await?;
        }

        Command::Db(args) => {
            let db = ai_supply_chain_trust_storage::Database::open(&db_path)?;
            match args.action {
                ai_supply_chain_trust_cli::DbAction::Init => {
                    println!("Database schema already initialized.");
                }
                ai_supply_chain_trust_cli::DbAction::Backup { path } => {
                    std::fs::copy(&db_path, &path)?;
                    println!("Backed up to {path}");
                }
                ai_supply_chain_trust_cli::DbAction::Restore { path } => {
                    std::fs::copy(&path, &db_path)?;
                    println!("Restored from {path}");
                }
                ai_supply_chain_trust_cli::DbAction::Stats => {
                    let metrics = db.metrics();
                    println!("{}", serde_json::to_string_pretty(&metrics)?);
                }
            }
        }

        Command::Daemon(args) => {
            println!(
                "Starting daemon (discovery every {}s, queue poll every {}s)...",
                args.discovery_interval, args.queue_poll_interval
            );
            let mut discovery_client =
                ai_supply_chain_trust_discovery::DiscoveryClient::with_timeout(
                    token.clone(),
                    discovery_timeout_seconds(),
                );
            let service = make_service(&db_path, token).await?;
            let mut discovery_tick =
                tokio::time::interval(std::time::Duration::from_secs(args.discovery_interval));

            loop {
                tokio::select! {
                    _ = discovery_tick.tick() => {
                        if !args.no_discovery {
                            let repos = discovery_client.discover_all(10).await;
                            let mut scans = tokio::task::JoinSet::new();
                            let concurrency = std::sync::Arc::new(tokio::sync::Semaphore::new(
                                args.max_concurrent.max(1),
                            ));
                            for r in &repos {
                                let service = service.clone();
                                let repo = r.repo.clone();
                                let concurrency = concurrency.clone();
                                scans.spawn(async move {
                                    let _permit = concurrency
                                        .acquire_owned()
                                        .await
                                        .expect("scan semaphore remains open");
                                    let result = service.run_scan(&repo).await;
                                    (repo, result)
                                });
                            }
                            while let Some(joined) = scans.join_next().await {
                                match joined {
                                    Ok((repo, Err(error))) => {
                                        tracing::warn!("Scan failed for {}: {}", repo, error);
                                    }
                                    Err(error) => tracing::warn!("Scan task failed: {}", error),
                                    Ok((_, Ok(_))) => {}
                                }
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        println!("Shutting down daemon...");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_netcheck(url: &str, github_token_from_env: bool) -> anyhow::Result<()> {
    let mut ok = false;
    for no_proxy in [false, true] {
        let label = if no_proxy {
            "reqwest no_proxy"
        } else {
            "reqwest default"
        };
        let mut builder = reqwest::Client::builder()
            .user_agent("ai-supply-chain-trust-netcheck/0.1")
            .timeout(std::time::Duration::from_secs(20));
        if no_proxy {
            builder = builder.no_proxy();
        }
        let client = builder.build()?;
        let started = std::time::Instant::now();
        let mut request = client.get(url);
        if github_token_from_env {
            if let Some(token) = first_github_token_from_env() {
                request = request.header("Authorization", format!("Bearer {token}"));
                println!("{label}: auth=github_token_present");
            } else {
                println!("{label}: auth=github_token_missing");
            }
        }
        match request.send().await {
            Ok(resp) => {
                ok = true;
                println!(
                    "{label}: status={} elapsed_ms={}",
                    resp.status(),
                    started.elapsed().as_millis()
                );
                for name in [
                    "server",
                    "x-github-request-id",
                    "x-ratelimit-limit",
                    "x-ratelimit-remaining",
                    "x-ratelimit-used",
                    "x-ratelimit-reset",
                    "x-oauth-scopes",
                    "x-accepted-oauth-scopes",
                ] {
                    if let Some(value) = resp.headers().get(name).and_then(|v| v.to_str().ok()) {
                        println!("{label}: {name}={value}");
                    }
                }
            }
            Err(error) => {
                println!(
                    "{label}: error={error:?} timeout={} connect={} elapsed_ms={}",
                    error.is_timeout(),
                    error.is_connect(),
                    started.elapsed().as_millis()
                );
            }
        }
    }
    if ok {
        Ok(())
    } else {
        anyhow::bail!("all netcheck requests failed")
    }
}

fn first_github_token_from_env() -> Option<String> {
    for name in ["GITHUB_TOKEN", "GITHUB_TOKENS"] {
        let Ok(value) = std::env::var(name) else {
            continue;
        };
        for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

async fn make_service(
    db_path: &str,
    token: Option<String>,
) -> anyhow::Result<std::sync::Arc<ai_supply_chain_trust_service::Service>> {
    let db = std::sync::Arc::new(ai_supply_chain_trust_storage::Database::open(db_path)?);
    Ok(std::sync::Arc::new(
        ai_supply_chain_trust_service::Service::new(db, token),
    ))
}
