/// Verification harness — validates Security Context reproducibility and
/// evidence integrity. Designed to be invoked as a CI gate.
///
/// Usage: `cargo run --bin verification-harness -- <owner/repo>`
use clap::Parser;
use std::sync::Arc;

use ai_supply_chain_trust_intelligence::IntelligenceClient;
use ai_supply_chain_trust_service::Service;
use ai_supply_chain_trust_storage::Database;

#[derive(Parser)]
#[command(
    name = "verification-harness",
    about = "Security Context verification harness"
)]
struct Args {
    #[arg(default_value = "octocat/Hello-World")]
    repo: String,

    #[arg(long, default_value = ".cache/ai-supply-chain-trust/verify.db")]
    db_path: String,

    #[arg(long, env = "GITHUB_TOKEN")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let db = Arc::new(Database::open(&args.db_path)?);
    let service = Service::new(db.clone(), args.token.clone());

    println!("Verification Harness — {}\n", args.repo);

    let r1 = service.run_scan(&args.repo).await;
    println!(
        "Run 1: {:?}",
        r1.as_ref().map(|_| "ok").map_err(|e| e.as_str())
    );

    let r2 = service.run_scan(&args.repo).await;
    println!(
        "Run 2: {:?}",
        r2.as_ref().map(|_| "ok").map_err(|e| e.as_str())
    );

    match (&r1, &r2) {
        (Ok(rep1), Ok(rep2)) => {
            let score1 = rep1
                .get("trust_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let score2 = rep2
                .get("trust_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let grade1 = rep1.get("grade").and_then(|v| v.as_str()).unwrap_or("");
            let grade2 = rep2.get("grade").and_then(|v| v.as_str()).unwrap_or("");

            println!("\nDeterminism check:");
            println!(
                "  Score: {score1:.1} vs {score2:.1} (delta={:.2})",
                (score1 - score2).abs()
            );
            println!("  Grade: {grade1} vs {grade2}");

            let pass = (score1 - score2).abs() < 1.0 && grade1 == grade2;
            if pass {
                println!("\nDETERMINISTIC — outputs match");
            } else {
                println!("\nDETERMINISM FAILURE — outputs diverge");
                std::process::exit(1);
            }
        }
        (Err(e1), _) => {
            eprintln!("Run 1 failed: {e1}");
            std::process::exit(1);
        }
        _ => {
            eprintln!("Run 2 failed");
            std::process::exit(1);
        }
    }

    if let Some(token) = &args.token {
        let client = IntelligenceClient::new(Some(token.clone()));
        let (owner, repo_name) = args.repo.split_once('/').unwrap_or((&args.repo, ""));
        match client.fetch_github_advisories(owner, repo_name).await {
            Ok(advisories) => {
                println!("Fresh GHSA CVEs: {}", advisories.len());
            }
            Err(e) => eprintln!("GHSA re-verification failed: {e:?}"),
        }
    }

    Ok(())
}
