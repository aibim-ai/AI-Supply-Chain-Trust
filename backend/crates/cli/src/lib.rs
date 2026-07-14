//! CLI argument parser — matches `cli.py` (~50 flags).
//! Uses clap derive for type-safe argument parsing.

use clap::{Parser, Subcommand, ValueEnum};

/// AI Supply Chain Trust — Free repository trust and supply-chain scanner.
#[derive(Parser, Debug)]
#[command(name = "ai-supply-chain-trust", version = "2.0.0", about, long_about = None)]
pub struct Cli {
    /// GitHub personal access token for API authentication
    #[arg(long, env = "GITHUB_TOKEN")]
    pub token: Option<String>,

    /// Database path (SQLite)
    #[arg(
        long,
        env = "AI_SUPPLY_CHAIN_TRUST_DB_PATH",
        default_value = ".cache/ai-supply-chain-trust/trust.db"
    )]
    pub db_path: String,

    /// Web directory for static assets
    #[arg(
        long,
        env = "AI_SUPPLY_CHAIN_TRUST_WEB_DIR",
        default_value = "frontend/web"
    )]
    pub web_dir: String,

    /// Base URL for artifact links
    #[arg(long, env = "AI_SUPPLY_CHAIN_TRUST_BASE_URL")]
    pub base_url: Option<String>,

    /// Log level filter
    #[arg(long, env = "RUST_LOG", default_value = "ai_supply_chain_trust=info")]
    pub log_level: String,

    /// Database backend: sqlite or postgres
    #[arg(
        long,
        env = "AI_SUPPLY_CHAIN_TRUST_DB_BACKEND",
        default_value = "sqlite"
    )]
    pub db_backend: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start HTTP server (API + web SPA)
    Serve(ServeArgs),

    /// Evaluate a single repository and print the report
    Eval(Box<EvalArgs>),

    /// Run discovery and score all discovered repos
    Discover(DiscoverArgs),

    /// Show leaderboard
    Leaderboard(LeaderboardArgs),

    /// Get security context for a repository
    SecurityContext(SecurityContextArgs),

    /// Run external scanner tools on a local repo
    Scan(ScanArgs),

    /// Print API index
    Api,

    /// Database operations
    Db(DbArgs),

    /// Run daemon (discovery + queue processing loop)
    Daemon(DaemonArgs),

    /// Print OpenAPI schema
    Openapi,

    /// Re-evaluate a repository with a different scoring version
    Reevaluate(ReevaluateArgs),

    /// Show repository history
    History(HistoryArgs),

    /// Check available CLI tools (doctor)
    Doctor,

    /// Check outbound HTTP connectivity from this binary
    Netcheck(NetcheckArgs),
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// HTTP server role: api, web, or all
    #[arg(long, default_value = "all")]
    pub role: String,

    /// Host to bind
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8000", env = "PORT")]
    pub port: u16,

    /// JWT secret for scheduler auth
    #[arg(long, env = "JWT_SECRET")]
    pub jwt_secret: Option<String>,

    /// Allowed origins for CORS
    #[arg(
        long,
        env = "AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS",
        default_value = "*"
    )]
    pub allowed_origins: String,
}

#[derive(Parser, Debug)]
pub struct EvalArgs {
    /// Repository to evaluate (owner/name or full URL)
    pub repo: String,

    /// Optional evaluation context
    #[arg(long)]
    pub context: Option<String>,

    /// Path to GitHub metadata JSON file
    #[arg(long)]
    pub metadata: Option<String>,

    /// Path to scorecard JSON output
    #[arg(long)]
    pub scorecard: Option<String>,

    /// Path to gitleaks JSON output
    #[arg(long)]
    pub gitleaks: Option<String>,

    /// Path to pip-audit JSON output
    #[arg(long)]
    pub pip_audit: Option<String>,

    /// Path to npm audit JSON output
    #[arg(long)]
    pub npm_audit: Option<String>,

    /// Path to semgrep JSON output
    #[arg(long)]
    pub semgrep: Option<String>,

    /// Path to bandit JSON output
    #[arg(long)]
    pub bandit: Option<String>,

    /// Path to trivy JSON output
    #[arg(long)]
    pub trivy: Option<String>,

    /// Path to HuggingFace metadata JSON
    #[arg(long)]
    pub hf_metadata: Option<String>,

    /// Path to downloaded model artifacts
    #[arg(long)]
    pub artifact_root: Option<String>,

    /// Fetch GitHub metadata live
    #[arg(long)]
    pub fetch_github_metadata: bool,

    /// Print JSON output
    #[arg(long)]
    pub json: bool,

    /// Write report to file
    #[arg(long, short = 'o')]
    pub output: Option<String>,

    /// Scoring version to use
    #[arg(long)]
    pub scoring_version: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DiscoverArgs {
    /// Max repos to discover per source
    #[arg(long, default_value = "10")]
    pub limit_per_source: i64,

    /// Max total repos to score
    #[arg(long, default_value = "50")]
    pub max_total: i64,

    /// Minimum star count filter
    #[arg(long, default_value = "5")]
    pub min_stars: i64,

    /// Only discover repos pushed in last N days
    #[arg(long)]
    pub days: Option<i64>,

    /// Skip existing repos already in DB
    #[arg(long)]
    pub skip_existing: bool,

    /// Don't score, just discover
    #[arg(long)]
    pub no_score: bool,
}

#[derive(Parser, Debug)]
pub struct NetcheckArgs {
    /// URL to request
    #[arg(default_value = "https://api.github.com/rate_limit")]
    pub url: String,

    /// Also send Authorization using the first configured GitHub token.
    #[arg(long)]
    pub github_token_from_env: bool,
}

#[derive(Parser, Debug)]
pub struct LeaderboardArgs {
    /// Search query filter
    #[arg(short, long)]
    pub query: Option<String>,

    /// Max rows to return
    #[arg(short, long, default_value = "20")]
    pub limit: i64,
}

#[derive(Parser, Debug)]
pub struct SecurityContextArgs {
    /// Repository (owner/name)
    pub repo: String,

    /// Output format: json, markdown, or text
    #[arg(long, default_value = "json")]
    pub format: String,
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Repository URL
    #[arg(short, long)]
    pub repo: Option<String>,

    /// Local source path
    #[arg(short, long)]
    pub path: Option<String>,

    /// Comma-separated scanners to run
    #[arg(
        long,
        default_value = "scorecard,gitleaks,pip-audit,npm-audit,semgrep,bandit,trivy"
    )]
    pub scanners: String,
}

#[derive(Parser, Debug)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Subcommand, Debug)]
pub enum DbAction {
    /// Initialize database schema
    Init,
    /// Backup database to file
    Backup { path: String },
    /// Restore database from file
    Restore { path: String },
    /// Show database statistics
    Stats,
}

#[derive(Parser, Debug)]
pub struct DaemonArgs {
    /// Discovery interval in seconds
    #[arg(long, default_value = "3600")]
    pub discovery_interval: u64,

    /// Queue poll interval in seconds
    #[arg(long, default_value = "10")]
    pub queue_poll_interval: u64,

    /// Max concurrent scan jobs
    #[arg(long, default_value = "3")]
    pub max_concurrent: usize,

    /// Don't run discovery, only process queue
    #[arg(long)]
    pub no_discovery: bool,
}

#[derive(Parser, Debug)]
pub struct ReevaluateArgs {
    /// Repository to re-evaluate
    pub repo: String,

    /// Scoring version to use
    #[arg(long)]
    pub scoring_version: Option<String>,
}

#[derive(Parser, Debug)]
pub struct HistoryArgs {
    /// Repository
    pub repo: String,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Markdown,
    Text,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_defaults() {
        let cli = Cli::try_parse_from(["ai-supply-chain-trust", "serve"]).unwrap();
        match cli.command {
            Command::Serve(args) => {
                assert_eq!(args.port, 8000);
                assert_eq!(args.host, "0.0.0.0");
            }
            _ => panic!("expected serve"),
        }
    }

    #[test]
    fn eval_with_repo() {
        let cli = Cli::try_parse_from(["ai-supply-chain-trust", "eval", "owner/repo"]).unwrap();
        match cli.command {
            Command::Eval(args) => assert_eq!(args.repo, "owner/repo"),
            _ => panic!("expected eval"),
        }
    }

    #[test]
    fn discover_with_args() {
        let cli = Cli::try_parse_from([
            "ai-supply-chain-trust",
            "discover",
            "--limit-per-source",
            "5",
            "--min-stars",
            "20",
            "--skip-existing",
        ])
        .unwrap();
        match cli.command {
            Command::Discover(args) => {
                assert_eq!(args.limit_per_source, 5);
                assert_eq!(args.min_stars, 20);
                assert!(args.skip_existing);
            }
            _ => panic!("expected discover"),
        }
    }
}
