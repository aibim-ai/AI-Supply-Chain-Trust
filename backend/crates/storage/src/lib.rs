//! Database storage layer.
//! Uses rusqlite (synchronous SQLite) with optional PostgreSQL via sqlx.
//! Set DATABASE_URL to a postgres:// URL to enable PostgreSQL backend.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

pub const DEFAULT_DB_PATH: &str = ".cache/ai-supply-chain-trust/trust.db";

pub struct Database {
    conn: Mutex<Connection>,
    pg: Option<PgPool>,
}

fn report_context_summary(report: &Value) -> (usize, usize, &'static str) {
    let fixes = report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|i| i.get("fix_commits"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let cves = report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|i| i.get("cves"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let scan_state = report
        .get("observed_metrics")
        .and_then(|m| m.get("scan_state"))
        .and_then(Value::as_str);
    let status = if matches!(scan_state, Some("fast_ready") | Some("enriching")) {
        "enriching"
    } else if report
        .get("observed_metrics")
        .and_then(|m| m.get("security_context_version"))
        .is_some()
    {
        "ready"
    } else {
        "none"
    };
    (fixes, cves, status)
}

fn report_has_critical_intel_errors(report: &Value) -> bool {
    report
        .get("observed_metrics")
        .and_then(|m| m.get("security_intel"))
        .and_then(|intel| intel.get("errors"))
        .and_then(Value::as_array)
        .is_some_and(|errors| {
            errors.iter().filter_map(Value::as_str).any(|error| {
                error.starts_with("advisories:")
                    || error.starts_with("commits:")
                    || error.starts_with("repo_meta:")
            })
        })
}

#[derive(Default)]
struct LlmDecisionMetrics {
    total: i64,
    rejected: i64,
    rate_limited: i64,
    model_missing: i64,
    latency_total_ms: u64,
    latency_samples: u64,
    by_source: BTreeMap<String, i64>,
    by_error_type: BTreeMap<String, i64>,
    by_model_task: BTreeMap<(String, String, String), i64>,
}

impl LlmDecisionMetrics {
    fn observe_report(&mut self, report: &Value) {
        self.observe_value(report);
    }

    fn observe_value(&mut self, value: &Value) {
        match value {
            Value::Object(map) => {
                if let Some(source) = map.get("decision_source").and_then(Value::as_str) {
                    self.total += 1;
                    if source == "rejected_hallucination" {
                        self.rejected += 1;
                    }
                    if source != "rule_based" && map.get("model").and_then(Value::as_str).is_none()
                    {
                        self.model_missing += 1;
                    }
                    if let Some(latency_ms) = map.get("latency_ms").and_then(Value::as_u64) {
                        self.latency_total_ms = self.latency_total_ms.saturating_add(latency_ms);
                        self.latency_samples = self.latency_samples.saturating_add(1);
                    }
                    if let Some(error_type) = map.get("error_type").and_then(Value::as_str) {
                        *self
                            .by_error_type
                            .entry(error_type.to_string())
                            .or_insert(0) += 1;
                        if error_type == "rate_limited" {
                            self.rate_limited += 1;
                        }
                    }
                    *self.by_source.entry(source.to_string()).or_insert(0) += 1;
                    let model = map
                        .get("model")
                        .and_then(Value::as_str)
                        .unwrap_or("none")
                        .to_string();
                    let task = map
                        .get("task")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    *self
                        .by_model_task
                        .entry((model, task, source.to_string()))
                        .or_insert(0) += 1;
                }
                for child in map.values() {
                    self.observe_value(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    self.observe_value(child);
                }
            }
            _ => {}
        }
    }

    fn rejection_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.rejected as f64 / self.total as f64
        }
    }

    fn average_latency_ms(&self) -> f64 {
        if self.latency_samples == 0 {
            0.0
        } else {
            self.latency_total_ms as f64 / self.latency_samples as f64
        }
    }
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Mutex::new(conn),
            pg: None,
        };
        db.init_schema()?;
        info!("Storage opened at {}", path.display());
        Ok(db)
    }

    pub fn open_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Mutex::new(conn),
            pg: None,
        };
        db.init_schema()?;
        Ok(db)
    }

    pub async fn open_with_pg(
        sqlite_path: impl AsRef<Path>,
        pg_url: &str,
    ) -> Result<Self, anyhow::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(pg_url)
            .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS evaluations (
                id SERIAL PRIMARY KEY, repo TEXT NOT NULL, evaluated_at TEXT NOT NULL,
                trust_score REAL NOT NULL, grade TEXT NOT NULL, verdict TEXT NOT NULL,
                action TEXT NOT NULL, next_review_date TEXT NOT NULL,
                coverage TEXT NOT NULL DEFAULT '', critical_flags_json TEXT NOT NULL DEFAULT '[]',
                pillar_scores_json TEXT NOT NULL DEFAULT '{}',
                scanner_runs_json TEXT NOT NULL DEFAULT '[]',
                metrics_json TEXT NOT NULL DEFAULT '{}',
                report_json TEXT NOT NULL DEFAULT '{}', scoring_version TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS trust_events (
                id SERIAL PRIMARY KEY, repo TEXT NOT NULL, event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&pool)
        .await?;

        for statement in [
            r#"CREATE TABLE IF NOT EXISTS regression_contracts (
                repo TEXT NOT NULL, contract_id TEXT NOT NULL, version BIGINT NOT NULL DEFAULT 1,
                lifecycle_state TEXT NOT NULL DEFAULT 'candidate', contract_json TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (repo, contract_id))"#,
            r#"CREATE TABLE IF NOT EXISTS regression_contract_events (
                id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL, contract_id TEXT NOT NULL,
                from_state TEXT NOT NULL, to_state TEXT NOT NULL, actor TEXT NOT NULL,
                reason TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'contract', comment TEXT,
                expires_at TIMESTAMPTZ, version BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"#,
            r#"CREATE TABLE IF NOT EXISTS regression_assessments (
                id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL, contract_id TEXT NOT NULL,
                base_sha TEXT NOT NULL, head_sha TEXT NOT NULL, assessment_json TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(repo, contract_id, base_sha, head_sha))"#,
            r#"CREATE TABLE IF NOT EXISTS regression_check_runs (
                repo TEXT NOT NULL, head_sha TEXT NOT NULL, check_run_id BIGINT NOT NULL,
                conclusion TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (repo, head_sha))"#,
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }

        info!("PostgreSQL connected, pool ready");

        let path = sqlite_path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Mutex::new(conn),
            pg: Some(pool),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn backend(&self) -> &str {
        if self.pg.is_some() {
            "postgresql"
        } else {
            "sqlite"
        }
    }

    fn init_schema(&self) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let version: i64 = conn
            .query_row(
                "SELECT value FROM daemon_state WHERE key = 'schema_version'",
                [],
                |row| {
                    let s: String = row.get(0)?;
                    Ok(s.parse::<i64>().unwrap_or(0))
                },
            )
            .unwrap_or(0);

        if version < 1 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS evaluations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    trust_score REAL NOT NULL,
                    grade TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    action TEXT NOT NULL,
                    next_review_date TEXT NOT NULL,
                    coverage TEXT NOT NULL DEFAULT '',
                    critical_flags_json TEXT NOT NULL DEFAULT '[]',
                    pillar_scores_json TEXT NOT NULL DEFAULT '{}',
                    scanner_runs_json TEXT NOT NULL DEFAULT '[]',
                    metrics_json TEXT NOT NULL DEFAULT '{}',
                    report_json TEXT NOT NULL DEFAULT '{}',
                    scoring_version TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS trust_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS daemon_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_evaluations_repo ON evaluations(repo);
                CREATE INDEX IF NOT EXISTS idx_evaluations_created ON evaluations(created_at);
                CREATE INDEX IF NOT EXISTS idx_trust_events_repo ON trust_events(repo);

                INSERT OR REPLACE INTO daemon_state (key, value, updated_at) VALUES ('schema_version', '1', datetime('now'));
                ",
            )?;
        }

        // v2: scan jobs, scanner tasks, audit events, queue
        if version < 2 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS scan_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    priority INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    started_at TEXT,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS scanner_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
                    scanner TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    result_json TEXT,
                    started_at TEXT,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    repo TEXT,
                    detail_json TEXT NOT NULL DEFAULT '{}',
                    ip_address TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS port_discrepancies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    python_output TEXT NOT NULL,
                    rust_output TEXT NOT NULL,
                    diff_paths TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_scan_jobs_repo ON scan_jobs(repo);
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
                CREATE INDEX IF NOT EXISTS idx_scanner_tasks_job ON scanner_tasks(job_id);
                CREATE INDEX IF NOT EXISTS idx_audit_events_repo ON audit_events(repo);

                INSERT OR REPLACE INTO daemon_state (key, value, updated_at) VALUES ('schema_version', '2', datetime('now'));"
            )?;
        }

        // v3: persist queue failure reasons for production auditability.
        if version < 3 {
            conn.execute_batch(
                "ALTER TABLE scan_jobs ADD COLUMN last_error TEXT;
                 INSERT OR REPLACE INTO daemon_state (key, value, updated_at) VALUES ('schema_version', '3', datetime('now'));",
            )?;
        }

        // v4: durable, idempotent evidence work for progressive scans.
        if version < 4 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS evidence_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                    source TEXT NOT NULL,
                    partition_key TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'queued',
                    priority INTEGER NOT NULL DEFAULT 0,
                    cursor TEXT,
                    checkpoint_json TEXT,
                    result_json TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 5,
                    next_attempt_at TEXT NOT NULL DEFAULT (datetime('now')),
                    lease_expires_at TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    completed_at TEXT,
                    UNIQUE(job_id, source, partition_key)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_tasks_ready
                    ON evidence_tasks(status, next_attempt_at, priority, id);
                CREATE INDEX IF NOT EXISTS idx_evidence_tasks_job
                    ON evidence_tasks(job_id, source);
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '4', datetime('now'));",
            )?;
        }

        // v5: cross-job source cache for immutable and conditional responses.
        if version < 5 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS source_cache (
                    cache_key TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    etag TEXT,
                    last_modified TEXT,
                    payload_json TEXT NOT NULL,
                    expires_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_source_cache_source_expiry
                    ON source_cache(source, expires_at);
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '5', datetime('now'));",
            )?;
        }

        // v6: durable operational failure inbox for scan/evidence triage.
        if version < 6 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS failure_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_kind TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    repo TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    severity TEXT NOT NULL DEFAULT 'error',
                    title TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 0,
                    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                    acknowledged_at TEXT,
                    resolved_at TEXT,
                    notification_status TEXT NOT NULL DEFAULT 'pending',
                    notification_error TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_failure_alerts_open_source
                    ON failure_alerts(source_kind, source_id)
                    WHERE status='open';
                CREATE INDEX IF NOT EXISTS idx_failure_alerts_status_seen
                    ON failure_alerts(status, last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS idx_failure_alerts_repo
                    ON failure_alerts(repo);
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '6', datetime('now'));",
            )?;
        }

        // v7: split interactive scans from background/research scan work.
        if version < 7 {
            conn.execute_batch(
                "ALTER TABLE scan_jobs ADD COLUMN lane TEXT NOT NULL DEFAULT 'foreground';
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_lane_status_priority
                    ON scan_jobs(lane, status, priority DESC, id);
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '7', datetime('now'));",
            )?;
        }

        // v8: auditable regression contracts, lifecycle, and immutable assessments.
        if version < 8 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS regression_contracts (
                    repo TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    lifecycle_state TEXT NOT NULL DEFAULT 'candidate',
                    contract_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (repo, contract_id)
                );
                CREATE TABLE IF NOT EXISTS regression_contract_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'contract',
                    comment TEXT,
                    expires_at TEXT,
                    version INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (repo, contract_id) REFERENCES regression_contracts(repo, contract_id)
                );
                CREATE TABLE IF NOT EXISTS regression_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    base_sha TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    assessment_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(repo, contract_id, base_sha, head_sha),
                    FOREIGN KEY (repo, contract_id) REFERENCES regression_contracts(repo, contract_id)
                );
                CREATE INDEX IF NOT EXISTS idx_regression_contracts_repo_state
                    ON regression_contracts(repo, lifecycle_state);
                CREATE INDEX IF NOT EXISTS idx_regression_events_contract
                    ON regression_contract_events(repo, contract_id, id);
                CREATE INDEX IF NOT EXISTS idx_regression_assessments_head
                    ON regression_assessments(repo, head_sha);
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '8', datetime('now'));",
            )?;
        }

        if version < 9 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS regression_check_runs (
                    repo TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    check_run_id INTEGER NOT NULL,
                    conclusion TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (repo, head_sha)
                );
                INSERT OR REPLACE INTO daemon_state (key, value, updated_at)
                    VALUES ('schema_version', '9', datetime('now'));",
            )?;
        }

        conn.execute(
            "UPDATE scan_jobs SET status='queued', started_at=NULL WHERE status='running'",
            [],
        )
        .ok();
        conn.execute(
            "UPDATE evidence_tasks
             SET status='queued', lease_expires_at=NULL, updated_at=datetime('now')
             WHERE status='running' AND lease_expires_at IS NOT NULL
               AND datetime(lease_expires_at) <= datetime('now')",
            [],
        )
        .ok();
        backfill_failed_scan_job_alerts_locked(&conn).ok();
        reconcile_superseded_failure_alerts_locked(&conn).ok();

        Ok(())
    }

    /// Record a shadow mode discrepancy.
    pub fn log_discrepancy(
        &self,
        repo: &str,
        endpoint: &str,
        python_output: &str,
        rust_output: &str,
        diff_paths: &[String],
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO port_discrepancies (repo, endpoint, python_output, rust_output, diff_paths) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![repo, endpoint, python_output, rust_output, diff_paths.join(",")],
        )?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Scan jobs
    // -------------------------------------------------------------------
    pub fn create_scan_job(&self, repo: &str, priority: i64) -> Result<i64, anyhow::Error> {
        self.create_scan_job_with_lane(repo, priority, "foreground")
    }

    pub fn create_scan_job_with_lane(
        &self,
        repo: &str,
        priority: i64,
        lane: &str,
    ) -> Result<i64, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scan_jobs (repo, status, priority, lane) VALUES (?1, 'queued', ?2, ?3)",
            rusqlite::params![repo, priority, normalize_scan_lane(lane)],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn queue_stats(&self) -> Value {
        let conn = self.conn.lock().unwrap();
        dedupe_queued_scan_jobs(&conn).ok();
        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_jobs WHERE status='queued'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let active: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_jobs WHERE status='running'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let paused_until = conn
            .query_row(
                "SELECT value FROM daemon_state WHERE key='queue_paused'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .filter(|value| !value.is_empty());
        let paused = paused_until
            .as_deref()
            .map(|value| {
                conn.query_row(
                    "SELECT datetime(?1) > datetime('now')",
                    params![value],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                    > 0
            })
            .unwrap_or(false);
        let mut lanes = serde_json::Map::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT lane, status, COUNT(*) FROM scan_jobs GROUP BY lane, status")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            }) {
                for row in rows.flatten() {
                    let lane = lanes.entry(row.0).or_insert_with(|| json!({}));
                    if let Some(statuses) = lane.as_object_mut() {
                        statuses.insert(row.1, json!(row.2));
                    }
                }
            }
        }
        let mut evidence = serde_json::Map::new();
        if let Ok(mut stmt) = conn
            .prepare("SELECT source, status, COUNT(*) FROM evidence_tasks GROUP BY source, status")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            }) {
                for row in rows.flatten() {
                    let source = evidence.entry(row.0).or_insert_with(|| json!({}));
                    if let Some(statuses) = source.as_object_mut() {
                        statuses.insert(row.1, json!(row.2));
                    }
                }
            }
        }
        let failures = Self::failure_alert_counts_locked(&conn);
        json!({"pending": pending, "active": active, "queued": pending, "paused": paused, "paused_until": paused_until, "lanes": lanes, "evidence": evidence, "failures": failures})
    }

    fn failure_alert_counts_locked(conn: &Connection) -> Value {
        let mut counts = serde_json::Map::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT status, COUNT(*) FROM failure_alerts GROUP BY status")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    counts.insert(row.0, json!(row.1));
                }
            }
        }
        Value::Object(counts)
    }

    pub fn scan_jobs_recent(&self, limit: i64) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        let stmt = conn
            .prepare(
                "SELECT id, repo, status, priority, created_at, started_at, completed_at, last_error, lane
                 FROM scan_jobs
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .ok();
        let Some(mut stmt) = stmt else { return vec![] };
        stmt.query_map(params![limit], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "repo": row.get::<_, String>(1)?,
                "status": row.get::<_, String>(2)?,
                "priority": row.get::<_, i64>(3)?,
                "created_at": row.get::<_, String>(4)?,
                "started_at": row.get::<_, Option<String>>(5)?,
                "completed_at": row.get::<_, Option<String>>(6)?,
                "last_error": row.get::<_, Option<String>>(7)?,
                "lane": row.get::<_, String>(8)?,
            }))
        })
        .ok()
        .into_iter()
        .flat_map(|rows| rows.filter_map(|r| r.ok()))
        .collect()
    }

    pub fn pause_queue(&self, seconds: i64) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let until = chrono::Utc::now() + chrono::Duration::seconds(seconds);
        conn.execute("INSERT OR REPLACE INTO daemon_state (key, value, updated_at) VALUES ('queue_paused', ?1, datetime('now'))",
            rusqlite::params![until.format("%Y-%m-%dT%H:%M:%SZ").to_string()])?;
        Ok(())
    }

    pub fn resume_queue(&self) -> Result<(), anyhow::Error> {
        self.set_daemon_state("queue_paused", "")
    }

    pub fn enqueue_rescan(&self, repo: &str, priority: i64) -> Result<i64, anyhow::Error> {
        self.enqueue_rescan_with_lane(repo, priority, "foreground")
    }

    pub fn enqueue_rescan_with_lane(
        &self,
        repo: &str,
        priority: i64,
        lane: &str,
    ) -> Result<i64, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let lane = normalize_scan_lane(lane);
        let existing = conn
            .query_row(
                "SELECT id, priority FROM scan_jobs
                 WHERE repo=?1 AND status IN ('queued', 'running') AND lane=?2
                 ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, priority DESC, id ASC
                 LIMIT 1",
                params![repo, lane],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .ok();
        if let Some((id, current_priority)) = existing {
            if priority > current_priority {
                conn.execute(
                    "UPDATE scan_jobs SET priority=?1 WHERE id=?2",
                    params![priority, id],
                )?;
            }
            conn.execute(
                "UPDATE scan_jobs
                 SET status='deduped', completed_at=datetime('now'), last_error=?1
                 WHERE repo=?2 AND status='queued' AND id<>?3 AND lane=?4",
                params![format!("deduped by scan job {id}"), repo, id, lane],
            )?;
            return Ok(id);
        }
        conn.execute(
            "INSERT INTO scan_jobs (repo, status, priority, lane) VALUES (?1, 'queued', ?2, ?3)",
            params![repo, priority, lane],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn claim_next_scan_job(&self) -> Result<Option<(i64, String)>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        dedupe_queued_scan_jobs(&conn)?;
        let paused: bool = conn.query_row("SELECT COUNT(*) FROM daemon_state WHERE key='queue_paused' AND datetime(value) > datetime('now')", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
        if paused {
            return Ok(None);
        }
        let next = conn
            .query_row(
                "SELECT id, repo FROM scan_jobs
                 WHERE status='queued'
                 ORDER BY CASE lane WHEN 'foreground' THEN 0 ELSE 1 END, priority DESC, id ASC
                 LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .ok();
        let Some((id, repo)) = next else {
            return Ok(None);
        };
        let changed = conn.execute(
            "UPDATE scan_jobs SET status='running', started_at=datetime('now'), last_error=NULL WHERE id=?1 AND status='queued'",
            params![id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some((id, repo)))
    }

    pub fn claim_next_scan_job_for_lane(
        &self,
        lane: &str,
    ) -> Result<Option<(i64, String)>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        dedupe_queued_scan_jobs(&conn)?;
        let paused: bool = conn.query_row("SELECT COUNT(*) FROM daemon_state WHERE key='queue_paused' AND datetime(value) > datetime('now')", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
        if paused {
            return Ok(None);
        }
        let lane = normalize_scan_lane(lane);
        let next = conn
            .query_row(
                "SELECT id, repo FROM scan_jobs
                 WHERE status='queued' AND lane=?1
                 ORDER BY priority DESC, id ASC LIMIT 1",
                params![lane],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .ok();
        let Some((id, repo)) = next else {
            return Ok(None);
        };
        let changed = conn.execute(
            "UPDATE scan_jobs SET status='running', started_at=datetime('now'), last_error=NULL WHERE id=?1 AND status='queued'",
            params![id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some((id, repo)))
    }

    pub fn complete_scan_job(
        &self,
        id: i64,
        ok: bool,
        error: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let status = if ok { "completed" } else { "failed" };
        conn.execute(
            "UPDATE scan_jobs SET status=?1, completed_at=datetime('now'), last_error=?2 WHERE id=?3",
            params![status, error, id],
        )?;
        if ok {
            resolve_failure_alert_locked(&conn, "scan_job", id)?;
            let repo = conn.query_row(
                "SELECT repo FROM scan_jobs WHERE id=?1",
                params![id],
                |row| row.get::<_, String>(0),
            )?;
            resolve_repo_failure_alerts_locked(&conn, &repo, "scan_job")?;
        } else if let Some(error) = error {
            let repo = conn.query_row(
                "SELECT repo FROM scan_jobs WHERE id=?1",
                params![id],
                |row| row.get::<_, String>(0),
            )?;
            upsert_failure_alert_locked(
                &conn,
                FailureAlertInput {
                    source_kind: "scan_job",
                    source_id: id,
                    repo: &repo,
                    severity: "error",
                    title: "Scan job failed",
                    error,
                    attempts: 1,
                    max_attempts: 1,
                },
            )?;
        }
        Ok(())
    }

    pub fn scan_job_repo(&self, id: i64) -> Result<Option<String>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT repo FROM scan_jobs WHERE id=?1",
            params![id],
            |row| row.get(0),
        ) {
            Ok(repo) => Ok(Some(repo)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn defer_scan_job(&self, id: i64, error: &str) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE scan_jobs SET status='queued', started_at=NULL, completed_at=NULL, last_error=?1 WHERE id=?2",
            params![error, id],
        )?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Progressive evidence tasks
    // -------------------------------------------------------------------
    pub fn enqueue_evidence_task(
        &self,
        job_id: i64,
        source: &str,
        partition_key: &str,
        priority: i64,
    ) -> Result<i64, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence_tasks (job_id, source, partition_key, priority)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(job_id, source, partition_key) DO UPDATE SET
               priority=MAX(priority, excluded.priority), updated_at=datetime('now')",
            params![job_id, source, partition_key, priority],
        )?;
        conn.query_row(
            "SELECT id FROM evidence_tasks WHERE job_id=?1 AND source=?2 AND partition_key=?3",
            params![job_id, source, partition_key],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    pub fn claim_next_evidence_task(
        &self,
        source: &str,
        lease_seconds: i64,
    ) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let next = conn
            .query_row(
                "SELECT id, job_id, source, partition_key, cursor, checkpoint_json, attempts
                 FROM evidence_tasks
                 WHERE source=?1 AND attempts < max_attempts
                   AND (status='queued' OR
                        (status='running' AND lease_expires_at IS NOT NULL
                         AND datetime(lease_expires_at) <= datetime('now')))
                   AND datetime(next_attempt_at) <= datetime('now')
                 ORDER BY priority DESC, id ASC LIMIT 1",
                params![source],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .ok();
        let Some((id, job_id, source, partition_key, cursor, checkpoint, attempts)) = next else {
            return Ok(None);
        };
        let changed = conn.execute(
            "UPDATE evidence_tasks SET status='running', attempts=attempts+1,
             lease_expires_at=datetime('now', '+' || ?1 || ' seconds'),
             updated_at=datetime('now')
             WHERE id=?2 AND (status='queued' OR datetime(lease_expires_at) <= datetime('now'))",
            params![lease_seconds.max(1), id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(json!({
            "id": id, "job_id": job_id, "source": source,
            "partition_key": partition_key, "cursor": cursor,
            "checkpoint": checkpoint.and_then(|raw| serde_json::from_str::<Value>(&raw).ok()),
            "attempts": attempts + 1
        })))
    }

    pub fn claim_evidence_task_for_job(
        &self,
        job_id: i64,
        source: &str,
        lease_seconds: i64,
    ) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let next = conn
            .query_row(
                "SELECT id, partition_key, cursor, checkpoint_json, attempts
                 FROM evidence_tasks WHERE job_id=?1 AND source=?2
                   AND attempts < max_attempts
                   AND (status='queued' OR (status='running' AND lease_expires_at IS NOT NULL
                     AND datetime(lease_expires_at) <= datetime('now')))
                   AND datetime(next_attempt_at) <= datetime('now') LIMIT 1",
                params![job_id, source],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .ok();
        let Some((id, partition_key, cursor, checkpoint, attempts)) = next else {
            return Ok(None);
        };
        let changed = conn.execute(
            "UPDATE evidence_tasks SET status='running', attempts=attempts+1,
             lease_expires_at=datetime('now', '+' || ?1 || ' seconds'), updated_at=datetime('now')
             WHERE id=?2 AND (status='queued' OR datetime(lease_expires_at) <= datetime('now'))",
            params![lease_seconds.max(1), id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(json!({
            "id": id, "job_id": job_id, "source": source,
            "partition_key": partition_key, "cursor": cursor,
            "checkpoint": checkpoint.and_then(|raw| serde_json::from_str::<Value>(&raw).ok()),
            "attempts": attempts + 1
        })))
    }

    pub fn pending_finalize_job_ids(&self, limit: i64) -> Result<Vec<i64>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT job_id FROM evidence_tasks
             WHERE source='finalize' AND attempts < max_attempts
               AND (status='queued' OR
                    (status='running' AND lease_expires_at IS NOT NULL
                     AND datetime(lease_expires_at) <= datetime('now')))
               AND datetime(next_attempt_at) <= datetime('now')
             ORDER BY priority DESC, id ASC LIMIT ?1",
        )?;
        let job_ids = stmt
            .query_map(params![limit.max(1)], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)?;
        Ok(job_ids)
    }

    pub fn checkpoint_evidence_task(
        &self,
        id: i64,
        generation: i64,
        cursor: Option<&str>,
        checkpoint: &Value,
        lease_seconds: i64,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE evidence_tasks SET cursor=?1, checkpoint_json=?2,
             lease_expires_at=datetime('now', '+' || ?3 || ' seconds'),
             updated_at=datetime('now') WHERE id=?4 AND status='running' AND attempts=?5
             AND datetime(lease_expires_at) > datetime('now')",
            params![
                cursor,
                serde_json::to_string(checkpoint)?,
                lease_seconds.max(1),
                id,
                generation
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("evidence lease lost for task {id} generation {generation}");
        }
        Ok(())
    }

    pub fn complete_evidence_task(
        &self,
        id: i64,
        generation: i64,
        result: &Value,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE evidence_tasks SET status='completed', result_json=?1,
             lease_expires_at=NULL, last_error=NULL, completed_at=datetime('now'),
             updated_at=datetime('now') WHERE id=?2 AND status='running' AND attempts=?3
             AND datetime(lease_expires_at) > datetime('now')",
            params![serde_json::to_string(result)?, id, generation],
        )?;
        if changed != 1 {
            anyhow::bail!("evidence lease lost for task {id} generation {generation}");
        }
        resolve_failure_alert_locked(&conn, "evidence_task", id)?;
        Ok(())
    }

    pub fn resolve_evidence_failure_alerts_for_repo(
        &self,
        repo: &str,
    ) -> Result<usize, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        resolve_repo_failure_alerts_locked(&conn, repo, "evidence_task")
    }

    pub fn retry_evidence_task(
        &self,
        id: i64,
        generation: i64,
        error: &str,
        delay_seconds: i64,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let task = conn.query_row(
            "SELECT e.job_id, e.source, e.partition_key, e.attempts, e.max_attempts, s.repo
             FROM evidence_tasks e JOIN scan_jobs s ON s.id=e.job_id
             WHERE e.id=?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let effective_delay = retry_backoff_seconds(error, delay_seconds, task.3);
        let changed = conn.execute(
            "UPDATE evidence_tasks SET
             status=CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
             last_error=?1, lease_expires_at=NULL,
             next_attempt_at=datetime('now', '+' || ?2 || ' seconds'),
             updated_at=datetime('now') WHERE id=?3 AND status='running' AND attempts=?4
             AND datetime(lease_expires_at) > datetime('now')",
            params![error, effective_delay, id, generation],
        )?;
        if changed != 1 {
            anyhow::bail!("evidence lease lost for task {id} generation {generation}");
        }
        let (_job_id, source, partition_key, attempts, max_attempts, repo) = task;
        if attempts >= max_attempts {
            upsert_failure_alert_locked(
                &conn,
                FailureAlertInput {
                    source_kind: "evidence_task",
                    source_id: id,
                    repo: &repo,
                    severity: "error",
                    title: &format!("Evidence task failed: {source}:{partition_key}"),
                    error,
                    attempts,
                    max_attempts,
                },
            )?;
        }
        Ok(())
    }

    pub fn failure_alerts(&self, status: Option<&str>, limit: i64) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        let status = status.unwrap_or("open");
        let stmt = if status == "all" {
            conn.prepare(
                "SELECT id, source_kind, source_id, repo, status, severity, title, error,
                        attempts, max_attempts, first_seen_at, last_seen_at, acknowledged_at,
                        resolved_at, notification_status, notification_error
                 FROM failure_alerts
                 ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
                          last_seen_at DESC, id DESC
                 LIMIT ?1",
            )
        } else {
            conn.prepare(
                "SELECT id, source_kind, source_id, repo, status, severity, title, error,
                        attempts, max_attempts, first_seen_at, last_seen_at, acknowledged_at,
                        resolved_at, notification_status, notification_error
                 FROM failure_alerts
                 WHERE status=?2
                 ORDER BY last_seen_at DESC, id DESC
                 LIMIT ?1",
            )
        };
        let Ok(mut stmt) = stmt else { return vec![] };
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "source_kind": row.get::<_, String>(1)?,
                "source_id": row.get::<_, i64>(2)?,
                "repo": row.get::<_, String>(3)?,
                "status": row.get::<_, String>(4)?,
                "severity": row.get::<_, String>(5)?,
                "title": row.get::<_, String>(6)?,
                "error": row.get::<_, String>(7)?,
                "attempts": row.get::<_, i64>(8)?,
                "max_attempts": row.get::<_, i64>(9)?,
                "first_seen_at": row.get::<_, String>(10)?,
                "last_seen_at": row.get::<_, String>(11)?,
                "acknowledged_at": row.get::<_, Option<String>>(12)?,
                "resolved_at": row.get::<_, Option<String>>(13)?,
                "notification_status": row.get::<_, String>(14)?,
                "notification_error": row.get::<_, Option<String>>(15)?,
            }))
        };
        let rows = if status == "all" {
            stmt.query_map(params![limit.max(1)], mapper)
        } else {
            stmt.query_map(params![limit.max(1), status], mapper)
        };
        rows.ok()
            .into_iter()
            .flat_map(|rows| rows.filter_map(|row| row.ok()))
            .collect()
    }

    pub fn failure_alert_counts(&self) -> Value {
        let conn = self.conn.lock().unwrap();
        Self::failure_alert_counts_locked(&conn)
    }

    /// Requeue failures caused by temporary upstream or local infrastructure
    /// conditions. Permanent failures (missing/private repositories, invalid
    /// input, authentication) are intentionally left for operator review.
    pub fn recover_transient_failures(&self, limit: i64) -> Result<(usize, usize), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.clamp(1, 500);

        let evidence = {
            let mut stmt = conn.prepare(
                "SELECT id, last_error FROM evidence_tasks
                 WHERE status='failed' AND COALESCE(last_error, '') <> ''
                 ORDER BY updated_at ASC, id ASC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(Result::ok)
                .filter(|(_, error)| is_retryable_operational_error(error))
                .collect::<Vec<_>>()
        };
        let mut evidence_requeued = 0;
        for (id, _) in evidence {
            evidence_requeued += conn.execute(
                "UPDATE evidence_tasks
                 SET status='queued', attempts=0, lease_expires_at=NULL,
                     next_attempt_at=datetime('now', '+5 minutes'), updated_at=datetime('now')
                 WHERE id=?1 AND status='failed'",
                params![id],
            )?;
            resolve_failure_alert_locked(&conn, "evidence_task", id)?;
        }

        let scans = {
            let mut stmt = conn.prepare(
                "SELECT id, last_error FROM scan_jobs
                 WHERE status='failed' AND COALESCE(last_error, '') <> ''
                 ORDER BY completed_at ASC, id ASC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(Result::ok)
                .filter(|(_, error)| is_retryable_operational_error(error))
                .collect::<Vec<_>>()
        };
        let mut scans_requeued = 0;
        for (id, _) in scans {
            scans_requeued += conn.execute(
                "UPDATE scan_jobs
                 SET status='queued', started_at=NULL, completed_at=NULL, last_error=NULL,
                     priority=MAX(priority, 50)
                 WHERE id=?1 AND status='failed'",
                params![id],
            )?;
            resolve_failure_alert_locked(&conn, "scan_job", id)?;
        }

        Ok((scans_requeued, evidence_requeued))
    }

    pub fn backfill_failed_scan_job_alerts(&self) -> Result<usize, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        backfill_failed_scan_job_alerts_locked(&conn)
    }

    pub fn pending_failure_notifications(&self, limit: i64) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
            return vec![];
        };

        let result = (|| -> rusqlite::Result<Vec<Value>> {
            let mut stmt = conn.prepare(
                "SELECT id, source_kind, source_id, repo, status, severity, title, error,
                        attempts, max_attempts, first_seen_at, last_seen_at
                 FROM failure_alerts
                 WHERE status='open' AND notification_status IN ('pending', 'failed')
                 ORDER BY last_seen_at ASC, id ASC
                 LIMIT ?1",
            )?;
            let alerts = stmt
                .query_map(params![limit.max(1)], |row| {
                    Ok(json!({
                        "id": row.get::<_, i64>(0)?,
                        "source_kind": row.get::<_, String>(1)?,
                        "source_id": row.get::<_, i64>(2)?,
                        "repo": row.get::<_, String>(3)?,
                        "status": row.get::<_, String>(4)?,
                        "severity": row.get::<_, String>(5)?,
                        "title": row.get::<_, String>(6)?,
                        "error": row.get::<_, String>(7)?,
                        "attempts": row.get::<_, i64>(8)?,
                        "max_attempts": row.get::<_, i64>(9)?,
                        "first_seen_at": row.get::<_, String>(10)?,
                        "last_seen_at": row.get::<_, String>(11)?,
                    }))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);

            for id in alerts
                .iter()
                .filter_map(|alert| alert.get("id").and_then(Value::as_i64))
            {
                conn.execute(
                    "UPDATE failure_alerts
                     SET notification_status='sending', notification_error=NULL
                     WHERE id=?1 AND notification_status IN ('pending', 'failed')",
                    params![id],
                )?;
            }
            Ok(alerts)
        })();

        match result {
            Ok(alerts) => {
                conn.execute_batch("COMMIT").ok();
                alerts
            }
            Err(_) => {
                conn.execute_batch("ROLLBACK").ok();
                vec![]
            }
        }
    }

    pub fn mark_failure_notification(
        &self,
        id: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE failure_alerts
             SET notification_status=?1, notification_error=?2, last_seen_at=last_seen_at
             WHERE id=?3",
            params![status, error, id],
        )?;
        Ok(())
    }

    pub fn acknowledge_failure_alert(&self, id: i64) -> Result<bool, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE failure_alerts
             SET status='acknowledged', acknowledged_at=datetime('now'), last_seen_at=datetime('now')
             WHERE id=?1 AND status='open'",
            params![id],
        )?;
        Ok(changed > 0)
    }

    pub fn retry_failure_alert(
        &self,
        id: i64,
        priority: i64,
    ) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let alert = conn
            .query_row(
                "SELECT source_kind, source_id, repo FROM failure_alerts WHERE id=?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .ok();
        let Some((source_kind, source_id, repo)) = alert else {
            return Ok(None);
        };
        match source_kind.as_str() {
            "scan_job" => {
                conn.execute(
                    "UPDATE scan_jobs
                     SET status='queued', priority=MAX(priority, ?1), started_at=NULL,
                         completed_at=NULL, last_error=NULL
                     WHERE id=?2",
                    params![priority, source_id],
                )?;
            }
            "evidence_task" => {
                conn.execute(
                    "UPDATE evidence_tasks
                     SET status='queued', attempts=0, lease_expires_at=NULL, last_error=NULL,
                         next_attempt_at=datetime('now'), updated_at=datetime('now')
                     WHERE id=?1",
                    params![source_id],
                )?;
            }
            _ => {}
        }
        conn.execute(
            "UPDATE failure_alerts
             SET status='resolved', resolved_at=datetime('now'), last_seen_at=datetime('now')
             WHERE id=?1",
            params![id],
        )?;
        Ok(Some(json!({
            "id": id,
            "source_kind": source_kind,
            "source_id": source_id,
            "repo": repo,
            "status": "queued"
        })))
    }

    pub fn completed_progressive_evidence(
        &self,
        job_id: i64,
        detail_limit: usize,
        history_page_limit: usize,
    ) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT source, status,
                    CASE WHEN source='github_history_page'
                              AND CAST(partition_key AS INTEGER) > ?2
                         THEN NULL ELSE result_json END
             FROM evidence_tasks
             WHERE job_id=?1 ORDER BY source, CAST(partition_key AS INTEGER), id",
        )?;
        let rows = stmt
            .query_map(params![job_id, history_page_limit.max(1) as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let history_rows = rows
            .iter()
            .filter(|(source, _, _)| source == "github_history_page")
            .take(history_page_limit.max(1))
            .collect::<Vec<_>>();
        let history_complete = !history_rows.is_empty()
            && history_rows
                .iter()
                .all(|(_, status, _)| status == "completed")
            && (history_rows.len() >= history_page_limit.max(1)
                || history_rows.iter().any(|(_, _, raw)| {
                    raw.as_deref()
                        .and_then(|value| serde_json::from_str::<Value>(value).ok())
                        .and_then(|value| value.get("count").and_then(Value::as_u64))
                        .is_some_and(|count| count < 100)
                }));
        let nvd_complete = rows
            .iter()
            .any(|(source, status, _)| source == "nvd" && status == "completed");
        let detail_manifest = rows
            .iter()
            .find(|(source, status, _)| source == "commit_detail_manifest" && status == "completed")
            .and_then(|(_, _, raw)| raw.as_deref())
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
        let detail_manifest_complete = detail_manifest.is_some();
        let required_shas = detail_manifest
            .as_ref()
            .and_then(|manifest| manifest.get("shas").and_then(Value::as_array))
            .map(|shas| {
                shas.iter()
                    .filter_map(Value::as_str)
                    .take(detail_limit)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let details_complete = required_shas.iter().all(|sha| {
            rows.iter().any(|(source, status, raw)| {
                source == "commit_detail"
                    && status == "completed"
                    && raw
                        .as_deref()
                        .and_then(|value| serde_json::from_str::<Value>(value).ok())
                        .and_then(|value| {
                            value.get("sha").and_then(Value::as_str).map(str::to_owned)
                        })
                        .as_deref()
                        == Some(sha.as_str())
            })
        });
        if !history_complete || !nvd_complete || !detail_manifest_complete || !details_complete {
            return Ok(None);
        }
        let history = history_rows
            .into_iter()
            .filter_map(|(_, _, raw)| raw.as_deref())
            .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
            .collect::<Vec<_>>();
        let nvd = rows
            .iter()
            .find(|(source, status, _)| source == "nvd" && status == "completed")
            .and_then(|(_, _, raw)| raw.as_deref())
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .unwrap_or_else(|| json!({"cves": []}));
        let commit_details = rows
            .iter()
            .filter(|(source, status, _)| source == "commit_detail" && status == "completed")
            .filter_map(|(_, _, raw)| raw.as_deref())
            .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|result| {
                required_shas.is_empty()
                    || result
                        .get("sha")
                        .and_then(Value::as_str)
                        .is_some_and(|sha| required_shas.iter().any(|required| required == sha))
            })
            .filter_map(|result| result.get("detail").cloned())
            .collect::<Vec<_>>();
        Ok(Some(
            json!({"history_pages": history, "nvd": nvd, "commit_details": commit_details}),
        ))
    }

    pub fn discard_unfinished_commit_detail_tasks(
        &self,
        job_id: i64,
    ) -> Result<usize, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM evidence_tasks
             WHERE job_id=?1 AND source='commit_detail' AND status!='completed'",
            params![job_id],
        )
        .map_err(Into::into)
    }

    pub fn completed_history_pages(
        &self,
        job_id: i64,
        history_page_limit: usize,
    ) -> Result<Option<Vec<Value>>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT status, result_json FROM evidence_tasks
             WHERE job_id=?1 AND source='github_history_page'
             ORDER BY CAST(partition_key AS INTEGER), id LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![job_id, history_page_limit.max(1) as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.is_empty() || rows.iter().any(|(status, _)| status != "completed") {
            return Ok(None);
        }
        let pages = rows
            .into_iter()
            .filter_map(|(_, raw)| raw)
            .filter_map(|raw| serde_json::from_str::<Value>(&raw).ok())
            .collect::<Vec<_>>();
        if pages.len() < history_page_limit.max(1)
            && !pages.iter().any(|page| {
                page.get("count")
                    .and_then(Value::as_u64)
                    .is_some_and(|v| v < 100)
            })
        {
            return Ok(None);
        }
        Ok(Some(pages))
    }

    // -------------------------------------------------------------------
    // Cross-job external source cache
    // -------------------------------------------------------------------
    pub fn get_source_cache(&self, cache_key: &str) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let raw = conn
            .query_row(
                "SELECT payload_json FROM source_cache
                 WHERE cache_key=?1 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))",
                params![cache_key],
                |row| row.get::<_, String>(0),
            )
            .ok();
        raw.map(|payload| serde_json::from_str(&payload).map_err(Into::into))
            .transpose()
    }

    pub fn get_source_cache_entry(&self, cache_key: &str) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT payload_json, etag, last_modified,
                 CASE WHEN expires_at IS NULL OR datetime(expires_at) > datetime('now') THEN 1 ELSE 0 END
                 FROM source_cache WHERE cache_key=?1",
                params![cache_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .ok();
        let Some((payload, etag, last_modified, fresh)) = row else {
            return Ok(None);
        };
        Ok(Some(json!({
            "payload": serde_json::from_str::<Value>(&payload)?,
            "etag": etag,
            "last_modified": last_modified,
            "fresh": fresh != 0
        })))
    }

    pub fn put_source_cache(
        &self,
        cache_key: &str,
        source: &str,
        payload: &Value,
        etag: Option<&str>,
        last_modified: Option<&str>,
        ttl_seconds: Option<i64>,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO source_cache
             (cache_key, source, etag, last_modified, payload_json, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5,
               CASE WHEN ?6 IS NULL THEN NULL ELSE datetime('now', '+' || ?6 || ' seconds') END)
             ON CONFLICT(cache_key) DO UPDATE SET source=excluded.source,
               etag=excluded.etag, last_modified=excluded.last_modified,
               payload_json=excluded.payload_json, expires_at=excluded.expires_at,
               updated_at=datetime('now')",
            params![
                cache_key,
                source,
                etag,
                last_modified,
                serde_json::to_string(payload)?,
                ttl_seconds
            ],
        )?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Audit events
    // -------------------------------------------------------------------
    pub fn record_audit_event(
        &self,
        event: &str,
        repo: Option<&str>,
        detail: &Value,
        ip: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO audit_events (event, repo, detail_json, ip_address) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![event, repo, serde_json::to_string(detail)?, ip])?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Report history
    // -------------------------------------------------------------------
    pub fn report_history(&self, repo: &str) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        let stmt = conn.prepare(
            "SELECT report_json FROM evaluations WHERE repo = ?1 OR repo = ?2 ORDER BY id DESC LIMIT 50"
        ).ok();
        let Some(mut stmt) = stmt else { return vec![] };
        stmt.query_map(
            rusqlite::params![repo, format!("github.com/{repo}")],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .into_iter()
        .flat_map(|rows| {
            rows.filter_map(|r| r.ok())
                .filter_map(|s| serde_json::from_str(&s).ok())
        })
        .collect()
    }

    pub fn get_report_by_id(&self, id: i64) -> Result<Option<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT report_json FROM evaluations WHERE id=?1",
            params![id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(raw) => Ok(Some(serde_json::from_str(&raw)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn get_report_by_id_async(&self, id: i64) -> Result<Option<Value>, anyhow::Error> {
        if let Some(ref pool) = self.pg {
            let row = sqlx::query("SELECT report_json FROM evaluations WHERE id=$1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
            return row
                .map(|row| {
                    serde_json::from_str::<Value>(row.get::<String, _>("report_json").as_str())
                })
                .transpose()
                .map_err(Into::into);
        }
        self.get_report_by_id(id)
    }

    pub async fn insert_report_async(&self, report: &Value) -> Result<i64, anyhow::Error> {
        if let Some(ref pool) = self.pg {
            let repo = report
                .get("repo")
                .and_then(Value::as_str)
                .unwrap_or("unknown/repo");
            let evaluated_at = report
                .get("evaluated_at")
                .and_then(Value::as_str)
                .unwrap_or("");
            let trust_score = report
                .get("trust_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
            let verdict = report.get("verdict").and_then(Value::as_str).unwrap_or("");
            let action = report.get("action").and_then(Value::as_str).unwrap_or("");
            let next_review = report
                .get("next_review_date")
                .and_then(Value::as_str)
                .unwrap_or("");
            let coverage = report.get("coverage").and_then(Value::as_str).unwrap_or("");
            let critical_flags = report.get("critical_flags").cloned().unwrap_or(json!([]));
            let pillar_scores = report.get("pillar_scores").cloned().unwrap_or(json!({}));
            let scanner_runs = report.get("scanner_runs").cloned().unwrap_or(json!([]));
            let metrics = report.get("observed_metrics").cloned().unwrap_or(json!({}));
            let report_json = serde_json::to_string(report)?;
            let scoring_version = report.get("scoring_version").and_then(Value::as_str);

            let row = sqlx::query(
                "INSERT INTO evaluations (repo, evaluated_at, trust_score, grade, verdict, action, next_review_date, coverage, critical_flags_json, pillar_scores_json, scanner_runs_json, metrics_json, report_json, scoring_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id",
            )
            .bind(repo).bind(evaluated_at).bind(trust_score).bind(grade).bind(verdict)
            .bind(action).bind(next_review).bind(coverage)
            .bind(serde_json::to_string(&critical_flags)?)
            .bind(serde_json::to_string(&pillar_scores)?)
            .bind(serde_json::to_string(&scanner_runs)?)
            .bind(serde_json::to_string(&metrics)?)
            .bind(&report_json).bind(scoring_version)
            .fetch_one(pool).await?;
            let id: i32 = row.get("id");
            return Ok(id as i64);
        }
        self.insert_report(report)
    }

    pub fn insert_report(&self, report: &Value) -> Result<i64, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let repo = report
            .get("repo")
            .and_then(Value::as_str)
            .unwrap_or("unknown/repo");
        let evaluated_at = report
            .get("evaluated_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        let trust_score = report
            .get("trust_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
        let verdict = report.get("verdict").and_then(Value::as_str).unwrap_or("");
        let action = report.get("action").and_then(Value::as_str).unwrap_or("");
        let next_review = report
            .get("next_review_date")
            .and_then(Value::as_str)
            .unwrap_or("");
        let coverage = report.get("coverage").and_then(Value::as_str).unwrap_or("");
        let critical_flags = report.get("critical_flags").cloned().unwrap_or(json!([]));
        let pillar_scores = report.get("pillar_scores").cloned().unwrap_or(json!({}));
        let scanner_runs = report.get("scanner_runs").cloned().unwrap_or(json!([]));
        let metrics = report.get("observed_metrics").cloned().unwrap_or(json!({}));
        let report_json = serde_json::to_string(report)?;
        let scoring_version = report.get("scoring_version").and_then(Value::as_str);

        conn.execute(
            "INSERT INTO evaluations (repo, evaluated_at, trust_score, grade, verdict, action, next_review_date, coverage, critical_flags_json, pillar_scores_json, scanner_runs_json, metrics_json, report_json, scoring_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![repo, evaluated_at, trust_score, grade, verdict, action, next_review, coverage,
                    serde_json::to_string(&critical_flags)?, serde_json::to_string(&pillar_scores)?,
                    serde_json::to_string(&scanner_runs)?, serde_json::to_string(&metrics)?,
                    report_json, scoring_version],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn upsert_regression_contracts(
        &self,
        repo: &str,
        contracts: &[Value],
    ) -> Result<(), anyhow::Error> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn.transaction()?;
        for contract in contracts {
            let Some(contract_id) = contract.get("id").and_then(Value::as_str) else {
                continue;
            };
            let generated_state = contract
                .get("lifecycle")
                .and_then(|lifecycle| lifecycle.get("state"))
                .and_then(Value::as_str)
                .unwrap_or("candidate");
            let existing = transaction
                .query_row(
                    "SELECT contract_json, lifecycle_state, version FROM regression_contracts
                     WHERE repo=?1 AND contract_id=?2",
                    params![repo, contract_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .ok();
            let (persisted, state, version) = if let Some((_raw, state, version)) = existing {
                let mut merged = contract.clone();
                if let Some(object) = merged.as_object_mut() {
                    object.insert(
                        "lifecycle".into(),
                        json!({
                            "state": state,
                            "reason": "persisted_lifecycle"
                        }),
                    );
                    object.insert("version".into(), json!(version));
                }
                (merged, state, version)
            } else {
                (contract.clone(), generated_state.to_string(), 1)
            };
            transaction.execute(
                "INSERT INTO regression_contracts
                    (repo, contract_id, version, lifecycle_state, contract_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(repo, contract_id) DO UPDATE SET
                    contract_json=excluded.contract_json, updated_at=datetime('now')",
                params![
                    repo,
                    contract_id,
                    version,
                    state,
                    serde_json::to_string(&persisted)?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn regression_contracts(&self, repo: &str) -> Result<Vec<Value>, anyhow::Error> {
        self.expire_regression_suppressions(repo)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT contract_json, version, lifecycle_state FROM regression_contracts
             WHERE repo=?1 ORDER BY lifecycle_state, contract_id",
        )?;
        let rows = stmt.query_map(params![repo], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        Ok(rows
            .filter_map(Result::ok)
            .filter_map(|(raw, version, state)| {
                let mut value = serde_json::from_str::<Value>(&raw).ok()?;
                if let Some(object) = value.as_object_mut() {
                    object.insert("version".into(), json!(version));
                    object.insert(
                        "lifecycle".into(),
                        json!({
                            "state": state,
                            "reason": "persisted_lifecycle"
                        }),
                    );
                }
                Some(value)
            })
            .collect())
    }

    fn expire_regression_suppressions(&self, repo: &str) -> Result<(), anyhow::Error> {
        let mut conn = self.conn.lock().unwrap();
        let expired = {
            let mut stmt = conn.prepare(
                "SELECT c.contract_id,c.version,c.contract_json
                 FROM regression_contracts c JOIN regression_contract_events e
                   ON e.repo=c.repo AND e.contract_id=c.contract_id AND e.version=c.version
                 WHERE c.repo=?1 AND c.lifecycle_state='suppressed'
                   AND e.expires_at IS NOT NULL
                   AND datetime(e.expires_at) <= datetime('now')",
            )?;
            let rows = stmt.query_map(params![repo], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.filter_map(Result::ok).collect::<Vec<_>>()
        };
        if expired.is_empty() {
            return Ok(());
        }
        let transaction = conn.transaction()?;
        for (contract_id, version, raw) in expired {
            let next_version = version + 1;
            let mut contract: Value = serde_json::from_str(&raw)?;
            contract["version"] = json!(next_version);
            contract["lifecycle"] = json!({
                "state":"active", "reason":"suppression_expired", "actor":"system"
            });
            transaction.execute(
                "UPDATE regression_contracts SET version=?3,lifecycle_state='active',
                    contract_json=?4,updated_at=datetime('now')
                 WHERE repo=?1 AND contract_id=?2 AND version=?5",
                params![
                    repo,
                    contract_id,
                    next_version,
                    serde_json::to_string(&contract)?,
                    version
                ],
            )?;
            transaction.execute(
                "INSERT INTO regression_contract_events
                    (repo,contract_id,from_state,to_state,actor,reason,scope,version)
                 VALUES (?1,?2,'suppressed','active','system','suppression_expired','contract',?3)",
                params![repo, contract_id, next_version],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn regression_contract(&self, repo: &str, contract_id: &str) -> Option<Value> {
        self.regression_contracts(repo)
            .ok()?
            .into_iter()
            .find(|contract| contract.get("id").and_then(Value::as_str) == Some(contract_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_regression_contract(
        &self,
        repo: &str,
        contract_id: &str,
        expected_version: i64,
        to_state: &str,
        actor: &str,
        reason: &str,
        scope: &str,
        comment: Option<&str>,
        expires_at: Option<&str>,
    ) -> Result<Value, anyhow::Error> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn.transaction()?;
        let (raw, from_state, version): (String, String, i64) = transaction.query_row(
            "SELECT contract_json, lifecycle_state, version FROM regression_contracts
             WHERE repo=?1 AND contract_id=?2",
            params![repo, contract_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if version != expected_version {
            anyhow::bail!("version_conflict: expected {expected_version}, current {version}");
        }
        let next_version = version + 1;
        let mut contract: Value = serde_json::from_str(&raw)?;
        if let Some(object) = contract.as_object_mut() {
            object.insert("version".into(), json!(next_version));
            object.insert(
                "lifecycle".into(),
                json!({
                    "state": to_state, "reason": reason, "actor": actor,
                    "scope": scope, "expires_at": expires_at
                }),
            );
        }
        let updated = transaction.execute(
            "UPDATE regression_contracts SET version=?3, lifecycle_state=?4,
                contract_json=?5, updated_at=datetime('now')
             WHERE repo=?1 AND contract_id=?2 AND version=?6",
            params![
                repo,
                contract_id,
                next_version,
                to_state,
                serde_json::to_string(&contract)?,
                expected_version
            ],
        )?;
        if updated != 1 {
            anyhow::bail!("version_conflict");
        }
        transaction.execute(
            "INSERT INTO regression_contract_events
                (repo, contract_id, from_state, to_state, actor, reason, scope,
                 comment, expires_at, version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                repo,
                contract_id,
                from_state,
                to_state,
                actor,
                reason,
                scope,
                comment,
                expires_at,
                next_version
            ],
        )?;
        transaction.commit()?;
        Ok(contract)
    }

    pub fn regression_contract_events(
        &self,
        repo: &str,
        contract_id: &str,
    ) -> Result<Vec<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT from_state,to_state,actor,reason,scope,comment,expires_at,version,created_at
             FROM regression_contract_events WHERE repo=?1 AND contract_id=?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![repo, contract_id], |row| {
            Ok(json!({
                "from_state": row.get::<_, String>(0)?, "to_state": row.get::<_, String>(1)?,
                "actor": row.get::<_, String>(2)?, "reason": row.get::<_, String>(3)?,
                "scope": row.get::<_, String>(4)?, "comment": row.get::<_, Option<String>>(5)?,
                "expires_at": row.get::<_, Option<String>>(6)?, "version": row.get::<_, i64>(7)?,
                "created_at": row.get::<_, String>(8)?
            }))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn insert_regression_assessment(
        &self,
        repo: &str,
        contract_id: &str,
        base_sha: &str,
        head_sha: &str,
        assessment: &Value,
    ) -> Result<bool, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO regression_assessments
                (repo,contract_id,base_sha,head_sha,assessment_json)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                repo,
                contract_id,
                base_sha,
                head_sha,
                serde_json::to_string(assessment)?
            ],
        )?;
        Ok(inserted == 1)
    }

    pub fn regression_assessments(
        &self,
        repo: &str,
        head_sha: &str,
    ) -> Result<Vec<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT contract_id,base_sha,head_sha,assessment_json,created_at
             FROM regression_assessments WHERE repo=?1 AND head_sha=?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![repo, head_sha], |row| {
            let raw: String = row.get(3)?;
            let assessment = serde_json::from_str::<Value>(&raw).unwrap_or(json!({}));
            Ok(json!({
                "contract_id": row.get::<_, String>(0)?, "base_sha": row.get::<_, String>(1)?,
                "head_sha": row.get::<_, String>(2)?, "assessment": assessment,
                "created_at": row.get::<_, String>(4)?
            }))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn regression_check_run(&self, repo: &str, head_sha: &str) -> Option<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT check_run_id FROM regression_check_runs WHERE repo=?1 AND head_sha=?2",
            params![repo, head_sha],
            |row| row.get(0),
        )
        .ok()
    }

    pub fn upsert_regression_check_run(
        &self,
        repo: &str,
        head_sha: &str,
        check_run_id: i64,
        conclusion: &str,
    ) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO regression_check_runs(repo,head_sha,check_run_id,conclusion)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(repo,head_sha) DO UPDATE SET check_run_id=excluded.check_run_id,
                conclusion=excluded.conclusion,updated_at=datetime('now')",
            params![repo, head_sha, check_run_id, conclusion],
        )?;
        Ok(())
    }

    pub fn latest_reports(&self, limit: i64) -> Result<Vec<Value>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT report_json FROM evaluations ORDER BY id DESC LIMIT 1000")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut seen = std::collections::BTreeSet::new();
        let mut reports = rows
            .filter_map(|row| row.ok())
            .filter_map(|raw| serde_json::from_str::<Value>(&raw).ok())
            .filter(|report| !report_has_critical_intel_errors(report))
            .filter_map(|report| {
                let repo = report.get("repo").and_then(Value::as_str)?.to_string();
                if !seen.insert(repo.clone()) {
                    return None;
                }
                Some(json!({
                    "repo": repo,
                    "trust_score": report.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0),
                    "grade": report.get("grade").and_then(Value::as_str).unwrap_or("-"),
                    "verdict": report.get("verdict").and_then(Value::as_str).unwrap_or(""),
                    "action": report.get("action").and_then(Value::as_str).unwrap_or(""),
                    "confidence": report.get("confidence").and_then(Value::as_str).unwrap_or("unknown"),
                    "evidence_coverage": report.get("evidence_coverage").and_then(Value::as_f64).unwrap_or(0.0),
                    "missing_evidence": report.get("missing_evidence").cloned().unwrap_or(json!([])),
                    "decision_reasons": report.get("decision_reasons").cloned().unwrap_or(json!([])),
                    "trust_decision": report.get("trust_decision").cloned().unwrap_or(json!(null)),
                    "coverage": report.get("coverage").and_then(Value::as_str).unwrap_or(""),
                    "evaluated_at": report.get("evaluated_at").and_then(Value::as_str).unwrap_or(""),
                    "next_review_date": report.get("next_review_date").and_then(Value::as_str).unwrap_or(""),
                }))
            })
            .collect::<Vec<_>>();
        reports.sort_by(|a, b| {
            b.get("trust_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .partial_cmp(&a.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        reports.truncate(limit as usize);
        Ok(reports)
    }

    pub async fn get_report_async(&self, repo: &str) -> Option<Value> {
        if let Some(ref pool) = self.pg {
            let github_repo = format!("github.com/{repo}");
            let repo_lower = repo.to_ascii_lowercase();
            let github_repo_lower = github_repo.to_ascii_lowercase();
            let rows = sqlx::query(
                "SELECT report_json FROM evaluations
                 WHERE repo = $1 OR repo = $2
                    OR lower(repo) = $3 OR lower(repo) = $4
                 ORDER BY CASE WHEN repo = $1 OR repo = $2 THEN 0 ELSE 1 END, id DESC
                 LIMIT 50",
            )
            .bind(repo)
            .bind(github_repo)
            .bind(repo_lower)
            .bind(github_repo_lower)
            .fetch_all(pool)
            .await
            .ok()?;
            return rows.into_iter().find_map(|row| {
                let text: String = row.get("report_json");
                let report = serde_json::from_str::<Value>(&text).ok()?;
                if report_has_critical_intel_errors(&report) {
                    None
                } else {
                    Some(report)
                }
            });
        }
        self.get_report(repo)
    }

    pub fn get_report(&self, repo: &str) -> Option<Value> {
        let conn = self.conn.lock().unwrap();
        let github_repo = format!("github.com/{repo}");
        let repo_lower = repo.to_ascii_lowercase();
        let github_repo_lower = github_repo.to_ascii_lowercase();
        let mut stmt = conn
            .prepare(
                "SELECT report_json FROM evaluations
             WHERE repo = ?1 OR repo = ?2
                OR lower(repo) = ?3 OR lower(repo) = ?4
             ORDER BY CASE WHEN repo = ?1 OR repo = ?2 THEN 0 ELSE 1 END, id DESC
             LIMIT 50",
            )
            .ok()?;
        let rows = stmt
            .query_map(
                params![repo, github_repo, repo_lower, github_repo_lower],
                |row| row.get::<_, String>(0),
            )
            .ok()?
            .filter_map(|row| row.ok())
            .collect::<Vec<_>>();
        rows.into_iter()
            .filter_map(|raw| serde_json::from_str::<Value>(&raw).ok())
            .find(|report| !report_has_critical_intel_errors(report))
    }

    pub fn recent_scans(&self, limit: i64) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        let stmt = conn
            .prepare("SELECT report_json FROM evaluations ORDER BY id DESC LIMIT 1000")
            .ok();
        let Some(mut stmt) = stmt else { return vec![] };
        let mut seen = std::collections::BTreeSet::new();
        stmt.query_map([], |row| row.get::<_, String>(0))
        .ok()
        .into_iter()
        .flat_map(|rows| rows.filter_map(|r| r.ok()))
        .filter_map(|raw| serde_json::from_str::<Value>(&raw).ok())
        .filter(|report| !report_has_critical_intel_errors(report))
        .filter_map(|report| {
            let repo = report.get("repo").and_then(Value::as_str)?.to_string();
            if !seen.insert(repo.clone()) {
                return None;
            }
            let (fixes, cves, status) = report_context_summary(&report);
            Some(json!({
                "repo": repo,
                "trust_score": report.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0),
                "grade": report.get("grade").and_then(Value::as_str).unwrap_or("-"),
                "verdict": report.get("verdict").and_then(Value::as_str).unwrap_or(""),
                "action": report.get("action").and_then(Value::as_str).unwrap_or(""),
                "confidence": report.get("confidence").and_then(Value::as_str).unwrap_or("unknown"),
                "evidence_coverage": report.get("evidence_coverage").and_then(Value::as_f64).unwrap_or(0.0),
                "missing_evidence": report.get("missing_evidence").cloned().unwrap_or(json!([])),
                "decision_reasons": report.get("decision_reasons").cloned().unwrap_or(json!([])),
                "trust_decision": report.get("trust_decision").cloned().unwrap_or(json!(null)),
                "coverage": report.get("coverage").and_then(Value::as_str).unwrap_or(""),
                "evaluated_at": report.get("evaluated_at").and_then(Value::as_str).unwrap_or(""),
                "fixes": fixes, "cves": cves, "status": status,
                "summary": {"fixes": fixes, "cves": cves, "status": status}
            }))
        })
        .take(limit as usize)
        .collect()
    }

    pub fn leaderboard(&self, query: Option<&str>, limit: i64) -> Value {
        let rows = self.latest_reports(limit).unwrap_or_default();
        let filtered: Vec<&Value> = if let Some(q) = query {
            let q = q.to_lowercase();
            rows.iter()
                .filter(|r| {
                    r.get("repo")
                        .and_then(Value::as_str)
                        .map(|repo| repo.to_lowercase().contains(&q))
                        .unwrap_or(false)
                })
                .collect()
        } else {
            rows.iter().collect()
        };
        let count = filtered.len() as i64;
        json!({
            "count": count,
            "rows": filtered.into_iter().take(limit as usize).cloned().collect::<Vec<_>>(),
            "metrics": {"tracked_repos": count, "critical_blocks": 0}
        })
    }

    pub fn publish_trust_event(
        &self,
        repo: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<i64, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        let payload_str = serde_json::to_string(payload)?;
        conn.execute(
            "INSERT INTO trust_events (repo, event_type, payload_json) VALUES (?1, ?2, ?3)",
            params![repo, event_type, payload_str],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn count_evaluations(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM evaluations", [], |row| row.get(0))
            .unwrap_or(0)
    }

    pub fn metrics(&self) -> Value {
        let conn = self.conn.lock().unwrap();
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM evaluations", [], |row| row.get(0))
            .unwrap_or(0);
        let unique: i64 = conn
            .query_row("SELECT COUNT(DISTINCT repo) FROM evaluations", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        let mut llm = LlmDecisionMetrics::default();
        if let Ok(mut stmt) = conn.prepare("SELECT report_json FROM evaluations") {
            if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                for raw in rows.flatten() {
                    if let Ok(report) = serde_json::from_str::<Value>(&raw) {
                        llm.observe_report(&report);
                    }
                }
            }
        }
        let by_source = llm
            .by_source
            .iter()
            .map(|(source, count)| (source.clone(), json!(count)))
            .collect::<serde_json::Map<String, Value>>();
        let by_model_task = llm
            .by_model_task
            .iter()
            .map(|((model, task, source), count)| {
                (
                    format!("{model}|{task}|{source}"),
                    json!({"model": model, "task": task, "decision_source": source, "count": count}),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        let by_error_type = llm
            .by_error_type
            .iter()
            .map(|(error_type, count)| (error_type.clone(), json!(count)))
            .collect::<serde_json::Map<String, Value>>();
        let regression_contracts: i64 = conn
            .query_row("SELECT COUNT(*) FROM regression_contracts", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        let verified_contracts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM regression_contracts WHERE lifecycle_state='verified'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let published_checks: i64 = conn
            .query_row("SELECT COUNT(*) FROM regression_check_runs", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        let mut assessment_states = BTreeMap::<String, i64>::new();
        let mut dispositions = BTreeMap::<String, i64>::new();
        if let Ok(mut stmt) = conn.prepare("SELECT assessment_json FROM regression_assessments") {
            if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                for raw in rows.flatten() {
                    if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                        if let Some(state) = value.get("state").and_then(Value::as_str) {
                            *assessment_states.entry(state.to_string()).or_insert(0) += 1;
                        }
                        if let Some(disposition) = value.get("disposition").and_then(Value::as_str)
                        {
                            *dispositions.entry(disposition.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        json!({
            "scans_total": total,
            "unique_repos": unique,
            "llm_decisions_total": llm.total,
            "llm_hallucination_rejections_total": llm.rejected,
            "llm_hallucination_rejection_rate": llm.rejection_rate(),
            "llm_rate_limited_total": llm.rate_limited,
            "llm_model_missing_total": llm.model_missing,
            "llm_latency_average_ms": llm.average_latency_ms(),
            "llm_latency_samples_total": llm.latency_samples,
            "llm_decisions_by_source": by_source,
            "llm_errors_by_type": by_error_type,
            "llm_decisions_by_model_task": by_model_task,
            "regression_contracts_total": regression_contracts,
            "regression_contracts_verified": verified_contracts,
            "regression_check_runs_published": published_checks,
            "regression_assessments_by_state": assessment_states,
            "regression_assessments_by_disposition": dispositions
        })
    }

    pub fn get_daemon_state(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM daemon_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .ok()
    }

    pub fn set_daemon_state(&self, key: &str, value: &str) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO daemon_state (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn trust_events_after(&self, after_id: i64, limit: i64) -> Vec<Value> {
        let conn = self.conn.lock().unwrap();
        let stmt = conn.prepare(
            "SELECT id, repo, event_type, payload_json, created_at FROM trust_events WHERE id > ?1 ORDER BY id ASC LIMIT ?2"
        ).ok();
        let Some(mut stmt) = stmt else { return vec![] };
        stmt.query_map(params![after_id, limit], |row| {
            let id: i64 = row.get(0)?;
            let repo: String = row.get(1)?;
            let event_type: String = row.get(2)?;
            let payload_json: String = row.get(3)?;
            let created_at: String = row.get(4)?;
            let payload = serde_json::from_str::<Value>(&payload_json)
                .unwrap_or(Value::String(payload_json));
            Ok(json!({"id": id, "repo": repo, "event_type": event_type, "payload": payload, "created_at": created_at}))
        }).ok().into_iter().flat_map(|rows| rows.filter_map(|r| r.ok())).collect()
    }

    pub fn latest_trust_event_id(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM trust_events", [], |row| {
            row.get(0)
        })
        .unwrap_or(0)
    }
}

fn dedupe_queued_scan_jobs(conn: &Connection) -> Result<(), anyhow::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, repo, lane
         FROM scan_jobs
         WHERE status='queued'
         ORDER BY repo ASC, lane ASC, priority DESC, id ASC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .filter_map(|row| row.ok())
        .collect::<Vec<_>>();

    let mut keep_by_repo: BTreeMap<(String, String), i64> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for (id, repo, lane) in rows {
        let key = (repo, lane);
        if let Some(keep_id) = keep_by_repo.get(&key).copied() {
            duplicates.push((id, keep_id));
        } else {
            keep_by_repo.insert(key, id);
        }
    }

    for (id, keep_id) in duplicates {
        conn.execute(
            "UPDATE scan_jobs
             SET status='deduped', completed_at=datetime('now'), last_error=?1
             WHERE id=?2 AND status='queued'",
            params![format!("deduped by scan job {keep_id}"), id],
        )?;
    }
    Ok(())
}

fn normalize_scan_lane(lane: &str) -> &'static str {
    match lane {
        "background" => "background",
        _ => "foreground",
    }
}

fn is_retryable_operational_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "githubratelimited",
        "github_rate_limited",
        "githubtimeout",
        "github_timeout",
        "databaselocked",
        "database_locked",
        "timed out",
        "timeout",
        "connection reset",
        "connection closed",
        "error sending request",
        "temporary failure",
        "dns error",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

fn retry_backoff_seconds(error: &str, base_delay_seconds: i64, attempts: i64) -> i64 {
    if error.to_ascii_lowercase().contains("rate_limit")
        || error.to_ascii_lowercase().contains("ratelimited")
    {
        return 15 * 60;
    }
    base_delay_seconds
        .max(0)
        .saturating_mul(attempts.clamp(1, 10))
        .min(60 * 60)
}

struct FailureAlertInput<'a> {
    source_kind: &'a str,
    source_id: i64,
    repo: &'a str,
    severity: &'a str,
    title: &'a str,
    error: &'a str,
    attempts: i64,
    max_attempts: i64,
}

fn upsert_failure_alert_locked(
    conn: &Connection,
    input: FailureAlertInput<'_>,
) -> Result<(), anyhow::Error> {
    conn.execute(
        "INSERT INTO failure_alerts (
            source_kind, source_id, repo, severity, title, error, attempts, max_attempts
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(source_kind, source_id) WHERE status='open'
         DO UPDATE SET
            repo=excluded.repo,
            severity=excluded.severity,
            title=excluded.title,
            error=excluded.error,
            attempts=excluded.attempts,
            max_attempts=excluded.max_attempts,
            last_seen_at=datetime('now'),
            notification_status=CASE
                WHEN failure_alerts.error = excluded.error THEN failure_alerts.notification_status
                ELSE 'pending'
            END,
            notification_error=NULL",
        params![
            input.source_kind,
            input.source_id,
            input.repo,
            input.severity,
            input.title,
            input.error,
            input.attempts,
            input.max_attempts
        ],
    )?;
    Ok(())
}

fn backfill_failed_scan_job_alerts_locked(conn: &Connection) -> Result<usize, anyhow::Error> {
    let changed = conn.execute(
        "INSERT INTO failure_alerts (
            source_kind, source_id, repo, severity, title, error, attempts, max_attempts
         )
         SELECT 'scan_job', sj.id, sj.repo, 'error', 'Scan job failed',
                sj.last_error, 1, 1
         FROM scan_jobs sj
         WHERE sj.status='failed'
           AND COALESCE(sj.last_error, '') <> ''
           AND NOT EXISTS (
                SELECT 1
                FROM failure_alerts fa
                WHERE fa.source_kind='scan_job'
                  AND fa.source_id=sj.id
           )",
        [],
    )?;
    Ok(changed)
}

fn resolve_failure_alert_locked(
    conn: &Connection,
    source_kind: &str,
    source_id: i64,
) -> Result<(), anyhow::Error> {
    conn.execute(
        "UPDATE failure_alerts
         SET status='resolved', resolved_at=datetime('now'), last_seen_at=datetime('now')
         WHERE source_kind=?1 AND source_id=?2 AND status IN ('open', 'acknowledged')",
        params![source_kind, source_id],
    )?;
    Ok(())
}

fn resolve_repo_failure_alerts_locked(
    conn: &Connection,
    repo: &str,
    source_kind: &str,
) -> Result<usize, anyhow::Error> {
    let changed = conn.execute(
        "UPDATE failure_alerts
         SET status='resolved', resolved_at=datetime('now'), last_seen_at=datetime('now')
         WHERE lower(repo)=lower(?1) AND source_kind=?2
           AND status IN ('open', 'acknowledged')",
        params![repo, source_kind],
    )?;
    Ok(changed)
}

fn reconcile_superseded_failure_alerts_locked(conn: &Connection) -> Result<usize, anyhow::Error> {
    let changed = conn.execute(
        "UPDATE failure_alerts AS fa
         SET status='resolved', resolved_at=datetime('now'), last_seen_at=datetime('now')
         WHERE fa.status IN ('open', 'acknowledged') AND (
           (fa.source_kind='scan_job' AND EXISTS (
              SELECT 1 FROM scan_jobs sj
              WHERE lower(sj.repo)=lower(fa.repo) AND sj.status='completed'
                AND datetime(sj.completed_at) > datetime(fa.last_seen_at)
           )) OR
           (fa.source_kind='evidence_task' AND EXISTS (
              SELECT 1 FROM evaluations e
              WHERE lower(e.repo)=lower(fa.repo)
                AND datetime(e.created_at) > datetime(fa.last_seen_at)
                AND json_extract(e.metrics_json, '$.scan_state')='complete'
           ))
         )",
        [],
    )?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_retrieve() {
        let db = Database::open_memory().unwrap();
        let report = json!({
            "repo": "test/example", "evaluated_at": "2026-07-09", "trust_score": 85.0,
            "grade": "A", "verdict": "Safe", "action": "Use", "next_review_date": "2026-10-07",
            "coverage": "5/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {},
            "scoring_version": "v1"
        });
        let id = db.insert_report(&report).unwrap();
        assert!(id > 0);
        let r = db.get_report("test/example").unwrap();
        assert_eq!(r["repo"], "test/example");
    }

    #[test]
    fn leaderboard() {
        let db = Database::open_memory().unwrap();
        db.insert_report(&json!({
            "repo": "a/b", "evaluated_at": "2026-07-09", "trust_score": 90.0,
            "grade": "A", "verdict": "Safe", "action": "Use", "next_review_date": "2026-10-07",
            "coverage": "7/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {},
            "scoring_version": "v1"
        }))
        .unwrap();
        let lb = db.leaderboard(None, 10);
        assert_eq!(lb["count"], 1);
    }

    #[test]
    fn metrics_include_llm_hallucination_rejection_rate() {
        let db = Database::open_memory().unwrap();
        db.insert_report(&json!({
            "repo": "a/b", "evaluated_at": "2026-07-09", "trust_score": 90.0,
            "grade": "A", "verdict": "Safe", "action": "Use", "next_review_date": "2026-10-07",
            "coverage": "7/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [],
            "observed_metrics": {
                "security_intel": {
                    "fix_commits": [{
                        "decision_source": "llm_verified",
                        "model": "google/gemma-4-31b-it:free",
                        "task": "vulnerability_classification",
                        "latency_ms": 120
                    }, {
                        "decision_source": "rejected_hallucination",
                        "model": "google/gemma-4-31b-it:free",
                        "task": "vulnerability_classification"
                    }, {
                        "decision_source": "rule_fallback_llm_unavailable",
                        "task": "ecosystem_resolution",
                        "error_type": "rate_limited",
                        "http_status": 429
                    }]
                }
            },
            "scoring_version": "v1"
        }))
        .unwrap();

        let metrics = db.metrics();

        assert_eq!(metrics["llm_decisions_total"], json!(3));
        assert_eq!(metrics["llm_hallucination_rejections_total"], json!(1));
        assert_eq!(metrics["llm_decisions_by_source"]["llm_verified"], json!(1));
        assert_eq!(
            metrics["llm_decisions_by_source"]["rejected_hallucination"],
            json!(1)
        );
        assert_eq!(
            metrics["llm_hallucination_rejection_rate"]
                .as_f64()
                .unwrap(),
            1.0 / 3.0
        );
        assert_eq!(metrics["llm_rate_limited_total"], json!(1));
        assert_eq!(metrics["llm_model_missing_total"], json!(1));
        assert_eq!(metrics["llm_latency_average_ms"], json!(120.0));
        assert_eq!(metrics["llm_latency_samples_total"], json!(1));
        assert_eq!(metrics["llm_errors_by_type"]["rate_limited"], json!(1));
    }

    #[test]
    fn scan_jobs_record_failure_reason() {
        let db = Database::open_memory().unwrap();
        let id = db.create_scan_job("owner/repo", 7).unwrap();
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((id, "owner/repo".to_string()))
        );

        db.complete_scan_job(
            id,
            false,
            Some("critical security intelligence fetch failed"),
        )
        .unwrap();
        let failed = db.scan_jobs_recent(1);

        assert_eq!(failed[0]["status"], json!("failed"));
        assert_eq!(
            failed[0]["last_error"],
            json!("critical security intelligence fetch failed")
        );

        let retry_id = db.create_scan_job("owner/repo", 8).unwrap();
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((retry_id, "owner/repo".to_string()))
        );
        let running = db.scan_jobs_recent(1);

        assert_eq!(running[0]["status"], json!("running"));
        assert_eq!(running[0]["last_error"], Value::Null);
    }

    #[test]
    fn scan_jobs_defer_rate_limited_job_for_retry() {
        let db = Database::open_memory().unwrap();
        let id = db.create_scan_job("owner/repo", 7).unwrap();
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((id, "owner/repo".to_string()))
        );

        db.defer_scan_job(id, "commits: GitHubRateLimited").unwrap();
        let jobs = db.scan_jobs_recent(1);

        assert_eq!(jobs[0]["status"], json!("queued"));
        assert_eq!(jobs[0]["started_at"], Value::Null);
        assert_eq!(jobs[0]["completed_at"], Value::Null);
        assert_eq!(jobs[0]["last_error"], json!("commits: GitHubRateLimited"));
    }

    #[test]
    fn evidence_tasks_are_idempotent_checkpointed_and_completed() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let task_id = db
            .enqueue_evidence_task(job_id, "github_history", "page:1", 20)
            .unwrap();
        let duplicate = db
            .enqueue_evidence_task(job_id, "github_history", "page:1", 30)
            .unwrap();
        assert_eq!(duplicate, task_id);

        let claimed = db
            .claim_next_evidence_task("github_history", 60)
            .unwrap()
            .unwrap();
        assert_eq!(claimed["id"], json!(task_id));
        assert_eq!(claimed["attempts"], json!(1));
        assert!(db
            .claim_next_evidence_task("github_history", 60)
            .unwrap()
            .is_none());

        db.checkpoint_evidence_task(
            task_id,
            1,
            Some("page:2"),
            &json!({"seen_shas": ["abc"]}),
            60,
        )
        .unwrap();
        db.complete_evidence_task(task_id, 1, &json!({"count": 100}))
            .unwrap();
        assert!(db
            .claim_next_evidence_task("github_history", 60)
            .unwrap()
            .is_none());
    }

    #[test]
    fn failed_scan_jobs_create_retryable_failure_alerts() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();

        db.complete_scan_job(job_id, false, Some("GitHubRateLimited"))
            .unwrap();

        let alerts = db.failure_alerts(Some("open"), 10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["source_kind"], json!("scan_job"));
        assert_eq!(alerts[0]["source_id"], json!(job_id));
        assert_eq!(alerts[0]["repo"], json!("owner/repo"));

        let retry = db
            .retry_failure_alert(alerts[0]["id"].as_i64().unwrap(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(retry["status"], json!("queued"));

        let jobs = db.scan_jobs_recent(1);
        assert_eq!(jobs[0]["status"], json!("queued"));
        assert_eq!(db.failure_alerts(Some("open"), 10).len(), 0);
        assert_eq!(db.failure_alerts(Some("resolved"), 10).len(), 1);
    }

    #[test]
    fn newer_success_resolves_older_scan_failure_for_same_repo() {
        let db = Database::open_memory().unwrap();
        let failed_job = db.create_scan_job("owner/repo", 7).unwrap();
        db.complete_scan_job(failed_job, false, Some("synthetic failure"))
            .unwrap();
        assert_eq!(db.failure_alerts(Some("open"), 10).len(), 1);

        let successful_job = db.enqueue_rescan("OWNER/REPO", 100).unwrap();
        db.complete_scan_job(successful_job, true, None).unwrap();

        assert!(db.failure_alerts(Some("open"), 10).is_empty());
        assert_eq!(db.failure_alerts(Some("resolved"), 10).len(), 1);
    }

    #[test]
    fn failure_alert_notifications_are_marked_after_delivery() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        db.complete_scan_job(job_id, false, Some("synthetic failure"))
            .unwrap();

        let pending = db.pending_failure_notifications(10);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["repo"], json!("owner/repo"));

        db.mark_failure_notification(pending[0]["id"].as_i64().unwrap(), "sent", None)
            .unwrap();
        assert!(db.pending_failure_notifications(10).is_empty());
        let alerts = db.failure_alerts(Some("open"), 10);
        assert_eq!(alerts[0]["notification_status"], json!("sent"));
    }

    #[test]
    fn failed_failure_notifications_are_retried() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        db.complete_scan_job(job_id, false, Some("synthetic failure"))
            .unwrap();

        let pending = db.pending_failure_notifications(10);
        let id = pending[0]["id"].as_i64().unwrap();
        db.mark_failure_notification(id, "failed", Some("webhook status 400"))
            .unwrap();

        let retried = db.pending_failure_notifications(10);
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0]["id"], json!(id));
        assert_eq!(retried[0]["error"], json!("synthetic failure"));
    }

    #[test]
    fn failed_scan_job_backfill_creates_pending_alerts_once() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        db.complete_scan_job(job_id, false, Some("repo_meta: GitHubTimeout"))
            .unwrap();
        db.acknowledge_failure_alert(
            db.failure_alerts(Some("open"), 10)[0]["id"]
                .as_i64()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(db.backfill_failed_scan_job_alerts().unwrap(), 0);

        let legacy_job = db.create_scan_job("legacy/repo", 7).unwrap();
        db.complete_scan_job(legacy_job, false, Some("advisories: GitHubTimeout"))
            .unwrap();
        db.acknowledge_failure_alert(
            db.failure_alerts(Some("open"), 10)[0]["id"]
                .as_i64()
                .unwrap(),
        )
        .unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM failure_alerts WHERE source_kind='scan_job' AND source_id=?1",
                params![legacy_job],
            )
            .unwrap();
        }

        assert_eq!(db.backfill_failed_scan_job_alerts().unwrap(), 1);
        assert_eq!(db.backfill_failed_scan_job_alerts().unwrap(), 0);
        let pending = db.pending_failure_notifications(10);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["source_id"], json!(legacy_job));
        assert_eq!(pending[0]["error"], json!("advisories: GitHubTimeout"));
    }

    #[test]
    fn exhausted_evidence_tasks_create_failure_alerts_and_retry() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let task_id = db
            .enqueue_evidence_task(job_id, "github_history_page", "1", 20)
            .unwrap();

        for attempt in 0..5 {
            let task = db
                .claim_next_evidence_task("github_history_page", 1)
                .unwrap()
                .unwrap();
            assert_eq!(task["id"], json!(task_id));
            let generation = task["attempts"].as_i64().unwrap();
            db.retry_evidence_task(task_id, generation, &format!("attempt {attempt} failed"), 0)
                .unwrap();
        }

        let alerts = db.failure_alerts(Some("open"), 10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["source_kind"], json!("evidence_task"));
        assert_eq!(alerts[0]["attempts"], json!(5));
        assert_eq!(alerts[0]["max_attempts"], json!(5));

        db.retry_failure_alert(alerts[0]["id"].as_i64().unwrap(), 100)
            .unwrap();
        let retried = db
            .claim_next_evidence_task("github_history_page", 60)
            .unwrap()
            .unwrap();
        assert_eq!(retried["attempts"], json!(1));
        db.complete_evidence_task(task_id, 1, &json!({"count": 0}))
            .unwrap();
        assert_eq!(db.failure_alerts(Some("open"), 10).len(), 0);
    }

    #[test]
    fn transient_failures_are_requeued_but_permanent_failures_remain_open() {
        let db = Database::open_memory().unwrap();
        let transient_job = db.create_scan_job("owner/transient", 7).unwrap();
        db.complete_scan_job(transient_job, false, Some("repo_meta: GitHubTimeout"))
            .unwrap();
        let permanent_job = db.create_scan_job("owner/missing", 7).unwrap();
        db.complete_scan_job(permanent_job, false, Some("repo_meta: GitHubRepoNotFound"))
            .unwrap();

        let evidence_job = db.create_scan_job("owner/history", 7).unwrap();
        let task_id = db
            .enqueue_evidence_task(evidence_job, "github_history_page", "1", 20)
            .unwrap();
        for _ in 0..5 {
            let task = db
                .claim_next_evidence_task("github_history_page", 1)
                .unwrap()
                .unwrap();
            db.retry_evidence_task(
                task_id,
                task["attempts"].as_i64().unwrap(),
                "GitHubTimeout",
                0,
            )
            .unwrap();
        }

        assert_eq!(db.recover_transient_failures(100).unwrap(), (1, 1));
        let jobs = db.scan_jobs_recent(10);
        assert_eq!(
            jobs.iter()
                .find(|job| job["id"] == json!(transient_job))
                .unwrap()["status"],
            json!("queued")
        );
        assert_eq!(
            jobs.iter()
                .find(|job| job["id"] == json!(permanent_job))
                .unwrap()["status"],
            json!("failed")
        );
        let open = db.failure_alerts(Some("open"), 10);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["source_id"], json!(permanent_job));
        assert_eq!(
            db.queue_stats()["evidence"]["github_history_page"]["queued"],
            json!(1)
        );
    }

    #[test]
    fn evidence_retry_backoff_preserves_rate_limit_budget() {
        assert_eq!(retry_backoff_seconds("GitHubRateLimited", 60, 1), 900);
        assert_eq!(retry_backoff_seconds("GitHubTimeout", 60, 4), 240);
        assert_eq!(retry_backoff_seconds("GitHubTimeout", 60, 100), 600);
    }

    #[test]
    fn expired_evidence_lease_resumes_from_checkpoint() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let task_id = db
            .enqueue_evidence_task(job_id, "github_history", "history", 20)
            .unwrap();
        db.claim_next_evidence_task("github_history", 1)
            .unwrap()
            .unwrap();
        db.checkpoint_evidence_task(
            task_id,
            1,
            Some("page:9"),
            &json!({"commits_scanned": 800}),
            1,
        )
        .unwrap();

        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE evidence_tasks SET lease_expires_at=datetime('now', '-1 second') WHERE id=?1",
                params![task_id],
            )
            .unwrap();
        }
        let resumed = db
            .claim_next_evidence_task("github_history", 60)
            .unwrap()
            .unwrap();
        assert_eq!(resumed["cursor"], json!("page:9"));
        assert_eq!(resumed["checkpoint"]["commits_scanned"], json!(800));
        assert_eq!(resumed["attempts"], json!(2));
    }

    #[test]
    fn stale_evidence_generation_cannot_overwrite_successor() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let task_id = db
            .enqueue_evidence_task(job_id, "nvd", "project", 20)
            .unwrap();
        let first = db.claim_next_evidence_task("nvd", 60).unwrap().unwrap();
        assert_eq!(first["attempts"], json!(1));
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE evidence_tasks SET lease_expires_at=datetime('now', '-1 second') WHERE id=?1",
                params![task_id],
            )
            .unwrap();
        }
        let second = db.claim_next_evidence_task("nvd", 60).unwrap().unwrap();
        assert_eq!(second["attempts"], json!(2));
        db.complete_evidence_task(task_id, 2, &json!({"cves":["CVE-SUCCESSOR"]}))
            .unwrap();
        assert!(db
            .complete_evidence_task(task_id, 1, &json!({"cves":["CVE-STALE"]}))
            .is_err());
        let conn = db.conn.lock().unwrap();
        let result: String = conn
            .query_row(
                "SELECT result_json FROM evidence_tasks WHERE id=?1",
                params![task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(result.contains("CVE-SUCCESSOR"));
        assert!(!result.contains("CVE-STALE"));
    }

    #[test]
    fn progressive_bundle_opens_only_after_terminal_history_and_nvd() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let history = db
            .enqueue_evidence_task(job_id, "github_history_page", "1", 20)
            .unwrap();
        let nvd = db
            .enqueue_evidence_task(job_id, "nvd", "project", 10)
            .unwrap();
        let manifest = db
            .enqueue_evidence_task(job_id, "commit_detail_manifest", "candidates", 5)
            .unwrap();
        assert!(db
            .completed_progressive_evidence(job_id, 100, 100)
            .unwrap()
            .is_none());

        db.claim_next_evidence_task("github_history_page", 60)
            .unwrap()
            .unwrap();

        db.complete_evidence_task(
            history,
            1,
            &json!({"page": 1, "count": 2, "commits": [{"sha": "abc"}]}),
        )
        .unwrap();
        assert!(db
            .completed_progressive_evidence(job_id, 100, 100)
            .unwrap()
            .is_none());
        db.claim_next_evidence_task("nvd", 60).unwrap().unwrap();
        db.complete_evidence_task(nvd, 1, &json!({"cves": [{"cve_id": "CVE-2026-1"}]}))
            .unwrap();
        assert!(db
            .completed_progressive_evidence(job_id, 100, 100)
            .unwrap()
            .is_none());
        db.claim_next_evidence_task("commit_detail_manifest", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(manifest, 1, &json!({"candidate_count": 0}))
            .unwrap();

        let bundle = db
            .completed_progressive_evidence(job_id, 100, 100)
            .unwrap()
            .unwrap();
        assert_eq!(bundle["history_pages"][0]["count"], json!(2));
        assert_eq!(bundle["nvd"]["cves"][0]["cve_id"], json!("CVE-2026-1"));
    }

    #[test]
    fn progressive_bundle_allows_limited_commit_details() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        let history = db
            .enqueue_evidence_task(job_id, "github_history_page", "1", 20)
            .unwrap();
        let nvd = db
            .enqueue_evidence_task(job_id, "nvd", "project", 10)
            .unwrap();
        let manifest = db
            .enqueue_evidence_task(job_id, "commit_detail_manifest", "candidates", 5)
            .unwrap();
        let first_detail = db
            .enqueue_evidence_task(job_id, "commit_detail", "abc", 15)
            .unwrap();
        db.enqueue_evidence_task(job_id, "commit_detail", "def", 15)
            .unwrap();

        db.claim_next_evidence_task("github_history_page", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(history, 1, &json!({"page": 1, "count": 2, "commits": []}))
            .unwrap();
        db.claim_next_evidence_task("nvd", 60).unwrap().unwrap();
        db.complete_evidence_task(nvd, 1, &json!({"cves": []}))
            .unwrap();
        db.claim_next_evidence_task("commit_detail_manifest", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(
            manifest,
            1,
            &json!({"candidate_count": 2, "shas": ["abc", "def"]}),
        )
        .unwrap();
        db.claim_next_evidence_task("commit_detail", 60)
            .unwrap()
            .unwrap();
        db.complete_evidence_task(
            first_detail,
            1,
            &json!({"sha": "abc", "detail": {"sha": "abc"}}),
        )
        .unwrap();

        let bundle = db
            .completed_progressive_evidence(job_id, 1, 100)
            .unwrap()
            .unwrap();
        assert_eq!(bundle["commit_details"].as_array().unwrap().len(), 1);
        assert_eq!(
            db.discard_unfinished_commit_detail_tasks(job_id).unwrap(),
            1
        );
    }

    #[test]
    fn pending_finalize_job_ids_returns_queued_finalize_tasks() {
        let db = Database::open_memory().unwrap();
        let job_id = db.create_scan_job("owner/repo", 7).unwrap();
        db.enqueue_evidence_task(job_id, "finalize", "report", 0)
            .unwrap();

        assert_eq!(db.pending_finalize_job_ids(10).unwrap(), vec![job_id]);
    }

    #[test]
    fn source_cache_persists_immutable_payload_and_honors_expiry() {
        let db = Database::open_memory().unwrap();
        db.put_source_cache(
            "github_commit_detail:owner/repo:abc",
            "github_commit_detail",
            &json!({"sha": "abc", "files": []}),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            db.get_source_cache("github_commit_detail:owner/repo:abc")
                .unwrap()
                .unwrap()["sha"],
            json!("abc")
        );

        db.put_source_cache(
            "temporary",
            "test",
            &json!({"value": 1}),
            Some("etag-1"),
            None,
            Some(60),
        )
        .unwrap();
        let entry = db.get_source_cache_entry("temporary").unwrap().unwrap();
        assert_eq!(entry["etag"], json!("etag-1"));
        assert_eq!(entry["fresh"], json!(true));
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE source_cache SET expires_at=datetime('now', '-1 second') WHERE cache_key='temporary'",
                [],
            )
            .unwrap();
        }
        assert!(db.get_source_cache("temporary").unwrap().is_none());
        let stale = db.get_source_cache_entry("temporary").unwrap().unwrap();
        assert_eq!(stale["fresh"], json!(false));
        assert_eq!(stale["payload"]["value"], json!(1));
    }

    #[test]
    fn running_scan_jobs_resume_after_storage_reopen() {
        let path = std::env::temp_dir().join(format!(
            "ai-supply-chain-trust-resume-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let db = Database::open(&path).unwrap();
            let id = db.create_scan_job("owner/repo", 7).unwrap();
            assert_eq!(
                db.claim_next_scan_job().unwrap(),
                Some((id, "owner/repo".to_string()))
            );
            assert_eq!(db.scan_jobs_recent(1)[0]["status"], json!("running"));
        }

        let db = Database::open(&path).unwrap();
        let jobs = db.scan_jobs_recent(1);
        assert_eq!(jobs[0]["status"], json!("queued"));
        assert_eq!(jobs[0]["started_at"], Value::Null);
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((jobs[0]["id"].as_i64().unwrap(), "owner/repo".to_string()))
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enqueue_rescan_reuses_existing_pending_job() {
        let db = Database::open_memory().unwrap();
        let id = db.enqueue_rescan("owner/repo", 7).unwrap();
        let duplicate = db.create_scan_job("owner/repo", 3).unwrap();
        let retry_id = db.enqueue_rescan("owner/repo", 20).unwrap();

        assert_eq!(retry_id, id);
        let jobs = db.scan_jobs_recent(10);
        let matching: Vec<_> = jobs
            .iter()
            .filter(|job| job["repo"] == json!("owner/repo") && job["status"] != json!("deduped"))
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0]["priority"], json!(20));
        assert_eq!(matching[0]["status"], json!("queued"));
        assert!(jobs.iter().any(|job| {
            job["id"] == json!(duplicate)
                && job["status"] == json!("deduped")
                && job["last_error"] == json!(format!("deduped by scan job {id}"))
        }));
    }

    #[test]
    fn enqueue_rescan_creates_new_job_after_failure() {
        let db = Database::open_memory().unwrap();
        let id = db.enqueue_rescan("owner/repo", 7).unwrap();
        db.complete_scan_job(id, false, Some("failed")).unwrap();

        let retry_id = db.enqueue_rescan("owner/repo", 20).unwrap();

        assert_ne!(retry_id, id);
        let jobs = db.scan_jobs_recent(10);
        let matching: Vec<_> = jobs
            .iter()
            .filter(|job| job["repo"] == json!("owner/repo"))
            .collect();
        assert_eq!(matching.len(), 2);
        assert!(matching.iter().any(|job| job["status"] == json!("failed")));
        assert!(matching.iter().any(|job| job["status"] == json!("queued")));
    }

    #[test]
    fn foreground_scan_jobs_are_claimed_before_background_research() {
        let db = Database::open_memory().unwrap();
        let background = db
            .create_scan_job_with_lane("owner/background", 100, "background")
            .unwrap();
        let foreground = db
            .create_scan_job_with_lane("owner/foreground", 10, "foreground")
            .unwrap();

        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((foreground, "owner/foreground".to_string()))
        );
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((background, "owner/background".to_string()))
        );
    }

    #[test]
    fn lane_claim_reserves_foreground_capacity() {
        let db = Database::open_memory().unwrap();
        let background = db
            .create_scan_job_with_lane("owner/background", 100, "background")
            .unwrap();
        let foreground = db
            .create_scan_job_with_lane("owner/foreground", 10, "foreground")
            .unwrap();

        assert_eq!(
            db.claim_next_scan_job_for_lane("foreground").unwrap(),
            Some((foreground, "owner/foreground".to_string()))
        );
        assert_eq!(
            db.claim_next_scan_job().unwrap(),
            Some((background, "owner/background".to_string()))
        );
    }

    #[test]
    fn scan_job_dedupe_keeps_foreground_and_background_lanes_separate() {
        let db = Database::open_memory().unwrap();
        let foreground = db
            .enqueue_rescan_with_lane("owner/repo", 10, "foreground")
            .unwrap();
        let background = db
            .enqueue_rescan_with_lane("owner/repo", 90, "background")
            .unwrap();

        assert_ne!(foreground, background);
        let stats = db.queue_stats();
        assert_eq!(stats["lanes"]["foreground"]["queued"], json!(1));
        assert_eq!(stats["lanes"]["background"]["queued"], json!(1));

        let jobs = db.scan_jobs_recent(10);
        assert!(jobs
            .iter()
            .any(|job| { job["id"] == json!(foreground) && job["lane"] == json!("foreground") }));
        assert!(jobs
            .iter()
            .any(|job| { job["id"] == json!(background) && job["lane"] == json!("background") }));
    }

    #[test]
    fn queue_stats_dedupes_backlog_and_exposes_pause_until() {
        let db = Database::open_memory().unwrap();
        let keep = db.create_scan_job("owner/repo", 20).unwrap();
        let duplicate = db.create_scan_job("owner/repo", 7).unwrap();
        db.create_scan_job("other/repo", 5).unwrap();
        db.pause_queue(60).unwrap();

        let stats = db.queue_stats();
        let jobs = db.scan_jobs_recent(10);

        assert_eq!(stats["pending"], json!(2));
        assert_eq!(stats["queued"], json!(2));
        assert_eq!(stats["paused"], json!(true));
        assert!(stats["paused_until"].as_str().unwrap_or("").ends_with('Z'));
        assert!(jobs.iter().any(|job| {
            job["id"] == json!(duplicate)
                && job["status"] == json!("deduped")
                && job["last_error"] == json!(format!("deduped by scan job {keep}"))
        }));
    }

    #[test]
    fn get_report_skips_critical_partial_security_intel_rows() {
        let db = Database::open_memory().unwrap();
        db.insert_report(&json!({
            "repo": "wolfssl/wolfssl", "evaluated_at": "2026-07-09", "trust_score": 70.0,
            "grade": "B", "verdict": "Previous", "action": "Use", "next_review_date": "2026-10-07",
            "coverage": "7/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {
                "security_intel": {"fix_commits": [{"sha": "abc"}], "errors": []}
            },
            "scoring_version": "v1"
        }))
        .unwrap();
        db.insert_report(&json!({
            "repo": "wolfssl/wolfssl", "evaluated_at": "2026-07-10", "trust_score": 68.0,
            "grade": "C", "verdict": "Partial", "action": "Hold", "next_review_date": "2026-10-07",
            "coverage": "4/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {
                "security_intel": {
                    "fix_commits": [],
                    "errors": ["commits: GitHubRateLimited", "repo_meta: GitHubRateLimited"]
                }
            },
            "scoring_version": "v1"
        }))
        .unwrap();

        let report = db.get_report("wolfssl/wolfssl").unwrap();

        assert_eq!(report["verdict"], json!("Previous"));
    }

    #[test]
    fn get_report_matches_repo_case_insensitively_after_exact_miss() {
        let db = Database::open_memory().unwrap();
        db.insert_report(&json!({
            "repo": "r1z4x/owaspattacksimulator",
            "evaluated_at": "2026-07-11",
            "trust_score": 35.0,
            "grade": "F",
            "verdict": "Manual review required",
            "action": "Do not approve without security owner",
            "next_review_date": "2026-10-09",
            "coverage": "3/7",
            "critical_flags": [],
            "pillar_scores": {},
            "scanner_runs": [{"tool": "github-metadata-rust", "status": "ok"}],
            "observed_metrics": {
                "security_context_version": "2026-07-14-history-precision-v2",
                "verification_status": "ok",
                "head_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
            },
            "scoring_version": "v1"
        }))
        .unwrap();

        let report = db.get_report("r1z4x/OWASPAttackSimulator").unwrap();

        assert_eq!(report["repo"], json!("r1z4x/owaspattacksimulator"));
    }

    #[test]
    fn listing_views_skip_critical_partial_security_intel_rows() {
        let db = Database::open_memory().unwrap();
        db.insert_report(&json!({
            "repo": "wolfssl/wolfssl", "evaluated_at": "2026-07-09", "trust_score": 70.0,
            "grade": "B", "verdict": "Previous", "action": "Use", "next_review_date": "2026-10-07",
            "coverage": "7/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {
                "security_intel": {"fix_commits": [{"sha": "abc"}], "cves": ["CVE-2026-0001"], "errors": []}
            },
            "scoring_version": "v1"
        }))
        .unwrap();
        db.insert_report(&json!({
            "repo": "wolfssl/wolfssl", "evaluated_at": "2026-07-10", "trust_score": 43.0,
            "grade": "D", "verdict": "Partial", "action": "Hold", "next_review_date": "2026-10-07",
            "coverage": "4/7", "critical_flags": [], "pillar_scores": {},
            "scanner_runs": [], "observed_metrics": {
                "security_intel": {
                    "fix_commits": [],
                    "cves": ["CVE-2026-0001", "CVE-2026-0002"],
                    "errors": ["commits: GitHubRateLimited", "repo_meta: GitHubRateLimited"]
                }
            },
            "scoring_version": "v1"
        }))
        .unwrap();

        let recent = db.recent_scans(1);
        let latest = db.latest_reports(1).unwrap();

        assert_eq!(recent[0]["verdict"], json!("Previous"));
        assert_eq!(recent[0]["fixes"], json!(1));
        assert_eq!(latest[0]["verdict"], json!("Previous"));
    }

    #[test]
    fn trust_events_are_ordered_resumable_and_structured() {
        let db = Database::open_memory().unwrap();
        assert_eq!(db.latest_trust_event_id(), 0);

        let first = db
            .publish_trust_event("owner/repo", "scan_fast_ready", &json!({"score": 72}))
            .unwrap();
        let second = db
            .publish_trust_event("owner/repo", "scan_complete", &json!({"fixes": 4}))
            .unwrap();

        assert_eq!(db.latest_trust_event_id(), second);
        let resumed = db.trust_events_after(first, 10);
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0]["id"], json!(second));
        assert_eq!(resumed[0]["event_type"], json!("scan_complete"));
        assert_eq!(resumed[0]["payload"]["fixes"], json!(4));
    }

    #[test]
    fn regression_contract_lifecycle_is_versioned_and_audited() {
        let db = Database::open_memory().unwrap();
        let contract = json!({
            "id":"rc_path_parser", "schema_version":"1.0",
            "lifecycle":{"state":"candidate"}, "title":"Preserve path guard"
        });
        db.upsert_regression_contracts("example/repo", &[contract])
            .unwrap();

        let updated = db
            .transition_regression_contract(
                "example/repo",
                "rc_path_parser",
                1,
                "active",
                "security-owner",
                "evidence_reviewed",
                "contract",
                Some("Accepted after review"),
                None,
            )
            .unwrap();

        assert_eq!(updated["version"], json!(2));
        assert_eq!(updated["lifecycle"]["state"], json!("active"));
        let events = db
            .regression_contract_events("example/repo", "rc_path_parser")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["actor"], json!("security-owner"));
        assert!(db
            .transition_regression_contract(
                "example/repo",
                "rc_path_parser",
                1,
                "retired",
                "owner",
                "obsolete",
                "contract",
                None,
                None
            )
            .is_err());

        db.transition_regression_contract(
            "example/repo",
            "rc_path_parser",
            2,
            "suppressed",
            "security-owner",
            "temporary_exception",
            "contract",
            None,
            Some("2000-01-01T00:00:00Z"),
        )
        .unwrap();
        let current = db
            .regression_contract("example/repo", "rc_path_parser")
            .unwrap();
        assert_eq!(current["lifecycle"]["state"], json!("active"));
        assert_eq!(current["version"], json!(4));
    }

    #[test]
    fn regression_assessments_are_immutable_and_idempotent() {
        let db = Database::open_memory().unwrap();
        db.upsert_regression_contracts(
            "example/repo",
            &[json!({"id":"rc_path_parser", "lifecycle":{"state":"active"}})],
        )
        .unwrap();
        let assessment = json!({"state":"needs_review", "disposition":"review"});

        assert!(db
            .insert_regression_assessment(
                "example/repo",
                "rc_path_parser",
                "base",
                "head",
                &assessment
            )
            .unwrap());
        assert!(!db
            .insert_regression_assessment(
                "example/repo",
                "rc_path_parser",
                "base",
                "head",
                &assessment
            )
            .unwrap());
        assert_eq!(
            db.regression_assessments("example/repo", "head")
                .unwrap()
                .len(),
            1
        );
    }
}
