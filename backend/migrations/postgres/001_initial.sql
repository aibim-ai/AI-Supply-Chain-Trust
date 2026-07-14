BEGIN;

CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
  id BIGSERIAL PRIMARY KEY,
  legacy_sqlite_id BIGINT UNIQUE,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  repo TEXT NOT NULL,
  evaluated_at DATE NOT NULL,
  trust_score NUMERIC(5,2) NOT NULL,
  grade TEXT NOT NULL,
  verdict TEXT NOT NULL,
  action TEXT NOT NULL,
  next_review_date DATE NOT NULL,
  openssf_raw NUMERIC(5,2),
  scoring_version TEXT NOT NULL DEFAULT 'unknown',
  report_json JSONB NOT NULL,
  metrics_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evaluation_pillar_scores (
  evaluation_id BIGINT NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
  pillar TEXT NOT NULL,
  score NUMERIC(5,2) NOT NULL,
  max_score NUMERIC(5,2) NOT NULL,
  normalized NUMERIC(5,2),
  applicable BOOLEAN NOT NULL DEFAULT true,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  concerns JSONB NOT NULL DEFAULT '[]'::jsonb,
  unavailable JSONB NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (evaluation_id, pillar)
);

CREATE TABLE IF NOT EXISTS evaluation_critical_flags (
  evaluation_id BIGINT NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  severity TEXT,
  message TEXT,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  location TEXT,
  automatic_fail BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (evaluation_id, code)
);

CREATE TABLE IF NOT EXISTS daemon_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_queue (
  id BIGSERIAL PRIMARY KEY,
  legacy_sqlite_id BIGINT UNIQUE,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  repo TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  source TEXT NOT NULL DEFAULT 'daemon',
  scheduled_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  result_json JSONB,
  error TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 3,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  repo TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'api',
  lane TEXT NOT NULL DEFAULT 'foreground',
  priority INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'queued',
  legacy_queue_id BIGINT,
  correlation_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scanner_tasks (
  id BIGSERIAL PRIMARY KEY,
  job_id BIGINT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  scanner TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 3,
  correlation_id TEXT,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_tasks (
  id BIGSERIAL PRIMARY KEY,
  job_id BIGINT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  partition_key TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 0,
  cursor TEXT,
  checkpoint_json JSONB,
  result_json JSONB,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_expires_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE(job_id, source, partition_key)
);

CREATE INDEX IF NOT EXISTS idx_evidence_tasks_ready
  ON evidence_tasks(status, next_attempt_at, priority DESC, id);
CREATE INDEX IF NOT EXISTS idx_evidence_tasks_job
  ON evidence_tasks(job_id, source);

CREATE TABLE IF NOT EXISTS source_cache (
  cache_key TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  etag TEXT,
  last_modified TEXT,
  payload_json JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_source_cache_source_expiry
  ON source_cache(source, expires_at);

CREATE TABLE IF NOT EXISTS scanner_results (
  id BIGSERIAL PRIMARY KEY,
  task_id BIGINT NOT NULL REFERENCES scanner_tasks(id) ON DELETE CASCADE,
  output_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ok',
  payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS discovery_source_state (
  source TEXT PRIMARY KEY,
  remaining INTEGER,
  reset_at TIMESTAMPTZ,
  last_status TEXT NOT NULL DEFAULT 'ok',
  failure_count INTEGER NOT NULL DEFAULT 0,
  circuit_state TEXT NOT NULL DEFAULT 'closed',
  opened_until TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS discovery_cache (
  source TEXT NOT NULL,
  query_key TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  etag TEXT,
  last_modified TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (source, query_key)
);

CREATE TABLE IF NOT EXISTS trust_events (
  event_id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  repo TEXT,
  event_type TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  audit_id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  event_type TEXT NOT NULL,
  actor TEXT,
  correlation_id TEXT,
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS regression_contracts (
  repo TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  lifecycle_state TEXT NOT NULL DEFAULT 'candidate',
  contract_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (repo, contract_id)
);

CREATE TABLE IF NOT EXISTS regression_contract_events (
  id BIGSERIAL PRIMARY KEY,
  repo TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'contract',
  comment TEXT,
  expires_at TIMESTAMPTZ,
  version BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (repo, contract_id) REFERENCES regression_contracts(repo, contract_id)
);

CREATE TABLE IF NOT EXISTS regression_assessments (
  id BIGSERIAL PRIMARY KEY,
  repo TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  base_sha TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  assessment_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(repo, contract_id, base_sha, head_sha),
  FOREIGN KEY (repo, contract_id) REFERENCES regression_contracts(repo, contract_id)
);

CREATE TABLE IF NOT EXISTS regression_check_runs (
  repo TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  check_run_id BIGINT NOT NULL,
  conclusion TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (repo, head_sha)
);

CREATE INDEX IF NOT EXISTS idx_evaluations_repo_id ON evaluations(repo, id DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_tenant_repo ON evaluations(tenant_id, repo, id DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_scoring_score ON evaluations(scoring_version, trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_next_review ON evaluations(next_review_date);
CREATE INDEX IF NOT EXISTS idx_evaluation_pillar_scores_pillar_score ON evaluation_pillar_scores(pillar, score);
CREATE INDEX IF NOT EXISTS idx_evaluation_critical_flags_code ON evaluation_critical_flags(code);
CREATE INDEX IF NOT EXISTS idx_scan_queue_status_priority ON scan_queue(status, priority DESC, id);
CREATE INDEX IF NOT EXISTS idx_scan_queue_repo_status ON scan_queue(repo, status);
CREATE INDEX IF NOT EXISTS idx_scan_queue_tenant_status ON scan_queue(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status, priority DESC, id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_lane_status_priority ON scan_jobs(lane, status, priority DESC, id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_legacy_queue ON scan_jobs(legacy_queue_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_correlation ON scan_jobs(correlation_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_status ON scan_jobs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scanner_tasks_job ON scanner_tasks(job_id, scanner);
CREATE INDEX IF NOT EXISTS idx_scanner_tasks_status ON scanner_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scanner_tasks_correlation ON scanner_tasks(correlation_id);
CREATE INDEX IF NOT EXISTS idx_scanner_tasks_tenant_status ON scanner_tasks(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_discovery_cache_expires ON discovery_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_trust_events_created ON trust_events(created_at);
CREATE INDEX IF NOT EXISTS idx_trust_events_repo ON trust_events(repo);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created ON audit_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_regression_contracts_repo_state ON regression_contracts(repo, lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_regression_events_contract ON regression_contract_events(repo, contract_id, id);
CREATE INDEX IF NOT EXISTS idx_regression_assessments_head ON regression_assessments(repo, head_sha);

COMMIT;
