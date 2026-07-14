import { Link } from "react-router-dom";

export function RepositoryGrid({ rows }) {
  if (!rows.length)
    return <div className="empty-state">No public contexts yet.</div>;
  return (
    <div className="scan-list scan-list-compact">
      {rows.map((row) => (
        <Link
          to={`/r/${row.repo}`}
          key={row.repo}
          className="scan-row context-row"
        >
          <span className={`grade-dot ${toneClass(row.grade || "A")}`} />
          <div className="repo-cell">
            <strong>{row.repo}</strong>
            <span>{contextSubtext(row)}</span>
          </div>
          <ContextMetrics row={row} />
          <RowMeta
            top=""
            bottom={formatListDate(row.evaluated_at || row.updated_at)}
          />
        </Link>
      ))}
    </div>
  );
}

export function HomeActivityList({ contexts, jobs }) {
  const activeJobs = jobs
      .filter((job) => job.status === "queued" || job.status === "running")
      .slice(0, 3),
    activeRepos = new Set(activeJobs.map((job) => job.repo)),
    contextRepos = new Set(contexts.map((row) => row.repo)),
    jobRows = uniqueRepoJobs(jobs)
      .filter((job) => job.status !== "queued" && job.status !== "running")
      .filter(
        (job) => !activeRepos.has(job.repo) && !contextRepos.has(job.repo),
      ),
    rows = contexts.filter((row) => !activeRepos.has(row.repo));
  if (!activeJobs.length && !rows.length && !jobRows.length)
    return (
      <div className="empty-state">
        No public contexts or queued packages yet.
      </div>
    );
  return (
    <div className="scan-list scan-list-compact live-activity-list">
      {activeJobs.map((job, index) => (
        <JobRow job={job} key={job.id || `job-${index}`} />
      ))}
      {rows.map((row) => (
        <RepositoryRow row={row} key={row.repo} />
      ))}
      {jobRows.map((job, index) => (
        <JobRow job={job} key={job.id || `job-history-${index}`} />
      ))}
    </div>
  );
}

export function PublicContextList({ contexts }) {
  if (!contexts.length)
    return <div className="empty-state">No public contexts yet.</div>;
  return (
    <div className="scan-list scan-list-compact live-activity-list">
      {contexts.map((row) => (
        <RepositoryRow row={row} key={row.repo} />
      ))}
    </div>
  );
}

export function RepositoryList({ rows }) {
  if (!rows.length)
    return <div className="empty-state">No matching contexts.</div>;
  return (
    <div className="scan-list scan-list-compact">
      {rows.map((row) => (
        <RepositoryRow row={row} key={row.repo} detailed />
      ))}
    </div>
  );
}

export function JobList({ rows }) {
  if (!rows.length) return <div className="empty-state">No matching jobs.</div>;
  return (
    <div className="scan-list scan-list-compact job-list">
      {rows.map((job, index) => (
        <JobRow job={job} key={job.id || index} />
      ))}
    </div>
  );
}

function RepositoryRow({ row, detailed = false }) {
  return (
    <Link
      className={`scan-row ${detailed ? "scan-row-detailed" : "context-row"}`}
      to={`/r/${row.repo}`}
    >
      <span className={`grade-dot ${toneClass(row.grade || "A")}`} />
      <div className="repo-cell">
        <strong>{row.repo}</strong>
        <span>
          {detailed ? row.verdict || contextDetail(row) : contextSubtext(row)}
        </span>
      </div>
      {detailed ? (
        <>
          <TrustMeter
            grade={row.grade}
            score={row.trust_score ?? row.score ?? 0}
          />
          <RowMeta
            top={row.coverage || ""}
            bottom={row.evaluated_at || row.updated_at || ""}
          />
        </>
      ) : (
        <>
          <ContextMetrics row={row} />
          <RowMeta
            top=""
            bottom={formatListDate(row.evaluated_at || row.updated_at)}
          />
        </>
      )}
    </Link>
  );
}

function ContextMetrics({ row }) {
  const score = Math.round(Number(row.trust_score ?? row.score ?? 0)),
    summary = row.summary || {},
    fixes = summary.fixes ?? row.fixes ?? 0,
    cves = summary.cves ?? row.cves ?? 0,
    status = summary.status || row.status || "ready",
    severity = summary.top_severity || row.top_severity,
    coverage = Number(
      row.evidence_coverage ?? row.trust_decision?.evidence_coverage ?? 0,
    ),
    confidence = cleanMetric(row.confidence || row.trust_decision?.confidence),
    rowCoverage = cleanMetric(row.coverage);
  const metrics = [
    ["Score", score || "-"],
    ["Grade", row.grade || "-"],
    confidence ? ["Confidence", confidence] : null,
    coverage > 0 ? ["Evidence", `${Math.round(coverage * 100)}%`] : null,
    ["Fixes", fixes],
    ["CVEs", cves],
    ["Status", status],
    rowCoverage ? ["Coverage", rowCoverage] : null,
    severity && severity !== "none" ? ["Severity", severity] : null,
  ].filter(Boolean);
  return (
    <span className="context-metrics">
      {metrics.map(([label, value]) => (
        <span
          className={`metric-${label.toLowerCase()} ${
            value === "enriching" || value === "queued" || value === "running"
              ? "is-active"
              : ""
          }`.trim()}
          key={label}
        >
          <em>{label}</em>
          <strong>{value}</strong>
        </span>
      ))}
    </span>
  );
}

function cleanMetric(value) {
  const text = String(value ?? "").trim();
  if (!text || text === "-" || text.toLowerCase() === "unknown") return "";
  return text;
}

function JobRow({ job }) {
  return (
    <Link className="scan-row job-row" to={`/r/${job.repo}?scan=${job.status}`}>
      <span
        className={`grade-dot ${job.status === "failed" ? "score-danger" : job.status === "completed" ? "score-success" : "score-warning"}`}
      />
      <div className="repo-cell">
        <strong>{job.repo}</strong>
        <span>{jobDetail(job)}</span>
      </div>
      <span className={`pill ${jobTone(job.status)}`}>
        {jobLabel(job.status)}
      </span>
      <RowMeta top="" bottom={formatListDate(job.created_at)} />
    </Link>
  );
}

function contextDetail(row) {
  const summary = row.summary || {};
  const fixes = summary.fixes ?? row.fixes ?? 0;
  const cves = summary.cves ?? row.cves ?? 0;
  return `${fixes} fixes · ${cves} CVEs · status ${row.status || "ready"}`;
}

function contextSubtext(row) {
  return (
    row.trust_decision?.label ||
    row.verdict ||
    row.action ||
    "Public security context"
  );
}

function jobDetail(job) {
  return [
    `priority ${job.priority ?? 0}`,
    job.status === "failed"
      ? "failed"
      : job.started_at
        ? `started ${job.started_at}`
        : "waiting",
  ]
    .filter(Boolean)
    .join(" · ");
}

function toneClass(grade) {
  const value = String(grade || "").toUpperCase();
  if (value.startsWith("A") || value.startsWith("B")) return "score-success";
  if (value.startsWith("C")) return "score-warning";
  if (value.startsWith("D")) return "score-high-risk";
  return "score-danger";
}

function jobTone(status) {
  if (status === "running") return "pill-warning";
  if (status === "failed") return "pill-danger";
  if (status === "completed") return "pill-success";
  return "pill-info";
}

function jobLabel(status) {
  if (status === "completed") return "complete";
  return status;
}

function TrustMeter({ grade, score }) {
  const rounded = Math.round(Number(score || 0));
  return (
    <span className={`trust-meter ${toneClass(grade)}`}>
      <strong>{rounded}</strong>
      <span className="meter-track">
        <i style={{ width: `${Math.max(0, Math.min(100, rounded))}%` }} />
      </span>
      <em>{grade || "-"}</em>
    </span>
  );
}

function RowMeta({ top, bottom }) {
  return (
    <span className="row-meta">
      <span>{top}</span>
      <span>{bottom}</span>
    </span>
  );
}

function formatListDate(value) {
  if (!value) return "";
  const text = String(value).trim();
  const match = text.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match) return match[1];
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;
  return date.toISOString().slice(0, 10);
}

function uniqueRepoJobs(jobs) {
  const seen = new Set();
  return jobs.filter((job) => {
    if (!job.repo || seen.has(job.repo)) return false;
    seen.add(job.repo);
    return true;
  });
}
