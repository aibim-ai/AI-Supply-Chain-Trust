import { Link, useSearchParams } from "react-router-dom";
import { ErrorState, PageLoader } from "../components/ui";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";

export default function ResultPage() {
  const [params] = useSearchParams(),
    repository = params.get("repo");
  const query = useAsync(async () => {
    if (!repository) throw new Error("A repository is required.");
    const [report, history, intelligence] = await Promise.all([
      trustApi.result(repository),
      trustApi.history(repository),
      trustApi.intelligence(repository),
    ]);
    return { report, history, intelligence };
  }, [repository]);
  if (query.status === "error")
    return (
      <section className="shell py-16">
        <ErrorState error={query.error} retry={query.retry} />
      </section>
    );
  if (query.status === "loading") return <PageLoader />;

  const { report, history, intelligence } = query.data;
  const scap = report.observed_metrics?.scap || {};
  const historyRows = normalizeHistory(history);
  const intelligenceRows = normalizeIntelligence(intelligence);
  return (
    <section className="page-stack">
      <header className="result-header decision-header">
        <div>
          <span className="eyebrow">Trust verdict</span>
          <h1>{report.repo}</h1>
          <p>
            {report.action} · Evaluated {report.evaluated_at} · Next review{" "}
            {report.next_review_date}
          </p>
        </div>
        <div className="result-score">
          <ScoreBadge grade={report.grade} score={report.trust_score} />
          <strong>{report.verdict}</strong>
        </div>
      </header>

      <div className="decision-band">
        <section className="panel">
          <span className="eyebrow">Decision</span>
          <h2>{report.action}</h2>
          <p>
            {report.context || "Evidence-backed repository trust decision."}
          </p>
        </section>
        <section className="panel">
          <span className="eyebrow">Coverage</span>
          <CoverageSummary report={report} />
        </section>
        <section className="panel">
          <span className="eyebrow">Actions</span>
          <div className="action-list">
            <Link className="button button-primary" to={`/r/${report.repo}`}>
              Security context
            </Link>
            <a
              className="button button-secondary"
              href={`https://github.com/${report.repo}`}
              rel="noopener"
            >
              Open repository
            </a>
            <a
              className="button button-secondary"
              href={`/api/v1/result?repo=${encodeURIComponent(report.repo)}`}
            >
              Export JSON
            </a>
          </div>
        </section>
      </div>

      <div className="result-layout">
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Findings</span>
              <h2>Critical flags</h2>
            </div>
          </div>
          <FlagsList rows={report.critical_flags || []} />
        </section>
        <aside className="panel">
          <span className="eyebrow">SCAP</span>
          <h2>{scap.risk_level || "unknown"}</h2>
          <p>{scap.reasoning_summary || "No SCAP summary available."}</p>
          <div className="risk-strip">
            {(scap.attack_patterns_detected || []).length ? (
              scap.attack_patterns_detected.map((item) => (
                <span key={item}>{item}</span>
              ))
            ) : (
              <span>No attack pattern</span>
            )}
          </div>
        </aside>
      </div>

      <div className="result-layout">
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Evidence trail</span>
              <h2>Pillar breakdown</h2>
            </div>
          </div>
          <div className="pillar-grid">
            {Object.values(report.pillar_scores || {}).map((pillar, index) => (
              <article className="pillar-card" key={pillar.name || index}>
                <div>
                  <strong>{pillar.name}</strong>
                  <span>{Math.round(pillar.normalized ?? 0)}%</span>
                </div>
                <div className="meter">
                  <span
                    style={{
                      width: `${Math.max(0, Math.min(100, Math.round(pillar.normalized ?? 0)))}%`,
                    }}
                  />
                </div>
                <p>
                  {pillar.concerns?.[0] ||
                    pillar.evidence?.[0] ||
                    pillar.unavailable?.[0] ||
                    "Evaluated."}
                </p>
              </article>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Velocity</span>
              <h2>Snapshot history</h2>
            </div>
          </div>
          <TrendChart rows={historyRows} />
        </section>
      </div>

      <div className="result-layout">
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Threat intel</span>
              <h2>{`${intelligenceRows.length} hits`}</h2>
            </div>
          </div>
          <FlagsList
            rows={intelligenceRows}
            empty="No threat-intelligence hits in the latest report."
          />
        </section>
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Scanners</span>
              <h2>Coverage</h2>
            </div>
          </div>
          <ScannerTable rows={report.scanner_runs || []} />
        </section>
      </div>
    </section>
  );
}

function normalizeHistory(payload) {
  if (Array.isArray(payload)) return payload;
  return Array.isArray(payload?.snapshots) ? payload.snapshots : [];
}

function normalizeIntelligence(payload) {
  if (Array.isArray(payload?.hits)) {
    return payload.hits.map(toIntelligenceRow);
  }
  const intel = payload?.hits;
  if (!intel || typeof intel !== "object") return [];
  const rows = [];
  for (const id of Array.isArray(intel.cves) ? intel.cves : []) {
    rows.push({ code: String(id), severity: "unknown", message: "CVE" });
  }
  for (const entry of Array.isArray(intel.nvd_cves) ? intel.nvd_cves : []) {
    rows.push({
      code: entry.cve_id || entry.id || "CVE",
      severity: entry.severity || "unknown",
      message: entry.description || "NVD",
      evidence: entry.source_url,
    });
  }
  for (const entry of Array.isArray(intel.advisories) ? intel.advisories : []) {
    rows.push({
      code: entry.cve_id || entry.ghsa_id || "Advisory",
      severity: entry.severity || "unknown",
      message: entry.summary || "GitHub advisory",
      evidence: entry.html_url,
    });
  }
  for (const entry of Array.isArray(intel.osv_vulns) ? intel.osv_vulns : []) {
    rows.push({
      code: entry.id || entry.aliases?.[0] || "OSV",
      severity: entry.severity || "unknown",
      message: entry.summary || "OSV",
      evidence: entry.references?.[0]?.url,
    });
  }
  const seen = new Set();
  return rows.filter((row) => {
    const key = String(row.code);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function toIntelligenceRow(hit) {
  return {
    code: hit.code || hit.cve_id || hit.id || "Intel",
    severity: hit.severity || "unknown",
    message: hit.message || hit.source || hit.summary || "Threat intelligence",
    evidence: hit.evidence || hit.source_url,
  };
}

function ScoreBadge({ grade, score }) {
  const value = Math.round(Number(score || 0));
  return (
    <span className={`score-badge ${toneClass(grade)}`}>
      <strong>{value}</strong>
      <em>{grade || "-"}</em>
    </span>
  );
}

function CoverageSummary({ report }) {
  const rows = report.scanner_runs || [];
  const ok = rows.filter((row) => row.status === "ok").length;
  return (
    <div className="coverage-checklist">
      <article>
        <span>Coverage</span>
        <strong>{report.coverage || `${ok}/${rows.length || 0}`}</strong>
      </article>
      <article>
        <span>Critical flags</span>
        <strong>{(report.critical_flags || []).length}</strong>
      </article>
      <article>
        <span>Scanner runs</span>
        <strong>{rows.length}</strong>
      </article>
    </div>
  );
}

function FlagsList({ rows, empty = "No critical flags in this report." }) {
  if (!rows.length) return <div className="empty-state">{empty}</div>;
  return (
    <div className="finding-list">
      {rows.map((flag, index) => (
        <article key={flag.code || index}>
          <span className={`pill ${toneClass(flag.severity || "F")}`}>
            {flag.severity || "critical"}
          </span>
          <strong>{flag.code}</strong>
          <p>
            {flag.message}
            {flag.evidence ? ` · ${flag.evidence}` : ""}
          </p>
        </article>
      ))}
    </div>
  );
}

function ScannerTable({ rows }) {
  if (!rows.length)
    return <div className="empty-state">No scanner runs recorded.</div>;
  return (
    <div className="table-shell">
      <table>
        <caption className="sr-only">Scanner execution results</caption>
        <thead>
          <tr>
            <th scope="col">Tool</th>
            <th scope="col">Status</th>
            <th scope="col">Detail</th>
            <th scope="col">Impact</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={row.tool || index}>
              <td data-label="Tool">
                <strong>{row.tool}</strong>
              </td>
              <td data-label="Status">
                <span className={`status-pill ${statusClass(row.status)}`}>
                  {row.status}
                </span>
              </td>
              <td data-label="Detail">{row.detail || row.reason || ""}</td>
              <td data-label="Impact">{row.impact || ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TrendChart({ rows }) {
  if (!rows.length) return <div className="empty-state">No history yet.</div>;
  return (
    <div className="trend-chart">
      {rows.map((row, index) => {
        const value = Math.round(row.trust_score ?? 0);
        return (
          <div style={{ "--value": value }} key={row.evaluated_at || index}>
            <span />
            <strong>{value}</strong>
            <small>{row.evaluated_at}</small>
          </div>
        );
      })}
    </div>
  );
}

function toneClass(value) {
  const text = String(value || "").toUpperCase();
  if (
    text === "OK" ||
    text.startsWith("A") ||
    text.startsWith("B") ||
    text === "LOW"
  )
    return "score-success";
  if (text.startsWith("C") || text === "MEDIUM") return "score-warning";
  if (text.startsWith("D") || text === "HIGH") return "score-high-risk";
  return "score-danger";
}

function statusClass(status) {
  if (status === "ok") return "status-ok";
  if (status === "missing") return "status-missing";
  return "status-skipped";
}
