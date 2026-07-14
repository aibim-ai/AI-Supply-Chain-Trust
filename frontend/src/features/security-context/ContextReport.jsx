import { Braces, FileText, MessageSquare } from "lucide-react";
import { useMemo, useState } from "react";
import { openFeedback } from "../../components/FeedbackWidget";

export function ContextReport({ repository, payload }) {
  const [filter, setFilter] = useState("default");
  const context = payload.context || {},
    summary = payload.summary || {};
  const trust = context.trust || payload.trust_decision || {};
  const fingerprints = context.fingerprints || [],
    cves = context.known_cves || [],
    contracts = Array.isArray(context.watchlist)
      ? context.watchlist.filter((item) => item?.schema_version && item?.title)
      : [],
    fixes = summary.fixes ?? fingerprints.length,
    cveCount = summary.cves ?? cves.length,
    coverage = Number(
      context.remediation?.coverage ?? summary.regression_coverage ?? 0,
    ),
    covered = Math.max(0, Math.min(34, Math.round((coverage / 100) * 34))),
    classCounts =
      context.vuln_class_counts ||
      context.vulnerability_classes ||
      summary.vuln_class_counts ||
      summary.vulnerability_classes ||
      {},
    componentCounts =
      context.component_counts ||
      context.components ||
      summary.component_counts ||
      summary.components ||
      {},
    topClass = topEntry(classCounts, "Security Fix"),
    topComponent = topEntry(componentCounts, "repository"),
    highCount = fingerprints.filter(
      (fp) => severityRank(fp.severity) >= 3,
    ).length,
    generated = payload.generated_at || context.generated_at || "unknown";
  const contractSummary = summarizeContracts(contracts);
  const visibleContracts = contracts.slice(0, 8);
  const remainingContracts = contracts.slice(8);
  const decisionReasons = [
    ...rowsFrom(trust.reasons || payload.decision_reasons)
      .slice(0, 3)
      .map((reason) => ({ text: reason })),
    ...rowsFrom(trust.missing_evidence || payload.missing_evidence)
      .slice(0, 2)
      .map((item) => ({
        text: `Missing: ${item}`,
        state: "missing",
      })),
  ];
  const visibleFingerprints = useMemo(
    () => sortFingerprints(fingerprints, filter),
    [fingerprints, filter],
  );

  return (
    <section className="securitycontext-page">
      <div className="sc-title">
        <div>
          <h1>Security context</h1>
          <p>
            What an agent needs to avoid regressing past fixes and find the next
            vuln in this repo.
          </p>
        </div>
        <button
          className="button button-secondary sc-feedback-button"
          type="button"
          onClick={() => openFeedback(repository)}
        >
          <MessageSquare size={15} /> Feedback
        </button>
      </div>
      <section className="sc-decision">
        <div className="sc-decision-copy">
          <span className="eyebrow">Decision support</span>
          <h2>
            {trust.label || payload.verdict || "Evidence review required"}
          </h2>
          <p>
            {trust.action || payload.action || "Review evidence before use."}
          </p>
          {decisionReasons.length > 0 && (
            <div className="sc-decision-reasons">
              {decisionReasons.map((reason) => (
                <span data-state={reason.state} key={reason.text}>
                  {reason.text}
                </span>
              ))}
            </div>
          )}
        </div>
        <dl>
          <div>
            <dt>Score</dt>
            <dd>
              {Math.round(Number(trust.score ?? payload.trust_score ?? 0))}
            </dd>
          </div>
          <div>
            <dt>Grade</dt>
            <dd>{trust.grade || payload.grade || "-"}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{trust.confidence || payload.confidence || "unknown"}</dd>
          </div>
          <div>
            <dt>Coverage</dt>
            <dd>
              {percent(trust.evidence_coverage ?? payload.evidence_coverage)}
            </dd>
          </div>
        </dl>
      </section>
      <section className="sc-hero">
        <aside className="sc-sidebar">
          <div className="sc-repo">
            <span className="sc-logo">▲</span>
            <strong>{repository}</strong>
          </div>
          <div className="sc-refline">
            <span>main</span>
            <code>@ {shortSha(context.revision || "current")}</code>
          </div>
          <dl>
            <dt>Fixes</dt>
            <dd>{fixes}</dd>
            <dt>CVEs</dt>
            <dd>{cveCount}</dd>
            <dt>Peak severity</dt>
            <dd>
              <SeverityPill value={summary.top_severity || "none"} />
            </dd>
            <dt>Commits</dt>
            <dd>{Number(context.commits_scanned || 0).toLocaleString()}</dd>
          </dl>
          <div className="sc-coverage">
            <div>
              <span>Regression coverage</span>
              <strong>{Math.round(coverage * 10) / 10}%</strong>
            </div>
            {fixes > 0 ? (
              <>
                <div className="sc-grid">
                  {Array.from({ length: 34 }, (_, idx) => (
                    <i className={idx < covered ? "on" : ""} key={idx} />
                  ))}
                </div>
                <small>{covered} / 34</small>
              </>
            ) : (
              <small>No security fixes to measure.</small>
            )}
          </div>
        </aside>
        <div className="sc-brief">
          <span className="eyebrow">Highlights</span>
          {Number(topClass[1]) > 0 ? (
            <div className="sc-highlight">
              <strong>{topClass[0]}:</strong> {topClass[1]} prior fixes.
              Scrutinize any change in this area.
            </div>
          ) : (
            <div className="sc-highlight">
              No prior security fixes were found in this repository history.
            </div>
          )}
          {Number(topComponent[1]) > 0 && (
            <div className="sc-highlight">
              <strong>{componentNameLabel(topComponent[0])}:</strong> most-fixed
              ({topComponent[1]} issues). Treat as high-risk during review.
            </div>
          )}
          <div className="sc-highlight">
            {highCount > 0 ? (
              <>
                <strong>{highCount} high-severity fixes</strong> in this
                history; regressions here are high-impact.
              </>
            ) : (
              "No high-severity security fixes in this history."
            )}
          </div>
          <div className="sc-patterns">
            <span className="eyebrow">Recurring patterns</span>
            <PatternList risks={context.top_risks || []} />
          </div>
        </div>
        <footer className="sc-footer">
          <span>Last analyzed {formatDate(generated)}</span>
          <div>{artifactButtons(payload.artifacts)}</div>
        </footer>
      </section>
      <section className="sc-section">
        <div className="sc-section-head">
          <h2>Regression watchlist</h2>
          <div className="sc-refs" aria-label="Regression contract summary">
            <span className="sc-ref">{contracts.length} contracts</span>
            <span className="sc-ref">{contractSummary.verified} verified</span>
            <span className="sc-ref">
              {contractSummary.needsCuration} need curation
            </span>
            <span className="sc-ref">
              {contractSummary.unavailable} analysis unavailable
            </span>
          </div>
        </div>
        <p>
          Historical security boundaries with explicit evidence and guard
          status. A watch entry is not a confirmed current vulnerability.
        </p>
        <div className="sc-table-shell">
          <table className="sc-watch">
            <thead>
              <tr>
                <th>Contract</th>
                <th>Protected surface</th>
                <th>Evidence and guard</th>
                <th>Current ref</th>
              </tr>
            </thead>
            <tbody>{watchRows(visibleContracts)}</tbody>
          </table>
        </div>
        {remainingContracts.length > 0 && (
          <details className="sc-more sc-watch-more">
            <summary>
              Show all regression contracts
              <span>({remainingContracts.length} more)</span>
            </summary>
            <div className="sc-table-shell">
              <table className="sc-watch sc-watch-continuation">
                <tbody>{watchRows(remainingContracts)}</tbody>
              </table>
            </div>
          </details>
        )}
      </section>
      <section className="sc-section">
        <h2>Distribution</h2>
        <div className="sc-dist">
          <article>
            <span className="eyebrow">Vulnerability classes</span>
            {distributionChart(classCounts)}
          </article>
          <article>
            <span className="eyebrow">Affected components</span>
            {distributionChart(componentCounts, componentNameLabel)}
          </article>
        </div>
      </section>
      <section className="sc-section">
        <div className="sc-section-head">
          <h2>
            Fixed vulnerabilities <span>({fixes})</span>
          </h2>
          <div
            className="sc-segment"
            role="group"
            aria-label="Vulnerability filters"
          >
            <button
              type="button"
              aria-pressed={filter.startsWith("class")}
              onClick={() =>
                setFilter((current) =>
                  current === "classAsc" ? "classDesc" : "classAsc",
                )
              }
            >
              Class
            </button>
            <button
              type="button"
              aria-pressed={filter.startsWith("severity")}
              onClick={() =>
                setFilter((current) =>
                  current === "severityDesc" ? "severityAsc" : "severityDesc",
                )
              }
            >
              Severity
            </button>
            <button
              type="button"
              aria-pressed={filter === "default"}
              onClick={() => setFilter("default")}
            >
              Default
            </button>
          </div>
        </div>
        <div className="sc-table-shell">
          <table className="sc-fixes">
            <tbody>
              {visibleFingerprints.length ? (
                visibleFingerprints.slice(0, 12).map(fixRow)
              ) : (
                <tr>
                  <td colSpan="5">
                    No fixed vulnerability fingerprints were generated.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {visibleFingerprints.length > 12 && (
          <details className="sc-more">
            <summary>
              Show all vulnerabilities{" "}
              <span>({visibleFingerprints.length - 12} more)</span>
            </summary>
            <div className="sc-table-shell">
              <table className="sc-fixes">
                <tbody>{visibleFingerprints.slice(12).map(fixRow)}</tbody>
              </table>
            </div>
          </details>
        )}
      </section>
      <section className="sc-section">
        <h2>
          Disclosed CVEs <span>({cveCount})</span>
        </h2>
        <div className="sc-cves">
          {cves.length ? (
            cves.slice(0, 6).map(cveCard)
          ) : (
            <div className="empty-state">
              No disclosed CVEs were returned for this repository.
            </div>
          )}
        </div>
        {cves.length > 6 && (
          <details className="sc-more">
            <summary>
              Show all CVEs <span>({cves.length - 6} more)</span>
            </summary>
            <div className="sc-cves">{cves.slice(6).map(cveCard)}</div>
          </details>
        )}
      </section>
    </section>
  );
}

function rowsFrom(value) {
  return Array.isArray(value) ? value.filter(Boolean).map(String) : [];
}

function percent(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return "-";
  return `${Math.round(number * 100)}%`;
}

function PatternList({ risks }) {
  const rows = risks.slice(0, 4);
  if (!rows.length) return <p>No recurring pattern narrative was generated.</p>;
  return rows.map((risk, index) => (
    <p key={index}>
      <strong>{risk.vuln_class || risk.component || "Security Fix"}:</strong>{" "}
      {cleanLeadText(risk.rationale || risk.summary || risk.check_hint || "")}
    </p>
  ));
}

function summarizeContracts(contracts) {
  return contracts.reduce(
    (summary, contract) => {
      if (contract.evidence_tier === "e4") summary.verified += 1;
      if (contract.lifecycle?.state === "candidate") summary.needsCuration += 1;
      if (contract.assessment?.state === "analysis_unavailable")
        summary.unavailable += 1;
      return summary;
    },
    { verified: 0, needsCuration: 0, unavailable: 0 },
  );
}

function watchRows(contracts) {
  if (!contracts.length)
    return (
      <tr>
        <td colSpan="4">
          No evidence-backed regression contracts were generated. Low-quality
          history is excluded instead of being presented as a guard.
        </td>
      </tr>
    );
  return contracts.map((contract) => {
    const surface = contract.surfaces?.[0] || {},
      assessment = contract.assessment || {},
      guards = contract.guards || [],
      evidence = contract.source_evidence || [];
    return (
      <tr key={contract.id}>
        <td data-label="Contract">
          <strong>{contract.title}</strong>
          <SeverityPill value={contract.impact} />
          <small>
            {String(contract.evidence_tier || "unknown").toUpperCase()} ·{" "}
            {contract.lifecycle?.state || "candidate"}
          </small>
          {contract.owner?.codeowners?.length > 0 && (
            <div className="sc-refs">
              {contract.owner.codeowners.map((owner) => (
                <span className="sc-ref" key={owner}>
                  owner: {owner}
                </span>
              ))}
            </div>
          )}
        </td>
        <td data-label="Protected surface">
          <span className="sc-redbar" />
          <code title={contract.invariant || ""}>
            {clip(surface.path || surface.component || "repository", 54)}
          </code>
          <small>
            {clip(contract.invariant || "Review historical evidence", 90)}
          </small>
        </td>
        <td data-label="Evidence and guard">
          <span className="sc-blackbar" />
          <strong>{guardLabel(assessment.guard_status)}</strong>
          <div className="sc-refs">
            {evidence.slice(0, 3).map((item) => (
              <span className="sc-ref" key={`${item.relation}:${item.id}`}>
                {shortEvidenceRef(item.id)}
              </span>
            ))}
            {guards.slice(0, 2).map((guard) => (
              <span className="sc-ref" key={guard.id}>
                {clip(guard.path, 28)}
              </span>
            ))}
          </div>
        </td>
        <td data-label="Current ref">
          <strong>{stateLabel(assessment.state)}</strong>
          <span className="sc-ref">
            check: {assessment.check_conclusion || "action_required"}
          </span>
          <small>
            {clip(assessment.explanation || "No assessment supplied", 96)}
          </small>
          {assessment.missing_analysis?.length > 0 && (
            <div className="sc-refs">
              {assessment.missing_analysis.map((item) => (
                <span className="sc-ref" key={item}>
                  missing: {item.replaceAll("_", " ")}
                </span>
              ))}
            </div>
          )}
        </td>
      </tr>
    );
  });
}

function guardLabel(status) {
  return (
    {
      verified: "Guard verified",
      present_unverified: "Guard present, not verified",
      not_found: "No guard found",
      analysis_unavailable: "Guard analysis unavailable",
    }[status] || "Guard status unknown"
  );
}

function stateLabel(state) {
  return String(state || "analysis_unavailable")
    .replaceAll("_", " ")
    .replace(/^./, (character) => character.toUpperCase());
}

function shortEvidenceRef(value) {
  const [kind, id] = String(value || "evidence:unknown").split(":", 2);
  return `${kind}:${kind === "commit" ? shortSha(id) : id}`;
}

function fixRow(fp, index) {
  return (
    <tr
      data-class={fp.vuln_class || "Security Fix"}
      data-severity={fp.severity || "none"}
      data-index={index}
      key={fp.commit_sha || index}
    >
      <td data-label="Severity">
        <SeverityPill value={fp.severity} />
      </td>
      <td data-label="Vulnerability">{clip(issueTitle(fp), 110)}</td>
      <td data-label="Component">
        <code title={firstComponent(fp)}>{clip(componentLabel(fp), 34)}</code>
      </td>
      <td data-label="Fixed" title={String(fp.commit_date || "")}>
        {formatDate(fp.commit_date)}
      </td>
      <td data-label="Commit">
        <code>{shortSha(fp.commit_sha)}</code>
      </td>
    </tr>
  );
}

function cveCard(cve, index) {
  return (
    <article className="sc-cve-row" key={cve.id || index}>
      <div>
        <strong>{cve.id || "CVE"}</strong>
        <SeverityPill value={cve.severity} />
        <span className="sc-ref">CVSS {cve.cvss ?? "-"}</span>
      </div>
      <p>{cve.summary || "No summary was returned for this CVE."}</p>
    </article>
  );
}

function SeverityPill({ value }) {
  const text =
    String(value || "unknown").toLowerCase() === "none"
      ? "unknown"
      : String(value || "unknown").toLowerCase();
  const tone =
    text === "critical"
      ? "danger"
      : text === "high"
        ? "high-risk"
        : text === "medium"
          ? "warning"
          : text === "low"
            ? "success"
            : "info";
  return <span className={`sc-pill pill-${tone}`}>{text}</span>;
}

function artifactButtons(artifacts = {}) {
  return Object.entries(artifacts).map(([name, href]) => (
    <a
      className="sc-icon-button"
      href={href}
      key={name}
      aria-label={name.replaceAll("_", " ")}
      title={name.replaceAll("_", " ")}
    >
      {name.toLowerCase().includes("json") ? <Braces /> : <FileText />}
      <span>{name.replaceAll("_", " ")}</span>
    </a>
  ));
}

function severityRank(value) {
  return (
    { critical: 4, high: 3, medium: 2, low: 1 }[
      String(value || "").toLowerCase()
    ] || 0
  );
}
function shortSha(value) {
  return String(value || "").slice(0, 7);
}
function clip(value, limit) {
  const text = String(value || "")
    .replace(/\s+/g, " ")
    .trim();
  return text.length <= limit
    ? text
    : `${text.slice(0, limit - 1).trimEnd()}...`;
}
function firstComponent(fp) {
  return Array.isArray(fp.components) && fp.components.length
    ? fp.components[0]
    : fp.component || "repository";
}
function componentLabel(fp) {
  const value = firstComponent(fp);
  if (value === "repository") return value;
  const base = value.split("/").pop() || value;
  const clean = base.replace(/\.(go|rs|js|jsx|ts|tsx|py|c|cc|cpp|h|hpp)$/i, "");
  return clean
    .split(/[-_.\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
function formatDate(value) {
  const text = String(value || "").slice(0, 10);
  if (!text) return "-";
  const date = new Date(`${text}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return text;
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}
function issueTitle(fp) {
  const raw = String(fp.summary || fp.commit_subject || "Security fix")
    .replace(/\s+/g, " ")
    .trim();
  return cleanLeadText(raw);
}
function cleanLeadText(value) {
  const raw = String(value || "")
    .replace(/\s+/g, " ")
    .trim();
  const text =
    raw.replace(/^(fix|harden|guard|limit|tighten|validate)\s+/i, "") || raw;
  return text.charAt(0).toUpperCase() + text.slice(1);
}
function sortFingerprints(fingerprints, filter) {
  const rows = [...fingerprints];
  if (filter.startsWith("class")) {
    const sorted = rows.sort(
      (a, b) =>
        String(a.vuln_class || "Security Fix").localeCompare(
          String(b.vuln_class || "Security Fix"),
        ) || severityRank(b.severity) - severityRank(a.severity),
    );
    return filter === "classDesc" ? sorted.reverse() : sorted;
  }
  if (filter.startsWith("severity")) {
    const sorted = rows.sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        String(a.vuln_class || "").localeCompare(String(b.vuln_class || "")),
    );
    return filter === "severityAsc" ? sorted.reverse() : sorted;
  }
  return rows;
}
function topEntry(obj, emptyLabel) {
  return (
    Object.entries(obj || {}).sort(
      (a, b) =>
        Number(b[1] || 0) - Number(a[1] || 0) || a[0].localeCompare(b[0]),
    )[0] || [emptyLabel, 0]
  );
}
function distributionChart(obj, labelFor = (value) => value) {
  const rows = Object.entries(obj || {})
    .sort(
      (a, b) =>
        Number(b[1] || 0) - Number(a[1] || 0) || a[0].localeCompare(b[0]),
    )
    .slice(0, 8);
  if (!rows.length)
    return (
      <div className="empty-state">No distribution data was generated.</div>
    );
  const total = Math.max(
      1,
      rows.reduce((sum, [, count]) => sum + Number(count || 0), 0),
    ),
    max = Math.max(...rows.map(([, count]) => Number(count || 0)), 1),
    top = rows[0],
    topPercent = Math.round((Number(top[1] || 0) / total) * 100);
  return (
    <div className="sc-distribution-chart">
      <div className="sc-chart-summary">
        <strong>{total}</strong>
        <span>
          total · top {labelFor(top[0])} ({top[1]}, {topPercent}%)
        </span>
      </div>
      <div
        className="sc-bar-chart"
        role="img"
        aria-label={`Ranked distribution with ${rows.length} categories`}
      >
        {rows.map(([name, count], index) => (
          <article key={name}>
            <div>
              <strong title={name}>{clip(labelFor(name), 34)}</strong>
              <span>{Math.round((Number(count || 0) / total) * 100)}%</span>
              <em>{count}</em>
            </div>
            <span className="sc-bar-track">
              <i
                className={`sc-chart-tone-${index % 6}`}
                style={{
                  width: `${Math.max(4, (Number(count || 0) / max) * 100)}%`,
                }}
              />
            </span>
          </article>
        ))}
      </div>
    </div>
  );
}
function componentNameLabel(value) {
  const fp = { components: [value] };
  return componentLabel(fp);
}
