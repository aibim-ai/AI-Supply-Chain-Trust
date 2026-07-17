import {
  Bot,
  Braces,
  ChevronDown,
  CircleAlert,
  Copy,
  ExternalLink,
  FileText,
  History,
  MoreHorizontal,
  Search,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { captureProductEvent } from "../../lib/posthog";

export function ContextReport({ repository, payload }) {
  const [filter, setFilter] = useState("default");
  const [watchColumn, setWatchColumn] = useState("balanced");
  const [copied, setCopied] = useState("");
  const [actionsOpen, setActionsOpen] = useState(false);
  const reportRef = useRef(null);
  const watchShellRef = useRef(null);
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
      context.remediation?.coverage ?? summary.remediation_coverage ?? 0,
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
  const evidenceGaps = rowsFrom(
    trust.missing_evidence || payload.missing_evidence,
  );
  const reviewLeads = Array.isArray(payload.leads?.leads)
    ? payload.leads.leads
    : Array.isArray(payload.leads?.findings)
      ? payload.leads.findings
      : [];
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
  const publicUrl =
    globalThis.window?.location?.href?.split("?")[0] ||
    `https://ai-supply-chain-trust.aibim.ai/r/${repository}`;

  useEffect(() => {
    if (!reportRef.current || !("IntersectionObserver" in globalThis))
      return undefined;
    const seen = new Set();
    const timers = new Map();
    const observer = new globalThis.IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const sectionName = entry.target.dataset.analyticsSection;
          if (!sectionName || seen.has(sectionName)) continue;
          if (entry.isIntersecting && entry.intersectionRatio >= 0.5) {
            if (timers.has(sectionName)) continue;
            const timer = globalThis.setTimeout(() => {
              seen.add(sectionName);
              timers.delete(sectionName);
              captureProductEvent("evidence_section_viewed", {
                section_name: sectionName,
                section_has_content: entry.target.dataset.hasContent === "true",
              });
              observer.unobserve(entry.target);
            }, 1000);
            timers.set(sectionName, timer);
          } else if (timers.has(sectionName)) {
            globalThis.clearTimeout(timers.get(sectionName));
            timers.delete(sectionName);
          }
        }
      },
      { threshold: [0.5] },
    );
    reportRef.current
      .querySelectorAll("[data-analytics-section]")
      .forEach((section) => observer.observe(section));
    return () => {
      timers.forEach((timer) => globalThis.clearTimeout(timer));
      observer.disconnect();
    };
  }, []);

  async function copyAction(kind, value, properties) {
    try {
      if (!globalThis.navigator?.clipboard?.writeText)
        throw new Error("Clipboard is unavailable");
      await globalThis.navigator.clipboard.writeText(value);
      setCopied(kind);
      captureProductEvent(kind, properties);
      globalThis.setTimeout(() => setCopied(""), 1600);
    } catch {
      setCopied("");
    }
  }

  function focusWatchColumn(value, columnIndex) {
    setWatchColumn(value);
    const shell = watchShellRef.current;
    if (!shell) return;
    globalThis.requestAnimationFrame(() => {
      if (value === "balanced") {
        shell.scrollTo({ left: 0, behavior: motionPreference() });
        return;
      }
      const header = shell.querySelectorAll("th")[columnIndex];
      if (!header) return;
      const centered =
        header.offsetLeft - (shell.clientWidth - header.offsetWidth) / 2;
      shell.scrollTo({
        left: Math.max(0, centered),
        behavior: motionPreference(),
      });
    });
  }

  function primaryContextActions() {
    return (
      <>
        <button
          type="button"
          onClick={() => {
            setActionsOpen(false);
            copyAction("public_context_shared", publicUrl, {
              share_method: "copy_link",
              share_surface: "context_title_actions",
            });
          }}
        >
          <Copy size={15} />
          {copied === "public_context_shared"
            ? "Link copied"
            : "Copy public link"}
        </button>
        <button
          type="button"
          onClick={() => {
            setActionsOpen(false);
            copyAction(
              "mcp_config_copied",
              `Use ${globalThis.window?.location?.origin || "https://ai-supply-chain-trust.aibim.ai"}/mcp to inspect ${repository}. Begin with evidence gaps, historical fixes or CVEs, and ranked review leads.`,
              {
                mcp_client: "generic_query",
                navigation_surface: "context_title_actions",
              },
            );
          }}
        >
          <Bot size={15} />
          {copied === "mcp_config_copied"
            ? "MCP query copied"
            : "Copy MCP query"}
        </button>
        <a className="sc-new-scan" href="/">
          <Search size={15} /> Scan another repository
        </a>
      </>
    );
  }

  return (
    <section className="securitycontext-page" ref={reportRef}>
      <div className="sc-title">
        <div>
          <h1>Security context</h1>
          <p>
            What an agent needs to avoid regressing past fixes and find the next
            vuln in this repo.
          </p>
        </div>
        <nav className="sc-title-actions" aria-label="Context actions">
          <button
            className="sc-action-menu-trigger"
            type="button"
            aria-expanded={actionsOpen}
            aria-controls="context-actions-panel"
            onClick={() => setActionsOpen((current) => !current)}
          >
            Actions <ChevronDown size={16} />
          </button>
          <div
            className="sc-title-actions-inline"
            id="context-actions-panel"
            data-open={actionsOpen}
          >
            {primaryContextActions()}
            {Object.keys(payload.artifacts || {}).length > 0 && (
              <details className="sc-action-more">
                <summary>
                  <MoreHorizontal size={16} /> More
                </summary>
                <div className="sc-action-popover">
                  <span>Export context</span>
                  {artifactButtons(payload.artifacts)}
                </div>
              </details>
            )}
          </div>
        </nav>
      </div>
      <section className="sc-decision-hub">
        <div className="sc-decision">
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
              <dt>Evidence coverage</dt>
              <dd>
                {percent(trust.evidence_coverage ?? payload.evidence_coverage)}
              </dd>
            </div>
          </dl>
        </div>
        <div className="sc-activation" aria-labelledby="inspect-next-title">
          <div className="sc-activation-heading">
            <span className="eyebrow">Inspect next</span>
            <h2 id="inspect-next-title">
              Start with the evidence that can change the review.
            </h2>
          </div>
          <div className="sc-activation-grid">
            <a href="#evidence-gaps">
              <CircleAlert size={19} />
              <strong>{evidenceGaps.length} evidence gaps</strong>
              <span>See which unavailable sources affect confidence.</span>
            </a>
            <a href="#historical-evidence">
              <History size={19} />
              <strong>{fixes + cveCount} historical signals</strong>
              <span>
                {fixes} fixes and {cveCount} disclosed CVEs to inspect.
              </span>
            </a>
            <a href="#review-leads">
              <Search size={19} />
              <strong>{reviewLeads.length} ranked review leads</strong>
              <span>
                Open an evidence-backed starting point for deeper review.
              </span>
            </a>
          </div>
        </div>
      </section>
      <section
        className="sc-section sc-evidence-gaps"
        id="evidence-gaps"
        data-analytics-section="missing_evidence"
        data-has-content={evidenceGaps.length > 0}
      >
        <div className="sc-section-head">
          <h2>
            Evidence gaps <span>({evidenceGaps.length})</span>
          </h2>
          <span className="sc-ref">A gap is not a clean finding</span>
        </div>
        {evidenceGaps.length ? (
          <div className="sc-gap-list">
            {evidenceGaps.map((gap, index) => (
              <article key={gap}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <p>{gap}</p>
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            No missing-evidence items were returned for this context.
          </div>
        )}
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
            <p>
              Share of measurable historical fixes with observed guard evidence.
            </p>
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
      <section
        className="sc-section sc-review-leads"
        id="review-leads"
        data-analytics-section="review_leads"
        data-has-content={reviewLeads.length > 0}
      >
        <div className="sc-section-head">
          <h2>
            Ranked review leads <span>({reviewLeads.length})</span>
          </h2>
          <span className="sc-ref">
            Starting points, not confirmed findings
          </span>
        </div>
        {reviewLeads.length ? (
          <div className="sc-lead-list">
            {reviewLeads.map((lead, index) => (
              <details
                key={`${lead.rank || index}:${lead.component || repository}`}
                onToggle={(event) => {
                  if (!event.currentTarget.open) return;
                  captureProductEvent("review_lead_opened", {
                    lead_type: "ranked_review",
                    lead_position_bucket: positionBucket(index),
                    evidence_tier: lead.evidence_tier || "unknown",
                    severity_band: lead.severity || "unknown",
                    source_section: "ranked_review_leads",
                  });
                }}
              >
                <summary>
                  <span className="sc-lead-rank">
                    #{lead.rank || index + 1}
                  </span>
                  <strong>{lead.component || repository}</strong>
                  <span>
                    {lead.vulnerability_class ||
                      lead.vuln_class ||
                      "review focus"}
                  </span>
                </summary>
                <div>
                  <p>{lead.why || lead.rationale || lead.evidence}</p>
                  <div className="sc-refs">
                    <span className="sc-ref">
                      {lead.vulnerability_class ||
                        lead.vuln_class ||
                        "review focus"}
                    </span>
                    <span className="sc-ref">
                      source:{" "}
                      {String(lead.decision_source || "rule based").replaceAll(
                        "_",
                        " ",
                      )}
                    </span>
                  </div>
                </div>
              </details>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            No ranked review lead was returned for this context.
          </div>
        )}
      </section>
      <section
        className="sc-section"
        id="historical-evidence"
        data-analytics-section="regression_watchlist"
        data-has-content={contracts.length > 0}
      >
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
        <div className="sc-table-tools">
          <span>Column focus</span>
          <div role="group" aria-label="Choose a regression watchlist column">
            {[
              ["balanced", "All"],
              ["contract", "Contract"],
              ["surface", "Surface"],
              ["evidence", "Evidence"],
              ["current", "Current ref"],
            ].map(([value, label], columnIndex) => (
              <button
                type="button"
                aria-pressed={watchColumn === value}
                onClick={() => focusWatchColumn(value, columnIndex - 1)}
                key={value}
              >
                {label}
              </button>
            ))}
          </div>
          <small>Tap a column to give dense evidence more room.</small>
        </div>
        <div
          className="sc-table-shell"
          role="region"
          aria-label="Regression watchlist table"
          tabIndex="0"
          ref={watchShellRef}
        >
          <table className="sc-watch" data-focus={watchColumn}>
            <caption>
              Regression contracts, protected surfaces, supporting evidence, and
              current analysis status
            </caption>
            <thead>
              <tr>
                <th scope="col">Contract</th>
                <th scope="col">Protected surface</th>
                <th scope="col">Evidence and guard</th>
                <th scope="col">Current ref</th>
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
            <div
              className="sc-table-shell"
              role="region"
              aria-label="Additional regression watchlist entries"
              tabIndex="0"
            >
              <table
                className="sc-watch sc-watch-continuation"
                data-focus={watchColumn}
              >
                <caption>Additional regression contracts</caption>
                <thead>
                  <tr>
                    <th scope="col">Contract</th>
                    <th scope="col">Protected surface</th>
                    <th scope="col">Evidence and guard</th>
                    <th scope="col">Current ref</th>
                  </tr>
                </thead>
                <tbody>{watchRows(remainingContracts)}</tbody>
              </table>
            </div>
          </details>
        )}
      </section>
      <section
        className="sc-section"
        data-analytics-section="fixed_vulnerabilities"
        data-has-content={visibleFingerprints.length > 0}
      >
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
      <section
        className="sc-section"
        data-analytics-section="cves"
        data-has-content={cves.length > 0}
      >
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
        <div
          className="sc-table-shell"
          role="region"
          aria-label="Fixed vulnerabilities table"
          tabIndex="0"
        >
          <table className="sc-fixes">
            <caption>Historical fixed vulnerabilities</caption>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Vulnerability</th>
                <th scope="col">Component</th>
                <th scope="col">Fixed</th>
                <th scope="col">Commit</th>
              </tr>
            </thead>
            <tbody>
              {visibleFingerprints.length ? (
                visibleFingerprints
                  .slice(0, 12)
                  .map((fp, index) => fixRow(fp, index, repository))
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
            <div
              className="sc-table-shell"
              role="region"
              aria-label="Additional fixed vulnerabilities"
              tabIndex="0"
            >
              <table className="sc-fixes">
                <caption>Additional historical fixed vulnerabilities</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Component</th>
                    <th scope="col">Fixed</th>
                    <th scope="col">Commit</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleFingerprints
                    .slice(12)
                    .map((fp, index) => fixRow(fp, index + 12, repository))}
                </tbody>
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
            cves.slice(0, 6).map((cve, index) => cveCard(cve, index))
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
            <div className="sc-cves">
              {cves.slice(6).map((cve, index) => cveCard(cve, index + 6))}
            </div>
          </details>
        )}
      </section>
    </section>
  );
}

function rowsFrom(value) {
  return Array.isArray(value) ? value.filter(Boolean).map(String) : [];
}

function motionPreference() {
  return globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    ? "auto"
    : "smooth";
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
          <div className="sc-cell-content">
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
          </div>
        </td>
        <td data-label="Protected surface">
          <div className="sc-cell-content">
            <span className="sc-redbar" />
            <code title={contract.invariant || ""}>
              {clip(surface.path || surface.component || "repository", 54)}
            </code>
            <small>
              {clip(contract.invariant || "Review historical evidence", 90)}
            </small>
          </div>
        </td>
        <td data-label="Evidence and guard">
          <div className="sc-cell-content">
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
          </div>
        </td>
        <td data-label="Current ref">
          <div className="sc-cell-content">
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
          </div>
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

function fixRow(fp, index, repository) {
  const commitUrl = fp.commit_sha
    ? `https://github.com/${repository}/commit/${fp.commit_sha}`
    : "";
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
        {commitUrl ? (
          <a href={commitUrl} target="_blank" rel="noreferrer">
            <code>{shortSha(fp.commit_sha)}</code>
            <ExternalLink size={12} />
          </a>
        ) : (
          <code>-</code>
        )}
      </td>
    </tr>
  );
}

function cveCard(cve, index) {
  const sourceUrl = cve.source_url || cve.url || cve.references?.[0]?.url || "";
  const evidenceUrl =
    sourceUrl ||
    (/^CVE-\d{4}-\d+$/i.test(String(cve.id || ""))
      ? `https://nvd.nist.gov/vuln/detail/${cve.id}`
      : "");
  return (
    <article className="sc-cve-row" key={cve.id || index}>
      <div>
        {evidenceUrl ? (
          <a href={evidenceUrl} target="_blank" rel="noreferrer">
            <strong>{cve.id || "CVE"}</strong>
            <ExternalLink size={12} />
          </a>
        ) : (
          <strong>{cve.id || "CVE"}</strong>
        )}
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
      onClick={() =>
        captureProductEvent("json_or_markdown_downloaded", {
          artifact_format: name.toLowerCase().includes("json")
            ? "json"
            : "markdown",
          artifact_variant: artifactVariant(name),
          source_section: "context_report",
          complete_context: true,
        })
      }
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
function positionBucket(index) {
  if (index < 3) return "top_3";
  if (index < 10) return "4_10";
  return "11_plus";
}
function artifactVariant(name) {
  return String(name).toLowerCase().includes("lead")
    ? "vulnerability_leads"
    : "security_context";
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
