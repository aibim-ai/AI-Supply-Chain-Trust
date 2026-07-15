import { ArrowLeft, RefreshCw, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ErrorState } from "../components/ui";
import { ContextReport } from "../features/security-context/ContextReport";
import { ScanProgress } from "../features/security-context/ScanProgress";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";
import { captureProductEvent } from "../lib/posthog";

export default function ContextPage() {
  const [rescan, setRescan] = useState({ status: "idle", error: "" });
  const location = useLocation();
  const navigate = useNavigate();
  const { owner, repository: name } = useParams(),
    repository = `${owner}/${name}`,
    params = new globalThis.URLSearchParams(location.search);
  const query = useAsync(() => trustApi.context(repository), [repository]);
  const resultQuery = useAsync(() => trustApi.result(repository), [repository]);
  const isEnriching = query.data?.status === "enriching";

  useEffect(() => {
    if (query.data?.status === "ready") {
      captureProductEvent("context_ready_viewed", { repository });
    } else if (query.data?.status === "enriching") {
      captureProductEvent("fast_result_viewed", { repository });
    }
  }, [query.data?.status, repository]);

  useEffect(() => {
    if (!isEnriching && query.data?.status !== "ready") return;
    setRescan((current) =>
      current.status === "queued" ? { status: "idle", error: "" } : current,
    );
    const next = new globalThis.URLSearchParams(location.search);
    const hadTransientStatus = next.has("scan") || next.has("job");
    next.delete("scan");
    next.delete("job");
    if (hadTransientStatus) {
      const search = next.toString();
      navigate(`${location.pathname}${search ? `?${search}` : ""}`, {
        replace: true,
      });
    }
  }, [
    isEnriching,
    location.pathname,
    location.search,
    navigate,
    query.data?.status,
  ]);

  useEffect(() => {
    if (!isEnriching) return undefined;
    const refresh = () => {
      query.retry();
      resultQuery.retry();
    };
    const poll = globalThis.setInterval(refresh, 10000);
    let events;
    if ("EventSource" in globalThis) {
      events = new globalThis.EventSource("/api/v1/events");
      events.onmessage = refresh;
    }
    return () => {
      globalThis.clearInterval(poll);
      events?.close();
    };
  }, [isEnriching, query.retry, resultQuery.retry]);

  async function queueRescan() {
    setRescan({ status: "loading", error: "" });
    try {
      await trustApi.rescan(repository);
      setRescan({ status: "queued", error: "" });
    } catch (error) {
      setRescan({ status: "error", error: error.message });
    }
  }
  if (query.status === "error")
    return (
      <section className="shell py-16">
        <ErrorState error={query.error} retry={query.retry} />
      </section>
    );
  if (
    rescan.status === "queued" ||
    query.status === "loading" ||
    (!isEnriching &&
      query.data?.status !== "ready" &&
      (params.has("scan") || params.has("job")))
  )
    return <ScanProgress repository={repository} retry={query.retry} />;
  if (isEnriching)
    return (
      <EnrichingContext
        repository={repository}
        report={resultQuery.data}
        refreshing={query.refreshing || resultQuery.refreshing}
      />
    );
  if (query.data.status !== "ready")
    return (
      <section className="context-unavailable-shell">
        <div className="context-unavailable panel">
          <div className="context-unavailable-icon" aria-hidden="true">
            <ShieldAlert size={24} />
          </div>
          <div className="context-unavailable-copy">
            <span className="eyebrow">Context needs evidence</span>
            <h1>{repository}</h1>
            <p>
              {query.data.message ||
                "This repository has not produced a verified security context yet."}
            </p>
          </div>
          <dl className="context-unavailable-meta">
            <div>
              <dt>Evaluation</dt>
              <dd>{query.data.summary?.generated_at || "Not available"}</dd>
            </div>
            <div>
              <dt>Context status</dt>
              <dd>{query.data.status || "not generated"}</dd>
            </div>
            <div>
              <dt>Evidence ref</dt>
              <dd>{query.data.summary?.head_sha || "not verified"}</dd>
            </div>
          </dl>
          <div className="context-unavailable-actions">
            <button
              className="button button-primary"
              disabled={rescan.status === "loading"}
              onClick={queueRescan}
              type="button"
            >
              <RefreshCw size={16} />
              {rescan.status === "loading" ? "Queueing…" : "Run evidence scan"}
            </button>
            <Link className="button button-secondary" to="/contexts">
              <ArrowLeft size={16} />
              All contexts
            </Link>
          </div>
          {rescan.error && (
            <p className="context-unavailable-error" role="alert">
              {rescan.error}
            </p>
          )}
        </div>
      </section>
    );
  return <ContextReport repository={repository} payload={query.data} />;
}

function EnrichingContext({ repository, report, refreshing }) {
  const trust = report?.trust_decision || {};
  const reasons = report?.decision_reasons || trust.reasons || [];
  return (
    <section className="enriching-context page-stack">
      <header className="enriching-context-header">
        <div>
          <span className="eyebrow">Fast trust result</span>
          <h1>{repository}</h1>
          <p>
            The initial decision is ready. Historical security evidence is being
            added without blocking this result.
          </p>
        </div>
        <span className="enrichment-badge" data-refreshing={refreshing}>
          <i /> Historical enrichment continues
        </span>
      </header>
      <section className="enriching-decision panel">
        <div className="enriching-score">
          <strong>{Math.round(Number(report?.trust_score || 0))}</strong>
          <span>{report?.grade || "–"}</span>
        </div>
        <div className="enriching-verdict">
          <span className="eyebrow">Current decision</span>
          <h2>{report?.verdict || "Evaluating repository trust"}</h2>
          <p>{report?.action || "Live repository evidence is available."}</p>
        </div>
        <dl>
          <div>
            <dt>Confidence</dt>
            <dd>{report?.confidence || trust.confidence || "pending"}</dd>
          </div>
          <div>
            <dt>Evidence</dt>
            <dd>
              {percent(report?.evidence_coverage ?? trust.evidence_coverage)}
            </dd>
          </div>
          <div>
            <dt>Updated</dt>
            <dd>{report?.evaluated_at || "today"}</dd>
          </div>
        </dl>
      </section>
      <div className="enriching-context-grid">
        <section className="panel">
          <span className="eyebrow">Why this decision</span>
          <div className="enriching-reasons">
            {reasons.slice(0, 4).map((reason) => (
              <p key={reason}>{reason}</p>
            ))}
            {!reasons.length && <p>Evidence summary is being prepared.</p>}
          </div>
        </section>
        <aside className="panel enriching-next">
          <span className="eyebrow">What happens next</span>
          <h2>Full context publishes automatically</h2>
          <p>
            Commit history, advisories, CVEs, and regression fingerprints are
            checkpointed in the background. This page refreshes through live
            events with a 10-second polling fallback.
          </p>
        </aside>
      </div>
    </section>
  );
}

function percent(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0
    ? `${Math.round(number * 100)}%`
    : "pending";
}
