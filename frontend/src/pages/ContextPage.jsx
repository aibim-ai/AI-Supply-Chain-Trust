import { ArrowLeft, RefreshCw, ShieldAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ErrorState } from "../components/ui";
import { ContextReport } from "../features/security-context/ContextReport";
import { ScanProgress } from "../features/security-context/ScanProgress";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";
import {
  captureProductEvent,
  createScanAttempt,
  durationBucketDays,
  getAnalyticsConsent,
  getScanAttempt,
  markFastResultSeen,
  recordCompletedRepository,
} from "../lib/posthog";

export default function ContextPage() {
  const [rescan, setRescan] = useState({ status: "idle", error: "" });
  const fastTracked = useRef(false);
  const completeTracked = useRef(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { owner, repository: name } = useParams(),
    repository = `${owner}/${name}`,
    params = new globalThis.URLSearchParams(location.search);
  const query = useAsync(() => trustApi.context(repository), [repository]);
  const resultQuery = useAsync(() => trustApi.result(repository), [repository]);
  const isEnriching = query.data?.status === "enriching";

  useEffect(() => {
    fastTracked.current = false;
    completeTracked.current = false;
  }, [repository]);

  useEffect(() => {
    const reportReady =
      resultQuery.data?.trust_score !== undefined ||
      Boolean(resultQuery.data?.grade);
    if (!isEnriching || !reportReady || fastTracked.current) return;
    fastTracked.current = true;
    const attempt =
      markFastResultSeen(repository) || getScanAttempt(repository);
    captureProductEvent("fast_result_ready", {
      scan_attempt_id: attempt?.id,
      time_to_fast_result_ms: attempt
        ? Math.max(0, Date.now() - attempt.started_at)
        : undefined,
      confidence_band:
        resultQuery.data?.confidence ||
        resultQuery.data?.trust_decision?.confidence ||
        "unknown",
      coverage_band: coverageBand(
        resultQuery.data?.evidence_coverage ??
          resultQuery.data?.trust_decision?.evidence_coverage,
      ),
      entry_mode: attempt ? "scan_flow" : "direct_context",
      observation: "client_rendered",
    });
  }, [isEnriching, repository, resultQuery.data]);

  useEffect(() => {
    if (query.data?.status !== "ready" || completeTracked.current) return;
    completeTracked.current = true;
    const attempt = getScanAttempt(repository);
    const trust =
      query.data?.context?.trust || query.data?.trust_decision || {};
    captureProductEvent("complete_context_ready", {
      scan_attempt_id: attempt?.id,
      time_to_complete_context_ms: attempt
        ? Math.max(0, Date.now() - attempt.started_at)
        : undefined,
      fast_result_seen: Boolean(attempt?.fast_result_seen),
      coverage_band: coverageBand(
        trust.evidence_coverage ?? query.data?.evidence_coverage,
      ),
      entry_mode: attempt ? "scan_flow" : "direct_context",
      observation: "client_rendered",
    });

    if (getAnalyticsConsent() !== "granted") return;
    const completed = recordCompletedRepository(repository);
    if (completed?.total === 2 && !completed.secondReported) {
      captureProductEvent("second_repository_scanned", {
        days_since_first_scan_bucket: durationBucketDays(
          Date.now() - completed.firstCompletedAt,
        ),
        same_session: Boolean(attempt),
        repository_ordinal: 2,
        second_scan_entry_mode: attempt ? "scan_flow" : "direct_context",
      });
    }
  }, [query.data, repository]);

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
    const attempt = createScanAttempt(repository, {
      request_origin: "context_rescan",
      existing_context: true,
      provider: "github",
    });
    captureProductEvent("scan_requested", {
      scan_attempt_id: attempt.id,
      request_origin: attempt.request_origin,
      existing_context: true,
      provider: "github",
    });
    const requestStarted = performance.now();
    setRescan({ status: "loading", error: "" });
    try {
      await trustApi.rescan(repository);
      captureProductEvent("scan_queued", {
        scan_attempt_id: attempt.id,
        queue_latency_ms: Math.round(performance.now() - requestStarted),
        request_origin: attempt.request_origin,
        existing_context: true,
      });
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

function coverageBand(value) {
  const number = Number(value);
  const percentValue = number <= 1 ? number * 100 : number;
  if (!Number.isFinite(percentValue)) return "unknown";
  if (percentValue < 25) return "0_24";
  if (percentValue < 50) return "25_49";
  if (percentValue < 75) return "50_74";
  return "75_100";
}
