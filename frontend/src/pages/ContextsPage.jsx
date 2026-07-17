import { Search, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState, PageHeader, PageLoader } from "../components/ui";
import { HomeActivityList } from "../features/repositories/RepositoryViews";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";

export default function ContextsPage() {
  const query = useAsync(async () => {
    const [recent, jobs, stats] = await Promise.allSettled([
      trustApi.recent(250),
      trustApi.jobs(250),
      trustApi.queueStats(),
    ]);
    const failedRequests = [recent, jobs, stats].filter(
      (result) => result.status === "rejected",
    );
    if (failedRequests.length === 3) {
      const cached = readCache("contexts.payload");
      if (cached) return { ...cached, partialError: failedRequests[0].reason };
      throw failedRequests[0].reason;
    }
    const payload = {
      recent: settledValue(recent, readCache("contexts.recent") || []),
      jobs: settledValue(jobs, readCache("contexts.jobs") || []),
      stats: settledValue(stats, readCache("contexts.stats") || {}),
      partialError: failedRequests[0]?.reason || null,
    };
    if (recent.status === "fulfilled")
      writeCache("contexts.recent", recent.value);
    if (jobs.status === "fulfilled") writeCache("contexts.jobs", jobs.value);
    if (stats.status === "fulfilled") writeCache("contexts.stats", stats.value);
    writeCache("contexts.payload", payload);
    return payload;
  }, []);
  const [search, setSearch] = useState(""),
    [status, setStatus] = useState("");
  useEffect(() => {
    let events;
    if ("EventSource" in globalThis) {
      events = new globalThis.EventSource("/api/v1/events");
      events.onmessage = () => query.retry();
    }
    return () => events?.close();
  }, [query.retry]);
  useEffect(() => {
    if (!query.data?.partialError) return undefined;
    const timer = globalThis.setTimeout(query.retry, 3000);
    return () => globalThis.clearTimeout(timer);
  }, [query.data?.partialError, query.retry]);
  if (query.status === "error")
    return (
      <section className="page-stack">
        <ErrorState error={query.error} retry={query.retry} />
      </section>
    );
  if (query.status === "loading") return <PageLoader />;
  const matches = (value) =>
    JSON.stringify(value).toLowerCase().includes(search.toLowerCase());
  const statusMatches = (value) => !status || value.status === status;
  const repositories = rowsFrom(query.data.recent).filter(
    (row) => statusMatches(row) && matches(row),
  );
  const jobs = rowsFrom(query.data.jobs).filter(
    (job) => (!status || job.status === status) && matches(job),
  );
  const visibleJobs = jobs
      .filter((job) => job.status === "queued" || job.status === "running")
      .slice(0, 3),
    visibleRepos = new Set(visibleJobs.map((job) => job.repo)),
    repositoryRepos = new Set(repositories.map((row) => row.repo)),
    jobOnlyRepos = new Set(
      jobs
        .filter((job) => !visibleRepos.has(job.repo))
        .filter((job) => !repositoryRepos.has(job.repo))
        .map((job) => job.repo),
    ),
    visibleCount =
      visibleJobs.length +
      repositories.filter((row) => !visibleRepos.has(row.repo)).length +
      jobOnlyRepos.size;
  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Operations"
        title="Context management"
        description="Filter stored packages, queued jobs, running scans, failures, grades, and verdicts from one page."
        action={
          <Link className="button button-primary" to="/">
            New scan
          </Link>
        }
      />
      <section className="panel">
        <div className="context-filter-toolbar" role="search">
          <label className="context-filter-search">
            <span className="sr-only">Filter packages</span>
            <Search size={18} aria-hidden="true" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter repo, status, grade, verdict"
            />
            {search && (
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => setSearch("")}
              >
                <X size={15} />
              </button>
            )}
          </label>
          <label className="context-filter-status">
            <SlidersHorizontal size={16} aria-hidden="true" />
            <span>Status</span>
            <select
              aria-label="Filter by status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All statuses</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="completed">Completed</option>
            </select>
          </label>
          <div
            className="context-live-state"
            aria-label={`${query.data.stats.pending || 0} queued, ${query.data.stats.active || 0} running`}
          >
            <span>
              {`${query.data.stats.pending || 0} queued · ${query.data.stats.active || 0} running`}
            </span>
          </div>
        </div>
        {query.data.partialError && (
          <p className="form-message" data-state="error">
            Some live data is retrying in the background.
          </p>
        )}
        <section className="context-activity-panel">
          <header className="panel-header panel-header-compact">
            <div>
              <span className="eyebrow">Unified</span>
              <h2>Repository activity</h2>
              <p>{visibleCount} visible repositories</p>
            </div>
          </header>
          <HomeActivityList contexts={repositories} jobs={jobs} />
        </section>
      </section>
    </section>
  );
}

function rowsFrom(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.rows)) return payload.rows;
  if (Array.isArray(payload?.jobs)) return payload.jobs;
  return [];
}

function readCache(key) {
  try {
    return JSON.parse(globalThis.localStorage?.getItem(`trust.${key}`) || "");
  } catch {
    return null;
  }
}

function writeCache(key, value) {
  try {
    globalThis.localStorage?.setItem(`trust.${key}`, JSON.stringify(value));
  } catch {
    // Cache is a best-effort fallback for transient API/deploy failures.
  }
}

function settledValue(result, fallback) {
  return result.status === "fulfilled" ? result.value : fallback;
}
