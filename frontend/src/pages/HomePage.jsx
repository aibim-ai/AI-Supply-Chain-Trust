import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Check,
  GitBranch,
  GitFork as Github,
  Globe2,
  Package,
  Search,
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorState, Spinner } from "../components/ui";
import HowItWorksPipeline from "../components/HowItWorksPipeline";
import ScanHeroBackground from "../components/ScanHeroBackground";
import { PublicContextList } from "../features/repositories/RepositoryViews";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";
import {
  buildSearchCandidates,
  productForInput,
} from "../lib/repository-search";
import { isRepository, normalizeRepository } from "../lib/repository";

export default function HomePage() {
  const navigate = useNavigate(),
    home = useAsync(async () => {
      try {
        const recent = await trustApi.recent(12);
        writeCache("home.recent", recent);
        return { recent };
      } catch (error) {
        const recent = readCache("home.recent");
        if (recent) return { recent, partialError: error };
        throw error;
      }
    }, []);
  const [repo, setRepo] = useState(""),
    [selectedRepo, setSelectedRepo] = useState(""),
    [suggestions, setSuggestions] = useState([]),
    [suggestStatus, setSuggestStatus] = useState("idle"),
    [dropdownOpen, setDropdownOpen] = useState(false),
    [activeIndex, setActiveIndex] = useState(0),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const syncHome = home.retry;
  const recentRows = rowsFrom(home.data?.recent);
  const product = productForInput(repo);
  const candidates = useMemo(
    () =>
      buildSearchCandidates({
        query: repo,
        suggestions,
        recent: recentRows,
      }),
    [repo, suggestions, recentRows],
  );
  const selectedCandidate =
    candidates.find((candidate) => candidate.repo === selectedRepo) ||
    candidates[activeIndex] ||
    null;

  useEffect(() => {
    let events;
    if ("EventSource" in globalThis) {
      events = new globalThis.EventSource("/api/v1/events");
      events.onmessage = () => syncHome();
    }
    return () => {
      events?.close();
    };
  }, [syncHome]);

  useEffect(() => {
    const query = repo.trim();
    setActiveIndex(0);
    if (selectedRepo && normalizeRepository(query) !== selectedRepo)
      setSelectedRepo("");
    if (query.length < 2) {
      setSuggestions([]);
      setSuggestStatus("idle");
      return;
    }

    let cancelled = false;
    setSuggestStatus("loading");
    const timer = globalThis.setTimeout(async () => {
      try {
        const payload = await trustApi.suggest(query);
        if (!cancelled) {
          setSuggestions(rowsFrom(payload.candidates));
          setSuggestStatus("ready");
        }
      } catch {
        if (!cancelled) {
          setSuggestions([]);
          setSuggestStatus("error");
        }
      }
    }, 180);

    return () => {
      cancelled = true;
      globalThis.clearTimeout(timer);
    };
  }, [repo, selectedRepo]);

  function selectCandidate(candidate) {
    setRepo(candidate.repo);
    setSelectedRepo(candidate.repo);
    setDropdownOpen(false);
    setError("");
  }

  async function queueScan(value) {
    if (!isRepository(value))
      return setError("Search and select a repository first.");
    setBusy(true);
    setError("");
    try {
      await trustApi.rescan(value);
      navigate(`/r/${value}?scan=queued`);
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  }

  async function scanCandidate(candidate) {
    selectCandidate(candidate);
    await queueScan(candidate.repo);
  }

  async function submit(event) {
    event.preventDefault();
    await queueScan(selectedCandidate?.repo || normalizeRepository(repo));
  }
  function keyDown(event) {
    if (!dropdownOpen || !candidates.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => Math.min(index + 1, candidates.length - 1));
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(index - 1, 0));
    }
    if (event.key === "Enter") {
      event.preventDefault();
      scanCandidate(candidates[activeIndex]);
    }
  }
  return (
    <section className="scan-home">
      <section className="scan-hero relative">
        <ScanHeroBackground />
        <div className="scan-hero-headline-overlay" aria-hidden="true" />
        <div className="relative z-10">
          <span className="eyebrow">Security Context for agents</span>
          <h1>
            <span>AI Supply Chain</span>
            <span>Trust</span>
          </h1>
          <p className="hero-subtitle">
            Paste a public repository. Get a reusable security context and
            ranked review leads, JSON/Markdown artifacts, and MCP output for
            coding agents.
          </p>
          <form className="hero-scan-form" onSubmit={submit} role="search">
            <div className="hero-input-row">
              <span
                className={`product-icon product-${product.id}`}
                aria-label={product.label}
                title={product.label}
              >
                <ProductIcon product={product.id} />
              </span>
              <input
                className="input"
                value={repo}
                onChange={(e) => {
                  setRepo(e.target.value);
                  setDropdownOpen(true);
                }}
                onFocus={() => setDropdownOpen(true)}
                onBlur={() =>
                  globalThis.setTimeout(() => setDropdownOpen(false), 120)
                }
                onKeyDown={keyDown}
                placeholder="Search repository or paste product link"
                type="search"
                inputMode="url"
                autoComplete="url"
                spellCheck="false"
                aria-autocomplete="list"
                aria-expanded={dropdownOpen ? "true" : "false"}
              />
              <button
                disabled={busy}
                className="hero-submit-button"
                data-loading={busy ? "true" : undefined}
              >
                {busy ? (
                  <Spinner />
                ) : (
                  <>
                    <span>Scan</span>
                    <ArrowRight size={16} />
                  </>
                )}
              </button>
              {dropdownOpen && repo.trim().length > 1 && (
                <SearchDropdown
                  candidates={candidates}
                  activeIndex={activeIndex}
                  selectedRepo={selectedRepo}
                  status={suggestStatus}
                  onPick={scanCandidate}
                />
              )}
            </div>
            <p
              className="form-message"
              data-state={error ? "error" : undefined}
            >
              {error ||
                (selectedCandidate?.scanned
                  ? `Existing scan: ${metricText(selectedCandidate)}`
                  : selectedCandidate
                    ? `Ready to scan ${selectedCandidate.repo}`
                    : "")}
            </p>
          </form>
          <p className="hero-copy">
            Built for public repository review. Results are public and
            cacheable; missing evidence is reported as unavailable, not
            invented.
          </p>
        </div>
      </section>
      <HowItWorksPipeline />
      <section className="home-list-panel">
        <div className="panel-header">
          <div>
            <span className="eyebrow">Live</span>
            <h2>Public contexts</h2>
          </div>
          <Link to="/contexts">Manage</Link>
        </div>
        {home.status === "error" ? (
          <ErrorState error={home.error} retry={home.retry} />
        ) : home.status === "loading" ? (
          <div className="grid place-items-center py-16">
            <Spinner />
          </div>
        ) : (
          <>
            {home.data.partialError && (
              <p className="form-message" data-state="error">
                Live data is retrying in the background.
              </p>
            )}
            <PublicContextList
              contexts={rowsFrom(home.data.recent).slice(0, 12)}
            />
          </>
        )}
      </section>
    </section>
  );
}

function ProductIcon({ product }) {
  if (product === "package") return <Package size={19} />;
  if (product === "gitlab" || product === "bitbucket")
    return <GitBranch size={19} />;
  if (product === "web") return <Globe2 size={19} />;
  return <Github size={19} />;
}

function SearchDropdown({
  candidates,
  activeIndex,
  selectedRepo,
  status,
  onPick,
}) {
  if (status === "loading" && !candidates.length)
    return (
      <div className="search-dropdown">
        <div className="search-dropdown-state">
          <Spinner />
          <span>Searching repositories...</span>
        </div>
      </div>
    );
  if (!candidates.length)
    return (
      <div className="search-dropdown">
        <div className="search-dropdown-state">
          <Search size={16} />
          <span>No repository matches yet.</span>
        </div>
      </div>
    );
  return (
    <div className="search-dropdown" role="listbox">
      <div className="search-dropdown-head">
        <span>Search results</span>
        <strong>Select one to scan</strong>
      </div>
      {candidates.map((candidate, index) => (
        <button
          type="button"
          role="option"
          aria-selected={candidate.repo === selectedRepo}
          className="search-result-row"
          data-active={index === activeIndex ? "true" : undefined}
          key={candidate.repo}
          onMouseDown={(event) => event.preventDefault()}
          onClick={() => onPick(candidate)}
        >
          <span className={`product-icon product-${candidate.product}`}>
            <ProductIcon product={candidate.product} />
          </span>
          <span className="search-result-main">
            <strong>{candidate.repo}</strong>
            <span>
              {candidate.scanned
                ? metricText(candidate)
                : candidate.description ||
                  starText(candidate) ||
                  "Not scanned yet"}
            </span>
          </span>
          {candidate.scanned ? (
            <span className="search-metric">
              <strong>{scoreText(candidate)}</strong>
              <em>{candidate.grade || "scanned"}</em>
            </span>
          ) : (
            <span className="search-metric muted">scan</span>
          )}
          {candidate.repo === selectedRepo && <Check size={16} />}
        </button>
      ))}
    </div>
  );
}

function scoreText(candidate) {
  const score = Number(candidate.score);
  if (Number.isFinite(score)) return Math.round(score);
  return "-";
}

function metricText(candidate) {
  const summary = candidate.summary || {};
  const fixes = summary.fixes ?? candidate.prior?.fixes ?? 0;
  const cves = summary.cves ?? candidate.prior?.cves ?? 0;
  const score = scoreText(candidate);
  return `score ${score} · ${fixes} fixes · ${cves} CVEs`;
}

function starText(candidate) {
  const stars = Number(candidate.stars);
  if (!Number.isFinite(stars)) return "";
  return `${stars.toLocaleString()} stars · not scanned yet`;
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
