import { useState } from "react";
import { Search } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, GradeBadge, PageHeader, Spinner } from "../components/ui";
import { useAsync } from "../hooks/use-async";
import { useDocumentMeta } from "../hooks/use-document-meta";
import { trustApi } from "../lib/api-client";
import { pageTitle } from "../lib/seo";

export default function LeaderboardPage() {
  const [search, setSearch] = useState("");
  const query = useAsync(() => trustApi.leaderboard(search), [search]);
  useDocumentMeta({
    title: pageTitle("Repository trust leaderboard"),
    description:
      "Compare stored trust verdicts for public GitHub repositories by score, grade, evidence coverage, and review age.",
    path: "/leaderboard",
  });
  return (
    <section className="shell py-14">
      <PageHeader
        eyebrow="Comparison ledger"
        title="Repository leaderboard"
        description="Compare stored trust verdicts by score, grade, coverage, and review age."
        action={
          <div className="relative w-full sm:w-72">
            <Search
              className="absolute left-4 top-4 text-slate-400"
              size={17}
            />
            <input
              className="input pl-11"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter repositories"
            />
          </div>
        }
      />
      <section className="card overflow-hidden">
        {query.status === "error" ? (
          <ErrorState error={query.error} retry={query.retry} />
        ) : query.status === "loading" ? (
          <div className="grid place-items-center p-16">
            <Spinner />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">
                Repositories ranked by trust score, with the evidence coverage
                the score is normalized over and the date of the stored review
              </caption>
              <thead>
                <tr>
                  <th scope="col">Rank</th>
                  <th scope="col">Repository</th>
                  <th scope="col">Grade</th>
                  <th scope="col">Trust</th>
                  <th scope="col">Evidence coverage</th>
                  <th scope="col">Reviewed</th>
                  <th scope="col">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {(query.data.rows || []).map((row, index) => (
                  <tr key={row.repo}>
                    <td data-label="Rank" className="font-mono text-slate-400">
                      {String(index + 1).padStart(2, "0")}
                    </td>
                    <td data-label="Repository">
                      <Link
                        className="font-semibold hover:text-indigo-600"
                        to={`/r/${row.repo}`}
                      >
                        {row.repo}
                      </Link>
                    </td>
                    <td data-label="Grade">
                      <GradeBadge grade={row.grade} />
                    </td>
                    <td data-label="Trust" className="font-semibold">
                      <span className="cell-stack">
                        <span>{Math.round(row.trust_score ?? 0)}/100</span>
                        <AnchoredScore row={row} />
                      </span>
                    </td>
                    <td data-label="Evidence coverage">
                      <CoverageCell row={row} />
                    </td>
                    <td data-label="Reviewed" className="text-slate-500">
                      <ReviewedCell row={row} />
                    </td>
                    <td data-label="Verdict" className="text-slate-500">
                      {row.verdict || row.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </section>
  );
}

// The trust score is normalized over the pillars that produced evidence, so it
// reads as a contradiction next to a "not enough evidence" verdict unless the
// coverage it was normalized over is shown with it.
function CoverageCell({ row }) {
  const coverage = coveragePercent(
    row.evidence_coverage ?? row.trust_decision?.evidence_coverage,
  );
  if (coverage === null)
    return <span className="cell-stack text-slate-400">Not reported</span>;
  return (
    <span className="cell-stack">
      <span className="font-semibold">{coverage}%</span>
      <small className="block text-xs font-normal text-slate-500">
        of evidence pillars observed
      </small>
    </span>
  );
}

function ReviewedCell({ row }) {
  const reviewed = formatDate(row.evaluated_at || row.updated_at);
  if (!reviewed)
    return <span className="cell-stack text-slate-400">Not recorded</span>;
  const age = reviewAge(row.evaluated_at || row.updated_at);
  const nextReview = formatDate(row.next_review_date);
  const footnote = [age, nextReview ? `next review ${nextReview}` : ""]
    .filter(Boolean)
    .join(" · ");
  return (
    <span className="cell-stack">
      <span>{reviewed}</span>
      {footnote && (
        <small className="block text-xs text-slate-400">{footnote}</small>
      )}
    </span>
  );
}

// Rendered only when the API carries the field; the backend is rolling it out.
function AnchoredScore({ row }) {
  const anchored = Number(
    row.evidence_anchored_score ??
      row.trust_decision?.evidence_anchored_score ??
      NaN,
  );
  if (!Number.isFinite(anchored)) return null;
  return (
    <small className="block text-xs font-normal text-slate-500">
      {Math.round(anchored)}/100 evidence-anchored
    </small>
  );
}

function coveragePercent(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return null;
  return Math.round(number <= 1 ? number * 100 : number);
}

function formatDate(value) {
  if (!value) return "";
  const text = String(value).trim();
  const match = text.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match) return match[1];
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text : date.toISOString().slice(0, 10);
}

function reviewAge(value) {
  const date = new Date(String(value || "").trim());
  if (Number.isNaN(date.getTime())) return "";
  const days = Math.floor((Date.now() - date.getTime()) / 86400000);
  if (days < 0) return "";
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}
