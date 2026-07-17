import { useState } from "react";
import { Search } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, GradeBadge, PageHeader, Spinner } from "../components/ui";
import { useAsync } from "../hooks/use-async";
import { trustApi } from "../lib/api-client";

export default function LeaderboardPage() {
  const [search, setSearch] = useState("");
  const query = useAsync(() => trustApi.leaderboard(search), [search]);
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
                Repositories ranked by trust score
              </caption>
              <thead>
                <tr>
                  <th scope="col">Rank</th>
                  <th scope="col">Repository</th>
                  <th scope="col">Grade</th>
                  <th scope="col">Trust</th>
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
                      {Math.round(row.trust_score ?? 0)}/100
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
