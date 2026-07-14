import { normalizeRepository } from "./repository";

export function productForInput(value) {
  const input = value.trim().toLowerCase();
  if (!input) return { id: "github", label: "GitHub" };
  if (/^[^/\s]+\/[^/\s]+$/.test(input))
    return { id: "github", label: "GitHub" };
  if (input.startsWith("npm:")) return { id: "package", label: "Package" };

  const hostname = hostnameFromInput(input);
  if (isProviderHost(hostname, "github.com"))
    return { id: "github", label: "GitHub" };
  if (isProviderHost(hostname, "gitlab.com"))
    return { id: "gitlab", label: "GitLab" };
  if (isProviderHost(hostname, "bitbucket.org"))
    return { id: "bitbucket", label: "Bitbucket" };
  if (isProviderHost(hostname, "npmjs.com"))
    return { id: "package", label: "Package" };
  return { id: "web", label: "Web" };
}

function hostnameFromInput(input) {
  try {
    const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(input)
      ? input
      : `https://${input}`;
    const url = new globalThis.URL(candidate);
    return url.protocol === "https:" || url.protocol === "http:"
      ? url.hostname.toLowerCase().replace(/\.$/, "")
      : "";
  } catch {
    return "";
  }
}

function isProviderHost(hostname, expected) {
  return hostname === expected || hostname === `www.${expected}`;
}

export function searchCandidateFromInput(value) {
  const repo = normalizeRepository(value);
  if (repo.split("/").length !== 2) return null;
  return {
    repo,
    product: productForInput(value).id,
    source: "input",
  };
}

export function buildSearchCandidates({
  query,
  suggestions = [],
  recent = [],
}) {
  const recentByRepo = new Map(
    recent
      .filter((row) => typeof row?.repo === "string")
      .map((row) => [row.repo.toLowerCase(), row]),
  );
  const seen = new Set();
  const rows = [];

  function add(candidate) {
    if (!candidate?.repo || seen.has(candidate.repo.toLowerCase())) return;
    seen.add(candidate.repo.toLowerCase());
    const prior = recentByRepo.get(candidate.repo.toLowerCase());
    rows.push({
      ...candidate,
      prior,
      scanned: Boolean(
        prior ||
        candidate.source === "scanned" ||
        candidate.grade ||
        candidate.summary,
      ),
      score:
        candidate.score ??
        prior?.trust_score ??
        prior?.score ??
        prior?.summary?.trust_score ??
        null,
      grade: candidate.grade || prior?.grade || null,
      status: candidate.status || prior?.status || null,
      summary: candidate.summary || prior?.summary || null,
      product: candidate.product || "github",
      description: candidate.description || null,
      stars: candidate.stars ?? null,
    });
  }

  suggestions.forEach((candidate) =>
    add({
      repo: typeof candidate.repo === "string" ? candidate.repo : "",
      score: candidate.score,
      grade: candidate.grade,
      status: candidate.status,
      summary: candidate.summary,
      source: candidate.source || "suggest",
      product: "github",
      description: candidate.description,
      stars: candidate.stars,
    }),
  );

  const normalizedQuery = query.trim().toLowerCase();
  recent
    .filter((row) => row?.repo?.toLowerCase().includes(normalizedQuery))
    .slice(0, 6)
    .forEach((row) =>
      add({
        repo: row.repo,
        source: "recent",
        product: "github",
      }),
    );

  add(searchCandidateFromInput(query));
  return rows.slice(0, 6);
}
