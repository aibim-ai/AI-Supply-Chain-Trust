export function normalizeRepository(value) {
  const input = value.trim();
  const match =
    input.match(
      /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s]+)\/?$/i,
    ) || input.match(/^([^/\s]+)\/([^/\s]+)\/?$/);
  if (!match) return "";

  const [, owner, rawRepo] = match;
  const repo = rawRepo.replace(/\.git$/i, "");
  return /^[\w.-]+$/.test(owner) && /^[\w.-]+$/.test(repo)
    ? `${owner}/${repo}`
    : "";
}

export const isRepository = (value) => /^[\w.-]+\/[\w.-]+$/.test(value);
