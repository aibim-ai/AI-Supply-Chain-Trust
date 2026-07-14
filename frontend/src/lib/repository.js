export function normalizeRepository(value) {
  return value
    .trim()
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/^github\.com\//i, "")
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/, "")
    .split("/")
    .slice(0, 2)
    .join("/");
}

export const isRepository = (value) => value.split("/").length === 2;
