const API_ROOT = "/api/v1";
const TRANSIENT_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const RETRY_DELAYS_MS = [250, 750, 1500, 3000, 5000];

async function request(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const retryable = method === "GET";
  let lastError;

  for (
    let attempt = 0;
    attempt <= (retryable ? RETRY_DELAYS_MS.length : 0);
    attempt += 1
  ) {
    try {
      const response = await fetch(path, {
        ...options,
        headers: { Accept: "application/json", ...options.headers },
      });
      const payload = await response.json().catch(() => null);
      if (response.ok) return payload;

      const error = new Error(
        payload?.error || `Request failed (${response.status})`,
      );
      error.status = response.status;
      if (
        !retryable ||
        !TRANSIENT_STATUS.has(response.status) ||
        attempt === RETRY_DELAYS_MS.length
      )
        throw error;
      lastError = error;
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      if (error?.status && !TRANSIENT_STATUS.has(error.status)) throw error;
      if (!retryable || attempt === RETRY_DELAYS_MS.length) throw error;
      lastError = error;
    }
    await wait(RETRY_DELAYS_MS[attempt], options.signal);
  }

  throw lastError;
}

function wait(ms, signal) {
  if (signal?.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const timer = globalThis.setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        globalThis.clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}

const jsonPost = (path, body) =>
  request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export const trustApi = {
  recent: (limit = 80) => request(`${API_ROOT}/recent-scans?limit=${limit}`),
  jobs: (limit = 100) => request(`${API_ROOT}/jobs?limit=${limit}`),
  queueStats: () => request(`${API_ROOT}/queue/stats`),
  failures: (status = "open", limit = 50) =>
    request(
      `${API_ROOT}/ops/failures?status=${encodeURIComponent(status)}&limit=${limit}`,
    ),
  leaderboard: (query = "") =>
    request(
      `${API_ROOT}/leaderboard${query ? `?q=${encodeURIComponent(query)}` : ""}`,
    ),
  suggest: (query) =>
    request(`${API_ROOT}/suggest?q=${encodeURIComponent(query)}`),
  context: (repo) =>
    request(
      `${API_ROOT}/context/${encodeURIComponent(repo).replace(/%2F/g, "/")}`,
    ),
  result: (repo) =>
    request(`${API_ROOT}/result?repo=${encodeURIComponent(repo)}`),
  history: (repo) =>
    request(`${API_ROOT}/history?repo=${encodeURIComponent(repo)}`),
  intelligence: (repo) =>
    request(`${API_ROOT}/intel/hits?repo=${encodeURIComponent(repo)}`),
  createContext: (repo) => jsonPost(`${API_ROOT}/context`, { repo }),
  scan: (repo) => jsonPost(`${API_ROOT}/scan`, { repo }),
  rescan: (repo) =>
    jsonPost(`${API_ROOT}/queue/rescan`, { repo, priority: 100 }),
  feedback: (payload) => jsonPost(`${API_ROOT}/feedback`, payload),
};
