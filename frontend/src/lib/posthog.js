const IS_PRODUCTION = import.meta.env.PROD;
const POSTHOG_KEY =
  import.meta.env.VITE_POSTHOG_KEY ||
  "phc_yl2174vdp1J5ED9c27Db5cRysADLP9EflxlIm2nZPp9";
const POSTHOG_HOST =
  import.meta.env.VITE_POSTHOG_HOST || "https://eu.i.posthog.com";
const GOOGLE_TAG_MANAGER_ID =
  import.meta.env.VITE_GTM_CONTAINER_ID || "GTM-5X8L82L8";

export const ANALYTICS_CONSENT_KEY = "trust.analytics_consent";
export const ANALYTICS_CONSENT_EVENT = "ai-trust:analytics-consent";
export const OPEN_ANALYTICS_CHOICES_EVENT = "ai-trust:analytics-choices";

const EVENT_SCHEMA_VERSION = 1;
const COMMON_PROPERTIES = new Set([
  "event_schema_version",
  "surface",
  "route_template",
  "entry_mode",
  "consent_state",
]);
const EVENT_PROPERTIES = {
  repository_search_started: [
    "input_type",
    "provider_guess",
    "query_length_bucket",
    "search_surface",
  ],
  valid_repository_selected: [
    "selection_method",
    "provider",
    "existing_context",
    "candidate_position",
  ],
  scan_requested: [
    "scan_attempt_id",
    "request_origin",
    "existing_context",
    "provider",
  ],
  scan_queued: [
    "scan_attempt_id",
    "queue_latency_ms",
    "request_origin",
    "existing_context",
  ],
  fast_result_ready: [
    "scan_attempt_id",
    "time_to_fast_result_ms",
    "confidence_band",
    "coverage_band",
    "observation",
  ],
  complete_context_ready: [
    "scan_attempt_id",
    "time_to_complete_context_ms",
    "fast_result_seen",
    "coverage_band",
    "observation",
  ],
  evidence_section_viewed: ["section_name", "section_has_content"],
  review_lead_opened: [
    "lead_type",
    "lead_position_bucket",
    "evidence_tier",
    "severity_band",
    "source_section",
  ],
  json_or_markdown_downloaded: [
    "artifact_format",
    "artifact_variant",
    "source_section",
    "complete_context",
  ],
  mcp_setup_opened: [
    "mcp_client_default",
    "navigation_surface",
    "context_available",
  ],
  mcp_config_copied: ["mcp_client", "navigation_surface"],
  public_context_shared: ["share_method", "share_surface"],
  second_repository_scanned: [
    "days_since_first_scan_bucket",
    "same_session",
    "repository_ordinal",
    "second_scan_entry_mode",
  ],
  feedback_submitted: [
    "feedback_category",
    "feedback_surface",
    "has_repository_context",
    "message_length_bucket",
  ],
};

let posthogPromise;
let initializedPostHog;
let googleTagManagerInitialized = false;
let googleConsentModeInitialized = false;

export function getAnalyticsConsent() {
  try {
    const value = globalThis.localStorage?.getItem(ANALYTICS_CONSENT_KEY);
    return value === "granted" || value === "denied" ? value : "unknown";
  } catch {
    return "unknown";
  }
}

export function setAnalyticsConsent(value) {
  if (value !== "granted" && value !== "denied") return;
  try {
    globalThis.localStorage?.setItem(ANALYTICS_CONSENT_KEY, value);
  } catch {
    // Consent still applies for this page even if storage is unavailable.
  }

  initializeGoogleConsentMode();
  if (value === "denied") {
    globalThis.gtag("consent", "update", {
      analytics_storage: "denied",
      ad_storage: "denied",
      ad_user_data: "denied",
      ad_personalization: "denied",
    });
    void initializedPostHog?.then((posthog) => {
      posthog?.opt_out_capturing?.();
      posthog?.reset?.(true);
      clearAnalyticsStorage();
    });
    clearAnalyticsStorage();
  } else if (IS_PRODUCTION) {
    globalThis.gtag("consent", "update", {
      analytics_storage: "granted",
      ad_storage: "denied",
      ad_user_data: "denied",
      ad_personalization: "denied",
    });
    void initializeAnalytics();
  }

  globalThis.dispatchEvent?.(
    new globalThis.CustomEvent(ANALYTICS_CONSENT_EVENT, { detail: { value } }),
  );
}

export function openAnalyticsChoices() {
  globalThis.dispatchEvent?.(
    new globalThis.CustomEvent(OPEN_ANALYTICS_CHOICES_EVENT),
  );
}

export function initializeGoogleConsentMode() {
  if (googleConsentModeInitialized || typeof window === "undefined") return;
  globalThis.dataLayer ||= [];
  globalThis.gtag ||= function gtag() {
    globalThis.dataLayer.push(arguments);
  };
  globalThis.gtag("consent", "default", {
    analytics_storage: "denied",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
  });
  googleConsentModeInitialized = true;
}

function loadPostHog() {
  posthogPromise ??= import("posthog-js").then((module) => module.default);
  return posthogPromise;
}

function sanitizePostHogEvent(event) {
  if (!event?.properties || typeof globalThis.location === "undefined")
    return event;
  const template = routeTemplateForPath(globalThis.location.pathname);
  event.properties.$current_url = `${globalThis.location.origin}${template}`;
  event.properties.$pathname = template;
  event.properties.$initial_current_url = `${globalThis.location.origin}${template}`;
  event.properties.$session_entry_url = `${globalThis.location.origin}${template}`;
  [
    "$referrer",
    "$referring_domain",
    "$initial_referrer",
    "$initial_referring_domain",
    "$initial_referrer_info",
  ].forEach((property) => delete event.properties[property]);
  return event;
}

export function initializePostHog() {
  if (
    !IS_PRODUCTION ||
    getAnalyticsConsent() !== "granted" ||
    !POSTHOG_KEY ||
    typeof window === "undefined"
  )
    return Promise.resolve(null);

  initializedPostHog ??= loadPostHog()
    .then((posthog) => {
      if (!posthog.__loaded) {
        posthog.init(POSTHOG_KEY, {
          api_host: POSTHOG_HOST,
          autocapture: false,
          before_send: sanitizePostHogEvent,
          capture_pageview: false,
          capture_pageleave: true,
          disable_capture_url_hashes: true,
          get_current_url: () => sanitizedPageLocation(),
          persistence: "localStorage+cookie",
          save_campaign_params: false,
          save_referrer: false,
          session_recording: {
            maskAllInputs: true,
            maskTextSelector: "body",
          },
        });
      }
      posthog.opt_in_capturing?.();
      posthog.register({ app: "supply-chain-trust" });
      return posthog;
    })
    .catch(() => null);

  return initializedPostHog.then((posthog) => {
    posthog?.opt_in_capturing?.();
    return posthog;
  });
}

function analyticsCookieDomains(hostname) {
  if (!hostname || hostname === "localhost") return [""];
  const labels = hostname.split(".").filter(Boolean);
  const domains = ["", hostname, `.${hostname}`];
  for (let index = 1; index <= labels.length - 2; index += 1) {
    const parent = labels.slice(index).join(".");
    domains.push(parent, `.${parent}`);
  }
  return [...new Set(domains)];
}

function clearAnalyticsStorage() {
  if (typeof document === "undefined") return;
  const hostname = globalThis.location?.hostname || "";
  document.cookie.split(";").forEach((cookie) => {
    const name = cookie.split("=")[0].trim();
    if (
      !["_ga", "_gid", "_gat", "_gcl", "ph_"].some((prefix) =>
        name.startsWith(prefix),
      )
    )
      return;
    for (const domain of analyticsCookieDomains(hostname)) {
      document.cookie = `${name}=; Max-Age=0; path=/${domain ? `; domain=${domain}` : ""}`;
    }
  });

  for (const storageName of ["localStorage", "sessionStorage"]) {
    try {
      const storage = globalThis[storageName];
      if (!storage) continue;
      const removable = [];
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (
          key &&
          key !== ANALYTICS_CONSENT_KEY &&
          (key.startsWith("ph_") ||
            key.startsWith("__ph_") ||
            key === "trust.analytics_pageview")
        )
          removable.push(key);
      }
      removable.forEach((key) => storage.removeItem(key));
    } catch {
      // Consent remains denied when browser storage is unavailable.
    }
  }
}

function initializeGoogleTagManager() {
  if (
    googleTagManagerInitialized ||
    !IS_PRODUCTION ||
    getAnalyticsConsent() !== "granted" ||
    !GOOGLE_TAG_MANAGER_ID ||
    typeof document === "undefined"
  )
    return;

  initializeGoogleConsentMode();
  globalThis.gtag("consent", "update", {
    analytics_storage: "granted",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
  });
  globalThis.dataLayer.push({ "gtm.start": Date.now(), event: "gtm.js" });

  if (!document.getElementById("google-tag-manager-script")) {
    const script = document.createElement("script");
    script.id = "google-tag-manager-script";
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtm.js?id=${encodeURIComponent(GOOGLE_TAG_MANAGER_ID)}`;
    document.head.appendChild(script);
  }
  googleTagManagerInitialized = true;
}

export async function initializeAnalytics() {
  if (getAnalyticsConsent() !== "granted") return null;
  initializeGoogleTagManager();
  return initializePostHog();
}

export function withPostHog(callback) {
  if (!IS_PRODUCTION || getAnalyticsConsent() !== "granted") return;
  void initializePostHog().then((posthog) => {
    if (posthog?.__loaded) callback(posthog);
  });
}

export function routeTemplateForPath(pathname = "/") {
  if (/^\/r\/[^/]+\/[^/]+\/?$/.test(pathname)) return "/r/:owner/:repository";
  return pathname || "/";
}

export function analyticsSurfaceForPath(pathname = "/") {
  if (["/about", "/editorial-policy", "/privacy"].includes(pathname))
    return "legal";
  if (pathname === "/") return "marketing";
  return "repository";
}

function currentContext(properties = {}) {
  const pathname = globalThis.location?.pathname || "/";
  return {
    event_schema_version: EVENT_SCHEMA_VERSION,
    surface: analyticsSurfaceForPath(pathname),
    route_template: routeTemplateForPath(pathname),
    entry_mode: properties.entry_mode || inferEntryMode(),
    consent_state: getAnalyticsConsent(),
  };
}

function inferEntryMode() {
  try {
    return globalThis.sessionStorage?.getItem("trust.scan_attempt")
      ? "scan_flow"
      : "direct_context";
  } catch {
    return "direct_context";
  }
}

export function sanitizeAnalyticsProperties(name, properties = {}) {
  const allowed = new Set([
    ...COMMON_PROPERTIES,
    ...(EVENT_PROPERTIES[name] || []),
  ]);
  const source = { ...currentContext(properties), ...properties };
  return Object.fromEntries(
    Object.entries(source)
      .filter(([key, value]) => allowed.has(key) && value !== undefined)
      .map(([key, value]) => [key, sanitizeValue(value)]),
  );
}

function sanitizeValue(value) {
  if (typeof value === "string") return value.slice(0, 100);
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  return String(value).slice(0, 100);
}

export function captureProductEvent(name, properties = {}) {
  if (!EVENT_PROPERTIES[name] || getAnalyticsConsent() !== "granted") return;
  const safeProperties = sanitizeAnalyticsProperties(name, properties);
  withPostHog((posthog) => posthog.capture(name, safeProperties));
  if (IS_PRODUCTION) {
    initializeGoogleTagManager();
    globalThis.dataLayer?.push({ event: name, ...safeProperties });
  }
}

export function capturePageView(pathname) {
  if (getAnalyticsConsent() !== "granted") return;
  const routeTemplate = routeTemplateForPath(pathname);
  const surface = analyticsSurfaceForPath(pathname);
  let sessionEntry = false;
  try {
    sessionEntry = !globalThis.sessionStorage?.getItem(
      "trust.analytics_pageview",
    );
    globalThis.sessionStorage?.setItem("trust.analytics_pageview", "1");
  } catch {
    // Session entry is optional analytics context.
  }
  const pageLocation = `${globalThis.location?.origin || ""}${routeTemplate}`;
  const properties = {
    event_schema_version: EVENT_SCHEMA_VERSION,
    surface,
    route_template: routeTemplate,
    referrer_category: referrerCategory(),
    session_entry: sessionEntry,
    consent_state: "granted",
  };
  withPostHog((posthog) =>
    posthog.capture("$pageview", {
      ...properties,
      $current_url: pageLocation,
    }),
  );
  if (IS_PRODUCTION) {
    initializeGoogleTagManager();
    globalThis.dataLayer?.push({
      event: "page_view",
      ...properties,
      page_location: pageLocation,
      page_path: routeTemplate,
    });
  }
}

function sanitizedPageLocation() {
  const template = routeTemplateForPath(globalThis.location?.pathname || "/");
  return `${globalThis.location?.origin || ""}${template}`;
}

function referrerCategory() {
  const referrer = globalThis.document?.referrer;
  if (!referrer) return "direct";
  try {
    const hostname = new globalThis.URL(referrer).hostname.toLowerCase();
    if (hostname === globalThis.location?.hostname) return "same_origin";
    if (/google|bing|duckduckgo|yahoo|yandex/.test(hostname)) return "search";
    if (/github|gitlab|bitbucket/.test(hostname)) return "developer_platform";
    if (/linkedin|twitter|x\.com|reddit|facebook/.test(hostname))
      return "social";
    return "other_referral";
  } catch {
    return "unknown";
  }
}

export function createScanAttempt(repository, metadata = {}) {
  const attempt = {
    id: globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`,
    repository_fingerprint: fingerprintRepository(repository),
    started_at: Date.now(),
    request_origin: metadata.request_origin || "hero",
    existing_context: Boolean(metadata.existing_context),
    provider: metadata.provider || "github",
    fast_result_seen: false,
  };
  try {
    globalThis.sessionStorage?.setItem(
      "trust.scan_attempt",
      JSON.stringify(attempt),
    );
  } catch {
    // Timing correlation is best effort.
  }
  return attempt;
}

export function getScanAttempt(repository) {
  try {
    const attempt = JSON.parse(
      globalThis.sessionStorage?.getItem("trust.scan_attempt") || "null",
    );
    return attempt?.repository_fingerprint === fingerprintRepository(repository)
      ? attempt
      : null;
  } catch {
    return null;
  }
}

export function markFastResultSeen(repository) {
  const attempt = getScanAttempt(repository);
  if (!attempt) return null;
  attempt.fast_result_seen = true;
  try {
    globalThis.sessionStorage?.setItem(
      "trust.scan_attempt",
      JSON.stringify(attempt),
    );
  } catch {
    // Timing correlation is best effort.
  }
  return attempt;
}

export function recordCompletedRepository(repository) {
  const now = Date.now();
  const fingerprint = fingerprintRepository(repository);
  try {
    const state = JSON.parse(
      globalThis.localStorage?.getItem("trust.completed_repositories") || "{}",
    );
    const fingerprints = Array.isArray(state.fingerprints)
      ? state.fingerprints
      : [];
    if (!fingerprints.includes(fingerprint)) fingerprints.push(fingerprint);
    const firstCompletedAt = state.first_completed_at || now;
    const result = {
      ordinal: fingerprints.indexOf(fingerprint) + 1,
      total: fingerprints.length,
      firstCompletedAt,
      secondReported: Boolean(state.second_reported),
    };
    globalThis.localStorage?.setItem(
      "trust.completed_repositories",
      JSON.stringify({
        fingerprints: fingerprints.slice(-100),
        first_completed_at: firstCompletedAt,
        second_reported: state.second_reported || fingerprints.length >= 2,
      }),
    );
    return result;
  } catch {
    return null;
  }
}

function fingerprintRepository(value) {
  let hash = 2166136261;
  for (const character of String(value).trim().toLowerCase()) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

export function durationBucketDays(milliseconds) {
  const days = Math.max(0, milliseconds / 86400000);
  if (days < 1) return "same_day";
  if (days < 7) return "1_6_days";
  if (days < 30) return "7_29_days";
  return "30_plus_days";
}

export function lengthBucket(length) {
  if (length < 50) return "10_49";
  if (length < 200) return "50_199";
  if (length < 500) return "200_499";
  return "500_plus";
}
