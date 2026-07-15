const IS_PRODUCTION = import.meta.env.PROD;
const POSTHOG_KEY =
  import.meta.env.VITE_POSTHOG_KEY ||
  "phc_yl2174vdp1J5ED9c27Db5cRysADLP9EflxlIm2nZPp9";
const POSTHOG_HOST =
  import.meta.env.VITE_POSTHOG_HOST || "https://eu.i.posthog.com";

let posthogPromise;
let initializedPromise;

function loadPostHog() {
  posthogPromise ??= import("posthog-js").then((module) => module.default);
  return posthogPromise;
}

export function initializePostHog() {
  if (!IS_PRODUCTION || !POSTHOG_KEY || typeof window === "undefined")
    return Promise.resolve(null);

  initializedPromise ??= loadPostHog()
    .then((posthog) => {
      if (!posthog.__loaded) {
        posthog.init(POSTHOG_KEY, {
          api_host: POSTHOG_HOST,
          capture_pageview: false,
          capture_pageleave: true,
          session_recording: { maskAllInputs: true },
          persistence: "localStorage+cookie",
        });
      }
      posthog.register({ app: "supply-chain-trust" });
      return posthog;
    })
    .catch(() => null);

  return initializedPromise;
}

export function withPostHog(callback) {
  if (!IS_PRODUCTION) return;

  const run = () => {
    void initializePostHog().then((posthog) => {
      if (posthog?.__loaded) callback(posthog);
    });
  };

  if ("requestIdleCallback" in window) {
    window.requestIdleCallback(run, { timeout: 3500 });
  } else {
    window.setTimeout(run, 3000);
  }
}

export function captureProductEvent(name, properties = {}) {
  withPostHog((posthog) => posthog.capture(name, properties));
}
