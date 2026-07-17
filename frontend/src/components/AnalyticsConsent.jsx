import { useEffect, useState } from "react";
import {
  ANALYTICS_CONSENT_EVENT,
  OPEN_ANALYTICS_CHOICES_EVENT,
  getAnalyticsConsent,
  initializeGoogleConsentMode,
  setAnalyticsConsent,
} from "../lib/posthog";

export function AnalyticsConsent() {
  const [consent, setConsent] = useState(getAnalyticsConsent);
  const [open, setOpen] = useState(() => consent === "unknown");

  useEffect(() => {
    initializeGoogleConsentMode();
    const update = (event) => {
      const value = event.detail?.value || getAnalyticsConsent();
      setConsent(value);
      setOpen(false);
    };
    const show = () => setOpen(true);
    globalThis.addEventListener(ANALYTICS_CONSENT_EVENT, update);
    globalThis.addEventListener(OPEN_ANALYTICS_CHOICES_EVENT, show);
    return () => {
      globalThis.removeEventListener(ANALYTICS_CONSENT_EVENT, update);
      globalThis.removeEventListener(OPEN_ANALYTICS_CHOICES_EVENT, show);
    };
  }, []);

  if (!open) return null;
  const hasChoice = consent !== "unknown";
  return (
    <aside
      className="analytics-consent"
      role="dialog"
      aria-modal="false"
      aria-labelledby="analytics-consent-title"
      aria-describedby="analytics-consent-description"
    >
      <div className="analytics-consent-header">
        <div>
          <strong id="analytics-consent-title">Optional analytics</strong>
          <span className={`analytics-consent-status consent-${consent}`}>
            {consent === "granted"
              ? "Currently allowed"
              : consent === "denied"
                ? "Currently off"
                : "Your choice"}
          </span>
        </div>
        {hasChoice && (
          <button
            type="button"
            className="analytics-consent-close"
            aria-label="Close analytics choices"
            onClick={() => setOpen(false)}
          >
            ×
          </button>
        )}
      </div>
      <p id="analytics-consent-description">
        Google Analytics and PostHog help us improve repository scans. They stay
        off unless you allow them. Repository names, search text, findings,
        artifact URLs, and feedback messages are never sent as analytics
        properties.
      </p>
      <a className="analytics-consent-link" href="/privacy">
        Read the privacy details
      </a>
      <div className="analytics-consent-actions">
        <button
          type="button"
          className="button button-secondary"
          onClick={() => setAnalyticsConsent("denied")}
        >
          Keep analytics off
        </button>
        <button
          type="button"
          className="button button-primary"
          onClick={() => setAnalyticsConsent("granted")}
        >
          Allow optional analytics
        </button>
      </div>
      <small>Necessary site functionality remains available either way.</small>
    </aside>
  );
}
