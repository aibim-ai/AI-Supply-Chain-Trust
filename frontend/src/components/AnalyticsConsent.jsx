import { useEffect, useState } from "react";
import {
  ANALYTICS_CONSENT_EVENT,
  OPEN_ANALYTICS_CHOICES_EVENT,
  getAnalyticsConsent,
  setAnalyticsConsent,
} from "../lib/posthog";

export function AnalyticsConsent() {
  const [consent, setConsent] = useState(getAnalyticsConsent);
  const [open, setOpen] = useState(() => consent === "unknown");

  useEffect(() => {
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
  return (
    <aside
      className="analytics-consent"
      role="dialog"
      aria-modal="false"
      aria-labelledby="analytics-consent-title"
    >
      <div>
        <strong id="analytics-consent-title">Analytics choices</strong>
        <p>
          Optional Google Analytics and PostHog data helps us improve repository
          scans. Repository names, search text, findings, and feedback messages
          are not sent as analytics properties.
        </p>
      </div>
      <div className="analytics-consent-actions">
        <button
          type="button"
          className="button button-secondary"
          onClick={() => setAnalyticsConsent("denied")}
        >
          Decline
        </button>
        <button
          type="button"
          className="button button-primary"
          onClick={() => setAnalyticsConsent("granted")}
        >
          Allow analytics
        </button>
      </div>
      {consent !== "unknown" && (
        <small>
          Current choice: {consent === "granted" ? "allowed" : "declined"}
        </small>
      )}
    </aside>
  );
}
