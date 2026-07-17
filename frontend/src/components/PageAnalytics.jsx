import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  ANALYTICS_CONSENT_EVENT,
  analyticsSurfaceForPath,
  capturePageView,
  getAnalyticsConsent,
} from "../lib/posthog";

export function resolveAnalyticsSurface(pathname) {
  return analyticsSurfaceForPath(pathname);
}

export function PageAnalytics() {
  const location = useLocation();
  const [consent, setConsent] = useState(getAnalyticsConsent);

  useEffect(() => {
    const update = (event) =>
      setConsent(event.detail?.value || getAnalyticsConsent());
    globalThis.addEventListener(ANALYTICS_CONSENT_EVENT, update);
    return () =>
      globalThis.removeEventListener(ANALYTICS_CONSENT_EVENT, update);
  }, []);

  useEffect(() => {
    if (consent === "granted") capturePageView(location.pathname);
  }, [consent, location.pathname]);

  return null;
}
