import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { withPostHog } from "../lib/posthog";

const GOOGLE_MEASUREMENT_ID = "G-G2RHCE7GEP";

export function resolveAnalyticsSurface(pathname) {
  if (
    pathname === "/about" ||
    pathname === "/editorial-policy" ||
    pathname === "/privacy"
  )
    return "legal";
  if (pathname === "/") return "marketing";
  return "repository";
}

export function PageAnalytics() {
  const location = useLocation();
  const firstGooglePageview = useRef(true);

  useEffect(() => {
    const route = location.pathname;
    const pageUrl = `${window.location.origin}${route}${location.search}`;
    const surface = resolveAnalyticsSurface(route);

    withPostHog((posthog) => {
      posthog.register({
        app: "supply-chain-trust",
        surface,
        route,
        page_url: pageUrl,
      });
      posthog.capture("$pageview", { $current_url: pageUrl });
    });

    if (firstGooglePageview.current) {
      firstGooglePageview.current = false;
    } else if (typeof window.gtag === "function") {
      window.gtag("config", GOOGLE_MEASUREMENT_ID, {
        page_path: `${route}${location.search}`,
      });
    }
  }, [location.pathname, location.search]);

  return null;
}
