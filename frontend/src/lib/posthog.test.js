// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ANALYTICS_CONSENT_EVENT,
  ANALYTICS_CONSENT_KEY,
  OPEN_ANALYTICS_CHOICES_EVENT,
  analyticsSurfaceForPath,
  capturePageView,
  captureProductEvent,
  createScanAttempt,
  durationBucketDays,
  getScanAttempt,
  getAnalyticsConsent,
  initializeGoogleConsentMode,
  initializeAnalytics,
  lengthBucket,
  markFastResultSeen,
  openAnalyticsChoices,
  recordCompletedRepository,
  routeTemplateForPath,
  sanitizeAnalyticsProperties,
  setAnalyticsConsent,
} from "./posthog";

describe("analytics privacy and local state", () => {
  beforeEach(() => {
    localStorage.clear();
    globalThis.sessionStorage.clear();
  });

  it("templates repository routes and strips disallowed sensitive properties", () => {
    expect(routeTemplateForPath("/r/private-owner/secret-name")).toBe(
      "/r/:owner/:repository",
    );

    const properties = sanitizeAnalyticsProperties("scan_queued", {
      scan_attempt_id: "attempt-1",
      queue_latency_ms: 42,
      request_origin: "hero",
      repository: "private-owner/secret-name",
      job_id: 99,
      cve_id: "CVE-2026-0001",
      feedback_message: "do not collect",
    });

    expect(properties).toMatchObject({
      event_schema_version: 1,
      scan_attempt_id: "attempt-1",
      queue_latency_ms: 42,
      request_origin: "hero",
    });
    expect(properties).not.toHaveProperty("repository");
    expect(properties).not.toHaveProperty("job_id");
    expect(properties).not.toHaveProperty("cve_id");
    expect(properties).not.toHaveProperty("feedback_message");
  });

  it("persists and broadcasts analytics consent", () => {
    const listener = vi.fn();
    globalThis.addEventListener(ANALYTICS_CONSENT_EVENT, listener);
    setAnalyticsConsent("denied");

    expect(getAnalyticsConsent()).toBe("denied");
    expect(listener).toHaveBeenCalledOnce();
    expect(listener.mock.calls[0][0].detail.value).toBe("denied");
    globalThis.removeEventListener(ANALYTICS_CONSENT_EVENT, listener);
  });

  it("defaults vendor consent to denied and clears analytics storage", () => {
    initializeGoogleConsentMode();
    const defaultConsent = globalThis.dataLayer.find(
      (entry) => entry?.[0] === "consent" && entry?.[1] === "default",
    );
    expect(defaultConsent?.[2]).toMatchObject({
      analytics_storage: "denied",
      ad_storage: "denied",
      ad_user_data: "denied",
      ad_personalization: "denied",
    });

    localStorage.setItem("ph_example", "vendor-state");
    globalThis.sessionStorage.setItem("trust.analytics_pageview", "1");
    setAnalyticsConsent("denied");

    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("denied");
    expect(localStorage.getItem("ph_example")).toBeNull();
    expect(
      globalThis.sessionStorage.getItem("trust.analytics_pageview"),
    ).toBeNull();
  });

  it("detects a second distinct repository without storing raw names", () => {
    const first = recordCompletedRepository("owner/first-repo");
    const second = recordCompletedRepository("owner/second-repo");
    const stored = localStorage.getItem("trust.completed_repositories");

    expect(first.total).toBe(1);
    expect(second.total).toBe(2);
    expect(second.secondReported).toBe(false);
    expect(stored).not.toContain("owner/first-repo");
    expect(stored).not.toContain("owner/second-repo");
  });

  it("keeps scan correlation without storing a raw repository", () => {
    const attempt = createScanAttempt("owner/private-interest", {
      request_origin: "hero",
    });
    const stored = globalThis.sessionStorage.getItem("trust.scan_attempt");

    expect(stored).not.toContain("owner/private-interest");
    expect(JSON.parse(stored)).toHaveProperty("repository_fingerprint");
    expect(getScanAttempt("owner/private-interest")).toMatchObject({
      id: attempt.id,
      fast_result_seen: false,
    });
    expect(getScanAttempt("owner/different")).toBeNull();
    expect(markFastResultSeen("owner/private-interest")).toMatchObject({
      fast_result_seen: true,
    });
    expect(markFastResultSeen("owner/different")).toBeNull();
  });

  it("classifies routes, durations, and message lengths at boundaries", () => {
    expect(routeTemplateForPath("/leaderboard")).toBe("/leaderboard");
    expect(analyticsSurfaceForPath("/")).toBe("marketing");
    expect(analyticsSurfaceForPath("/privacy")).toBe("legal");
    expect(analyticsSurfaceForPath("/contexts")).toBe("repository");

    expect(durationBucketDays(0)).toBe("same_day");
    expect(durationBucketDays(86400000)).toBe("1_6_days");
    expect(durationBucketDays(7 * 86400000)).toBe("7_29_days");
    expect(durationBucketDays(30 * 86400000)).toBe("30_plus_days");
    expect(lengthBucket(49)).toBe("10_49");
    expect(lengthBucket(50)).toBe("50_199");
    expect(lengthBucket(200)).toBe("200_499");
    expect(lengthBucket(500)).toBe("500_plus");
  });

  it("covers consented page analytics without loading vendors in tests", async () => {
    const choices = vi.fn();
    globalThis.addEventListener(OPEN_ANALYTICS_CHOICES_EVENT, choices);

    setAnalyticsConsent("invalid");
    expect(getAnalyticsConsent()).toBe("unknown");
    captureProductEvent("scan_queued", { queue_latency_ms: 10 });
    capturePageView("/r/owner/repository");

    setAnalyticsConsent("granted");
    captureProductEvent("unknown_event", { repository: "owner/repository" });
    captureProductEvent("scan_queued", {
      queue_latency_ms: 10,
      request_origin: "hero",
    });
    capturePageView("/r/owner/repository");
    capturePageView("/contexts");
    await expect(initializeAnalytics()).resolves.toBeNull();

    openAnalyticsChoices();
    expect(choices).toHaveBeenCalledOnce();
    expect(globalThis.sessionStorage.getItem("trust.analytics_pageview")).toBe(
      "1",
    );
    globalThis.removeEventListener(OPEN_ANALYTICS_CHOICES_EVENT, choices);
  });

  it("sanitizes unexpected values and tolerates malformed local state", () => {
    setAnalyticsConsent("granted");
    const properties = sanitizeAnalyticsProperties("scan_queued", {
      scan_attempt_id: "x".repeat(120),
      queue_latency_ms: Number.NaN,
      existing_context: true,
      request_origin: { source: "hero" },
    });

    expect(properties.scan_attempt_id).toHaveLength(100);
    expect(properties.queue_latency_ms).toBe(0);
    expect(properties.existing_context).toBe(true);
    expect(properties.request_origin).toBe("[object Object]");

    globalThis.sessionStorage.setItem("trust.scan_attempt", "not-json");
    localStorage.setItem("trust.completed_repositories", "not-json");
    expect(getScanAttempt("owner/repository")).toBeNull();
    expect(recordCompletedRepository("owner/repository")).toBeNull();
  });
});
