// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ANALYTICS_CONSENT_EVENT,
  createScanAttempt,
  getAnalyticsConsent,
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
    createScanAttempt("owner/private-interest", { request_origin: "hero" });
    const stored = globalThis.sessionStorage.getItem("trust.scan_attempt");

    expect(stored).not.toContain("owner/private-interest");
    expect(JSON.parse(stored)).toHaveProperty("repository_fingerprint");
  });
});
