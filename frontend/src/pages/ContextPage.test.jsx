// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import ContextPage from "./ContextPage";

const api = vi.hoisted(() => ({
  context: vi.fn(),
  result: vi.fn(),
  rescan: vi.fn(),
}));
const analytics = vi.hoisted(() => ({ capture: vi.fn() }));
vi.mock("../lib/api-client", () => ({ trustApi: api }));
vi.mock("../lib/posthog", () => ({
  captureProductEvent: analytics.capture,
  createScanAttempt: vi.fn(() => ({
    id: "attempt-rescan",
    request_origin: "context_rescan",
  })),
  durationBucketDays: vi.fn(() => "same_day"),
  getAnalyticsConsent: vi.fn(() => "denied"),
  getScanAttempt: vi.fn(() => null),
  markFastResultSeen: vi.fn(() => null),
  recordCompletedRepository: vi.fn(() => null),
}));

function renderPage(path = "/r/owner/repo") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/r/:owner/:repository" element={<ContextPage />} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );
}

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location">{`${location.pathname}${location.search}`}</output>
  );
}

describe("ContextPage", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows the fast trust result while historical enrichment continues", async () => {
    api.context.mockResolvedValue({
      repo: "owner/repo",
      status: "enriching",
      scan_state: "fast_ready",
    });
    api.result.mockResolvedValue({
      repo: "owner/repo",
      trust_score: 72,
      grade: "B",
      verdict: "Review with missing evidence",
      action: "Complete missing evidence before approval",
      confidence: "low",
      evidence_coverage: 0.6,
      evaluated_at: "2026-07-12",
      decision_reasons: ["Historical evidence is incomplete."],
    });
    renderPage("/r/owner/repo?scan=running");

    expect(await screen.findByText("Fast trust result")).toBeTruthy();
    expect(screen.getByText("Historical enrichment continues")).toBeTruthy();
    expect(screen.getByText("Review with missing evidence")).toBeTruthy();
    expect(screen.getByText("72")).toBeTruthy();
    await waitFor(() =>
      expect(analytics.capture).toHaveBeenCalledWith(
        "fast_result_ready",
        expect.objectContaining({
          confidence_band: "low",
          coverage_band: "50_74",
          observation: "client_rendered",
        }),
      ),
    );
    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).toBe("/r/owner/repo"),
    );
  });

  it("tracks a complete context render without exposing the repository", async () => {
    api.context.mockResolvedValue({
      status: "ready",
      evidence_coverage: 0.8,
      context: { trust: { evidence_coverage: 0.8 } },
    });
    api.result.mockResolvedValue({});
    renderPage();

    expect(await screen.findByText("Security context")).toBeTruthy();
    await waitFor(() =>
      expect(analytics.capture).toHaveBeenCalledWith(
        "complete_context_ready",
        expect.objectContaining({
          coverage_band: "75_100",
          entry_mode: "direct_context",
        }),
      ),
    );
    const completeCall = analytics.capture.mock.calls.find(
      ([name]) => name === "complete_context_ready",
    );
    expect(completeCall[1]).not.toHaveProperty("repository");
  });

  it("shows a stable failed state without exposing retry controls", async () => {
    api.context.mockResolvedValue({
      repo: "owner/repo",
      status: "none",
      message: "No generated context exists yet.",
    });
    api.result.mockResolvedValue({});
    renderPage("/r/owner/repo?scan=failed");

    expect(await screen.findByText("Scan failed")).toBeTruthy();
    expect(
      screen.getByText("Scan stopped before a context could be published"),
    ).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });
});
