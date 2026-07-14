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
vi.mock("../lib/api-client", () => ({ trustApi: api }));

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
      expect(screen.getByTestId("location").textContent).toBe("/r/owner/repo"),
    );
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
