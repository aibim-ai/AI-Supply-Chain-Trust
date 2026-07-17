// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import HomePage from "./HomePage";

const api = vi.hoisted(() => ({
  recent: vi.fn(),
  suggest: vi.fn(),
  rescan: vi.fn(),
}));
const analytics = vi.hoisted(() => ({
  capture: vi.fn(),
  createAttempt: vi.fn(() => ({
    id: "attempt-1",
    request_origin: "hero",
    provider: "github",
  })),
}));

vi.mock("../lib/api-client", () => ({ trustApi: api }));
vi.mock("../lib/posthog", () => ({
  captureProductEvent: analytics.capture,
  createScanAttempt: analytics.createAttempt,
}));
vi.mock("../components/ScanHeroBackground", () => ({
  default: () => <div data-testid="hero-background" />,
}));

describe("HomePage", () => {
  beforeEach(() => {
    localStorage.clear();
    api.recent.mockResolvedValue({ rows: [] });
    api.suggest.mockResolvedValue({
      candidates: [
        {
          repo: "r1z4x/OWASPAttackSimulator",
          score: 35,
          grade: "F",
          summary: { fixes: 2, cves: 1 },
        },
        { repo: "r1z4x/another-repo", stars: 10 },
      ],
    });
    api.rescan.mockResolvedValue({ status: "queued", job_id: 77 });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("explains the progressive evidence and bounded LLM pipeline", async () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    expect(
      screen.getByRole("heading", {
        name: "From repository to trusted context.",
      }),
    ).toBeTruthy();
    expect(screen.getByRole("list", { name: "Trust pipeline" })).toBeTruthy();
    expect(screen.getByText("Bounded LLM assist")).toBeTruthy();
    expect(screen.getByText("Optional")).toBeTruthy();
    expect(screen.getByText("Web · JSON · MCP")).toBeTruthy();
  });

  it("opens an existing context without queueing a duplicate scan", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route
            path="/r/:owner/:repo"
            element={<div>Scan detail route</div>}
          />
        </Routes>
      </MemoryRouter>,
    );

    const input = screen.getByPlaceholderText(
      "Paste a public GitHub URL or owner/repo",
    );
    await user.type(input, "r1z4x");
    const result = await screen.findByText("r1z4x/OWASPAttackSimulator");

    expect(screen.getByRole("listbox")).toBeTruthy();
    expect(screen.getByText("score 35 · 2 fixes · 1 CVEs")).toBeTruthy();
    await user.click(result);

    expect(api.rescan).not.toHaveBeenCalled();
    expect(await screen.findByText("Scan detail route")).toBeTruthy();
  });

  it("queues a repository that has no existing context", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route
            path="/r/:owner/:repo"
            element={<div>Scan detail route</div>}
          />
        </Routes>
      </MemoryRouter>,
    );

    const input = screen.getByPlaceholderText(
      "Paste a public GitHub URL or owner/repo",
    );
    await user.type(input, "another");
    await user.click(await screen.findByText("r1z4x/another-repo"));

    await waitFor(() =>
      expect(api.rescan).toHaveBeenCalledWith("r1z4x/another-repo"),
    );
    expect(analytics.capture).toHaveBeenCalledWith(
      "valid_repository_selected",
      expect.objectContaining({
        selection_method: "suggestion",
        existing_context: false,
      }),
    );
    expect(analytics.capture).toHaveBeenCalledWith(
      "scan_requested",
      expect.objectContaining({ scan_attempt_id: "attempt-1" }),
    );
    expect(analytics.capture).toHaveBeenCalledWith(
      "scan_queued",
      expect.objectContaining({ scan_attempt_id: "attempt-1" }),
    );
    expect(
      analytics.capture.mock.calls.some(([, properties]) =>
        Object.hasOwn(properties || {}, "repository"),
      ),
    ).toBe(false);
    expect(await screen.findByText("Scan detail route")).toBeTruthy();
  });

  it("renders cached public contexts when the initial request fails", async () => {
    localStorage.setItem(
      "trust.home.recent",
      JSON.stringify({
        rows: [
          {
            repo: "owner/cached",
            grade: "B",
            verdict: "Use with awareness",
            evaluated_at: "2026-07-12T01:00:00Z",
          },
        ],
      }),
    );
    api.recent.mockRejectedValue(new Error("temporary upstream failure"));

    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("owner/cached")).toBeTruthy();
    expect(
      screen.getByText("Live data is retrying in the background."),
    ).toBeTruthy();
  });
});
