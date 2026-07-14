// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import ResultPage from "./ResultPage";

const api = vi.hoisted(() => ({
  result: vi.fn(),
  history: vi.fn(),
  intelligence: vi.fn(),
}));
vi.mock("../lib/api-client", () => ({ trustApi: api }));

describe("ResultPage", () => {
  beforeEach(() => {
    api.result.mockResolvedValue({
      repo: "owner/repo",
      trust_score: 72,
      grade: "B",
      verdict: "Use with awareness",
      action: "Review evidence",
      evaluated_at: "2026-07-12",
      next_review_date: "2026-10-10",
      coverage: "2/3",
      critical_flags: [
        {
          code: "UNPINNED_ACTION",
          severity: "medium",
          message: "Pin workflow actions",
          evidence: ".github/workflows/ci.yml",
        },
      ],
      pillar_scores: {
        repository_health: {
          name: "Repository health",
          normalized: 80,
          evidence: ["Active repository"],
          concerns: [],
          unavailable: [],
        },
      },
      scanner_runs: [{ tool: "scorecard", status: "ok", detail: "available" }],
      observed_metrics: {
        scap: {
          risk_level: "medium",
          reasoning_summary: "Review workflow controls",
          attack_patterns_detected: ["dependency confusion"],
        },
      },
    });
    api.history.mockResolvedValue({
      snapshots: [
        { evaluated_at: "2026-07-11", trust_score: 70 },
        { evaluated_at: "2026-07-12", trust_score: 72 },
      ],
    });
    api.intelligence.mockResolvedValue({
      summary: "1 hit",
      hits: [
        {
          code: "CVE-2026-0001",
          severity: "high",
          source: "OSV",
          evidence: "OSV-1",
        },
      ],
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("renders decision, evidence, history, intelligence, and scanner contracts", async () => {
    render(
      <MemoryRouter initialEntries={["/?repo=owner/repo"]}>
        <ResultPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { name: "owner/repo" }),
    ).toBeTruthy();
    expect(screen.getByText("Use with awareness")).toBeTruthy();
    expect(screen.getByText("UNPINNED_ACTION")).toBeTruthy();
    expect(screen.getByText("Repository health")).toBeTruthy();
    expect(screen.getByText("dependency confusion")).toBeTruthy();
    expect(screen.getByText("CVE-2026-0001")).toBeTruthy();
    expect(screen.getByText("scorecard").closest("td")?.dataset.label).toBe(
      "Tool",
    );
  });

  it("accepts the live history array and intelligence object contracts", async () => {
    api.history.mockResolvedValue([
      { evaluated_at: "2026-07-12", trust_score: 72 },
    ]);
    api.intelligence.mockResolvedValue({
      repo: "owner/repo",
      hits: {
        cves: ["CVE-2026-0001"],
        advisories: [],
        nvd_cves: [],
        osv_vulns: [],
      },
    });

    render(
      <MemoryRouter initialEntries={["/?repo=owner/repo"]}>
        <ResultPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("CVE-2026-0001")).toBeTruthy();
    expect(screen.getByText("1 hits")).toBeTruthy();
    expect(screen.getAllByText("2026-07-12").length).toBeGreaterThan(0);
  });

  it("requires a repository query parameter", async () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <ResultPage />
      </MemoryRouter>,
    );
    expect(await screen.findByText("A repository is required.")).toBeTruthy();
  });
});
