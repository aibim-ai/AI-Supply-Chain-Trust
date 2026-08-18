// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import LeaderboardPage from "./LeaderboardPage";
import LegalPage from "./LegalPage";
import NotFoundPage from "./NotFoundPage";

const api = vi.hoisted(() => ({ leaderboard: vi.fn() }));
vi.mock("../lib/api-client", () => ({ trustApi: api }));

describe("secondary pages", () => {
  beforeEach(() => {
    api.leaderboard.mockResolvedValue({
      rows: [
        {
          repo: "owner/repo",
          grade: "B",
          trust_score: 72.4,
          verdict: "Review with known gaps",
          evidence_coverage: 0.47,
          evaluated_at: "2026-07-12T01:00:00Z",
          next_review_date: "2026-10-12",
        },
      ],
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("loads leaderboard rows and refetches for the entered filter", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <LeaderboardPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("owner/repo")).toBeTruthy();
    expect(screen.getByText("72/100")).toBeTruthy();
    await user.type(screen.getByPlaceholderText("Filter repositories"), "own");
    await waitFor(() =>
      expect(api.leaderboard).toHaveBeenLastCalledWith("own"),
    );
  });

  it("reports the evidence coverage and review age the score is read against", async () => {
    render(
      <MemoryRouter>
        <LeaderboardPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("owner/repo")).toBeTruthy();
    expect(screen.getByText("47%")).toBeTruthy();
    expect(screen.getByText("of evidence pillars observed")).toBeTruthy();
    expect(screen.getByText("2026-07-12")).toBeTruthy();
    expect(screen.getByText(/next review 2026-10-12/).textContent).toContain(
      "days ago",
    );
    expect(
      screen.getByRole("columnheader", { name: "Evidence coverage" }),
    ).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Reviewed" })).toBeTruthy();
    expect(document.title).toBe(
      "Repository trust leaderboard | AI Supply Chain Trust",
    );
  });

  it("renders an evidence-anchored score only when the row carries one", async () => {
    api.leaderboard.mockResolvedValue({
      rows: [
        { repo: "owner/plain", grade: "A", trust_score: 100 },
        {
          repo: "owner/anchored",
          grade: "A",
          trust_score: 100,
          evidence_anchored_score: 47,
        },
      ],
    });
    render(
      <MemoryRouter>
        <LeaderboardPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("owner/plain")).toBeTruthy();
    expect(screen.getAllByText("100/100")).toHaveLength(2);
    expect(screen.getAllByText("47/100 evidence-anchored")).toHaveLength(1);
    expect(screen.getAllByText("Not reported")).toHaveLength(2);
    expect(screen.getAllByText("Not recorded")).toHaveLength(2);
  });

  it.each([
    ["about", "About"],
    ["policy", "Editorial policy"],
    ["privacy", "Privacy"],
  ])("renders the %s legal contract", (type, title) => {
    render(<LegalPage type={type} />);
    expect(screen.getByRole("heading", { name: title })).toBeTruthy();
  });

  it("renders a usable not-found route", () => {
    render(
      <MemoryRouter>
        <NotFoundPage />
      </MemoryRouter>,
    );
    expect(screen.getByText("Page not found")).toBeTruthy();
    expect(
      screen.getByRole("link", { name: "Return home" }).getAttribute("href"),
    ).toBe("/");
  });
});
