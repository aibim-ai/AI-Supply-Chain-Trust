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
