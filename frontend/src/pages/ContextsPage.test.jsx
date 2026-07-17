// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import ContextsPage from "./ContextsPage";

const api = vi.hoisted(() => ({
  recent: vi.fn(),
  jobs: vi.fn(),
  queueStats: vi.fn(),
}));

vi.mock("../lib/api-client", () => ({ trustApi: api }));

describe("ContextsPage", () => {
  beforeEach(() => {
    localStorage.clear();
    api.recent.mockResolvedValue({
      rows: [
        {
          repo: "owner/ready",
          status: "ready",
          grade: "B",
          trust_score: 75,
          summary: { fixes: 4, cves: 2 },
          evaluated_at: "2026-07-12T01:00:00Z",
        },
      ],
    });
    api.jobs.mockResolvedValue({
      jobs: [
        { id: 1, repo: "owner/one", status: "running", priority: 100 },
        { id: 2, repo: "owner/two", status: "queued", priority: 90 },
        { id: 3, repo: "owner/three", status: "queued", priority: 80 },
        { id: 4, repo: "owner/four", status: "queued", priority: 70 },
        { id: 5, repo: "owner/done", status: "completed", priority: 60 },
      ],
    });
    api.queueStats.mockResolvedValue({ pending: 3, active: 1 });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("normalizes rows and jobs envelopes into one activity list", async () => {
    render(
      <MemoryRouter>
        <ContextsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("owner/ready")).toBeTruthy();
    expect(screen.getByText("owner/one")).toBeTruthy();
    expect(screen.getByText("owner/two")).toBeTruthy();
    expect(screen.getByText("owner/three")).toBeTruthy();
    expect(screen.queryByText("owner/four")).toBeNull();
    expect(screen.getByText("owner/done")).toBeTruthy();
    expect(screen.getByText("3 queued · 1 running")).toBeTruthy();
    expect(screen.getByRole("search")).toBeTruthy();
    expect(screen.getByLabelText("Filter by status")).toBeTruthy();
  });

  it("applies status and text filters repeatedly", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ContextsPage />
      </MemoryRouter>,
    );
    await screen.findByText("owner/ready");

    const status = screen.getByRole("combobox");
    await user.selectOptions(status, "completed");
    expect(await screen.findByText("owner/done")).toBeTruthy();
    expect(screen.queryByText("owner/ready")).toBeNull();

    await user.selectOptions(status, "");
    const search = screen.getByPlaceholderText(
      "Filter repo, status, grade, verdict",
    );
    await user.type(search, "ready");
    await waitFor(() => expect(screen.getByText("owner/ready")).toBeTruthy());
    await user.clear(search);
    await user.type(search, "done");
    expect(await screen.findByText("owner/done")).toBeTruthy();

    await user.click(screen.getByLabelText("Clear search"));
    expect(search.value).toBe("");
  });
});
