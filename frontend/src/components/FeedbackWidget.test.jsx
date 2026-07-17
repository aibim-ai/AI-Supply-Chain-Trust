// @vitest-environment jsdom

import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  FeedbackWidget,
  OPEN_FEEDBACK_EVENT,
  openFeedback,
} from "./FeedbackWidget";

const api = vi.hoisted(() => ({ feedback: vi.fn() }));
const analytics = vi.hoisted(() => ({ capture: vi.fn() }));

vi.mock("../lib/api-client", () => ({ trustApi: api }));
vi.mock("../lib/posthog", async (importOriginal) => ({
  ...(await importOriginal()),
  captureProductEvent: analytics.capture,
}));

describe("FeedbackWidget", () => {
  beforeEach(() => api.feedback.mockResolvedValue({ status: "accepted" }));

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("submits repository feedback and clears the form", async () => {
    const user = userEvent.setup();
    render(<FeedbackWidget />);

    openFeedback("owner/repository");
    expect(await screen.findByText("owner/repository")).toBeTruthy();
    await user.selectOptions(screen.getByLabelText("Category"), "bug");
    await user.type(
      screen.getByLabelText("Message"),
      "The CVE evidence is missing from this result.",
    );
    fireEvent.submit(screen.getByRole("dialog").querySelector("form"));

    await waitFor(() =>
      expect(api.feedback).toHaveBeenCalledWith({
        category: "bug",
        message: "The CVE evidence is missing from this result.",
        website: "",
        repo: "owner/repository",
        page: "/",
      }),
    );
    expect(
      await screen.findByText("Thanks — your feedback was sent."),
    ).toBeTruthy();
    expect(screen.getByLabelText("Message").value).toBe("");
    expect(analytics.capture).toHaveBeenCalledWith("feedback_submitted", {
      feedback_category: "bug",
      feedback_surface: "marketing",
      has_repository_context: true,
      message_length_bucket: "10_49",
    });
  });

  it("reports submission errors and supports every close path", async () => {
    const user = userEvent.setup();
    api.feedback.mockImplementationOnce(() => {
      throw new Error("Feedback service unavailable");
    });
    render(<FeedbackWidget />);

    await user.click(screen.getByLabelText("Send feedback"));
    await user.type(
      screen.getByLabelText("Message"),
      "A reproducible UI issue.",
    );
    fireEvent.submit(screen.getByRole("dialog").querySelector("form"));
    expect(
      await screen.findByText("Feedback service unavailable"),
    ).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();

    globalThis.dispatchEvent(new globalThis.CustomEvent(OPEN_FEEDBACK_EVENT));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(globalThis, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();

    openFeedback();
    const backdrop = (await screen.findByRole("dialog")).parentElement;
    fireEvent.mouseDown(backdrop);
    expect(screen.queryByRole("dialog")).toBeNull();

    openFeedback();
    await user.click(await screen.findByLabelText("Close feedback"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
