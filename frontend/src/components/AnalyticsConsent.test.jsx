// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ANALYTICS_CONSENT_KEY, openAnalyticsChoices } from "../lib/posthog";
import { AnalyticsConsent } from "./AnalyticsConsent";

describe("AnalyticsConsent", () => {
  beforeEach(() => localStorage.clear());
  afterEach(cleanup);

  it("requires an explicit choice and can be reopened", async () => {
    const user = userEvent.setup();
    render(<AnalyticsConsent />);

    expect(
      screen.getByRole("dialog", { name: "Optional analytics" }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: "Close analytics choices" }),
    ).toBeNull();
    await user.click(
      screen.getByRole("button", { name: "Keep analytics off" }),
    );
    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("denied");
    expect(screen.queryByRole("dialog")).toBeNull();

    openAnalyticsChoices();
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Currently off")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Close analytics choices" }),
    ).toBeTruthy();
    await user.click(
      screen.getByRole("button", { name: "Allow optional analytics" }),
    );
    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("granted");
  });

  it("lets a returning visitor review and close the saved choice", async () => {
    localStorage.setItem(ANALYTICS_CONSENT_KEY, "granted");
    const user = userEvent.setup();
    render(<AnalyticsConsent />);

    expect(screen.queryByRole("dialog")).toBeNull();
    openAnalyticsChoices();
    expect(await screen.findByText("Currently allowed")).toBeTruthy();
    await user.click(
      screen.getByRole("button", { name: "Close analytics choices" }),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("granted");
  });
});
