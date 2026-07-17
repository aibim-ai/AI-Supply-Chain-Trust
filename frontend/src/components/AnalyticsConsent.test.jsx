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
      screen.getByRole("dialog", { name: "Analytics choices" }),
    ).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Decline" }));
    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("denied");
    expect(screen.queryByRole("dialog")).toBeNull();

    openAnalyticsChoices();
    expect(await screen.findByRole("dialog")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Allow analytics" }));
    expect(localStorage.getItem(ANALYTICS_CONSENT_KEY)).toBe("granted");
  });
});
