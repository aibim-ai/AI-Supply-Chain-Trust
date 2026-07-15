// @vitest-environment jsdom

import { describe, expect, it } from "vitest";
import { resolveAnalyticsSurface } from "./PageAnalytics";

describe("PageAnalytics", () => {
  it.each([
    ["/", "marketing"],
    ["/privacy", "legal"],
    ["/contexts", "repository"],
    ["/r/aibim-ai/AI-Repo-Trust", "repository"],
  ])("maps %s to the %s analytics surface", (pathname, surface) => {
    expect(resolveAnalyticsSurface(pathname)).toBe(surface);
  });
});
