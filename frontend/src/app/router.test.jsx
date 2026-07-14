// @vitest-environment jsdom

import { describe, expect, it } from "vitest";
import { router } from "./router";

describe("browser router contract", () => {
  it("registers every supported public SPA path and the fallback", () => {
    const children = router.routes[0].children;
    expect(children.map((route) => route.path || "index")).toEqual([
      "index",
      "contexts",
      "recent-scans",
      "leaderboard",
      "result",
      "r/:owner/:repository",
      "about",
      "editorial-policy",
      "privacy",
      "*",
    ]);
    expect(router.basename).toBe("/");
  });
});
