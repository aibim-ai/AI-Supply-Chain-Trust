import { afterEach, describe, expect, it, vi } from "vitest";
import { trustApi } from "./api-client";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("trust API contract", () => {
  it("creates a context without legacy queue fields", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ status: "ready" }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetch);

    await trustApi.createContext("drupal/drupal");

    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/context",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ repo: "drupal/drupal" }),
      }),
    );
  });

  it("reports the API error message", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ error: "not found" }), { status: 404 }),
        ),
    );
    await expect(trustApi.result("missing/repo")).rejects.toThrow("not found");
  });

  it("retries transient read failures", async () => {
    vi.useFakeTimers();
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("", { status: 502 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ rows: [] }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetch);

    const request = trustApi.recent(12);
    await vi.advanceTimersByTimeAsync(250);

    await expect(request).resolves.toEqual({ rows: [] });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
