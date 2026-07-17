// @vitest-environment jsdom

import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ContextReport } from "./ContextReport";

const analytics = vi.hoisted(() => ({ capture: vi.fn() }));
vi.mock("../../lib/posthog", () => ({
  captureProductEvent: analytics.capture,
}));

const payload = {
  status: "ready",
  artifacts: {
    security_context_json: "/r/example/repo.json",
    vulnerability_leads_md: "/r/example/repo.leads.md",
  },
  leads: {
    leads: [
      {
        rank: 1,
        component: "parser",
        why: "Review parser boundaries.",
        vulnerability_class: "Input validation",
        evidence_tier: "e3",
        severity: "high",
      },
    ],
  },
  context: { trust: {}, fingerprints: [], known_cves: [], watchlist: [] },
};

describe("ContextReport analytics", () => {
  beforeEach(() => {
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("tracks share, artifact download, and a specific review lead safely", async () => {
    const user = userEvent.setup();
    render(<ContextReport repository="example/repo" payload={payload} />);

    await user.click(screen.getByRole("button", { name: "Copy public link" }));
    expect(analytics.capture).toHaveBeenCalledWith("public_context_shared", {
      share_method: "copy_link",
      share_surface: "context_title_actions",
    });

    const artifactLink = screen.getAllByLabelText("security context json")[0];
    artifactLink.addEventListener("click", (event) => event.preventDefault(), {
      once: true,
    });
    fireEvent.click(artifactLink);
    expect(analytics.capture).toHaveBeenCalledWith(
      "json_or_markdown_downloaded",
      {
        artifact_format: "json",
        artifact_variant: "security_context",
        source_section: "context_report",
        complete_context: true,
      },
    );

    await user.click(screen.getByText("parser"));
    await waitFor(() =>
      expect(analytics.capture).toHaveBeenCalledWith("review_lead_opened", {
        lead_type: "ranked_review",
        lead_position_bucket: "top_3",
        evidence_tier: "e3",
        severity_band: "high",
        source_section: "ranked_review_leads",
      }),
    );
    expect(
      analytics.capture.mock.calls.some(([, properties]) =>
        Object.hasOwn(properties || {}, "repository"),
      ),
    ).toBe(false);
  });

  it("tracks evidence only after a section remains visible", () => {
    vi.useFakeTimers();
    let observerCallback;
    const unobserve = vi.fn();
    vi.stubGlobal(
      "IntersectionObserver",
      class IntersectionObserver {
        constructor(callback) {
          observerCallback = callback;
        }
        observe() {}
        unobserve(target) {
          unobserve(target);
        }
        disconnect() {}
      },
    );
    render(<ContextReport repository="example/repo" payload={payload} />);
    const section = document.querySelector(
      '[data-analytics-section="review_leads"]',
    );

    act(() => {
      observerCallback([
        { target: section, isIntersecting: true, intersectionRatio: 0.5 },
      ]);
      vi.advanceTimersByTime(1000);
    });

    expect(analytics.capture).toHaveBeenCalledWith("evidence_section_viewed", {
      section_name: "review_leads",
      section_has_content: true,
    });
    expect(unobserve).toHaveBeenCalledWith(section);
  });
});
