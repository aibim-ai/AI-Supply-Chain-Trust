// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from "vitest";
import {
  PRODUCTION_ORIGIN,
  absoluteUrl,
  applyDocumentMeta,
  pageTitle,
  repositoryJsonLd,
  safeUrl,
  siteOrigin,
  websiteJsonLd,
} from "./seo";

const head = () => document.head;
const select = (selector) => Array.from(head().querySelectorAll(selector));
const content = (selector) => select(selector)[0]?.getAttribute("content");

describe("document metadata", () => {
  beforeEach(() => {
    head().innerHTML = "";
    document.title = "AI Supply Chain Trust";
  });

  it("derives absolute URLs from the browser origin and falls back to production", () => {
    expect(siteOrigin()).toBe(globalThis.window.location.origin);
    expect(absoluteUrl("/leaderboard")).toBe(`${siteOrigin()}/leaderboard`);
    expect(absoluteUrl("leaderboard")).toBe(`${siteOrigin()}/leaderboard`);
    expect(absoluteUrl(`${PRODUCTION_ORIGIN}/about`)).toBe(
      `${PRODUCTION_ORIGIN}/about`,
    );
    expect(pageTitle("Privacy")).toBe("Privacy | AI Supply Chain Trust");
    expect(pageTitle("")).toBe("AI Supply Chain Trust");
  });

  it("creates the full tag set once and rewrites it in place on navigation", () => {
    applyDocumentMeta({
      title: "First | AI Supply Chain Trust",
      description: "First description",
      path: "/contexts",
    });
    applyDocumentMeta({
      title: "Second | AI Supply Chain Trust",
      description: "Second description",
      path: "/leaderboard",
      type: "article",
    });

    expect(document.title).toBe("Second | AI Supply Chain Trust");
    for (const selector of [
      'link[rel="canonical"]',
      'meta[name="description"]',
      'meta[property="og:title"]',
      'meta[property="og:description"]',
      'meta[property="og:url"]',
      'meta[property="og:type"]',
      'meta[property="og:site_name"]',
      'meta[name="twitter:card"]',
      'meta[name="twitter:title"]',
      'meta[name="twitter:description"]',
    ])
      expect(select(selector)).toHaveLength(1);

    expect(content('meta[name="description"]')).toBe("Second description");
    expect(select('link[rel="canonical"]')[0].getAttribute("href")).toBe(
      `${siteOrigin()}/leaderboard`,
    );
    expect(content('meta[property="og:url"]')).toBe(
      `${siteOrigin()}/leaderboard`,
    );
    expect(content('meta[property="og:type"]')).toBe("article");
    expect(content('meta[property="og:site_name"]')).toBe(
      "AI Supply Chain Trust",
    );
    expect(content('meta[name="twitter:title"]')).toBe(
      "Second | AI Supply Chain Trust",
    );
  });

  it("reuses server-injected tags instead of appending a second copy", () => {
    head().innerHTML = `
      <meta name="description" content="server description" />
      <link rel="canonical" href="https://ai-supply-chain-trust.aibim.ai/stale" />
      <meta property="og:title" content="server title" />
      <meta property="og:title" content="server duplicate" />
      <script type="application/ld+json">{"@type":"WebSite"}</script>
    `;

    applyDocumentMeta({
      title: "Client | AI Supply Chain Trust",
      description: "client description",
      path: "/",
      jsonLd: { "@context": "https://schema.org", "@type": "WebSite" },
    });

    expect(select('meta[name="description"]')).toHaveLength(1);
    expect(content('meta[name="description"]')).toBe("client description");
    expect(select('link[rel="canonical"]')).toHaveLength(1);
    expect(select('link[rel="canonical"]')[0].getAttribute("href")).toBe(
      `${siteOrigin()}/`,
    );
    expect(select('meta[property="og:title"]')).toHaveLength(1);
    expect(content('meta[property="og:title"]')).toBe(
      "Client | AI Supply Chain Trust",
    );
    expect(select('script[type="application/ld+json"]')).toHaveLength(1);
    expect(
      select('script[type="application/ld+json"]')[0].getAttribute("data-seo"),
    ).toBe("route");
  });

  it("removes structured data and robots directives when a route omits them", () => {
    applyDocumentMeta({
      title: "Home",
      description: "home",
      path: "/",
      robots: "noindex, follow",
      jsonLd: websiteJsonLd({ description: "home" }),
    });
    expect(select('script[type="application/ld+json"]')).toHaveLength(1);
    expect(
      JSON.parse(select('script[type="application/ld+json"]')[0].textContent),
    ).toHaveLength(2);
    expect(content('meta[name="robots"]')).toBe("noindex, follow");

    applyDocumentMeta({
      title: "Privacy",
      description: "privacy",
      path: "/privacy",
    });
    expect(select('script[type="application/ld+json"]')).toHaveLength(0);
    expect(select('meta[name="robots"]')).toHaveLength(0);
  });

  it("describes a repository verdict only with values present in the payload", () => {
    const url = `${PRODUCTION_ORIGIN}/r/owner/repo`;
    const loading = repositoryJsonLd({ repository: "owner/repo", url });
    expect(loading["@type"]).toBe("SoftwareSourceCode");
    expect(loading.codeRepository).toBe("https://github.com/owner/repo");
    expect(loading.subjectOf).toBeUndefined();
    expect(loading.description).toBeUndefined();

    const loaded = repositoryJsonLd({
      repository: "owner/repo",
      url,
      description: "Review with known gaps",
      score: 72.4,
      grade: "B",
      verdict: "Review with known gaps",
      action: "Complete missing evidence",
      evaluatedAt: "2026-07-12",
    });
    expect(loaded.subjectOf.reviewRating).toEqual({
      "@type": "Rating",
      ratingValue: 72,
      bestRating: 100,
      worstRating: 0,
      alternateName: "B",
    });
    expect(loaded.subjectOf.datePublished).toBe("2026-07-12");
    expect(loaded.subjectOf.reviewBody).toBe(
      "Review with known gaps — Complete missing evidence",
    );
  });
});

describe("safeUrl", () => {
  it("keeps http(s) URLs and normalizes relative paths against the origin", () => {
    expect(safeUrl("https://example.test/r/a/b")).toBe(
      "https://example.test/r/a/b",
    );
    expect(safeUrl("/r/owner/repo", "https://example.test")).toBe(
      "https://example.test/r/owner/repo",
    );
  });

  it("refuses every non-http(s) scheme reaching the canonical href", () => {
    // `<link rel=canonical>` is not user-navigable, but the sink is an href
    // attribute and must not accept a script-bearing scheme on any path.
    for (const hostile of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      "data:text/html;base64,PHNjcmlwdD4=",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
    ]) {
      expect(safeUrl(hostile, "https://example.test")).toBe(
        "https://example.test/",
      );
    }
  });

  it("falls back to the origin for unparseable input", () => {
    expect(safeUrl(null, "https://example.test")).toBe("https://example.test/");
    expect(safeUrl("http://", "https://example.test")).toBe(
      "https://example.test/",
    );
  });

  it("never returns a non-http(s) URL through absoluteUrl", () => {
    expect(absoluteUrl("javascript:alert(1)")).not.toMatch(/^javascript:/i);
  });
});
