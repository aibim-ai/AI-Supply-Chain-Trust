import { describe, expect, it } from "vitest";
import {
  buildSearchCandidates,
  productForInput,
  searchCandidateFromInput,
} from "./repository-search";

describe("repository search candidates", () => {
  it("uses product icons from pasted links", () => {
    expect(productForInput("https://github.com/php/php-src").id).toBe("github");
    expect(productForInput("github.com/php/php-src").id).toBe("github");
    expect(productForInput("https://gitlab.com/gitlab-org/gitlab").id).toBe(
      "gitlab",
    );
    expect(productForInput("https://bitbucket.org/team/repo").id).toBe(
      "bitbucket",
    );
    expect(productForInput("https://www.npmjs.com/package/react").id).toBe(
      "package",
    );
    expect(productForInput("npm:react").id).toBe("package");
  });

  it("does not trust provider names embedded in an unrelated URL", () => {
    for (const input of [
      "https://github.com.attacker.example/owner/repo",
      "https://gitlab.com@attacker.example/owner/repo",
      "https://attacker.example/bitbucket.org/team/repo",
      "https://attacker.example/?package=npmjs.com/react",
    ]) {
      expect(productForInput(input).id).toBe("web");
    }
  });

  it("creates a scan candidate from a repository-like input", () => {
    expect(searchCandidateFromInput("github.com/php/php-src")?.repo).toBe(
      "php/php-src",
    );
  });

  it("merges suggestions with prior scan metrics", () => {
    const rows = buildSearchCandidates({
      query: "php",
      suggestions: [{ repo: "php/php-src", score: 81, source: "scanned" }],
      recent: [{ repo: "php/php-src", grade: "A", summary: { cves: 4 } }],
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].scanned).toBe(true);
    expect(rows[0].grade).toBe("A");
    expect(rows[0].summary.cves).toBe(4);
  });

  it("keeps scanned metrics from suggestion payloads", () => {
    const rows = buildSearchCandidates({
      query: "wolfssl",
      suggestions: [
        {
          repo: "wolfssl/wolfssl",
          score: 73,
          grade: "B",
          summary: { fixes: 10, cves: 2 },
          source: "scanned",
        },
      ],
      recent: [],
    });
    expect(rows[0].scanned).toBe(true);
    expect(rows[0].grade).toBe("B");
    expect(rows[0].summary.fixes).toBe(10);
  });
});
