import { describe, expect, it } from "vitest";
import { isRepository, normalizeRepository } from "./repository";

describe("repository input", () => {
  it("normalizes supported GitHub URL forms", () => {
    expect(normalizeRepository("https://github.com/drupal/drupal.git/")).toBe(
      "drupal/drupal",
    );
    expect(normalizeRepository(" github.com/drupal/drupal ")).toBe(
      "drupal/drupal",
    );
  });

  it("requires an owner and repository", () => {
    expect(isRepository(normalizeRepository("drupal"))).toBe(false);
    expect(isRepository(normalizeRepository("drupal/drupal"))).toBe(true);
  });
});
