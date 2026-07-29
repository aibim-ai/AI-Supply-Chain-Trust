import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test.use({ viewport: { width: 390, height: 844 } });

test("public home release is accessible and exposes mobile navigation", async ({
  page,
}) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await expect(
    page.getByRole("heading", {
      name: "Paste a repo. See the evidence, the gaps, and where review should start.",
    }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Toggle menu" }).click();
  await expect(page.locator("nav.mobile-nav")).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact),
    ),
  ).toEqual([]);
});
