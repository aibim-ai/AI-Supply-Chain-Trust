import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function stubApi(page, { rescanStatus = 200 } = {}) {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.pathname === "/api/v1/events") return route.abort();
    if (url.pathname === "/api/v1/recent-scans")
      return route.fulfill({ json: { rows: [] } });
    if (url.pathname === "/api/v1/suggest")
      return route.fulfill({ json: { candidates: [] } });
    if (
      url.pathname === "/api/v1/queue/rescan" &&
      request.method() === "POST"
    ) {
      return route.fulfill({
        status: rescanStatus,
        json:
          rescanStatus < 400
            ? { status: "queued", job_id: 1 }
            : { error: "Queue temporarily unavailable" },
      });
    }
    return route.fulfill({ status: 404, json: { error: "Not stubbed" } });
  });
}

test("homepage has no serious or critical axe violations", async ({ page }) => {
  await stubApi(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", {
      name: "Paste a repo. See the evidence, the gaps, and where review should start.",
    }),
  ).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact),
    ),
  ).toEqual([]);
});

test("shows an actionable queue failure without navigating", async ({
  page,
}) => {
  await stubApi(page, { rescanStatus: 503 });
  await page.goto("/");

  await page
    .getByPlaceholder("Paste a public GitHub URL or owner/repo")
    .fill("acme/demo");
  await page.getByRole("button", { name: "Start free scan" }).click();

  await expect(page.getByText("Queue temporarily unavailable")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test.describe("mobile navigation", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("opens the mobile menu and reaches contexts", async ({ page }) => {
    await stubApi(page);
    await page.goto("/");

    await page.getByRole("button", { name: "Toggle menu" }).click();
    await expect(page.locator("nav.mobile-nav")).toBeVisible();
    await page
      .locator("nav.mobile-nav")
      .getByRole("link", { name: "Contexts" })
      .click();
    await expect(page).toHaveURL(/\/contexts$/);
  });
});
