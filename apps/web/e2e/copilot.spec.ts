import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";

async function openCopilot(page: Page) {
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.getByRole("button", { name: "Toggle the AI Copilot" }).click();
  await expect(page.getByRole("complementary", { name: "AI Copilot" })).toBeVisible();
}

test("Copilot answers from documentation with no model, says so, and cites what it used", async ({ page }) => {
  await openCopilot(page);
  const panel = page.getByRole("complementary", { name: "AI Copilot" });
  await expect(panel.getByText(/No AI model: documentation and stored data only/)).toBeVisible();
  await panel.getByLabel("Ask the Copilot").fill("How do I create a case?");
  await panel.getByRole("button", { name: "Send" }).click();
  await expect(panel.getByText(/No AI model answered/)).toBeVisible({ timeout: 20_000 });
  await expect(panel.getByText(/Create case/).first()).toBeVisible();
  await expect(panel.getByLabel("Sources")).toBeVisible();
  await panel.getByLabel("Ask the Copilot").fill("Does the app have a Telegram scraper?");
  await panel.getByRole("button", { name: "Send" }).click();
  await expect(panel.getByText(/isn't in the documentation I have/)).toBeVisible({ timeout: 20_000 });
  const res = await new AxeBuilder({ page }).include("aside.copilot").withTags(["wcag2a", "wcag2aa"]).analyze();
  expect(res.violations.filter((v) => v.impact === "serious" || v.impact === "critical").map((v) => v.id)).toEqual([]);
});

test("history survives a reload", async ({ page }) => {
  await openCopilot(page);
  const panel = page.getByRole("complementary", { name: "AI Copilot" });
  await panel.getByLabel("Ask the Copilot").fill("What is RDAP?");
  await panel.getByRole("button", { name: "Send" }).click();
  await expect(panel.getByText(/registration/i).first()).toBeVisible({ timeout: 20_000 });
  await page.reload();
  await expect(page.getByRole("complementary", { name: "AI Copilot" }).getByText("What is RDAP?")).toBeVisible({ timeout: 20_000 });
});

test("tutor highlights the real control on screen, step by step", async ({ page }) => {
  await openCopilot(page);
  const panel = page.getByRole("complementary", { name: "AI Copilot" });
  await panel.getByRole("tab", { name: "Tutor" }).click();
  await panel.getByRole("button", { name: /▶ Create and manage an investigation/ }).click();
  const tour = page.getByRole("dialog", { name: /Guided tutorial/ });
  await expect(tour).toBeVisible();
  await expect(page).toHaveURL(/#\/cases/);
  await expect(tour.getByText(/step 1 of 4/)).toBeVisible();
  await expect(page.locator(".tour-hole")).toBeVisible({ timeout: 10_000 });
  const hole = await page.locator(".tour-hole").boundingBox();
  const target = await page.locator('[data-tour="case-title"]').boundingBox();
  expect(hole && target && Math.abs(hole.x - (target.x - 6)) < 4 && Math.abs(hole.y - (target.y - 6)) < 4).toBeTruthy();   // the hole sits on the real input
  for (let i = 0; i < 3; i++) await tour.getByRole("button", { name: "Next" }).click();
  await tour.getByRole("button", { name: "Done" }).click();
  await expect(tour).toHaveCount(0);
});

test("inside a case: Recommend next steps is computed from the case and links to the right tab", async ({ page }) => {
  await openCopilot(page);
  await page.goto("/#/cases");
  await page.getByLabel("Case title").fill("Copilot case");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.getByRole("heading", { name: /Copilot case/ })).toBeVisible();
  const panel = page.getByRole("complementary", { name: "AI Copilot" });
  await expect(panel.getByRole("tab", { name: "Investigation" })).toHaveAttribute("aria-selected", "true");
  await panel.getByRole("button", { name: "Recommend next steps" }).click();
  await expect(panel.getByText(/Write the case purpose/).first()).toBeVisible({ timeout: 20_000 });
  await expect(panel.getByText(/Nothing has been run/)).toBeVisible();
  await panel.getByRole("button", { name: /Go to Notes tab/ }).first().click();
  await expect(page.getByRole("tab", { name: "Notes" })).toHaveAttribute("aria-selected", "true");
});
