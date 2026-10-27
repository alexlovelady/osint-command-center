import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";

// Not part of the normal run: E2E_SERVER=demo_server.py E2E_SCREENSHOTS=1 pnpm exec playwright test e2e/screenshots.spec.ts
// Captures the core screens against SYNTHETIC data (scripts/demo_server.py) for the release notes.
const TOKEN = "e2e-token-local-only";
const OUT = "../../docs/screenshots";

async function shot(page: Page, name: string) {
  mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false });
}

test.skip(!process.env.E2E_SCREENSHOTS, "screenshots are captured on request only");
test.use({ viewport: { width: 1366, height: 900 } });

test("capture the simple-mode screens", async ({ page }) => {
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
  await page.evaluate(() => { localStorage.setItem("osintcc.copilot.open", "0"); localStorage.setItem("osintcc.advanced", "0"); });
  await page.goto("/#/home");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Home" })).toBeVisible();
  await expect(page.getByLabel("Investigation Jane Example")).toBeVisible();
  await shot(page, "01-home");

  await page.getByRole("button", { name: "New investigation" }).first().click();
  await page.getByLabel("Add an identifier").fill("jane.example@gmail.com, @jane-example, https://example.org/jane");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Purpose", { exact: true }).fill("self audit of my own public footprint");
  await page.getByRole("checkbox", { name: /I confirm this is my own information/ }).check();
  await page.getByLabel("Your name").fill("Jane Example");
  await page.getByRole("button", { name: "Review plan" }).click();
  await expect(page.getByLabel("Plan")).toContainText("What will happen");
  await shot(page, "02-new-investigation");

  await page.goto("/#/investigations");
  await page.getByLabel("Investigation Jane Example").getByRole("button").click();
  await expect(page.getByLabel("Progress")).toBeVisible();
  await shot(page, "03-overview");
  const tabs = page.getByRole("tablist", { name: "Investigation views" });
  await tabs.getByRole("tab", { name: "Profile" }).click();
  await expect(page.getByLabel("Accounts & online presence")).toBeVisible();
  await shot(page, "04-dossier");
  await tabs.getByRole("tab", { name: /Findings/ }).click();
  await expect(page.getByLabel("Findings on GitHub")).toBeVisible();
  await shot(page, "05-findings");
  await tabs.getByRole("tab", { name: /Activity/ }).click();
  await expect(page.getByLabel("Activity log")).toBeVisible();
  await shot(page, "06-activity-coverage");

  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Review" }).click();
  await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
  await page.getByLabel("Select GitHub").first().check();
  await shot(page, "07-review");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Settings" }).click();
  await expect(page.getByLabel("Providers and keys")).toBeVisible();
  await shot(page, "08-settings");
  await page.getByLabel("Provider usage", { exact: true }).scrollIntoViewIfNeeded();
  await expect(page.getByLabel("Provider VirusTotal")).toBeVisible();
  await page.getByLabel("SEC EDGAR contact").first().scrollIntoViewIfNeeded();
  await shot(page, "11-provider-usage");
  await page.getByRole("checkbox", { name: /Advanced mode/ }).check();
  await shot(page, "09-advanced-mode");
  await page.getByRole("checkbox", { name: /Advanced mode/ }).uncheck();
  await page.goto("/#/investigations");
  await page.getByLabel("Investigation Acme Example LLC").getByRole("button").click();
  await expect(page.getByLabel("Waiting for provider limits")).toBeVisible();
  await shot(page, "10-waiting-for-limits");
});
