import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";
const EML = "From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: hello\r\nDate: Mon, 03 Mar 2025 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n\r\nSee https://example.org/x\r\n";

async function openApp(page: Page) {
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
}

async function expectNoSeriousA11y(page: Page, label: string) {
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.nodes.length}) ${v.help} :: ${v.nodes.slice(0, 3).map((n) => n.html.slice(0, 120) + " " + (n.any[0]?.message ?? "")).join(" | ")}`), "serious/critical accessibility violations").toEqual([]);
}

test("token in the URL fragment is scrubbed and the app loads", async ({ page }) => {
  await openApp(page);
  expect(page.url()).not.toContain("token");
  await page.getByRole("link", { name: "Cases" }).click();
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
});

test("create case, preview, confirm and run a passive search against the mocked network", async ({ page }) => {
  await openApp(page);
  await page.goto(`/#/cases`);
  await page.getByLabel("Case title").fill("E2E case");
  await page.getByLabel("Purpose").fill("verify ownership of example.com");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.getByRole("heading", { name: /E2E case/ })).toBeVisible();

  await page.getByLabel("Target", { exact: true }).fill("example.com");
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByText("Detected: domain")).toBeVisible();
  // Typing and previewing contacted nothing: no run exists yet.
  await expect(page.getByText("Run", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: /Confirm and run/ }).click();
  await expect(page.locator(".badge.succeeded").first()).toBeVisible({ timeout: 30_000 });

  await page.getByRole("tab", { name: "Findings" }).click();
  await expect(page.getByText("rdap.registrar").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Promote to claim" }).first()).toBeVisible();
  await expectNoSeriousA11y(page, "findings");

  await page.getByRole("tab", { name: "Graph" }).click();
  await expect(page.getByRole("img", { name: /Entity graph/ })).toBeVisible();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByText("SHA-256")).toBeVisible();
});

test("import a user-supplied email, see it as an observation, and preview a multi-INT report", async ({ page }) => {
  await openApp(page);
  await page.goto(`/#/cases`);
  await page.getByLabel("Case title").fill("Import case");
  await page.getByRole("button", { name: "Create case" }).click();
  await page.getByRole("tab", { name: "Imports" }).click();
  const file = page.getByLabel("Import analysis file");
  await expect(file).toBeDisabled();                       // consent first
  await page.getByLabel(/I own or am authorized to analyse/).check();
  await file.setInputFiles({ name: "msg.eml", mimeType: "message/rfc822", buffer: Buffer.from(EML) });
  await expect(page.getByText("email.message").first().or(page.getByText("COMINT").first())).toBeVisible({ timeout: 15_000 });

  await page.getByRole("tab", { name: "Reports" }).click();
  await page.getByLabel("Profile").selectOption("multi_int");
  await page.getByRole("button", { name: "Preview what will be included" }).click();
  const prev = page.getByLabel("Report preview");
  await expect(prev).toContainText("Included");
  await expect(prev).toContainText("Withheld");
  await expect(prev).toContainText("rounded");
  await page.getByRole("button", { name: "Generate" }).click();
  await expect(page.getByText(/Generated/)).toBeVisible();
});

test("collection plan shows blocked sources and runs nothing until approved", async ({ page }) => {
  await openApp(page);
  await page.goto(`/#/cases`);
  await page.getByLabel("Case title").fill("Plan case");
  await page.getByRole("button", { name: "Create case" }).click();
  await page.getByRole("tab", { name: "Plans" }).click();
  await page.getByLabel("Plan target").fill("example.com");
  await page.getByLabel("Reason").fill("ownership check");
  await page.getByRole("button", { name: "Preview plan" }).click();
  await expect(page.getByText(/preview \(not saved\)/)).toBeVisible();
  await page.getByRole("button", { name: "Save plan" }).click();
  await expect(page.getByRole("button", { name: "Approve and run" })).toBeVisible();
  await page.getByRole("tab", { name: "Findings" }).click();
  await expect(page.getByText("No findings")).toBeVisible();   // saving a plan collected nothing
});

for (const scheme of ["light", "dark"] as const) {
test(`every top-level page and case tab has no serious or critical accessibility violations (${scheme})`, async ({ page }) => {
  await page.emulateMedia({ colorScheme: scheme });
  await openApp(page);
  for (const [hash, name] of [["overview", "overview"], ["cases", "cases"], ["tools", "tools"], ["setup", "setup"], ["settings", "settings"]]) {
    await page.goto(`/#/${hash}`);
    await page.waitForLoadState("networkidle");
    await expectNoSeriousA11y(page, name);
  }
  await page.goto(`/#/cases`);
  await page.getByLabel("Case title").fill("A11y case");
  await page.getByRole("button", { name: "Create case" }).click();
  for (const t of ["Search", "Plans", "Findings", "Graph", "Timeline", "Map", "Evidence", "Imports", "Analysis", "Cross-links", "Workflows", "Humint", "AI", "Hardware", "Notes", "Reports"]) {
    await page.getByRole("tab", { name: t, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await expectNoSeriousA11y(page, `tab ${t}`);
  }
});
}

test("keyboard: Ctrl+K opens universal search and Escape closes it", async ({ page }) => {
  await openApp(page);
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});
