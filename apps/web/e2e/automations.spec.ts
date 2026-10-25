import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";
const AUTH = { Authorization: `Bearer ${TOKEN}` };

async function openApp(page: Page) {
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
  await page.evaluate(() => localStorage.setItem("osintcc.copilot.open", "0"));
}

async function a11y(page: Page, label: string) {
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.nodes.length}) ${v.help} :: ${v.nodes.slice(0, 2).map((n) => n.html.slice(0, 110)).join(" | ")}`), "serious/critical accessibility violations").toEqual([]);
}

test("library shows 52 templates with honest availability and installs only a disabled draft", async ({ page }) => {
  await openApp(page);
  await page.goto("/#/automations");
  await expect(page.getByRole("heading", { name: "Automations" })).toBeVisible();
  await expect(page.locator("article.tpl")).toHaveCount(52);
  await page.getByLabel("Search templates").fill("phishing");
  await expect(page.locator("article.tpl")).toHaveCount(1);
  await page.getByLabel("Search templates").fill("");
  const id01 = page.getByRole("article", { name: /ID-01 Username Footprint/ });
  await expect(id01.getByText("setup required")).toBeVisible();
  await id01.getByRole("button", { name: "Details" }).click();
  await expect(id01.getByText(/sherlock/i).first()).toBeVisible();
  await expect(id01.getByText(/not installed/i).first()).toBeVisible();
  const cy01 = page.getByRole("article", { name: /CY-01 Domain Recon/ });
  await expect(cy01.getByText("ready")).toBeVisible();
  await a11y(page, "automations library");
});

test("create from a template, see it on the canvas, dry-run it, drive the canvas by keyboard", async ({ page }) => {
  await openApp(page);
  await page.goto("/#/automations");
  const cy02 = page.getByRole("article", { name: /CY-02 Domain Change Watch/ });
  await cy02.getByRole("button", { name: "Details" }).click();
  await cy02.getByLabel(/Domain you own/).fill("example.com");
  await cy02.getByRole("button", { name: "Create from template" }).click();
  await expect(page.getByRole("heading", { name: "Domain Change Watch" })).toBeVisible();
  await expect(page.getByText(/It stays OFF until you approve and activate it/)).toBeVisible();
  const canvas = page.getByRole("application", { name: /Workflow canvas with 9 steps/ });
  await expect(canvas).toBeVisible();
  const scope = page.getByRole("button", { name: /^scope, Scope check/ });
  await scope.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: "Inspector" }).getByText("Scope check")).toBeVisible();
  await page.keyboard.press("ArrowRight");
  await expect(page.locator("g.cv-node:focus")).toHaveAttribute("data-node", /rdap|dns|crtsh/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: "Inspector" }).getByText("Source query").first()).toBeVisible();
  await page.getByRole("button", { name: "Dry run" }).click();
  await expect(page.getByText(/SIMULATED: fixture data, no network, nothing written/)).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("region", { name: "Dry run result" }).getByText("diff")).toBeVisible();
  await expect(page.getByRole("button", { name: /^diff,.*succeeded/ })).toBeVisible();          // the canvas shows the run overlay
  await page.getByRole("tab", { name: "Explanation" }).click();
  await expect(page.getByRole("region", { name: "Explanation" }).getByText(/starts disabled/)).toBeVisible();
  await page.getByRole("tab", { name: "Checks" }).click();
  await expect(page.getByText(/Valid: the graph, references, scope checks and limits pass the validator/)).toBeVisible();
  await a11y(page, "automation builder");
});

test("publish, request approval, approve with an expiry, activate; then run a manual workflow and read its run", async ({ page }) => {
  await openApp(page);
  const case1 = await (await page.request.post("/api/v1/cases", { headers: AUTH, data: { title: "Automation e2e", purpose: "e2e" } })).json();
  await page.goto("/#/automations");
  const cy02 = page.getByRole("article", { name: /CY-02 Domain Change Watch/ });
  await cy02.getByRole("button", { name: "Details" }).click();
  await cy02.getByLabel("Case for this automation").selectOption(case1.id);
  await cy02.getByLabel(/Domain you own/).fill("example.com");
  await cy02.getByRole("button", { name: "Create from template" }).click();
  await expect(page.getByRole("heading", { name: "Domain Change Watch" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Activate" })).toBeDisabled();                    // unpublished
  await page.getByRole("button", { name: "Publish version" }).click();
  await expect(page.getByText(/Published revision 1/)).toBeVisible();
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByText(/activation approval for this exact version is required/i)).toBeVisible();   // no approval: refused
  await page.getByRole("button", { name: "Request approval" }).click();
  const region = page.getByRole("region", { name: "Approvals and running" });
  await expect(region.getByText("pending")).toBeVisible();
  await region.getByRole("button", { name: "Approve" }).click();
  await expect(region.getByText("approved")).toBeVisible();
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByText(/Activated\./)).toBeVisible();
  await expect(page.locator(".badge", { hasText: "active" }).first()).toBeVisible();
  await region.getByRole("button", { name: "Run now" }).click();
  await page.getByRole("tab", { name: "Runs" }).click();
  await expect(page.getByRole("table", { name: "Runs" }).getByText(/completed/).first()).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Details" }).first().click();
  const run = page.getByRole("region", { name: /^Run / });
  await expect(run.getByRole("table", { name: "Step timeline" })).toBeVisible();
  await expect(run.getByText(/version 1/)).toBeVisible();
  await a11y(page, "run console");
});

test("inbox, runs and settings pages are accessible and the AI builder falls back to a labelled template without a model", async ({ page }) => {
  await openApp(page);
  await page.goto("/#/automations");
  for (const t of ["My automations", "Runs", "Inbox", "Settings"]) {
    await page.getByRole("tab", { name: new RegExp(`^${t}`) }).click();
    await page.waitForLoadState("networkidle");
    await a11y(page, `automations ${t}`);
  }
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(page.getByLabel(/Suggest repetitive task automations/)).not.toBeChecked();         // off by default
  await page.goto("/#/automations");
  await page.getByRole("tab", { name: "Library" }).click();
  const cy05 = page.getByRole("article", { name: /CY-05/ });
  await cy05.getByRole("button", { name: "Details" }).click();
  await cy05.getByRole("button", { name: "Create from template" }).click();
  await page.getByLabel("Describe the automation").fill("alert me when new lookalike phishing domains appear for example.com");
  await page.getByRole("button", { name: "Generate a draft" }).click();
  const draft = page.getByRole("region", { name: "Proposed draft" });
  await expect(draft.getByText("closest template")).toBeVisible({ timeout: 20_000 });
  await expect(draft.getByText(/stays off until you approve/)).toBeVisible();
  await expect(draft.getByText(/No model was used/)).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`automation pages and the builder have no serious or critical accessibility violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openApp(page);
    await page.goto("/#/automations");
    for (const t of ["Library", "My automations", "Runs", "Inbox", "Settings"]) {
      await page.getByRole("tab", { name: new RegExp(`^${t}`) }).click();
      await page.waitForLoadState("networkidle");
      await a11y(page, `${t} (${scheme})`);
    }
    await page.getByRole("tab", { name: "Library" }).click();
    const t = page.getByRole("article", { name: /CASE-05/ });
    await t.getByRole("button", { name: "Details" }).click();
    await t.getByRole("button", { name: "Create from template" }).click();
    await expect(page.getByRole("application", { name: /Workflow canvas/ })).toBeVisible();
    await page.getByRole("button", { name: "Dry run" }).click();
    await expect(page.getByText(/SIMULATED: fixture data/)).toBeVisible({ timeout: 20_000 });
    await a11y(page, `builder (${scheme})`);
  });
}
