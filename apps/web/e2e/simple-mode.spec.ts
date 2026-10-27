import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";

async function openApp(page: Page) {
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
  await page.evaluate(() => { localStorage.setItem("osintcc.copilot.open", "0"); localStorage.setItem("osintcc.advanced", "0"); });
  await page.goto("/#/home");
  await page.reload();
}

async function a11y(page: Page, label: string) {
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.nodes.length}) ${v.help} :: ${v.nodes.slice(0, 2).map((n) => n.html.slice(0, 110)).join(" | ")}`), "serious/critical accessibility violations").toEqual([]);
}

test("simple mode: four destinations, one email is enough, the plan names who is contacted, and the advanced switch restores the workbench", async ({ page }) => {
  await openApp(page);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("link")).toHaveText(["Home", "Investigations", "Review", "Settings"]);
  await expect(page.getByRole("heading", { name: "Home" })).toBeVisible();
  await a11y(page, "home");

  await page.getByRole("button", { name: "New investigation" }).first().click();
  await expect(page.getByRole("heading", { name: "New investigation" })).toBeVisible();
  await page.getByLabel("Add an identifier").fill("jane.doe@gmail.com");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByLabel("Identifiers to investigate")).toContainText("jane.doe@gmail.com");
  await expect(page.getByRole("button", { name: "Review plan" })).toBeDisabled();       // nothing happens before the person confirms their right to research
  await page.getByLabel("Purpose", { exact: true }).fill("self audit of my own public footprint");
  await page.getByRole("checkbox", { name: /I confirm this is my own information/ }).check();
  await page.getByLabel("Your name").fill("Jane");
  await page.getByRole("button", { name: "Review plan" }).click();
  const plan = page.getByLabel("Plan");
  await expect(plan).toContainText("What will happen");
  await expect(plan).toContainText(/Will run if you approve/);
  await expect(plan).not.toContainText(/RDAP|crt\.sh/);                                   // a mailbox provider's domain is never researched
  await expect(plan).toContainText(/Needs an API key/);                                   // Brave is listed as unavailable, not silently dropped
  await a11y(page, "new investigation");

  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await expect(page.getByRole("heading", { name: "jane.doe@gmail.com" })).toBeVisible();
  const tabs = page.getByRole("tablist", { name: "Investigation views" });
  await expect(tabs.getByRole("tab")).toHaveText([/Overview/, /Profile/, /Findings/, /Activity & Coverage/]);
  await expect(page.getByLabel("Progress")).toBeVisible();
  await expect(page.getByLabel("Limits")).toContainText(/key|could not|No supported/i);
  await tabs.getByRole("tab", { name: "Profile" }).click();
  await expect(page.getByText(/An empty field means not researched|unknown, never evidence/).first()).toBeVisible();
  await tabs.getByRole("tab", { name: /Activity/ }).click();
  await expect(page.getByLabel("Activity log")).toContainText("Investigation created");
  await a11y(page, "investigation");

  await nav.getByRole("link", { name: "Review" }).click();
  await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
  await a11y(page, "review");
  await nav.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByLabel("Providers and keys")).toBeVisible();
  await a11y(page, "settings");

  await page.getByRole("checkbox", { name: /Advanced mode/ }).check();
  await expect(nav.getByRole("link", { name: "Cases" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Tool Manager" })).toBeVisible();
  await page.getByRole("checkbox", { name: /Advanced mode/ }).uncheck();
  await expect(nav.getByRole("link", { name: "Cases" })).toHaveCount(0);
  await page.goto("/#/cases");                                                           // deep links keep working in either mode
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`simple mode screens have no serious or critical accessibility violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openApp(page);
    const AUTH = { Authorization: `Bearer ${TOKEN}` };
    const prep = await (await page.request.post("/api/v1/investigations", { headers: AUTH, data: { inputs: [{ kind: "email", value: "axe.check@gmail.com" }, { kind: "phone", value: "+1 555 010 1111" }], purpose: "self audit", authorization: { verification_method: "self_attestation", verifier: "axe" } } })).json();
    const run = await (await page.request.post(`/api/v1/subjects/${prep.subject_id}/investigations`, { headers: AUTH, data: { approved_sources: "listed" } })).json();
    for (const hash of ["home", "investigations", "new", "review", "settings", `investigation/${run.id}`]) {
      await page.goto(`/#/${hash}`);
      await expect(page.getByRole("main")).toBeVisible();
      await page.waitForTimeout(400);
      await a11y(page, `${hash} (${scheme})`);
    }
    await page.goto(`/#/investigation/${run.id}`);
    for (const t of ["Profile", "Findings", "Activity & Coverage"]) {
      await page.getByRole("tablist", { name: "Investigation views" }).getByRole("tab", { name: new RegExp(t) }).click();
      await page.waitForTimeout(300);
      await a11y(page, `${t} (${scheme})`);
    }
  });
}

test("simple mode screens fit common desktop and narrow widths without sideways scrolling, and the main actions work by keyboard", async ({ page }) => {
  await openApp(page);
  const AUTH = { Authorization: `Bearer ${TOKEN}` };
  const prep = await (await page.request.post("/api/v1/investigations", { headers: AUTH, data: { inputs: [{ kind: "email", value: "fit.check@gmail.com" }], purpose: "self audit", authorization: { verification_method: "self_attestation", verifier: "fit" } } })).json();
  const run = await (await page.request.post(`/api/v1/subjects/${prep.subject_id}/investigations`, { headers: AUTH, data: { approved_sources: "listed" } })).json();
  for (const width of [1366, 1024, 800]) {
    await page.setViewportSize({ width, height: 800 });
    for (const hash of ["home", "new", "review", `investigation/${run.id}`]) {
      await page.goto(`/#/${hash}`);
      await page.waitForTimeout(250);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(over, `${hash} at ${width}px overflows by ${over}px`).toBeLessThanOrEqual(2);
    }
  }
  await page.setViewportSize({ width: 1366, height: 800 });
  await page.goto("/#/new");
  await page.getByLabel("Add an identifier").focus();
  await page.keyboard.type("keyboard.user@example.org");
  await page.keyboard.press("Enter");                                                    // Enter adds the value without the mouse
  await expect(page.getByLabel("Identifiers to investigate")).toContainText("keyboard.user@example.org");
  await page.keyboard.press("Tab");
  await expect(page.locator(":focus")).toBeVisible();
});

test("settings: the SEC contact says Saved and survives a reload; Shodan is shown as a disabled paid provider; usage never shows a key", async ({ page }) => {
  await openApp(page);
  await page.goto("/#/settings");
  const field = page.getByLabel("SEC EDGAR contact", { exact: false }).locator("input").first();
  await expect(field).toBeVisible();
  await field.fill("Quota Tester quota.tester@example.org");
  await expect(page.getByRole("status").filter({ hasText: "Unsaved changes" })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).first().click();
  await expect(page.getByRole("status").filter({ hasText: /^Saved at / })).toBeVisible();
  await expect(field).toHaveValue("Quota Tester quota.tester@example.org");                       // still there, not cleared
  await page.reload();
  await expect(page.getByLabel("SEC EDGAR contact", { exact: false }).locator("input").first()).toHaveValue("Quota Tester quota.tester@example.org");
  const usage = page.getByLabel("Provider usage").first();
  await expect(usage).toBeVisible();
  await expect(page.getByLabel("Provider Shodan")).toContainText("Disabled — paid provider");
  await expect(page.getByLabel("Provider Shodan").getByRole("button", { name: "Turn on" })).toHaveCount(0);
  await expect(usage).toContainText("Spend guard: $0");
  const text = await page.getByRole("main").innerText();
  expect(text).not.toMatch(/Bearer |x-apikey|censys_[a-z0-9]{10}/i);
});
