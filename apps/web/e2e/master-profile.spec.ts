import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";
const AUTH = { Authorization: `Bearer ${TOKEN}` };

async function openApp(page: Page) {
  await page.addInitScript(() => localStorage.setItem("osintcc.advanced", "1"));
  await page.goto(`/#token=${TOKEN}`);
  await expect(page.getByRole("heading", { name: "OSINT Command Center" })).toBeVisible();
  await page.evaluate(() => localStorage.setItem("osintcc.copilot.open", "0"));
}

async function a11y(page: Page, label: string) {
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.nodes.length}) ${v.help} :: ${v.nodes.slice(0, 2).map((n) => n.html.slice(0, 110)).join(" | ")}`), "serious/critical accessibility violations").toEqual([]);
}

async function seed(page: Page) {
  const post = async (url: string, data: unknown) => (await page.request.post(`/api/v1${url}`, { headers: AUTH, data })).json();
  const c = await post("/cases", { title: `Master e2e ${Date.now()}`, category: "people", purpose: "self audit of my own public footprint" });
  const s = await post(`/cases/${c.id}/subjects`, { display_name: "Jane Doe", mode: "self" });
  const exp = new Date(Date.now() + 30 * 864e5).toISOString();
  await post(`/subjects/${s.id}/consent`, { verification_method: "email_confirmation", verifier: "Jane", source_classes: ["public_passive", "public_site_query"], permitted_purposes: ["self audit"], expires_at: exp });
  return { caseId: c.id as string };
}

test("master profile: an email entered once is an input, restricted values stay masked, and empty means not researched", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "Profile", exact: true }).click();
  const master = page.getByLabel("Master profile");
  await expect(master).toBeVisible();
  await master.getByRole("tab", { name: /Contact/ }).click();
  await master.getByLabel("Value").fill("jane.doe@gmail.com");
  await master.getByRole("button", { name: "Add", exact: true }).click();
  await expect(master.getByLabel("Contact items")).toContainText("jane.doe@gmail.com");
  await expect(master.getByLabel("Contact items")).toContainText("feeds research");
  await expect(page.getByLabel("Email-first discovery")).toContainText(/email-first/i);
  await master.getByRole("tab", { name: /Education/ }).click();
  await expect(master).toContainText(/never evidence that nothing exists/);
  await master.getByRole("tab", { name: /Identity/ }).click();
  await master.getByLabel("Item type").selectOption({ label: "Date of birth" });
  await master.getByLabel("Value").fill("1990-04-12");
  await master.getByLabel("Need to know").fill("needed to tell two people apart in my self audit");
  await master.getByRole("button", { name: "Add", exact: true }).click();
  await expect(master.getByLabel("Identity items")).toContainText("1990-••-••");
  await expect(master).not.toContainText("1990-04-12");
  await page.getByRole("tab", { name: "Associated emails" }).click();
  await expect(page.getByLabel("Your email inputs")).toContainText("jane.doe@gmail.com");
  await a11y(page, "master profile");
});
