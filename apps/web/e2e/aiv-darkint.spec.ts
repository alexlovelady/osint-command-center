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

async function seed(page: Page) {
  const post = async (url: string, data: unknown) => (await page.request.post(`/api/v1${url}`, { headers: AUTH, data })).json();
  const c = await post("/cases", { title: `AIV e2e ${Date.now()}`, category: "people", purpose: "self audit of my own public footprint" });
  const s = await post(`/cases/${c.id}/subjects`, { display_name: "Jane Example", mode: "self" });
  await post(`/subjects/${s.id}/identifiers`, { kind: "email", value: "jane.doe@example.com" });
  const exp = new Date(Date.now() + 30 * 864e5).toISOString();
  await post(`/subjects/${s.id}/consent`, { verification_method: "email_confirmation", verifier: "Jane (subject)", source_classes: ["exposure_check"], permitted_purposes: ["self audit"], expires_at: exp });
  return { caseId: c.id as string, subjectId: s.id as string };
}

test("Verification is off by default: it says so, lists what is never done, and offers no plan builder", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("osintcc:tab", { detail: "Verification" })));
  await expect(page.getByLabel("Verification workbench")).toBeVisible();
  await expect(page.getByText(/Active verification is OFF/)).toBeVisible();
  await expect(page.getByText("exploitation or payload delivery")).toBeVisible();
  await page.getByLabel("Verification sections").getByRole("tab", { name: "Plans" }).click();
  await expect(page.getByText("Verification is switched off")).toBeVisible();
  await expect(page.getByLabel("Build a verification plan")).toHaveCount(0);
  await page.getByLabel("Verification sections").getByRole("tab", { name: "Status" }).click();
  await a11y(page, "verification status");
});

test("the DARKINT tab separates 'not checked' from 'no exposure' and sends nothing from a preview", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "DARKINT" }).click();
  await expect(page.getByLabel("Exposure coverage")).toContainText("Not checked");
  await expect(page.getByLabel("Exposure coverage")).toContainText(/not the same as no exposure/);
  await expect(page.getByLabel("Exposure providers")).toContainText("manual only");
  await page.getByLabel("Input to check").selectOption({ index: 1 });
  await page.getByRole("checkbox", { name: /Have I Been Pwned/ }).check();
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByLabel("Check preview")).toContainText(/refused|Not enabled/);
  await expect(page.getByRole("button", { name: "Confirm and check" })).toBeDisabled();
  await a11y(page, "darkint tab");
});

test("the DARKINT page and the product-name card are reachable and accessible", async ({ page }) => {
  await openApp(page);
  await seed(page);
  await page.getByRole("link", { name: "DARKINT" }).click();
  await expect(page.getByRole("heading", { name: /DARKINT/ })).toBeVisible();
  await expect(page.getByLabel("Totals")).toContainText("Match reported");
  await a11y(page, "darkint page");
  await page.getByRole("link", { name: "Settings" }).click();
  const card = page.getByLabel("Product name");
  await expect(card).toContainText("OSINT Command Center");
  await expect(card.getByRole("button", { name: "Apply" })).toBeDisabled();
  await a11y(page, "settings product name");
});
