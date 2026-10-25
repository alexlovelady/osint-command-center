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
  const c = await post("/cases", { title: `Emails e2e ${Date.now()}`, category: "people", purpose: "self audit of my own public footprint" });
  const s = await post(`/cases/${c.id}/subjects`, { display_name: "Jane Doe", mode: "self" });
  await post(`/subjects/${s.id}/identifiers`, { kind: "email", value: "jane.doe@example.com" });
  await post(`/subjects/${s.id}/identifiers`, { kind: "username", value: "janedoe" });
  const exp = new Date(Date.now() + 30 * 864e5).toISOString();
  await post(`/subjects/${s.id}/consent`, { verification_method: "email_confirmation", verifier: "Jane", source_classes: ["public_passive", "public_site_query"], permitted_purposes: ["self audit"], expires_at: exp });
  await post(`/subjects/${s.id}/associated-emails`, { address: "jane.work@acme-example.com", url: "https://acme-example.com/team", note: "listed on the team page" });
  return { caseId: c.id as string, subjectId: s.id as string };
}

test("associated emails: a candidate is labelled, explained and needs a reason to be decided; the plan marks what needs approval", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "Associated emails" }).click();
  const table = page.getByLabel("Associated emails", { exact: true });
  await expect(table).toContainText("jane.work@acme-example.com");
  await expect(table).toContainText("Possible");
  await expect(page.getByText(/never a fact/)).toBeVisible();
  await page.getByRole("button", { name: "Why" }).first().click();
  await expect(page.getByLabel("Details for jane.work@acme-example.com")).toContainText(/One source ties it|no source says it belongs/);
  await page.getByLabel("Select jane.work@acme-example.com").check();
  await expect(page.getByRole("button", { name: "Confirm", exact: true })).toBeDisabled();
  await page.getByLabel("Reason for the decision").fill("it is her employer's team page");
  await page.getByRole("button", { name: "Reject", exact: true }).click();
  await page.getByRole("button", { name: /Rejected \(1\)/ }).click();
  await expect(table).toContainText("Rejected");
  const plan = page.getByLabel("Cross-INT research plan");
  await expect(plan).toContainText(/own approval/);
  await expect(plan).toContainText(/rejected address/);
  await a11y(page, "associated emails");
});
