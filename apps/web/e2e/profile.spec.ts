import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e-token-local-only";
const AUTH = { Authorization: `Bearer ${TOKEN}` };
const PNG_1X1 = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "base64");

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

async function seed(page: Page, withConsent = true) {
  const post = async (url: string, data: unknown) => (await page.request.post(`/api/v1${url}`, { headers: AUTH, data })).json();
  const c = await post("/cases", { title: `Profile e2e ${Date.now()}`, category: "people", purpose: "self audit of my own public footprint" });
  const s = await post(`/cases/${c.id}/subjects`, { display_name: "Jane Example", mode: "self" });
  const dom = await post(`/subjects/${s.id}/identifiers`, { kind: "domain", value: "example.com" });
  await post(`/subjects/${s.id}/identifiers`, { kind: "email", value: "jane.doe@example.com" });
  if (withConsent) {
    const exp = new Date(Date.now() + 30 * 864e5).toISOString();
    await post(`/subjects/${s.id}/consent`, { verification_method: "email_confirmation", verifier: "Jane (subject)", source_classes: ["public_passive", "image_analysis", "exposure_check"], permitted_purposes: ["self audit"], expires_at: exp });
  }
  await post(`/subjects/${s.id}/claims`, { field: "employer", value: "Acme Corp" });
  return { caseId: c.id as string, subjectId: s.id as string, domainId: dom.id as string };
}

test("a people case opens on the Target profile; the advanced workbench keeps every old tab", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await expect(page.getByRole("heading", { name: "Jane Example" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Target profile" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByLabel("Target header")).toContainText(/self audit/);
  await expect(page.getByRole("status", { name: "Authorization status" })).toContainText(/active/i);
  const work = page.getByRole("region", { name: /^Work and education$/ });
  await expect(work.getByText("candidate")).toBeVisible();                                  // an unreviewed claim is labelled candidate, never verified
  await expect(page.getByRole("region", { name: "Public business associations" }).getByText(/Not assessed/)).toBeVisible();
  await page.getByRole("tab", { name: "Advanced workbench" }).click();
  for (const t of ["Search", "Plans", "Findings", "Graph", "Evidence", "Reports"]) await expect(page.getByRole("tab", { name: t, exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Search", exact: true }).click();
  await expect(page.getByLabel("Target", { exact: true })).toBeVisible();
});

test("research: preview contacts nothing; an approved passive plan runs and the coverage grid says what ran", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "Research" }).click();
  await expect(page.getByLabel("Coverage grid")).toContainText(/not run/);
  await page.getByRole("button", { name: /Preview what would be contacted/ }).click();
  const rdap = page.getByLabel("Run RDAP registration data on example.com");
  await expect(rdap).toBeVisible();
  await expect(rdap).not.toBeChecked();                                                    // nothing is preselected
  await expect(page.getByRole("button", { name: "Approve and run 0 source(s)" })).toBeDisabled();
  await expect(page.getByRole("table", { name: "Tasks" })).not.toContainText("rdap");                        // preview created no task
  await rdap.check();
  await page.getByRole("button", { name: "Approve and run 1 source(s)" }).click();
  await expect(page.getByRole("table", { name: "Tasks" }).getByText("completed")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByLabel("Coverage grid")).toContainText(/completed.*RDAP registration data/);
  await expect(page.getByText(/not a measure of how much information exists/)).toBeVisible();
});

test("without authorization nothing can be selected, and recording one is explicit", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page, false);
  await page.goto(`/#/case/${caseId}`);
  await expect(page.getByRole("status", { name: "Authorization status" })).toContainText(/none/i);
  await page.getByRole("tab", { name: "Research" }).click();
  await page.getByRole("button", { name: /Preview what would be contacted/ }).click();
  await expect(page.getByLabel("Run RDAP registration data on example.com")).toBeDisabled();
  await expect(page.getByText(/Blocked: authorization: no authorization on record/).first()).toBeVisible();
  await page.getByRole("tab", { name: "Authorization" }).click();
  await page.getByLabel("Verified by").fill("Jane (subject)");
  await page.getByRole("button", { name: "Record authorization" }).click();
  await expect(page.getByRole("table", { name: "Authorization history" }).getByText("current")).toBeVisible();
  await page.getByRole("tab", { name: "Research" }).click();
  await page.getByRole("button", { name: /Preview what would be contacted/ }).click();
  await expect(page.getByLabel("Run RDAP registration data on example.com")).toBeEnabled();
});

test("the password check hashes in the browser and sends only five characters", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  let body = "";
  await page.route("**/api/v1/subjects/*/exposure/password-range", async (route) => {
    body = route.request().postData() ?? "";
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ suffixes: ["1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493"], padded: true, note: "x" }) });
  });
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "Exposure", exact: true }).click();
  await page.getByLabel("Password to check").fill("password");
  await page.getByRole("button", { name: "Check", exact: true }).click();
  await expect(page.getByText(/appears 3,861,493 time/)).toBeVisible();
  expect(JSON.parse(body)).toEqual({ prefix: "5BAA6" });
  expect(body).not.toContain("1E4C9B93");
  await expect(page.getByLabel("Password to check")).toHaveValue("");
});

test("image import shows a sanitized preview and cannot be done without confirming rights", async ({ page }) => {
  await openApp(page);
  const { caseId } = await seed(page);
  await page.goto(`/#/case/${caseId}`);
  await page.getByRole("tab", { name: "Images" }).click();
  await page.getByLabel("Image file").setInputFiles({ name: "me.png", mimeType: "image/png", buffer: PNG_1X1 });
  await expect(page.getByRole("button", { name: "Import" })).toBeDisabled();
  await page.getByLabel(/I have the right to analyse this image/).check();
  await page.getByRole("button", { name: "Import" }).click();
  const card = page.getByRole("article", { name: /^Image [0-9a-f]{8}/ });
  await expect(card).toBeVisible();
  await expect(card.getByAltText("Sanitized preview of the imported image")).toBeVisible();
  await expect(card).toContainText("Metadata can be missing, removed or forged.");
  await expect(page.getByText(/does not recognise or identify people/)).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`every Target profile screen has no serious or critical accessibility violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openApp(page);
    const { caseId } = await seed(page);
    await page.goto(`/#/case/${caseId}`);
    await expect(page.getByRole("heading", { name: "Jane Example" })).toBeVisible();
    for (const t of ["Profile", "Review queue", "Research", "Images", "Exposure", "Remediation", "Reports", "Workflows", "Authorization", "Privacy & data"]) {
      await page.getByRole("tab", { name: new RegExp(`^${t.replace("&", "\\&")}`) }).click();
      await page.waitForLoadState("networkidle");
      await a11y(page, `${t} (${scheme})`);
    }
  });
}
