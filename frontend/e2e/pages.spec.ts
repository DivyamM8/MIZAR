import { expect, type Page, test } from "@playwright/test";

// Expects a server seeded by e2e/seed.py; MIZAR_CASE names the seeded case.
const caseId = process.env.MIZAR_CASE ?? "";
const shots = process.env.MIZAR_SHOTS ?? "test-results/shots";

function watchConsole(page: Page): string[] {
  const problems: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") problems.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
  page.on("response", (response) => {
    if (response.status() >= 500) problems.push(`HTTP ${response.status()} ${response.url()}`);
  });
  return problems;
}

async function visit(page: Page, path: string, name: string, ready: string) {
  await page.goto(path);
  await expect(page.locator(ready).first()).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true });
}

test("every page renders without console errors", async ({ page }) => {
  const problems = watchConsole(page);
  const c = `/cases/${caseId}`;
  await visit(page, "/", "01-cases", "text=Cases");
  await visit(page, c, "02-overview", "text=Latest analysis");
  await visit(page, `${c}/evidence`, "03-evidence", "text=Evidence files");
  await page.locator("tr.clickable").first().click();
  await expect(page.locator("text=Detection candidates").first()).toBeVisible();
  await page.screenshot({ path: `${shots}/04-evidence-detail.png`, fullPage: true });
  await visit(page, `${c}/findings`, "05-findings", "text=Sorted by severity");
  await page.locator("table a[href*='/findings/']").first().click();
  await expect(page.locator("text=Analyst review")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: `${shots}/06-finding.png`, fullPage: true });
  await page.locator("tr.clickable").first().click();
  await expect(page.locator("aside.drawer >> text=Original record")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: `${shots}/07-event-drawer.png` });
  await visit(page, `${c}/timeline`, "08-timeline", "figure.histogram");
  await page.screenshot({ path: `${shots}/08b-timeline-viewport.png` });
  await visit(page, `${c}/timeline?min_severity=high`, "09-timeline-high", "text=Events");
  await visit(page, `${c}/events?event_type=logon`, "10-events", "text=Event search");
  await visit(page, `${c}/entities`, "11-entities", "text=Entities");
  await page.locator("table a[href*='entities/detail']").first().click();
  await expect(page.locator("text=Findings naming this")).toBeVisible();
  await page.screenshot({ path: `${shots}/12-entity.png`, fullPage: true });
  await visit(page, `${c}/sessions`, "13-sessions", "text=Sessions");
  await visit(page, `${c}/runs`, "14-runs", "text=Analysis runs");
  await page.locator("table a[href*='/runs/']").first().click();
  await expect(page.locator("text=Versions, rules and parameters")).toBeVisible();
  await page.screenshot({ path: `${shots}/15-run.png`, fullPage: true });
  await visit(page, "/rules", "16-rules", "text=Detection rules");
  await page.emulateMedia({ colorScheme: "dark" });
  await visit(page, `${c}/findings`, "17-findings-dark", "text=Sorted by severity");
  expect(problems).toEqual([]);
});

test("analyst can change a finding's status", async ({ page }) => {
  const problems = watchConsole(page);
  await page.goto(`/cases/${caseId}/findings`);
  await page.locator("table a[href*='/findings/']").first().click();
  await page.locator("select[name=status]").selectOption("investigating");
  await page.locator("textarea[name=analyst_notes]").fill("Checked with the owner.");
  await page.locator("text=Save review").click();
  await expect(page.locator("text=Saved.")).toBeVisible();
  await expect(page.locator(".badge", { hasText: "investigating" }).first()).toBeVisible();
  expect(problems).toEqual([]);
});
