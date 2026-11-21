import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import { pathToFileURL } from "node:url";

export async function checkDeliveryDropout(browser, url) {
  const page = await browser.newPage({ baseURL: url });
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await page.goto("/#delivery-dropout", { waitUntil: "domcontentloaded" });
  const view = page.locator("#delivery-dropout");
  const damaged = view.locator('[data-recording="dropout"]');
  const original = view.locator('[data-recording="complete"]');
  await damaged.getByText("Observation unknown").waitFor();
  await original.locator("img").waitFor();
  const before = view.getByRole("button", { name: /Last frame before gap/ });
  const inside = view.getByRole("button", { name: /Inside gap/ });
  const resume = view.getByRole("button", { name: /First frame after gap/ });
  async function checkCourierDuringGap() {
    await inside.click();
    assert.equal(await original.getAttribute("data-segment"), "32");
    const frame = original.getByRole("img", { name: "Complete recording, porch camera at 4 s", exact: true });
    // The courier is visible in cell (0, 4) of the digest-checked, eight-column source sheet.
    const crop = await frame.evaluate(async img => {
      await img.decode();
      const sheet = img.getBoundingClientRect();
      const screen = img.parentElement.getBoundingClientRect();
      return [Math.round((screen.left - sheet.left) / screen.width), Math.round((screen.top - sheet.top) / screen.height)];
    });
    assert.deepEqual(crop, [0, 4]);
    assert.ok(await original.getByText("Tracker recorded no confirmed entry", { exact: true }).isVisible());
    assert.ok(await view.getByText("No confirmed track entry", { exact: true }).isVisible());
    assert.equal(await damaged.locator("img").count(), 0);
    assert.ok(await damaged.getByText("No source picture at this time", { exact: true }).isVisible());
    assert.ok(await damaged.getByText("No absence claim", { exact: true }).isVisible());
  }
  await before.click();
  await damaged.locator("img").waitFor();
  assert.equal(await damaged.getAttribute("data-segment"), "23");
  await checkCourierDuringGap();
  await resume.click();
  assert.equal(await damaged.getAttribute("data-segment"), "24");
  await page.waitForFunction(() => document.querySelector('[data-recording="dropout"] img')?.naturalWidth === 4096);
  await inside.click();
  const originalFrame = await original.getAttribute("data-segment");
  await page.evaluate(() => {
    const raf = window.requestAnimationFrame;
    window.deliveryReplayTestTicks = 0;
    window.restoreDeliveryReplayClock = () => { window.requestAnimationFrame = raf; };
    window.requestAnimationFrame = callback => raf.call(window, () => {
      if (document.querySelector('[aria-label="Pause delivery replay"]')) window.deliveryReplayTestTicks++;
      callback(0);
    });
  });
  try {
    await view.getByRole("button", { name: "Play delivery replay" }).click();
    await page.waitForFunction(() => window.deliveryReplayTestTicks >= 3, null, { polling: 25 });
    assert.equal(await original.getAttribute("data-segment"), originalFrame,
      "A stale animation timestamp must keep playback at the selected scene frame");
    assert.equal(await damaged.getAttribute("data-segment"), "unknown");
  } finally {
    await page.evaluate(() => window.restoreDeliveryReplayClock());
  }
  await page.waitForFunction(() => Number(document.querySelector('[data-recording="dropout"]')?.dataset.segment) >= 24);
  await view.getByRole("button", { name: "Pause delivery replay" }).click();

  // Substitute a real, valid image from the other camera archive. Only the matching bytes may be drawn.
  const completeSheet = await page.request.get("/watch/delivery-dropout/complete.webp");
  const interruptedSheet = await page.request.get("/watch/delivery-dropout/dropout.webp");
  assert.deepEqual([completeSheet.status(), interruptedSheet.status()], [200, 200]);
  await page.route("**/watch/delivery-dropout/dropout.webp*", route => route.fulfill({ response: completeSheet }));
  await page.route("**/watch/delivery-dropout/complete.webp*", route => route.fulfill({ response: interruptedSheet }));
  await page.reload({ waitUntil: "domcontentloaded" });
  await resume.click();
  await damaged.getByText("Frame preview unavailable").waitFor();
  await original.getByText("Frame preview unavailable").waitFor();
  assert.equal(await damaged.locator("img").count(), 0);
  assert.equal(await original.locator("img").count(), 0);
  assert.equal(await damaged.getAttribute("data-segment"), "24");
  await page.unroute("**/watch/delivery-dropout/dropout.webp*");
  await page.unroute("**/watch/delivery-dropout/complete.webp*");
  await damaged.getByRole("button", { name: "Retry preview" }).click();
  await original.getByRole("button", { name: "Retry preview" }).click();
  await page.waitForFunction(() =>
    document.querySelector('[data-recording="dropout"] img')?.naturalHeight === 1728 &&
    document.querySelector('[data-recording="complete"] img')?.naturalHeight === 2304);
  await page.setViewportSize({ width: 390, height: 844 });
  await checkCourierDuringGap();
  assert.ok(await damaged.getByText("Observation unknown").isVisible());
  assert.ok(await view.evaluate(el => el.scrollWidth <= el.clientWidth + 1));
  assert.deepEqual(errors, []);
  await page.close();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const url = process.argv[2];
  if (!url) throw Error("Supply the origin of the exported site.");
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
    args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  try {
    await checkDeliveryDropout(browser, url);
    console.log("Passed shared-clock markers, monotonic playback, recovery, preview retry and mobile layout.");
  } finally {
    await browser.close();
  }
}
