// Exercise failures that require individually valid but mismatched camera files.
// Run against the residential case site with node scripts/check-recording-recovery.mjs <origin>.
import assert from "node:assert/strict";
import { chromium } from "playwright-core";

const origin = process.argv[2];
if (!origin) throw Error("Pass the URL of the residential case site.");
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage({ baseURL: origin });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (msg) => {
    if (/same key/.test(msg.text())) errors.push(msg.text());
  });
  const read = async (path) => {
    const response = await page.request.get(path);
    assert.equal(response.status(), 200, path);
    return response;
  };
  const { cases } = await (await read("/night-evidence/index.json")).json();
  const entry = cases["after-hours"].views.entry;
  const porch = cases["after-hours"].views.porch;
  const swapped = await read(cases.delivery.views.entry.film);
  const wrongWatch = await read(cases.delivery.views.entry.watch);
  const pair = Object.values(cases["after-hours"].associations.pairs).find(
    (p) => p.cameras.includes("entry") && p.cameras.includes("porch"),
  );
  await page.route(entry.film, (route) => route.fulfill({ response: swapped }));
  await page.route(entry.watch, (route) => route.fulfill({ response: wrongWatch }));
  await page.route(porch.film, (route) => route.fulfill({ status: 503 }));
  await page.route(pair.report, (route) => route.fulfill({ response: wrongWatch }));
  await page.goto("/incidents/after-hours/");
  const reviews = page.locator(".recording");
  const play = page.getByRole("button", { name: "Play recording", exact: true });
  await reviews.getByText("The recording differs", { exact: false }).waitFor();
  assert.equal(await reviews.locator("video,.track-overlay").count(), 0);
  assert.ok(await play.isDisabled());
  await page.locator(".track-events").getByText(/could not be/).waitFor();
  await page.getByRole("button", { name: "Compare cameras" }).click();
  await reviews.getByText("Camera film unavailable.", { exact: false }).waitFor();
  await page.locator(".ground-review").getByText(/could not be/).waitFor();
  await page.unroute(entry.film);
  await reviews.getByRole("button", { name: /Retry .*entry.* recording/i }).click();
  assert.ok(await play.isDisabled(), "second camera still unavailable");
  await page.unroute(porch.film);
  await reviews.getByRole("button", { name: /Retry .*porch.* recording/i }).click();
  await page.waitForFunction(() => {
    const videos = [...document.querySelectorAll(".recording video")];
    return videos.length === 2 && videos.every((video) => video.readyState >= 2);
  });
  assert.deepEqual(await reviews.locator("video").evaluateAll(
    (videos) => videos.map((video) => video.dataset.recording),
  ), [entry.film, porch.film]);
  await play.click();
  await page.waitForFunction(() =>
    [...document.querySelectorAll(".recording video")].every((v) => v.currentTime > 0.5 && !v.paused),
  );
  await page.getByRole("button", { name: "Pause recording" }).click();
  const times = await reviews.locator("video").evaluateAll((videos) => videos.map((v) => v.currentTime));
  assert.ok(Math.abs(times[0] - times[1]) < 0.13, "recovered cameras must share the playhead");

  await page.route(entry.film, (route) => route.fulfill({ response: swapped }));
  await page.goto("/");
  const card = page.locator(".case-card").first();
  await card.locator(".case-preview").click();
  const retry = card.getByRole("button", { name: "Retry recording" });
  await retry.waitFor();
  await page.unroute(entry.film);
  await retry.click();
  await page.waitForFunction(() => document.querySelector(".case-card video")?.currentTime > 0);

  await page.route("/estate/stills.json", (route) => route.fulfill({
    json: { stills: [{ camera: null }] },
  }), { times: 1 });
  await page.goto("/exhibits/digital-twin/");
  const details = page.locator(".estate-photographs details");
  const summary = details.locator("summary");
  await summary.click();
  await details.getByText(/render index could not be loaded/).waitFor();
  await summary.click();
  await summary.click();
  await details.locator("a").first().waitFor();
  assert.ok(await details.locator("a").count() > 1, "reopened index contains images");
  assert.deepEqual(errors, []);
  console.log("Camera and report substitutions were refused. Both cameras, the preview and stills recovered.");
} finally {
  await browser.close();
}
