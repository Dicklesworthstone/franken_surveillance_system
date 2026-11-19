// Exercise the deployed static export, including actual MP4 playback and the no-WebGL path.
import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import { cases } from "../lib/scenarios.js";
const origin = process.argv[2];
if (!origin) throw Error("Pass the URL of the static export.");
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: [
    "--no-sandbox",
    "--enable-unsafe-swiftshader",
    "--use-angle=swiftshader",
  ],
});
try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({
      viewport: { width, height: 900 },
      reducedMotion: "reduce",
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("response", (r) => {
      if (r.status() >= 400)
        errors.push(r.status() + " " + new URL(r.url()).pathname);
    });
    await page.goto(origin);
    await page.locator("canvas").waitFor();
    for (const s of cases) {
      await page.getByRole("button", { name: s.short, exact: true }).click();
      await page
        .getByRole("button", { name: "3D overview", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Toggle camera fields of view" })
        .click();
      for (const camera of ["Porch", "Garden", "Driveway"]) {
        await page
          .locator(".views")
          .getByRole("button", { name: camera, exact: true })
          .click();
        assert.equal(
          await page.locator(".viewer-top>span").innerText(),
          camera.toUpperCase() + " CAMERA",
        );
      }
      await page
        .getByRole("button", { name: "FSS replay", exact: true })
        .click();
      await page.locator(".native-trace").waitFor();
      await page.waitForFunction(
        () => document.querySelector(".film-frame video")?.readyState >= 2,
      );
      await page
        .getByRole("button", { name: "Play simulation", exact: true })
        .click();
      await page.waitForFunction(
        () => Number(document.querySelector("input[type=range]").value) > 0.35,
      );
      await page
        .getByRole("button", { name: "Pause simulation", exact: true })
        .click();
      const report = await (
        await page.request.get(
          new URL("/evidence/" + s.id + ".json", origin).href,
        )
      ).json();
      assert.equal(report.frames_decoded, 48);
      assert.equal(
        await page.locator(".native-trace button").count(),
        report.candidate_count,
      );
      if (report.candidate_count) {
        await page.locator(".native-trace button").first().click();
        assert.ok((await page.locator(".native-box").count()) > 0);
      }
      await page.locator(".film-card").nth(cases.indexOf(s)).click();
      await page.waitForFunction(
        () => document.querySelector("dialog video")?.readyState >= 2,
      );
      assert.equal(
        await page.locator("dialog video").evaluate((v) => v.duration),
        12,
      );
      await page.getByRole("button", { name: "Close film" }).click();
    }
    await page.getByRole("button", { name: "Expand viewport" }).click();
    await page.keyboard.press("Escape");
    assert.equal(await page.locator(".expanded").count(), 0);
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    assert.deepEqual(errors, []);
    await page.close();
    console.log(
      "All scenarios, cameras, evidence and films passed at width",
      width,
    );
  }
  const fallback = await browser.newPage();
  await fallback.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
      return kind.startsWith("webgl")
        ? null
        : original.call(this, kind, ...args);
    };
  });
  await fallback.goto(origin);
  await fallback.getByText("WebGL unavailable", { exact: false }).waitFor();
  await fallback.waitForFunction(
    () => document.querySelector(".viewport-surface video")?.readyState >= 2,
  );
  await fallback.close();
  console.log("Camera film fallback passed with WebGL unavailable");
} finally {
  await browser.close();
}
