// Run against the built export. Exercise the selected footage, measured boxes,
// archive and shared timeline in a real browser, including failure paths.
import { checkExhibits } from "./check-exhibits.mjs";
import { checkField } from "./check-field.mjs";
import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import {
  cases,
  cameras,
  cameraAsset,
  recording,
  DURATION,
} from "../lib/scenarios.js";

const origin = process.argv[2];
if (!origin) throw Error("Pass the URL of the static export.");
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: [
    "--no-sandbox",
    "--enable-unsafe-swiftshader",
    "--use-angle=swiftshader",
    "--disable-dev-shm-usage",
  ],
});
const feed = (page, asset) => page.locator('[data-feed="' + asset + '"]');
const button = (page, name) => page.getByRole("button", { name, exact: true });
const viewpoint = (page, name) => button(page.locator(".views"), name);
async function report(page, file) {
  const res = await page.request.get(new URL("/evidence/" + file, origin).href);
  assert.equal(res.status(), 200);
  return res.json();
}
async function aligned(page, asset, segment) {
  const selector =
    '[data-feed="' + asset + '"][data-segment="' + segment + '"]';
  await page.waitForFunction((selector) => {
    const v = document.querySelector(selector + " video");
    return v && v.readyState >= 2 && !v.seeking;
  }, selector);
  const actual = await feed(page, asset)
    .locator("video")
    .evaluate((v) => ({
      src: v.dataset.recording,
      time: v.currentTime,
    }));
  assert.equal(actual.src, "/films/" + asset + ".mp4");
  assert.ok(
    Math.abs(
      actual.time - (segment / recording.nativeFps + 0.5 / recording.fps),
    ) < 0.002,
  );
}
try {
  await checkExhibits(browser, origin);
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
    await checkField(page, width);
    const index = await report(page, "index.json");
    for (const s of cases) {
      await button(page, s.short).click();
      await viewpoint(page, "3D overview").click();
      await page.locator("canvas").waitFor();
      await button(page, "Toggle camera fields of view").click();
      await viewpoint(page, "Driveway").click();
      assert.equal(
        await page.locator(".viewer-top>span").innerText(),
        "DRIVEWAY CAMERA",
      );
      await viewpoint(page, "FSS replay").click();
      await aligned(page, cameraAsset(s, "drive"), 0);
      for (const camera of cameras) {
        await viewpoint(page, camera.label).click();
        const asset = cameraAsset(s, camera.id);
        const r = await report(page, asset + ".json");
        const link = page.locator(".proof-link");
        assert.equal(
          await link.getAttribute("href"),
          "/evidence/" + asset + ".json",
        );
        await page
          .getByText("Decoded frames", { exact: true })
          .locator("..")
          .getByText(String(DURATION * recording.nativeFps), { exact: true })
          .waitFor();
        assert.equal(
          await page.locator('[data-observation="track"]').count(),
          r.candidate_count,
        );
        if (r.candidates.length) {
          await page
            .locator('[data-observation="track"]')
            .filter({
              hasText: "Track " + r.candidates[0].track_id + " enters",
            })
            .click();
          const segment = r.candidates[0].entry_segment;
          await aligned(page, asset, segment);
          const box = feed(page, asset)
            .locator(".native-box")
            .filter({ hasText: "T" + r.candidates[0].track_id })
            .first();
          await box.waitFor();
          const sample = r.candidates[0].evidence.find(
            (e) => e.segment === segment,
          );
          const [cx, cy, w, h] = sample.track_box_cxcywh;
          const coords = await box.evaluate((el) =>
            ["left", "top", "width", "height"].map((k) =>
              parseFloat(el.style[k]),
            ),
          );
          for (const [j, expected] of [
            (cx - w / 2) / r.width,
            (cy - h / 2) / r.height,
            w / r.width,
            h / r.height,
          ].entries())
            assert.ok(Math.abs(coords[j] - 100 * expected) < 0.001);
        }
        for (const c of r.candidates) {
          for (const e of c.class_evidence.filter(
            (sample) => sample.outcome === "associated",
          )) {
            await page
              .locator(
                '[data-observation="model"][data-segment="' + e.segment + '"]',
              )
              .filter({ hasText: " on T" + c.track_id })
              .click();
            await aligned(page, asset, e.segment);
            await feed(page, asset)
              .locator(".model-box")
              .getByText(e.label, { exact: true })
              .first()
              .waitFor();
          }
        }
      }
      await button(page, "Play simulation").click();
      await button(page, "Pause simulation").waitFor();
      await button(page, "Pause simulation").click();
      await viewpoint(page, "Compare cameras").click();
      for (let i = 0; i < cameras.length; i++) {
        for (const other of cameras.slice(i + 1)) {
          const first = cameras[i];
          await viewpoint(page, first.label).click();
          await page.getByLabel("Second camera").selectOption(other.id);
          const file =
            s.id + "-" + [first.id, other.id].sort().join("-") + ".json";
          const r = await report(page, file);
          assert.equal(
            await page.locator(".proof-link").getAttribute("href"),
            "/evidence/" + file,
          );
          const facts = page
            .getByText("Ground-zone entries", { exact: true })
            .first()
            .locator("..");
          await facts
            .getByText(String(r.entries.length), { exact: true })
            .waitFor();
          assert.equal(
            await page.locator(".native-trace button").count(),
            r.entries.length,
          );
          let segment = 0;
          if (r.entries.length) {
            const entry = r.entries.toSorted(
              (a, b) => a.segment - b.segment,
            )[0];
            segment = entry.segment;
            await page.locator(".native-trace button").first().click();
            await feed(page, cameraAsset(s, entry.camera))
              .getByText("Zone entry", { exact: true })
              .first()
              .waitFor();
          } else {
            await page.getByRole("slider").focus();
            await page.keyboard.press("Home");
          }
          await aligned(page, cameraAsset(s, first.id), segment);
          await aligned(page, cameraAsset(s, other.id), segment);
        }
      }
      await page.locator(".film-card").nth(cases.indexOf(s)).click();
      for (const camera of cameras) {
        const asset = cameraAsset(s, camera.id);
        await page
          .getByRole("dialog")
          .getByLabel("Camera", { exact: true })
          .selectOption(camera.id);
        await page.waitForFunction((asset) => {
          const v = document.querySelector("dialog video");
          return (
            v?.readyState >= 2 &&
            v.dataset.recording === "/films/" + asset + ".mp4"
          );
        }, asset);
        const digest = await page
          .locator("dialog video")
          .evaluate(async (video) => {
            const bytes = await (await fetch(video.currentSrc)).arrayBuffer();
            const hash = new Uint8Array(
              await crypto.subtle.digest("SHA-256", bytes),
            );
            return (
              "sha256:" +
              Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("")
            );
          });
        assert.equal(digest, index[s.id].views[camera.id].filmDigest);
        assert.equal(
          await page.locator("dialog video").evaluate((v) => v.duration),
          DURATION,
        );
        assert.equal(
          await page
            .getByRole("link", { name: "Native FSS report" })
            .getAttribute("href"),
          "/evidence/" + asset + ".json",
        );
      }
      await button(page, "Close film").click();
      console.log("Verified", s.id, "at width", width);
    }
    await button(page, "Expand viewport").click();
    await page.keyboard.press("Escape");
    assert.equal(await page.locator(".expanded").count(), 0);
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    assert.deepEqual(errors, []);
    if (process.env.SCREENSHOT_DIR) {
      await button(page, "Delivery").click();
      await page.locator(".simulator").screenshot({
        path: process.env.SCREENSHOT_DIR + "/comparison-" + width + ".png",
      });
      await viewpoint(page, "3D overview").click();
      await page.locator("canvas").waitFor();
      await page.locator(".simulator").screenshot({
        path: process.env.SCREENSHOT_DIR + "/overview-" + width + ".png",
      });
    }
    await page.close();
    console.log(
      "All nine films, native reports and synchronized camera pairs passed at width",
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
  for (const camera of cameras) {
    await viewpoint(fallback, camera.label).click();
    await fallback.waitForFunction(
      (asset) => {
        const v = document.querySelector(".viewport-surface video");
        return (
          v?.readyState >= 2 &&
          !v.seeking &&
          v.dataset.recording === "/films/" + asset + ".mp4" &&
          Math.abs(v.currentTime - 3.2) < 0.01
        );
      },
      cameraAsset(cases[0], camera.id),
    );
  }
  await fallback.route("**/evidence/delivery-drive.json", (route) =>
    route.fulfill({ status: 503, body: "Unavailable" }),
  );
  await viewpoint(fallback, "FSS replay").click();
  await fallback.getByText("Camera report unavailable.").waitFor();
  await fallback.route("**/evidence/delivery-drive-porch.json", (route) =>
    route.fulfill({ status: 503, body: "Unavailable" }),
  );
  await viewpoint(fallback, "Compare cameras").click();
  await fallback.getByLabel("Second camera").selectOption("porch");
  await fallback.getByText("Pair report unavailable.").waitFor();
  assert.equal(await fallback.locator(".native-box").count(), 0);
  await button(fallback, "Event ledger").click();
  await fallback.route("**/field/*.bin", (route) =>
    route.fulfill({ status: 503, body: "Unavailable" }),
  );
  await button(fallback, "Verify bytes").click();
  await fallback.locator('[data-verdict="unavailable"]').waitFor();
  await fallback.close();
  console.log(
    "All fallback cameras and both unavailable-report states passed.",
  );
} finally {
  await browser.close();
}
