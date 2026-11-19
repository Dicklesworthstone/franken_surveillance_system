import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "playwright-core";
import {
  exhibits,
  pathFor,
  cases,
  displayCamera,
} from "../lib/night/catalog.js";

const origin = process.argv[2];
if (!origin) throw Error("Pass the URL of a running static export.");
const shots = process.env.FSS_SITE_SCREENSHOTS;
if (shots) await mkdir(shots, { recursive: true });
const domain = new URL(origin).hostname,
  ip = process.env.FSS_SITE_ORIGIN_IP;
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--enable-unsafe-swiftshader",
    "--ignore-gpu-blocklist",
    ...(process.env.FSS_CHROME_ANGLE
      ? [
          "--enable-gpu",
          "--use-gl=angle",
          "--use-angle=" + process.env.FSS_CHROME_ANGLE,
        ]
      : []),
    ...(ip ? ["--host-resolver-rules=MAP " + domain + " " + ip] : []),
  ],
});
const button = (page, name) => page.getByRole("button", { name, exact: true });
const absolute = (path) => new URL(path, origin).href;
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage(),
    errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const screenshot = async (name) => {
    if (shots)
      await page.screenshot({
        path: join(shots, name + ".png"),
        animations: "disabled",
      });
  };
  const open = async (id, query = "") => {
    const res = await page.goto(absolute(pathFor(id) + query), {
      waitUntil: "networkidle",
    });
    assert.equal(res.status(), 200, id);
    assert.ok(await page.getByRole("heading", { level: 1 }).isVisible());
    const selectedCase = new URLSearchParams(query).get("case");
    if (selectedCase) {
      await page
        .getByRole("button", { name: exhibits[selectedCase].title, exact: true, pressed: true })
        .waitFor();
    }
  };
  const request = async (path) =>
    page.evaluate(async (href) => {
      const r = await fetch(href);
      return {
        status: r.status,
        type: r.headers.get("content-type"),
        body: await r.text(),
      };
    }, path);
  await open("home");
  const archive = JSON.parse(
    (await request("/night-evidence/index.json")).body,
  );
  const social = new Set();
  for (const id of Object.keys(exhibits)) {
    const article = await page.evaluate(async (url) => {
      const response = await fetch(url);
      const html = new DOMParser().parseFromString(
        await response.text(),
        "text/html",
      );
      const card = (key) =>
        html.querySelector(
          'meta[property="' + key + '"],meta[name="' + key + '"]',
        )?.content;
      return {
        status: response.status,
        text: html.querySelector("main")?.textContent,
        title: html.querySelector("h1")?.textContent,
        cards: {
          "og:image": card("og:image"),
          "twitter:image": card("twitter:image"),
        },
      };
    }, pathFor(id));
    assert.equal(article.status, 200, id);
    assert.ok(article.title, id);
    assert.doesNotMatch(article.text, /basketball|bounce pass|Juniper House/i);
    for (const [key, height] of [
      ["og:image", 630],
      ["twitter:image", 600],
    ]) {
      const path = new URL(article.cards[key]).pathname;
      assert.ok(path.startsWith(pathFor(id)));
      const meta = await page.evaluate(async (p) => {
        const r = await fetch(p),
          b = await r.arrayBuffer(),
          dv = new DataView(b);
        return {
          status: r.status,
          type: r.headers.get("content-type"),
          width: dv.getUint32(16),
          height: dv.getUint32(20),
          length: b.byteLength,
          prefix: dv.getUint32(0),
        };
      }, path);
      assert.deepEqual(
        [meta.status, meta.prefix, meta.width, meta.height],
        [200, 0x89504e47, 1200, height],
        id + " " + key,
      );
      assert.match(meta.type, /image\/png/);
      assert.ok(meta.length > 12000);
      assert.ok(!social.has(path));
      social.add(path);
    }
  }
  await open("home");
  await screenshot("desktop");
  const hero = page.locator(".hero-photo");
  assert.ok(await hero.evaluate((el) => el.naturalWidth >= 1000));
  await page.getByRole("button", { name: /Watch the site film/ }).click();
  const screening = page.getByRole("dialog", { name: "Alder House site film" });
  await screening.waitFor();
  await screening
    .locator("video")
    .evaluate(
      (v) =>
        v.readyState >= 1 ||
        new Promise((done) =>
          v.addEventListener("loadedmetadata", done, { once: true }),
        ),
    );
  assert.ok(
    await screening
      .locator("video")
      .evaluate((v) => v.duration > 16 && v.textTracks.length === 1),
  );
  await page.keyboard.press("Escape");
  await screening.waitFor({ state: "hidden" });
  const browserIssues = [];
  for (const id of cases) {
    await open(id);
    const main = page.locator(".recording video").first();
    await main.evaluate(
      (v) =>
        v.readyState >= 1 ||
        new Promise((resolve) =>
          v.addEventListener("loadedmetadata", resolve, { once: true }),
        ),
    );
    assert.ok(
      await main.evaluate(
        (v) => v.videoWidth > 0 && Number.isFinite(v.duration),
      ),
    );
    await button(page, "Next frame").click();
    assert.ok(
      Number.parseFloat(await page.locator(".transport output").innerText()) >
        0,
    );
    await button(page, "Compare cameras").click();
    assert.equal(await page.locator(".recording video").count(), 2);
    await button(page, "Seek recording ↗").click();
    await button(page, "Play recording").click();
    await page.waitForFunction(
      () =>
        document.querySelector(".recording video").currentTime > 1 &&
        !document.querySelector(".recording video").paused,
    );
    await button(page, "Pause recording").click();
    const values = await page
      .locator(".recording video")
      .evaluateAll((els) => els.map((el) => el.currentTime));
    assert.ok(
      Math.abs(values[0] - values[1]) < 0.3,
      id + " view skew " + values,
    );
    await button(page, "Verify recording").click();
    await page
      .getByText("The downloaded bytes match the retained digest.")
      .last()
      .waitFor();
    const measured = page.getByLabel("Measured track event");
    if (await measured.count()) {
      await measured.selectOption({ index: 1 });
      const selected = await measured.locator("option:checked").innerText();
      assert.ok(
        Math.abs(
          parseFloat(selected) -
            parseFloat(await page.locator(".transport output").innerText()),
        ) < 0.03,
      );
    }
    const ledger = archive.cases[id].ledger;
    if (ledger.status === "verified") {
      await button(page, "Verify object").click();
      await page
        .locator(".reading")
        .getByText("The downloaded bytes match the retained digest.")
        .waitFor();
    }
    await open("agent-console", "?case=" + id);
    await button(page, "Workspace handoff").click();
    const native = page.locator(".envelope");
    await native.locator("summary").click();
    assert.equal(
      JSON.parse(await native.locator("pre").innerText()).schema,
      "fss.agent_response_envelope.v1",
    );
    await button(page, "Resumed session").click();
    await page.waitForFunction(() =>
      document.querySelector(".envelope pre")?.textContent.includes("handoff"),
    );
    await open("camera-fusion", "?case=" + id);
    assert.equal(
      await page.locator(".reading .proof-links a").count(),
      Object.keys(archive.cases[id].associations.pairs).length,
    );
  }
  await open("digital-twin");
  const photographs = page
    .getByRole("region", { name: "Architectural stills" })
    .getByRole("link");
  assert.equal(await photographs.count(), 3);
  for (const link of await photographs.all()) {
    const shot = await link.getAttribute("href");
    const resolution = await page.evaluate(async (src) => {
      const image = new Image();
      image.src = src;
      await image.decode();
      return image.naturalWidth;
    }, shot);
    assert.ok(resolution >= 1000, shot);
  }
  await page.getByText("All architectural and camera views", {exact: true}).click();
  await page.getByRole("link", {name: /Download render index/}).waitFor();
  const album = JSON.parse((await request("/estate/stills.json")).body);
  assert.ok(album.stills.length >= 4);
  assert.equal(await page.locator(".estate-photographs li a").count(), album.stills.length + 1);
  const surface = page.locator("[data-estate-state]");
  await page.waitForFunction(
    () =>
      document.querySelector("[data-estate-state]")?.dataset.estateState ===
      "ready",
    {},
    { timeout: 120000 },
  );
  const canvas = surface.locator("canvas"),
    hash = async () =>
      createHash("sha256")
        .update(await canvas.screenshot())
        .digest("hex");
  const baseline = await hash();
  const viewpoint = page.getByLabel("Viewpoint");
  await viewpoint.selectOption({ index: 1 });
  const lens = await hash();
  assert.notEqual(baseline, lens);
  await page.getByLabel("Person stature").focus();
  await page.keyboard.press("ArrowRight");
  await page.getByText(/Custom reconstruction/).waitFor();
  await button(page, "Reset scene").click();
  await page.getByText(/Reference take/).waitFor();
  await screenshot("twin");
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    for (const id of [
      "home",
      "after-hours",
      "event-ledger",
      "agent-console",
      "digital-twin",
      "poster-room",
    ]) {
      await open(id);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - innerWidth,
      );
      if (overflow > 1)
        browserIssues.push(id + " at " + width + "px overflows by " + overflow);
      if (id === "digital-twin" && width === 390) {
        await page
          .locator('[data-estate-state="ready"]')
          .waitFor({ timeout: 120000 });
        const usedCompactTexture = await page.evaluate(async () => {
          const receipt = await (
            await fetch("/estate/mesh-receipt.json")
          ).json();
          const loaded = new Set(
            performance
              .getEntriesByType("resource")
              .map((r) => new URL(r.name).pathname),
          );
          return Object.entries(receipt.compactTextures).some(
            ([full, reduced]) => full !== reduced && loaded.has(reduced),
          );
        });
        assert.ok(
          usedCompactTexture,
          "Narrow interactive viewer must load its compact material maps",
        );
      }
      if (id === "home") {
        await button(page, "Open navigation").click();
        await page
          .getByRole("link", { name: "Estate twin", exact: true })
          .last()
          .waitFor();
        await button(page, "Close navigation").click();
        if (width === 390) await screenshot("mobile");
      }
    }
  }
  assert.deepEqual(browserIssues, []);
  const fallback = await context.newPage();
  await fallback.addInitScript(() => {
    const get = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
      return String(kind).includes("webgl")
        ? null
        : get.call(this, kind, ...args);
    };
  });
  await fallback.goto(absolute(pathFor("digital-twin")));
  await fallback.getByText(/3D view unavailable/).waitFor();
  assert.ok(await fallback.locator("video").first().isVisible());
  await fallback.close();
  assert.deepEqual(errors, []);
  console.log(
    "Browser verified " +
      Object.keys(exhibits).length +
      " pages, " +
      social.size +
      " social images, three camera reviews, source and ledger verification, workspace handoff, live WebGL, mobile widths and fallback.",
  );
} finally {
  await browser.close();
}
