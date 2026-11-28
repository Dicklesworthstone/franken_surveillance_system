// Checks a running copy of the site in a real browser.
//
//   node scripts/check-site.mjs http://127.0.0.1:8000
//
// Set FSS_SITE_SCREENSHOTS to a directory to keep a screenshot of each width.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { checkDeliveryDropout } from "./check-delivery-dropout-browser.mjs";

const origin = process.argv[2];
if (!origin) throw Error("Pass the URL of a running copy of the site.");
const shots = process.env.FSS_SITE_SCREENSHOTS;
if (shots) await mkdir(shots, { recursive: true });
const take = fileURLToPath(new URL("../public/watch/intrusion/", import.meta.url));
const absolute = (path) => new URL(path, origin).href;
const WIDTHS = [1440, 768, 390, 320];
const RETIRED = ["/incidents/after-hours/", "/exhibits/camera-wall/", "/v2/"];

const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: ["--no-sandbox", "--disable-dev-shm-usage", "--autoplay-policy=no-user-gesture-required"],
});
const done = [];
const pass = (text) => done.push(text);

async function open(context) {
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push("page error: " + e.message));
  page.on("crash", () => errors.push("the browser tab crashed"));
  page.on("console", (m) => m.type() === "error" && errors.push("console: " + m.text()));
  page.on("response", (r) => r.status() >= 400 && errors.push(r.status() + " " + r.url()));
  const response = await page.goto(absolute("/"), { waitUntil: "networkidle" });
  assert.equal(response.status(), 200, "home page status");
  return { page, errors };
}

const films = (page) =>
  page.evaluate(() =>
    [...document.querySelectorAll(".console video")].map((v) => ({
      t: v.currentTime,
      ready: v.readyState,
      paused: v.paused,
      blob: v.src.startsWith("blob:"),
    })),
  );
const clockText = (page) => page.locator(".timeline__now .data").textContent();

try {
  // The page at each width: one headline, nothing wider than the window, no failed request.
  for (const width of WIDTHS) {
    const context = await browser.newContext({
      viewport: { width, height: width < 600 ? 844 : 900 },
      deviceScaleFactor: width < 600 ? 2 : 1,
      isMobile: width < 600,
      hasTouch: width < 600,
    });
    const { page, errors } = await open(context);
    assert.equal(await page.locator("h1").count(), 1, `one h1 at ${width}`);
    assert.ok(await page.locator("h1").isVisible(), `h1 visible at ${width}`);
    for (const id of ["minute", "how", "inputs", "fusion", "coverage", "belief", "agent", "effects", "record", "status"])
      assert.equal(await page.locator("#" + id).count(), 1, `section #${id}`);
    // Before any scrolling the page has fetched only what its first screen needs: the site renders
    // further down wait until their section comes near, and the one image it preloads is the hero still.
    const early = await page.evaluate(() => ({
      renders: performance.getEntriesByType("resource").map((e) => e.name).filter((name) => /\/twin\/[^/]+\.jpg$/.test(name)),
      preloads: [...document.querySelectorAll('link[rel="preload"][as="image"]')].map((l) => l.getAttribute("href") ?? l.getAttribute("imagesrcset")),
    }));
    assert.deepEqual(early.renders, [], `no site render fetched before scrolling at ${width}`);
    assert.deepEqual(early.preloads, ["/watch/intrusion/hero-still.jpg"], `the hero still is the only image preloaded at ${width}`);
    await page.evaluate(async () => {
      for (let y = 0; y < document.documentElement.scrollHeight; y += 700) {
        scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 60));
      }
    });
    await page.waitForLoadState("networkidle");
    const extra = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.equal(extra, 0, `no sideways scroll at ${width}`);
    // The header and the dock are fixed, so running past the edge of the window would not make the page scroll.
    const outside = await page.evaluate(() =>
      [...document.querySelectorAll(".topbar a, .dock a")]
        .filter((el) => {
          const r = el.getBoundingClientRect();
          return r.width > 0 && (r.left < 0 || r.right > document.documentElement.clientWidth);
        })
        .map((el) => el.textContent.trim()),
    );
    assert.deepEqual(outside, [], `header and dock inside the window at ${width}`);
    if (width < 600) {
      // On a touch screen a tap on the fusion plan places the person there.
      const plan = page.locator(".bench__plan");
      await plan.scrollIntoViewIfNeeded();
      const where = () => page.locator(".bench__handle").getAttribute("aria-valuetext");
      const was = await where();
      const box = await plan.boundingBox();
      await page.touchscreen.tap(box.x + box.width * 0.8, box.y + box.height * 0.3);
      await page.waitForFunction((old) => document.querySelector(".bench__handle").getAttribute("aria-valuetext") !== old, was);
      assert.notEqual(await where(), was, `tap moves the person at ${width}`);
    }
    assert.deepEqual([...new Set(errors)], [], `no errors at ${width}`);
    if (shots) await page.screenshot({ path: join(shots, `home-${width}.png`) });
    await context.close();
  }
  pass(`Home page renders at ${WIDTHS.join(", ")} px with no sideways scroll and no failed request. Its first screen preloads only the hero still and fetches no site render.`);

  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const { page, errors } = await open(context);

  // Supporting figures are folded into drawers. Open each one the way a reader would, so every
  // check below reads them, page text included.
  const drawers = page.locator("details.drawer");
  const drawerCount = await drawers.count();
  for (let i = 0; i < drawerCount; i++) {
    const summary = drawers.nth(i).locator(":scope > summary");
    await summary.scrollIntoViewIfNeeded();
    await summary.click();
  }
  assert.equal(await page.locator("details.drawer[open]").count(), drawerCount, "every drawer opens");
  pass(`${drawerCount} drawers of supporting figures open.`);

  // Copy rules the owner set: no estate name, no dash punctuation in prose. The estates' working
  // names (Alder House, and Juniper House with its court) also stay out of copy that is not on
  // screen: hidden panels and SVG titles, alt text, labels and titles, the titles and descriptions
  // link previews read, and each chapter's share page. Addresses in metadata and attributes are
  // not copy and are not searched.
  const text = await page.evaluate(() => document.body.innerText);
  const unseen = await page.evaluate(() => {
    // Text nodes in place: a cloned body would clone the films and start fetching them again.
    const words = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!node.parentElement?.closest("script, style, noscript")) words.push(node.data);
    }
    // Metadata and attribute values that are addresses (og:image, og:url) are skipped; page text
    // never is, even when it starts with a slash.
    const values = [
      document.title,
      ...[...document.querySelectorAll("meta[name=description], meta[property^='og:'], meta[name^='twitter:']")].map((m) => m.content),
      ...[...document.querySelectorAll("[alt], [aria-label], [title]")].flatMap((e) =>
        ["alt", "aria-label", "title"].map((name) => e.getAttribute(name)),
      ),
    ].filter((value) => value && !/^(https?:)?\//.test(value));
    return [...words, ...values].join("\n");
  });
  const shares = [...new Set(await page.locator('a[href^="/chapter/"]').evaluateAll((links) => links.map((a) => a.getAttribute("href"))))];
  assert.ok(shares.length >= 5, `every chapter links its share page (${shares.length} found)`);
  const shareCopy = [];
  for (const share of shares) {
    const response = await page.request.get(absolute(share));
    assert.equal(response.status(), 200, `${share} is served`);
    const html = await response.text();
    const body = html.match(/<body[^>]*>([\s\S]*)<\/body>/)?.[1];
    assert.ok(body, `${share} has a body to read`);
    shareCopy.push(
      body.replace(/<(script|style)[\s\S]*?<\/\1>/g, " ").replace(/<[^>]+>/g, " "),
      ...[...html.matchAll(/<title>([^<]*)<\/title>|<meta [^>]*content="([^"]*)"/g)]
        .map((m) => m[1] ?? m[2])
        .filter((copy) => !/^(https?:)?\//.test(copy)),
    );
  }
  for (const copy of [text, unseen, shareCopy.join("\n")]) assert.doesNotMatch(copy, /alder|juniper/i, "estate name absent");
  assert.ok(!/[—–]/.test(text), "no em or en dash in the page text");
  assert.match(await page.title(), /^Franken Surveillance/);
  pass(`Page text, labels and ${shares.length} share pages have no estate name, and the text has no dash punctuation.`);

  // Every picture and film the page names is served.
  const media = await page.evaluate(() => [
    ...new Set(
      [...document.querySelectorAll("img[src], video[poster], image")]
        .flatMap((el) => [el.getAttribute("src"), el.getAttribute("poster"), el.getAttribute("href")])
        .filter((u) => u && !u.startsWith("blob:") && !u.startsWith("data:")),
    ),
  ]);
  const scene = await (await page.request.get(absolute("/watch/intrusion/scene.json"))).json();
  for (const url of [...media, ...scene.cameras.map((c) => c.video), "/opengraph-image.jpg", "/twitter-image.jpg", "/watch/intrusion/CREDITS.txt"]) {
    const status = (await page.request.get(absolute(url))).status();
    assert.equal(status, 200, url);
  }
  assert.equal(scene.cameras.length, 5, "five cameras");
  pass(`${media.length} pictures and ${scene.cameras.length} films are served.`);

  // Every size a picture is offered in is served, and is as wide as the page tells the browser it is.
  const offered = await page.evaluate(() =>
    [...document.querySelectorAll("img[srcset]")].flatMap((el) => el.getAttribute("srcset").split(", ").map((entry) => entry.split(" "))),
  );
  assert.ok(offered.length > 0, "the chapter pictures are offered in several sizes");
  for (const [url, descriptor] of offered) {
    const wide = await page.evaluate(async (u) => {
      const response = await fetch(u);
      return response.ok ? (await createImageBitmap(await response.blob())).width : response.status;
    }, url);
    assert.equal(descriptor, wide + "w", url);
  }
  pass(`${offered.length} picture sizes are as wide as they are offered.`);

  // The console: films load into memory, play together, pause, and follow the keyboard.
  await page.locator("#minute").scrollIntoViewIfNeeded();
  await page.waitForFunction(() => {
    const list = [...document.querySelectorAll(".console video")];
    return list.length === 5 && list.every((v) => v.readyState >= 2 && v.src.startsWith("blob:"));
  });
  await page.getByRole("button", { name: "Play", exact: true }).click();
  await page.waitForTimeout(3500);
  let state = await films(page);
  assert.ok(state.every((v) => !v.paused && v.t > 1), "all five films are playing");
  assert.ok(Math.max(...state.map((v) => v.t)) - Math.min(...state.map((v) => v.t)) < 0.35, "films within 0.35 s of each other while playing");
  await page
    .getByRole("button", { name: "Pause", exact: true })
    .click({ timeout: 5000 })
    .catch(async (error) => {
      const seen = await page.evaluate(() => ({
        label: document.querySelector(".timeline__play")?.getAttribute("aria-label"),
        clock: document.querySelector(".timeline__now .data")?.textContent,
        films: [...document.querySelectorAll(".console video")].map((v) => v.currentTime.toFixed(1) + (v.paused ? " paused" : "")),
        address: location.href,
        text: document.body.innerText.slice(0, 160),
      }));
      throw Error("Pause button not found: " + JSON.stringify({ ...seen, errors }), { cause: error });
    });
  const slider = page.getByRole("slider", { name: "Time in the recording" });
  await slider.focus();
  await page.keyboard.press("Home");
  for (let i = 0; i < 100; i++) await page.keyboard.press("ArrowRight");
  await page.waitForFunction(() => [...document.querySelectorAll(".console video")].every((v) => !v.seeking));
  state = await films(page);
  const at = +(await slider.inputValue());
  assert.ok(at > 20, "keyboard moved the clock");
  assert.ok(state.every((v) => v.paused && Math.abs(v.t - at) < 0.06), "paused films sit on the clock");
  pass(`Five films play in step and follow the keyboard (checked at ${at.toFixed(2)} s).`);

  // The staged account and the console agree: at the marker for the first two-camera
  // agreement, the console itself shows two cameras on the first track.
  await page.getByRole("button", { name: "Two cameras agree" }).click();
  await page.waitForFunction(() => /Two or more cameras/.test(document.querySelector(".readout")?.textContent ?? ""));
  pass("The marker for the first two-camera agreement lands where the console shows two cameras.");

  // Choosing a camera, and switching the site view.
  const gate = page.getByRole("button", { name: "Show the gate camera" });
  await gate.click();
  assert.equal(await gate.getAttribute("aria-pressed"), "true");
  const backdrop = () => page.locator(".console__site image").first().getAttribute("href");
  const model = await backdrop();
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  assert.notEqual(await backdrop(), model, "plan backdrop differs from model backdrop");
  await page.getByRole("button", { name: "Model", exact: true }).click();
  assert.equal(await backdrop(), model);
  pass("Camera selection and the model and plan views switch.");

  // A time in the walk-through moves the console and brings it into view.
  const before = await clockText(page);
  await page.locator("#effects .seek").click();
  await page.waitForFunction((old) => document.querySelector(".timeline__now .data")?.textContent !== old, before);
  // The page scrolls smoothly, so wait for it to come to rest with the console just under the top edge.
  await page.waitForFunction(() => {
    const top = document.querySelector("#console").getBoundingClientRect().top;
    const still = window.__lastTop === top;
    window.__lastTop = top;
    return still && top >= 0 && top < 120;
  }, null, { polling: 250 });
  pass(`A walk-through time moved the clock from ${before} to ${await clockText(page)}.`);

  // Measured panels appear only when the project's own output is published.
  const measured = await page.locator(".measured").count();
  if (existsSync(join(take, "native.json"))) assert.ok(measured >= 5, "measured panels present");
  else assert.equal(measured, 0, "no measured panel without native output");
  pass(measured ? `${measured} measured panels are shown.` : "No measured output is published, and no measured panel is shown.");

  if (existsSync(join(take, "fusion-replay.json"))) {
    const excerpt = page.getByRole("region", {name: "Two views of the same person"});
    await excerpt.scrollIntoViewIfNeeded();
    const proofUrl = await excerpt.getByRole("link", {name: /source frames/}).getAttribute("href");
    const proof = await (await page.request.get(absolute(proofUrl))).json();
    const reportUrl = await excerpt.getByRole("link", {name: /native fusion report/}).getAttribute("href");
    const report = await (await page.request.get(absolute(reportUrl))).json();
    const [advice] = report.calibrated_class_advice.candidates;
    for (const [index, source] of proof.cameras.entries()) {
      const score = advice.scores.find((s) => s.sensor === "sensor:" + source.camera);
      const figure = excerpt.locator("figure").nth(index);
      assert.ok((await figure.textContent()).includes((score.score_ppm_outward[0] / 1e6).toFixed(3)));
      const video = figure.locator("video.is-shown");
      await video.waitFor();
      assert.equal(await video.evaluate((v, fps) => Math.floor(v.currentTime * fps), scene.clock.fps), source.source_frame);
      const filmHash = await video.evaluate(async (v) => {
        const bytes = await (await fetch(v.currentSrc)).arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        return "sha256:" + Array.from(new Uint8Array(digest), (n) => n.toString(16).padStart(2, "0")).join("");
      });
      assert.equal(filmHash, source.source_film_sha256);
    }
    assert.equal(advice.outcome.supporting_clusters, 1);
    assert.deepEqual(advice.outcome.counterfactuals[0].posterior_log_odds_millibans, advice.query.prior);
    pass("The two calibration stills, their detector scores and the group-removal result match the native replay.");
  }

  const relayRoot = join(take, "relay-replay.json");
  const relayPanel = page.getByRole("region", { name: "Follow a notification to its receiver" });
  if (existsSync(relayRoot)) {
    const indexLink = await relayPanel.getByRole("link", { name: "Replay inputs and results" }).getAttribute("href");
    const indexResponse = await page.request.get(absolute(indexLink));
    assert.equal(indexResponse.status(), 200, "published relay comparison");
    assert.deepEqual(await indexResponse.body(), await readFile(relayRoot), "served relay generation matches the local capture");
    const proof = await indexResponse.json();
    const object = async (link, reference) => {
      const address = await link.getAttribute("href");
      assert.equal(address, "/watch/intrusion/" + reference.path);
      const response = await page.request.get(absolute(address));
      assert.equal(response.status(), 200, "open relay receipt");
      const bytes = await response.body();
      assert.equal("sha256:" + createHash("sha256").update(bytes).digest("hex"), reference.sha256);
      return JSON.parse(bytes);
    };
    for (const [row, branchId, phase] of [
      ["accepted", "accepted", "dispatch"], ["repeat", "accepted", "repeat"],
      ["lost-ack", "lost-ack", "dispatch"], ["held", "held", "plan"],
    ]) {
      const field = relayPanel.locator(`[data-relay-case="${row}"]`);
      const branch = proof.branches.find((record) => record.id === branchId);
      const step = branch.steps.find((entry) => entry.phase === phase);
      const native = await object(field.getByRole("link", { name: /native result/ }), step.native);
      const receiver = await object(field.getByRole("link", { name: /receiver log/ }), branch.listener);
      const observed = receiver.observations.find((entry) => entry.phase === phase);
      const received = observed.received.length;
      assert.equal(observed.native_sha256, step.native.sha256);
      assert.equal(received, row === "accepted" || row === "lost-ack" ? 1 : 0, branchId + " listener");
      const text = await field.innerText();
      assert.ok(text.includes(`${received} ${received === 1 ? "POST" : "POSTs"} received during this call.`));
      assert.ok(text.includes(native.payload?.state ?? native.outcome), row + " native state");
      if (received) {
        const wire = observed.received[0];
        const request = await object(field.getByRole("link", { name: /POST body/ }), wire.body);
        assert.equal("sha256:" + request.event_revision_sha256, branch.event.revision_digest);
        assert.equal("sha256:" + request.precondition_sha256, native.payload.preconditionDigest);
        assert.equal(wire.idempotency_key, createHash("sha256").update(native.payload.idempotencyKey).digest("hex"));
      }
      if (row === "accepted") assert.ok(text.includes(`HTTP ${observed.received[0].response_status}`));
      if (row === "lost-ack") {
        assert.equal(native.outcome, "indeterminate");
        assert.equal(observed.received[0].response_disposition, "connection_closed_without_response");
        assert.ok(text.includes("without replying") && text.includes("0 additional POSTs"));
        const inspection = branch.steps.find((entry) => entry.phase === "inspect");
        const readBack = await object(field.getByRole("link", { name: "fresh process" }), inspection.native);
        assert.equal(readBack.payload.state, "indeterminate");
      }
      if (row === "held") assert.equal(native.outcome, "refused");
    }
    pass("The four relay comparisons match the linked native calls and the receiver’s observed HTTP requests.");
  } else if (measured) {
    assert.equal(await relayPanel.count(), 0);
    assert.ok(await page.getByText("No separate retry and acknowledgement comparison was published for this take.").isVisible());
  }

  if (measured) {
    const raw = await (await page.request.get(absolute("/watch/intrusion/native.json"))).json();
    const pairs = raw.associations.filter(p => p.separate_devices?.candidates?.length);
    const retainedRow = (candidate) => {
      const time = Array.isArray(candidate.t) ? Math.min(...candidate.t) : candidate.t;
      const distance = candidate.nearest_scripted_person?.distance_m;
      return distance == null ? "no scripted-person comparison" :
        distance.toFixed(2) + " m from the nearest staged person at " + time + " s";
    };
    if (pairs.length) await page.getByText("Retained comparisons at the earlier camera frame", { exact: true }).click();
    for (const pair of pairs) {
      const maxima = [];
      for (const c of pair.separate_devices.candidates) {
        const row = page.locator('[data-match-event="' + c.event_id + '"]');
        assert.ok(await row.isVisible());
        assert.ok((await row.innerText()).includes(retainedRow(c)), c.event_id);
        const times = Array.isArray(c.t) ? c.t : [c.t];
        const frames = times.map(t => Math.round(t * scene.clock.fps));
        const distances = Object.values(scene.tracks).flatMap(track => {
          const observed = [];
          for (let f = Math.min(...frames); f <= Math.max(...frames); f++)
            if (track.x[f] != null && track.z[f] != null && c.ground)
              observed.push(Math.hypot(track.x[f] - c.ground[0], track.z[f] - c.ground[1]));
          return observed.length ? [Math.max(...observed)] : [];
        });
        const closest = Math.min(...distances);
        if (closest <= raw.fss.settings.distance_gate_m) maxima.push(closest);
      }
      if (maxima.length) {
        const text = await page.locator('[data-camera-pair="' + pair.cameras.join("+") + '"]').innerText();
        const bound = Number(text.match(/never more than ([\d.]+) m/)?.[1]);
        const exact = Math.max(...maxima);
        assert.ok(bound >= exact && bound - exact < 0.01, pair.cameras + " interval upper bound");
      }
    }
    const alerted = raw.events.find(e => e.id === raw.agent?.facts?.alert?.event_id);
    if (alerted?.ground) {
      const detail = page.locator('[data-alert-event="' + alerted.id + '"]');
      assert.ok((await detail.innerText()).includes(retainedRow(alerted)), alerted.id);
    }
    pass("Visible pair and alert comparisons use retained metres and observation times; interval bounds round upwards.");
  }

  // The interactive figures respond.
  const plan = page.locator(".bench__plan");
  await plan.scrollIntoViewIfNeeded();
  const person = () => page.locator(".bench__handle").getAttribute("aria-valuetext");
  const stood = await person();
  const frame = await plan.boundingBox();
  await page.mouse.move(frame.x + frame.width * 0.3, frame.y + frame.height * 0.4);
  await page.mouse.down();
  await page.mouse.move(frame.x + frame.width * 0.7, frame.y + frame.height * 0.6, { steps: 4 });
  await page.mouse.up();
  assert.notEqual(await person(), stood, "dragging on the fusion plan moves the person");
  const verdict = page.locator(".bench__verdict .data");
  for (const name of ["Gate", "Driveway", "Front door", "Porch", "Front lawn"])
    await page.locator(".bench__cameras").getByLabel(name, { exact: true }).uncheck();
  assert.equal(await verdict.textContent(), "not_observable");
  const sum = page.locator(".belief__total strong");
  const whole = await sum.textContent();
  await page.locator(".belief__rows input:not([disabled])").first().uncheck();
  assert.notEqual(await sum.textContent(), whole, "removing evidence changes the sum");
  await page.locator("#bytes-object").press("End");
  await page.locator("#bytes-object").pressSequentially(" ");
  await page.waitForFunction(() => /No match/.test(document.querySelector(".bytes__verdict").textContent));
  pass("The fusion bench, the evidence sum and the byte check respond.");

  assert.deepEqual([...new Set(errors)], [], "no errors during the console checks");
  await context.close();

  // Both a readable film from the wrong camera and a temporary outage can be retried in place.
  const recordedGate = scene.cameras.find((camera) => camera.id === "gate");
  const driveway = scene.cameras.find((camera) => camera.id === "driveway");
  for (const fault of ["wrong film", "unavailable"]) {
    const faultPage = await browser.newPage();
    const wrongFilm = await faultPage.request.get(absolute(driveway.video));
    let recover = false;
    await faultPage.route(absolute(recordedGate.video), (route) => {
      if (recover) return route.continue();
      if (fault === "wrong film") return route.fulfill({ response: wrongFilm });
      return route.fulfill({ status: 503, body: "Temporary outage" });
    });
    await faultPage.goto(absolute("/"));
    await faultPage.locator("#minute").scrollIntoViewIfNeeded();
    await faultPage.getByRole("button", { name: "Show the gate camera" }).click();
    const feed = faultPage.locator(".feed--large");
    const retry = feed.getByRole("button", { name: "Load this film again" });
    await retry.waitFor();
    // Frame 34 contains a staged person in the retained gate recording.
    await faultPage.evaluate((t) => window.dispatchEvent(new CustomEvent("fss:seek", { detail: t })), 34 / scene.clock.fps);
    assert.equal(await feed.locator("video").getAttribute("src"), null, fault);
    assert.equal(await feed.locator("svg rect,.feed__label").count(), 0, fault);
    await faultPage.waitForFunction(() => [...document.querySelectorAll(".console video")].filter((v) => v.readyState >= 2).length === 4);
    recover = true;
    await retry.click();
    await feed.locator(".feed__label").first().waitFor();
    const verified = await feed.locator("video").evaluate(async (v) => {
      const bytes = await (await fetch(v.currentSrc)).arrayBuffer();
      return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
        .map((n) => n.toString(16).padStart(2, "0")).join("");
    });
    assert.equal(verified, recordedGate.video_sha256, fault + " recovered the captured gate film");
    await faultPage.close();
  }
  pass("A film swapped for another camera and a film that fails to load both hide their outlines while the other four play, and loading again restores the right film.");

  for (const fault of ["missing recorded digest", "WebCrypto unavailable"]) {
    const faultPage = await browser.newPage();
    if (fault === "missing recorded digest") {
      // The initial Next document carries the camera summary consumed by both players.
      await faultPage.route(absolute("/"), async (route) => {
        const response = await route.fetch();
        const html = await response.text();
        assert.ok(html.includes(recordedGate.video_sha256), "document contains the retained gate digest");
        await route.fulfill({ response, body: html.replaceAll(recordedGate.video_sha256, "") });
      });
    } else {
      await faultPage.addInitScript(() => Object.defineProperty(globalThis.crypto, "subtle", { value: undefined }));
    }
    await faultPage.goto(absolute("/"));
    await faultPage.locator("#minute").scrollIntoViewIfNeeded();
    await faultPage.getByRole("button", { name: "Show the gate camera" }).click();
    await faultPage.evaluate((t) => window.dispatchEvent(new CustomEvent("fss:seek", { detail: t })), 34 / scene.clock.fps);
    const affected = faultPage.locator(fault === "missing recorded digest" ? ".feed--large" : ".console .feed");
    const count = fault === "missing recorded digest" ? 1 : scene.cameras.length;
    await affected.locator(".film-error").nth(count - 1).waitFor();
    assert.equal(await affected.locator("video[src], .feed__marks, .feed__label").count(), 0, fault);
    const still = faultPage.locator(".frames--wall .frame").filter({ hasText: /Gate/i }).first();
    await still.scrollIntoViewIfNeeded();
    await still.getByRole("button", { name: "Load this film again" }).waitFor();
    assert.equal(await still.locator("video[src], video.is-shown").count(), 0, fault + " obscures the gate still");
    await faultPage.close();
  }
  pass("A missing capture digest or unavailable WebCrypto keeps unverified frames, outlines and labels hidden.");

  const nativePath = join(take, "native.json");
  const nativeReport = existsSync(nativePath) ? JSON.parse(await readFile(nativePath, "utf8")) : null;
  const boxesFile = nativeReport?.detector_boxes ?? "native-boxes.json";
  const boxesPath = join(take, boxesFile);
  const measuredBoxes = existsSync(boxesPath) ? JSON.parse(await readFile(boxesPath, "utf8")) : null;
  const occupied = 34, substitute = 100;
  const seekFrame = (tab, frame) => tab.evaluate(
    (seconds) => window.dispatchEvent(new CustomEvent("fss:seek", { detail: seconds })), frame / scene.clock.fps,
  );
  const dimensions = (boxes) => boxes.map(([x, y, right, bottom]) => [x, y, right - x, bottom - y]);
  const rectangles = (feed, style) => feed.locator(style).evaluateAll((nodes) =>
    nodes.map((node) => ["x", "y", "width", "height"].map((name) => Number(node.getAttribute(name)))),
  );
  for (const file of measuredBoxes ? ["scene.json", boxesFile] : ["scene.json"]) {
    const verifyingScene = file === "scene.json";
    const altered = structuredClone(verifyingScene ? scene : measuredBoxes);
    const rows = verifyingScene ? altered.boxes.gate.a : altered.cameras.gate.person;
    assert.notDeepEqual(rows[occupied], rows[substitute], file + " substitution changes the retained gate box");
    rows[occupied] = rows[substitute];
    const tab = await browser.newPage();
    let recover = false;
    await tab.route(absolute("/watch/intrusion/" + file), (route) =>
      recover ? route.continue() : route.fulfill({ json: altered }),
    );
    await tab.goto(absolute("/"));
    await tab.locator("#minute").scrollIntoViewIfNeeded();
    await tab.getByRole("button", { name: "Show the gate camera" }).click();
    await seekFrame(tab, occupied);
    const feed = tab.locator(".feed--large");
    const retry = tab.getByRole("button", { name: verifyingScene ? "Retry positions" : "Retry detector results" });
    await retry.waitFor();
    await tab.waitForFunction(() => document.querySelector(".feed--large video")?.readyState >= 2);
    assert.equal(await feed.locator(verifyingScene ? ".feed__staged,.feed__label" : ".feed__measured").count(), 0, file);
    if (verifyingScene) {
      assert.ok(await tab.getByText("Unavailable", { exact: true }).first().isVisible());
      if (measuredBoxes) await feed.locator(".feed__measured").first().waitFor();
    } else {
      assert.equal(await tab.locator(".console__detector-status").innerText(), "Detector results unavailable.");
      await feed.locator(".feed__staged").first().waitFor();
    }
    recover = true;
    await retry.click();
    await feed.locator(".feed__staged").first().waitFor();
    const expectedStaged = Object.values(scene.boxes.gate).map((track) => track[occupied])
      .filter((box) => box && box[4] >= 0.25 && box[3] - box[1] >= 0.05);
    assert.deepEqual(await rectangles(feed, ".feed__staged"), dimensions(expectedStaged));
    if (measuredBoxes) {
      const gateRun = measuredBoxes.cameras.gate;
      await feed.locator(".feed__measured").first().waitFor();
      assert.deepEqual(await rectangles(feed, ".feed__measured"), dimensions(gateRun.person[occupied]));
      const empty = gateRun.inferred.find((frame) => !gateRun.person[frame]?.length);
      assert.ok(Number.isInteger(empty), "retained gate report includes an inferred frame with zero person boxes");
      await seekFrame(tab, empty);
      await tab.getByText("The detector returned 0 person boxes in this frame.").waitFor();
      assert.equal(await feed.locator(".feed__measured").count(), 0);
    }
    await tab.close();
  }
  pass("The console rejects substituted overlay files. Retry restores the retained coordinates over verified footage.");

  const stalled = await browser.newPage();
  await stalled.goto(absolute("/"));
  await stalled.locator("#minute").scrollIntoViewIfNeeded();
  await stalled.getByRole("button", { name: "Show the gate camera" }).click();
  const gateFeed = stalled.locator(".feed--large");
  await seekFrame(stalled, occupied);
  await gateFeed.locator(".feed__staged").first().waitFor();
  if (measuredBoxes) await gateFeed.locator(".feed__measured").first().waitFor();
  const occupiedClock = await stalled.locator(".console__caption .data").innerText();
  // Seek the actual decoder independently while the site clock holds at frame 34.
  // Then prevent this camera from advancing while the console plays normally.
  const observed = await gateFeed.locator("video").evaluate(async (v, { fps, target }) => {
    let submitted, since;
    let callback;
    const observe = (now, { mediaTime }) => {
      submitted = Math.round(mediaTime * fps);
      since = now;
      callback = v.requestVideoFrameCallback(observe);
    };
    callback = v.requestVideoFrameCallback(observe);
    v.currentTime = target / fps;
    const tick = () => new Promise((resolve) => requestAnimationFrame(resolve));
    const deadline = performance.now() + 5000;
    while ((submitted !== target || v.seeking) && performance.now() < deadline) await tick();
    if (submitted !== target || v.seeking) throw Error("The gate decoder did not present the independent seek");
    await tick();
    await tick();
    const capture = () => ({
      frame: submitted,
      staged: [...v.closest(".feed").querySelectorAll(".feed__staged")].map((r) => Number(r.getAttribute("x"))),
      measured: [...v.closest(".feed").querySelectorAll(".feed__measured")].map((r) => Number(r.getAttribute("x"))),
      caption: document.querySelector(".console__detector-status").textContent,
      cameraTime: document.querySelector(".console__caption .data")?.textContent,
    });
    const independent = capture();
    const stopped = [];
    v.playbackRate = 0;
    document.querySelector(".timeline__play").click();
    const stopDeadline = performance.now() + 10000;
    while (stopped.length < 3 && performance.now() < stopDeadline) {
      const now = await tick();
      if (submitted !== target && !v.seeking && now - since > 50) stopped.push(capture());
    }
    v.playbackRate = 1;
    const advancing = [];
    const frameNumbers = new Set();
    const playDeadline = performance.now() + 10000;
    while (frameNumbers.size < 5 && performance.now() < playDeadline) {
      await tick();
      if (!v.seeking && v.closest(".feed").querySelector(".feed__marks")) {
        advancing.push(capture());
        frameNumbers.add(submitted);
      }
    }
    document.querySelector(".timeline__play").click();
    v.cancelVideoFrameCallback(callback);
    return { independent, stopped, advancing };
  }, { fps: scene.clock.fps, target: substitute });
  assert.equal(observed.independent.frame, substitute);
  assert.ok(observed.independent.cameraTime && observed.independent.cameraTime !== occupiedClock, "camera clock follows the independently presented frame");
  assert.ok(observed.stopped.length >= 3, `observed ${observed.stopped.length} stable samples while only the console played`);
  assert.ok(new Set(observed.advancing.map((s) => s.frame)).size >= 5, "sampled at least five advancing decoder frames");
  for (const sample of [observed.independent, ...observed.stopped, ...observed.advancing]) {
    const projected = Object.values(scene.boxes.gate).map((track) => track[sample.frame])
      .filter((box) => box && box[4] >= 0.25 && box[3] - box[1] >= 0.05);
    assert.deepEqual(sample.staged, projected.map((box) => box[0]), "staged boxes at presented frame " + sample.frame);
    if (measuredBoxes) {
      const native = measuredBoxes.cameras.gate.person[sample.frame] ?? [];
      assert.deepEqual(sample.measured, native.map((box) => box[0]), "measured boxes at presented frame " + sample.frame);
      assert.ok(sample.caption.includes(`returned ${native.length} person`), "caption uses the presented frame");
    }
  }
  // Play while a real decoder seek is pending. A user scrub can still supersede it.
  const pending = await gateFeed.locator("video").evaluate((v) => {
    const target = document.querySelector(".timeline__slider").valueAsNumber < 4 ? 8 : 1;
    v.currentTime = target;
    const seeking = v.seeking;
    document.querySelector(".timeline__play").click();
    const afterPlay = v.currentTime;
    const playing = !v.paused;
    window.dispatchEvent(new CustomEvent("fss:seek", { detail: 3 }));
    return { seeking, playing, target, afterPlay, afterScrub: v.currentTime };
  });
  assert.ok(pending.seeking && pending.playing, "an actual pending camera seek as playback starts");
  assert.equal(pending.afterPlay, pending.target, "playback preserves the decoder's in-flight seek");
  assert.equal(pending.afterScrub, 3, "an explicit user seek takes precedence");

  // A real media decoding failure clears the boxes. Retry creates a fresh element with the verified bytes.
  await gateFeed.locator("video").evaluate((v) => { v.src = "data:video/mp4;base64,AA=="; v.load(); });
  const reloadFilm = gateFeed.getByRole("button", { name: "Load this film again" });
  await reloadFilm.waitFor();
  assert.equal(await gateFeed.locator(".feed__marks,.feed__label").count(), 0);
  await reloadFilm.click();
  await seekFrame(stalled, occupied);
  await gateFeed.locator(".feed__staged").first().waitFor();
  assert.equal(await gateFeed.locator(".feed__staged").first().getAttribute("x"), String(scene.boxes.gate.a[occupied][0]));
  const gateStill = stalled.locator(".frames--wall .frame").filter({ hasText: /Gate/i }).first();
  await gateStill.scrollIntoViewIfNeeded();
  const picture = gateStill.locator("video.is-shown");
  await picture.waitFor();
  const captured = await picture.evaluate((v) => ({ time: v.currentTime, source: v.currentSrc }));
  await picture.evaluate((v) => { v.src = "data:video/mp4;base64,AA=="; v.load(); });
  const retryStill = gateStill.getByRole("button", { name: "Load this film again" });
  await retryStill.waitFor();
  assert.ok(await gateStill.locator("video").evaluate((v) => v.error != null), "real still decoder failure");
  assert.equal(await picture.count(), 0, "failed still is hidden");
  await retryStill.click();
  await picture.waitFor();
  const restored = await picture.evaluate(async (v) => {
    const bytes = await (await fetch(v.currentSrc)).arrayBuffer();
    return { hash: [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((n) => n.toString(16).padStart(2, "0")).join(""),
      time: v.currentTime, source: v.currentSrc, paused: v.paused };
  });
  assert.equal(restored.hash, recordedGate.video_sha256);
  assert.notEqual(restored.source, captured.source);
  assert.ok(restored.paused && Math.abs(restored.time - captured.time) < 0.001, "still recovers the retained recording at the caption time");
  pass("A story still reports a decoder failure and its retry restores the verified film at its original caption time.");
  await stalled.close();
  const untimed = await browser.newPage();
  await untimed.addInitScript(() => Object.defineProperty(HTMLVideoElement.prototype, "requestVideoFrameCallback", { value: undefined }));
  await untimed.goto(absolute("/"));
  await untimed.locator("#minute").scrollIntoViewIfNeeded();
  await untimed.getByRole("button", { name: "Show the gate camera" }).click();
  await seekFrame(untimed, occupied);
  await untimed.waitForFunction(() => document.querySelector(".feed--large video")?.readyState >= 2);
  if (measuredBoxes) await untimed.getByText("Frame timing is unavailable in this browser.").waitFor();
  assert.equal(await untimed.locator(".console .feed__marks,.console .feed__label").count(), 0);
  await untimed.close();
  pass("Native and staged outlines follow the decoder through independent seeks, stalled playback and decoder recovery.");

  // Reduced motion: the still stays and no loop is started.
  const calm = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
  const quiet = await open(calm);
  await quiet.page.waitForTimeout(600);
  assert.equal(await quiet.page.locator(".hero__plate video").count(), 0, "no hero loop under reduced motion");
  assert.equal(await quiet.page.locator(".hero__plate img").count(), 1, "hero still present");
  const readout = (page) => page.evaluate(() => document.querySelector(".hero__hud dl").innerText);
  const atRest = await readout(quiet.page);
  // The readout over the picture never covers the words beside it.
  for (const [width, height] of [[1024, 768], [1280, 720], [1366, 768], [1440, 900], [1920, 1080]]) {
    await quiet.page.setViewportSize({ width, height });
    const covered = await quiet.page.evaluate(() => {
      const hud = document.querySelector(".hero__hud").getBoundingClientRect();
      const meets = (r) => r.left < hud.right && hud.left < r.right && r.top < hud.bottom && hud.top < r.bottom;
      return [...document.querySelectorAll(".hero__words h1, .hero__lede, .hero__actions a, .hero__foot")]
        .filter((el) => {
          const range = document.createRange();
          range.selectNodeContents(el);
          return (el.matches("a") ? [el.getBoundingClientRect()] : [...range.getClientRects()]).some(meets);
        })
        .map((el) => el.className || el.tagName);
    });
    assert.deepEqual(covered, [], `hero readout clear of the words at ${width} by ${height}`);
  }
  await calm.close();
  // Asking for less motion while the loop plays brings back the still, and the still's own readout with it.
  const turned = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const { page: loop } = await open(turned);
  await loop.waitForFunction(
    (still) =>
      document.querySelector(".hero__plate video")?.hasAttribute("data-shown") &&
      document.querySelector(".hero__hud dl").innerText !== still,
    atRest,
  );
  await loop.emulateMedia({ reducedMotion: "reduce" });
  await loop.waitForFunction(() => !document.querySelector(".hero__plate video"));
  assert.equal(await readout(loop), atRest, "the readout returns to the still's moment");
  await turned.close();
  pass("Reduced motion shows the still and starts no loop. The readout agrees with the picture on screen and covers no words.");

  // Retired addresses are gone.
  const probe = await browser.newContext();
  for (const path of RETIRED) {
    const status = (await probe.request.get(absolute(path))).status();
    assert.equal(status, 404, path);
  }
  // What such an address shows: the site's own page, not Next's default, which drew the site's light
  // text on its own white background and so read as blank. It must be legible, lead back to the top and
  // to every chapter, keep the copy rules and fit a phone.
  const lost = await probe.newPage();
  await lost.setViewportSize({ width: 390, height: 844 });
  await lost.goto(absolute("/404.html"), { waitUntil: "load" });
  const missing = await lost.evaluate(() => {
    const rgb = (c) => c.match(/[\d.]+/g).slice(0, 3).map(Number);
    const lum = (c) =>
      rgb(c)
        .map((v) => (v / 255 <= 0.03928 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4))
        .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
    const h1 = document.querySelector("h1");
    const [hi, lo] = [lum(getComputedStyle(h1).color), lum(getComputedStyle(document.body).backgroundColor)].sort((a, b) => b - a);
    return {
      heading: h1.innerText.trim(),
      contrast: (hi + 0.05) / (lo + 0.05),
      home: document.querySelectorAll('a[href="/"]').length,
      chapters: [...document.querySelectorAll('a[href^="/#"]')].map((a) => a.getAttribute("href").slice(2)),
      text: document.body.innerText,
      sideways: document.documentElement.scrollWidth > innerWidth,
    };
  });
  await lost.close();
  assert.ok(missing.heading, "the missing page has a heading");
  assert.ok(missing.contrast >= 4.5, `the missing page's heading is legible (contrast ${missing.contrast.toFixed(2)})`);
  assert.ok(missing.home >= 1, "the missing page links back to the top");
  const homeHtml = await (await probe.request.get(absolute("/"))).text();
  assert.equal(missing.chapters.length, 5, "the missing page links every chapter");
  for (const id of missing.chapters) assert.ok(homeHtml.includes(`id="${id}"`), `chapter #${id} exists on the home page`);
  assert.doesNotMatch(missing.text, /alder|juniper/i, "estate name absent from the missing page");
  assert.ok(!/[—–]/.test(missing.text), "no em or en dash on the missing page");
  assert.ok(!missing.sideways, "the missing page fits a phone");
  await probe.close();
  pass(`${RETIRED.length} retired addresses return 404. A missing address shows the site's own page, legible, with a way back to the top and to all 5 chapters.`);
  await checkDeliveryDropout(browser, origin);
  pass("The courier recording loses and regains its picture at the measured gap boundaries. Swapped previews are rejected and retry restores both.");

  console.log(done.map((line) => "ok  " + line).join("\n"));
} finally {
  await browser.close();
}
