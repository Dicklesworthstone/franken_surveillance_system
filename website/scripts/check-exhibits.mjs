// Verify crawler-visible metadata without hydration, then exercise the exhibit entry points.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { exhibitPath, exhibits } from "../lib/exhibits.js";
import { cases } from "../lib/scenarios.js";

export async function checkExhibits(browser, origin) {
  const bot = await browser.newContext({ javaScriptEnabled: false });
  const page = await bot.newPage();
  const unique = new Set();
  for (const [slug, exhibit] of Object.entries(exhibits)) {
    const pathname = exhibitPath(slug);
    const response = await page.goto(new URL(pathname, origin).href);
    assert.equal(response.status(), 200);
    assert.equal(await page.locator("h1").count(), 1);
    const tags = (family, key) =>
      page
        .locator(
          `meta[${family === "og" ? "property" : "name"}="${family}:${key}"]`,
        )
        .getAttribute("content");
    for (const [family, height] of [
      ["og", 630],
      ["twitter", 600],
    ]) {
      const url = new URL(await tags(family, "image"));
      assert.equal(url.origin, "https://franken-surveillance.com");
      assert.ok(
        url.pathname.startsWith(
          pathname + (family === "og" ? "opengraph" : "twitter") + "-image/",
        ),
        slug,
      );
      assert.ok(
        (await tags(family, "image:alt")).startsWith(exhibit.title),
        slug,
      );
      assert.equal(Number(await tags(family, "image:width")), 1200);
      assert.equal(Number(await tags(family, "image:height")), height);
      const image = await page.request.get(
        new URL(url.pathname + url.search, origin).href,
      );
      assert.equal(image.status(), 200);
      assert.match(image.headers()["content-type"], /image\/png/);
      const bytes = await image.body(),
        digest = createHash("sha256").update(bytes).digest("hex");
      assert.deepEqual(
        [...bytes.subarray(0, 8)],
        [137, 80, 78, 71, 13, 10, 26, 10],
      );
      assert.deepEqual(
        [bytes.readUInt32BE(16), bytes.readUInt32BE(20)],
        [1200, height],
      );
      assert.equal(url.pathname.split("/").pop(), digest.slice(0, 20) + ".png");
      assert.ok(!unique.has(digest));
      unique.add(digest);
    }
    assert.equal(await tags("twitter", "card"), "summary_large_image");
  }
  await bot.close();
  const client = await browser.newPage({
    viewport: { width: 390, height: 844 },
  });
  const open = (slug) => client.goto(new URL(exhibitPath(slug), origin).href);
  await open("event-ledger");
  await client.getByRole("button", { name: "Verify bytes" }).waitFor();
  await client.getByRole("button", { name: "Belief lab" }).click();
  await client.waitForURL("**/exhibits/belief-lab/");
  await client
    .getByRole("heading", { name: "How much does a second view add?" })
    .waitFor();
  await open("owner-response");
  await client
    .getByText("ERR-ALERT-NOT-ELIGIBLE-001", { exact: true })
    .waitFor();
  await open("camera-fusion");
  await client.getByRole("button", { name: "Locate on twin" }).click();
  await client.waitForURL("**/digital-twin/?focus=entry");
  await client.locator(".survey-point.porch:visible").waitFor();
  assert.equal(await client.getByRole("slider").inputValue(), "5.75");
  await client.getByRole("button", { name: "Overhead plan view" }).click();
  await client.getByRole("button", { name: "Reset orbit" }).click();
  await open("camera-wall");
  for (const s of cases) {
    await client.getByRole("button", { name: s.title, exact: true }).click();
    const film = client.locator(".wall-player video");
    await client
      .getByRole("button", { name: "Play synchronized reel" })
      .click();
    await client.waitForFunction(
      () => document.querySelector(".wall-player video")?.readyState >= 2,
    );
    await film.evaluate(async (v) => {
      await v.play();
      v.pause();
    });
    assert.equal(await film.evaluate((v) => v.duration), 12);
    const next = client.getByRole("button", { name: "Next wall frame" });
    if (s.id === "delivery") {
      await client.getByRole("button", { name: "First inference" }).click();
      await client
        .locator(".wall-readout")
        .getByText("person", { exact: true })
        .first()
        .waitFor();
      await next.click();
      await client
        .locator(".wall-readout")
        .getByText("Frame not sampled", { exact: true })
        .first()
        .waitFor();
    } else {
      await next.click();
    }
    assert.equal(await client.locator(".wall-sources a").count(), 3);
    assert.ok(
      await client.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
  }
  await client.route("**/wall/delivery.mp4", (route) => route.abort());
  await client
    .getByRole("button", { name: cases[0].title, exact: true })
    .click();
  await client.getByRole("button", { name: "Play synchronized reel" }).click();
  await client.getByText("Camera film unavailable", { exact: true }).waitFor();
  assert.equal(await client.locator(".wall-sources a").count(), 3);
  await client.close();
  console.log(
    "Verified all " +
      unique.size +
      " social cards, static exhibit links, camera wall frames and survey handoff.",
  );
}
