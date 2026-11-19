import assert from "node:assert/strict";
import { cases } from "../lib/scenarios.js";

export async function checkCourtUI(browser, origin) {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({
      viewport: { width, height: 900 },
      reducedMotion: "reduce",
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("response", (r) => {
      if (r.status() >= 400) errors.push(r.url());
    });
    const button = (name) => page.getByRole("button", { name, exact: true });
    await page.goto(origin);
    await page.locator(".exhibit-menu summary").click();
    assert.equal(await page.locator(".exhibit-catalog a:visible").count(), 12);
    await page.keyboard.press("Escape");
    assert.equal(
      await page.locator(".exhibit-menu").getAttribute("open"),
      null,
    );
    await button("Play The bounce pass").click();
    await page.waitForFunction(
      () => document.querySelector(".cover-screen video")?.currentTime > 0,
    );
    await button("Return to film still").click();
    await button("Camera wall The night garden").click();
    await page.getByRole("link", { name: "Open the camera wall" }).click();
    await page.waitForURL("**/camera-wall/?case=wildlife");
    await page
      .getByRole("button", {
        name: cases.find((c) => c.id === "wildlife").title,
        pressed: true,
      })
      .waitFor();
    await page.goto(origin);
    await page.getByRole("link", { name: "Open the courtyard" }).click();
    const stage = page.locator(".court-screen");
    await page.locator('[data-court-state="webgl"]').waitFor();
    assert.equal(
      await page.locator(".review-grid .detector-plate i").count(),
      4,
    );
    await page
      .locator(".review-grid article")
      .first()
      .getByRole("button")
      .click();
    assert.equal(
      await page.getByRole("slider", { name: "Pass time" }).inputValue(),
      "1",
    );
    assert.equal(await stage.locator("i").count(), 2);
    await page
      .getByRole("slider", { name: "Player spacing" })
      .press("ArrowRight");
    assert.equal(await stage.locator("i").count(), 0);
    await page.getByText("Custom pass", { exact: true }).last().waitFor();
    await button("Restore reference pass ↗").click();
    await button("Motion-triggered watch").click();
    const v = await (
      await page.request.get(new URL("/court/analysis.json", origin).href)
    ).json();
    const segment = v.views.garden.samples.find(
      (f) => f.status === "inferred",
    ).segment;
    await page.getByLabel("Watch sample time").selectOption(String(segment));
    await page
      .locator(".review-grid article")
      .first()
      .getByRole("button")
      .click();
    assert.equal(
      Number(
        await page.getByRole("slider", { name: "Pass time" }).inputValue(),
      ),
      segment / 4,
    );
    assert.equal(
      await stage.locator("i").count(),
      v.views.garden.samples.find((f) => f.segment === segment).detections
        .length,
    );
    await page.locator(".earlier-take summary").click();
    assert.equal(
      await page.locator(".earlier-take .detector-plate i").count(),
      1,
    );
    const earlier = await page.request.get(
      new URL("/court/earlier/garden.json", origin).href,
    );
    assert.equal(earlier.status(), 200);
    await button("Courtyard").click();
    await page.getByLabel("Pass setup").selectOption("Soft bounce");
    await button("At receiver").click();
    assert.equal(
      await page.locator("[data-pass-phase]").innerText(),
      "Missed catch",
    );
    await page.getByLabel("Pass setup").selectOption("Chest pass");
    await button("At receiver").click();
    assert.equal(await page.locator("[data-pass-phase]").innerText(), "Caught");
    assert.equal(await button("First bounce").count(), 0);
    await page.getByLabel("Pass setup").selectOption("Bounce pass");
    await button("First bounce").click();
    assert.ok(
      Number(
        await page.getByRole("slider", { name: "Pass time" }).inputValue(),
      ) > 1,
    );
    await button("Play pass").click();
    await button("Pause pass").click();
    await button("Flight path").click();
    assert.equal(
      await button("Flight path").getAttribute("aria-pressed"),
      "false",
    );
    await button("Flight path").click();
    await page.getByLabel("Pass setup").selectOption("Chest pass");
    await page.getByLabel("Pass setup").selectOption("Bounce pass");
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    if (process.env.SCREENSHOT_DIR) {
      await page.evaluate(() =>
        window.scrollTo({ top: 0, behavior: "instant" }),
      );
      await page.screenshot({
        path: process.env.SCREENSHOT_DIR + "/courtyard-" + width + ".png",
      });
      await page.locator(".court-evidence").screenshot({
        path: process.env.SCREENSHOT_DIR + "/court-evidence-" + width + ".png",
      });
    }
    assert.deepEqual(errors, []);
    await page.close();
  }
  const page = await browser.newPage({ viewport: { width: 320, height: 720 } });
  await page.route("**/court/receiver.glb", (r) =>
    r.fulfill({ status: 503, body: "Unavailable" }),
  );
  await page.goto(new URL("/exhibits/courtyard/", origin).href);
  await page.locator('[data-court-state="diagram"]').waitFor();
  await page.locator(".exhibit-menu summary").click();
  assert.equal(await page.locator(".exhibit-catalog a:visible").count(), 12);
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.keyboard.press("Escape");
  assert.ok(
    await page
      .getByRole("button", { name: "Patio camera", exact: true })
      .isDisabled(),
  );
  await page.getByLabel("Pass setup").selectOption("Soft bounce");
  await page.getByRole("button", { name: "At receiver", exact: true }).click();
  assert.equal(
    await page.locator("[data-pass-phase]").innerText(),
    "Missed catch",
  );
  await page.close();
  console.log(
    "Courtyard passed both browser sizes, three film entry points, recorded-frame alignment, false-positive review, custom passes and missing-asset fallback.",
  );
}
