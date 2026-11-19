import assert from "node:assert/strict";

export async function checkMotionUI(browser, origin) {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({
      viewport: { width, height: 930 },
      reducedMotion: "reduce",
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("response", (r) => {
      if (r.status() >= 400) errors.push(r.url());
    });
    await page.goto(origin);
    await page
      .getByRole("button", { name: "Motion lab The parcel drop" })
      .click();
    await page.getByRole("link", { name: "Enter the motion lab" }).click();
    await page.waitForURL("**/exhibits/motion-study/");
    const stage = page.locator(".motion-viewport"),
      screen = page.locator(".motion-workspace");
    const button = (name) => page.getByRole("button", { name, exact: true });
    const slider = (name) => page.getByRole("slider", { name, exact: true });
    const phase = page.locator("[data-motion-phase]");
    await stage.locator("canvas").waitFor();
    await page.locator('[data-ready="webgl"]').waitFor();
    assert.equal(await page.locator(".detector-plate i").count(), 2);
    await button("See this instant in the twin").click();
    assert.equal(await stage.locator(".camera-ident i").count(), 2);
    const [porch, drive] = await stage.locator(".camera-ident span").all();
    const a = await porch.boundingBox(),
      b = await drive.boundingBox();
    assert.ok(width > 1000 ? b.x > a.x + a.width : b.y > a.y + a.height);
    assert.equal(await slider("Study time").inputValue(), "1");
    assert.equal(
      await button("Camera pair").getAttribute("aria-pressed"),
      "true",
    );
    if (process.env.SCREENSHOT_DIR)
      await stage.screenshot({
        path: process.env.SCREENSHOT_DIR + "/pair-" + width + ".png",
      });
    await slider("Stature").press("ArrowUp");
    assert.equal(await slider("Study time").inputValue(), "1");
    assert.equal(await stage.locator(".camera-ident i").count(), 0);
    assert.match(
      await stage.locator(".camera-ident").first().innerText(),
      /simulation/,
    );
    await button("Property").click();
    const box = await stage.boundingBox();
    await page.mouse.move(box.x + box.width * 0.55, box.y + box.height * 0.55);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.64, box.y + box.height * 0.5, {
      steps: 5,
    });
    await page.mouse.up();
    await button("Studio").click();
    await button("Joint trails").click();
    assert.equal(
      await button("Joint trails").getAttribute("aria-pressed"),
      "false",
    );
    await page.getByLabel("Scenario").selectOption("Springy parcel");
    assert.equal(await page.locator(".detector-plate").count(), 0);
    await button("First contact").click();
    assert.equal(await phase.textContent(), "Rebounding");
    await button("Settled").click();
    assert.equal(await phase.textContent(), "At rest");
    await button("Release").click();
    assert.equal(await phase.textContent(), "Falling");
    await slider("Stature").press("Home");
    assert.equal(await slider("Stature").inputValue(), "1.48");
    assert.equal(await page.getByLabel("Scenario").inputValue(), "");
    await slider("Restitution").press("Home");
    await button("First contact").click();
    assert.equal(await phase.textContent(), "At rest");
    await button("Play motion").click();
    await button("Pause motion").click();
    await button("Restore reference delivery").click();
    assert.equal(await slider("Stature").inputValue(), "1.74");
    assert.equal(await page.locator(".detector-plate i").count(), 2);
    await button("Joint trails").click();
    await screen.scrollIntoViewIfNeeded();
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
        path: process.env.SCREENSHOT_DIR + "/motion-" + width + ".png",
      });
    }
    assert.deepEqual(errors, []);
    await page.close();
  }
  const fallback = await browser.newPage();
  const issues = [];
  fallback.on("pageerror", (e) => issues.push(e.message));
  await fallback.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...rest) {
      return kind.startsWith("webgl")
        ? null
        : original.call(this, kind, ...rest);
    };
  });
  await fallback.goto(new URL("/exhibits/motion-study/", origin).href);
  await fallback.locator('[data-ready="elevation"]').waitFor();
  assert.equal(
    await fallback.getByRole("button", { name: "Camera pair" }).isDisabled(),
    true,
  );
  const rect = fallback.locator(".motion-elevation rect");
  const before = await rect.getAttribute("y");
  await fallback.getByRole("button", { name: "Settled", exact: true }).click();
  assert.notEqual(await rect.getAttribute("y"), before);
  assert.deepEqual(issues, []);
  await fallback.close();
  console.log(
    "Motion controls, exact native-frame links, parameter invalidation and live fallback passed at desktop and mobile sizes.",
  );
}
