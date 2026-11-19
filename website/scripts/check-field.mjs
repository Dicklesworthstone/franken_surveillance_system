import assert from "node:assert/strict";

export async function checkField(page, width) {
  const byName = (name) => page.getByRole("button", { name, exact: true });
  await page.getByRole("heading", { name: "The home control room." }).waitFor();
  await page.waitForFunction(
    () => document.querySelector(".hero-art")?.naturalWidth > 1000,
  );
  const captures = process.env.SCREENSHOT_DIR;
  if (captures)
    await page.screenshot({ path: captures + "/home-" + width + ".png" });
  await byName("250 ms").click();
  await page.getByText("No qualifying pair.", { exact: true }).waitFor();
  await byName("500 ms").click();
  await page.getByText("One witnessed entry.", { exact: true }).waitFor();
  await byName("Play both feeds").click();
  await page.waitForFunction(
    () => document.querySelector(".feature-film video")?.readyState >= 2,
  );
  const film = page.locator(".feature-film video");
  assert.equal(await film.evaluate((v) => v.duration), 12);
  await byName("Back to frames").click();
  if (captures)
    await page
      .locator("#casebook")
      .screenshot({ path: captures + "/fusion-" + width + ".png" });
  await byName("Locate on twin").click();
  assert.equal(
    await byName("Survey mode").getAttribute("aria-pressed"),
    "true",
  );
  await page.locator(".survey-key").waitFor();
  assert.match(
    await page.locator(".survey-key").innerText(),
    /measured entries/,
  );
  assert.equal(await page.getByRole("slider").inputValue(), "5.75");
  if (captures)
    await page
      .locator("#simulator")
      .screenshot({ path: captures + "/survey-" + width + ".png" });
  assert.match(
    await page.locator(".survey-point.porch").innerText(),
    /00:05.50/,
  );
  assert.match(
    await page.locator(".survey-point.drive").innerText(),
    /00:05.75/,
  );
  await byName("Survey mode").click();
  await byName("Belief lab").click();
  let firstInterval;
  for (const [i, title] of [
    "One camera",
    "Shared source",
    "Independent sources",
  ].entries()) {
    await byName(title).click();
    const interval = await page.locator(".prob-result strong").innerText();
    if (!i) firstInterval = interval;
    if (i === 1) assert.equal(interval, firstInterval);
    if (i === 2) assert.notEqual(interval, firstInterval);
  }
  await byName("Event ledger").click();
  for (const [name, state] of [
    ["Original bytes", "verified"],
    ["Change one byte", "mismatch"],
    ["Original bytes", "verified"],
  ]) {
    await byName(name).click();
    await byName("Verify bytes").click();
    await page.locator('[data-verdict="' + state + '"]').waitFor();
  }
  for (const [op, title] of [
    ["orient", "Read situation"],
    ["explain", "Explain event"],
    ["alert", "Plan notification"],
    ["handoff", "Hand off case"],
    ["resume", "Resume session"],
  ]) {
    await page.locator(".agent-menu button").filter({ hasText: title }).click();
    const link = page.getByRole("link", { name: "Inspect response JSON" });
    assert.equal(await link.getAttribute("href"), "/field/" + op + ".json");
    const response = await (
      await page.request.get(new URL("/field/" + op + ".json", page.url()).href)
    ).json();
    assert.equal(
      await page.locator(".response-heading b").innerText(),
      response.outcome.toUpperCase(),
    );
    if (op === "alert")
      await page.getByText(response.errorId, { exact: true }).waitFor();
  }
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
    false,
  );
  console.log(
    "Verified fusion, belief ranges, custody and agent operations at width",
    width,
  );
}
