import assert from "node:assert/strict";
import test from "node:test";
import { createClock } from "../components/site/clock.js";

test("a queued animation timestamp cannot move the console back before its play command", (t) => {
  let next;
  const original = globalThis.requestAnimationFrame;
  globalThis.requestAnimationFrame = callback => {
    next = callback;
    return 1;
  };
  t.after(() => {
    if (original) globalThis.requestAnimationFrame = original;
    else delete globalThis.requestAnimationFrame;
  });

  const clock = createClock(8, 24);
  const queued = performance.now() - 100;
  clock.play();
  next(queued);
  assert.equal(clock.time(), 0);
  assert.equal(clock.frame(), 0);
  const delivered = performance.now() + 200;
  next(delivered);
  const forward = clock.time();
  assert.ok(forward > 0);
  next(delivered - 25);
  assert.equal(clock.time(), forward);

  clock.seek(Number.NaN);
  assert.equal(clock.time(), forward);
  clock.seek(8);
  assert.equal(clock.time(), 8);
  assert.equal(clock.frame(), 191);
});
