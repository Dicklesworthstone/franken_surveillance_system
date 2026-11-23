// The outline and the camera lamps over the hero loop come from lib/watch/hero.js, which repeats the
// lens that art/estate/take_hero.py renders with and the ground that art/estate/takes.py walks people
// on. This checks that they still agree, and that every frame's lamps are the cameras scene.json has
// seeing the man.
//
//   node --test scripts/test-hero-truth.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as hero from "../lib/watch/hero.js";
import { SEEN, TALL, adapt } from "../lib/watch/take.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");
const scene = JSON.parse(await read("../public/watch/intrusion/scene.json"));
const truth = hero.heroTruth(adapt(scene));

test("the lens is the one the loop was rendered with", async () => {
  const source = await read("../art/estate/take_hero.py");
  const numbers = (name) => source.match(new RegExp(`^${name} = (.*?)(?:\\s+#.*)?$`, "m"))[1].match(/-?[\d.]+/g).map(Number);
  assert.deepEqual(numbers("EYE"), hero.EYE);
  assert.deepEqual(numbers("LOOK"), hero.LOOK);
  assert.deepEqual(numbers("LENS"), [hero.LENS_MM]);
  assert.deepEqual(numbers("LEAD"), [hero.LEAD]);
  assert.deepEqual(numbers("SECONDS"), [hero.SECONDS]);
  const size = source.match(/resolution_x, scene\.render\.resolution_y = (\d+), (\d+)/).slice(1).map(Number);
  assert.deepEqual(size, [hero.WIDTH, hero.HEIGHT]);
});

test("he stands on the ground the renderer stands him on", async () => {
  const source = await read("../art/estate/takes.py");
  const body = source.match(/^def ground\(x, y\):\n([\s\S]*?)\n\n/m)[1];
  const [halfWidth, north, south] = body.match(/abs\(x\) <= ([\d.]+) and (-?[\d.]+) <= z <= ([\d.]+)/).slice(1).map(Number);
  const [top, steps] = body.match(/\(([\d.]+) - z\) \/ ([\d.]+)/).slice(1).map(Number);
  assert.equal(top, south);
  const height = Number((await read("../art/estate/plan.py")).match(/^PORTICO = dict\(.*\bfloor=([\d.]+)/m)[1]);
  assert.deepEqual(hero.PORTICO, { halfWidth, north, south, steps, height });
  const ground = (x, z) =>
    Math.abs(x) <= halfWidth && north <= z && z <= south ? height * Math.min(1, Math.max(0, (south - z) / steps)) : 0;
  for (let x = -4; x <= 4; x += 0.05)
    for (let z = -3; z <= 6; z += 0.05) assert.equal(hero.floor(x, z), ground(x, z), `${x}, ${z}`);
});

test("every frame lists exactly the cameras that see him", () => {
  assert.equal(truth.frames.length, hero.SECONDS * truth.fps);
  truth.frames.forEach((row, i) => {
    const frame = Math.floor((truth.start + i / truth.fps) * scene.clock.fps);
    const expected = scene.cameras.flatMap((cam, index) => {
      const box = scene.boxes[cam.id]?.a?.[frame];
      return box && box[4] >= SEEN && box[3] - box[1] >= TALL ? [index] : [];
    });
    assert.deepEqual(row.seen, expected, `frame ${i}`);
    assert.equal(row.action, scene.tracks.a.action[frame], `frame ${i}`);
  });
});

test("the loop starts before the lights and the outline leaves with him", () => {
  assert.ok(truth.start < truth.lights && truth.lights - truth.start < hero.LEAD + 0.1);
  const first = truth.frames.findIndex((row) => !row.box);
  assert.ok(first > 0, "he leaves the picture");
  assert.ok(truth.frames.slice(0, first).every((row) => row.box), "one stretch in the picture");
  assert.ok(truth.frames.slice(first).every((row) => !row.box), "no outline once he has gone");
  // He runs toward the lens, so he is drawn larger at the end than at the door.
  assert.ok(truth.frames[first - 1].box[3] > 2 * truth.frames[0].box[3]);
});
