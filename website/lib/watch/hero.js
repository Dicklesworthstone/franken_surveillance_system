// Server side: what the script says about the first person, frame by frame, for
// the loop at the top of the page. The loop has a camera of its own, so his
// scripted position is projected through that lens here. The numbers are the
// ones art/estate/take_hero.py renders with and the ones art/estate/takes.py
// walks people on; if either changes, these must too, and
// scripts/test-hero-truth.mjs compares them.
import { seenBy } from "./take.js";

export const EYE = [-9.6, 2.9, 15.2]; // plan x (east), height, plan z (south), in metres
export const LOOK = [-1.2, 1.9, 2.0];
export const LENS_MM = 30;
const SENSOR_MM = 36;
export const WIDTH = 1920;
export const HEIGHT = 1080;
const FPS = 24;
export const SECONDS = 10;
export const LEAD = 2.2; // seconds of the loop before the lights
const TALL = 1.88; // head of the cap above the ground he stands on
/** The portico floor and its three steps, in plan metres: takes.py `ground`, with its floor height from plan.py. */
export const PORTICO = { halfWidth: 2.55, north: -0.5, south: 3.69, steps: 0.99, height: 0.57 };
const ACTOR = "a";

const sub = (a, b) => a.map((n, i) => n - b[i]);
const dot = (a, b) => a.reduce((sum, n, i) => sum + n * b[i], 0);
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const unit = (a) => a.map((n) => n / Math.hypot(...a));

const forward = unit(sub(LOOK, EYE));
const right = unit(cross(forward, [0, 1, 0]));
const up = cross(right, forward);
const focal = (LENS_MM / SENSOR_MM) * WIDTH;

function project(point) {
  const d = sub(point, EYE);
  const depth = dot(d, forward);
  if (depth < 0.1) return null;
  return [0.5 + (focal * dot(d, right)) / depth / WIDTH, 0.5 - (focal * dot(d, up)) / depth / HEIGHT];
}

/** Height of the walking surface under a point of the plan. */
export function floor(x, z) {
  if (Math.abs(x) > PORTICO.halfWidth || z < PORTICO.north || z > PORTICO.south) return 0;
  return PORTICO.height * Math.min(1, Math.max(0, (PORTICO.south - z) / PORTICO.steps));
}

const round = (n) => Math.round(n * 10000) / 10000;

/**
 * One entry per frame of the loop: `box` as [left, top, width, height] in
 * fractions of the picture or null when he is out of it, the cameras that see
 * him as indexes into `take.cameras`, and what he is doing.
 */
export function heroTruth(take) {
  const lights = take.effects.find((e) => e.kind === "lights_on")?.t ?? take.beats.lights_on;
  const track = take.tracks[ACTOR];
  if (lights == null || !track) return null;
  // Film frame f is scene frame 1 + 2f, and the loop starts LEAD seconds of scene frames before the lights.
  const start = (2 * Math.round(lights * take.fps) - Math.trunc(LEAD * FPS)) / FPS;
  const frames = [];
  for (let i = 0; i < SECONDS * FPS; i++) {
    const at = (start + i / FPS) * take.fps;
    const f = Math.min(take.frames - 2, Math.floor(at));
    const u = at - f;
    const lerp = (list) => list[f] + (list[f + 1] - list[f]) * u;
    const here = [track.x[f], track.x[f + 1], track.z[f], track.z[f + 1]].every(Number.isFinite);
    let box = null;
    if (here) {
      const [x, z] = [lerp(track.x), lerp(track.z)];
      const ground = floor(x, z);
      const foot = project([x, ground, z]);
      const head = project([x, ground + TALL, z]);
      const height = foot && head ? foot[1] - head[1] : 0;
      const width = (height * HEIGHT * 0.46) / WIDTH;
      const left = foot && head ? (foot[0] + head[0]) / 2 - width / 2 : 1;
      if (height > 0 && left < 0.985 && left + width > 0.015) box = [left, head[1], width, height].map(round);
    }
    const seen = seenBy(take, ACTOR, f);
    frames.push({
      box,
      seen: take.cameras.flatMap((cam, index) => (seen.includes(cam.id) ? [index] : [])),
      action: track.action[f] ?? null,
    });
  }
  return { start: round(start), fps: FPS, lights, track: take.actors.find((a) => a.id === ACTOR).track, frames };
}
