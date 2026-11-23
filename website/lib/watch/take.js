// Turns a rendered take's scene.json into the shape the page components use.
// Runs on the server at build time and in the browser.
import { ellipse, information, lens } from "./geometry.js";

const NAMES = {
  gate: "Gate",
  driveway: "Driveway",
  doorbell: "Front door",
  porch: "Porch",
  entry: "Front lawn",
};
const COLOURS = { a: "var(--track-a)", b: "var(--track-b)" };
// A camera counts as seeing someone when at least this much of them is unoccluded.
export const SEEN = 0.25;
// ...and when they stand at least this tall in the frame, as a fraction of its height.
export const TALL = 0.05;
export const CLOSE_AFTER = 10;

export function adapt(scene) {
  const { fps, frames } = scene.clock;
  const cameras = scene.cameras.map((c) => ({
    id: c.id,
    name: NAMES[c.id] ?? c.label ?? c.id,
    product: c.product,
    mode: c.mode,
    width: c.width,
    height: c.height,
    offset: c.clock_offset_s ?? 0,
    position: c.position,
    // A fisheye is treated as a 120 degree lens when estimating position bounds.
    vfov: c.lens?.vfov ?? 120,
    fisheye: c.lens?.model !== "rectilinear",
    video: c.video,
    videoDigest: c.video_sha256,
    footprint: c.footprint ?? [],
    // Frame spans in which the renderer held one picture because nobody was in view.
    held: c.held_spans ?? [],
  }));
  const actors = scene.actors.map((a, i) => ({
    id: a.id,
    label: "Person " + (i + 1),
    track: "T" + (i + 1),
    description: a.description,
    colour: COLOURS[a.id] ?? "var(--text)",
  }));
  return {
    id: scene.take,
    start: Date.parse(scene.clock.start),
    zone: scene.clock.start.slice(-6),
    fps,
    frames,
    duration: frames / fps,
    cameras,
    actors,
    tracks: scene.tracks,
    boxes: scene.boxes,
    effects: scene.effects ?? [],
    beats: scene.beats ?? {},
    twin: scene.twin,
    blend: scene.source_blend_sha256 ?? null,
  };
}

/** Wall-clock label for take time `t`, on a camera's own clock when given. */
export function stamp(take, t, offset = 0, tenths = false) {
  const zone = take.zone.match(/([+-])(\d\d):(\d\d)/);
  const shift = zone ? (zone[1] === "-" ? -1 : 1) * (+zone[2] * 60 + +zone[3]) * 60000 : 0;
  const d = new Date(take.start + (t + offset) * 1000 + shift);
  const two = (n) => String(n).padStart(2, "0");
  const base = `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}`;
  return tenths ? base + "." + Math.floor(d.getUTCMilliseconds() / 100) : base;
}

export const frameAt = (take, t) =>
  Math.max(0, Math.min(take.frames - 1, Math.round(t * take.fps)));

export function boxAt(take, camera, actor, frame) {
  const b = take.boxes[camera]?.[actor]?.[frame];
  return b && b[4] >= SEEN && b[3] - b[1] >= TALL ? b : null;
}

/** Ids of the cameras that see `actor` at `frame`. */
export function seenBy(take, actor, frame) {
  const out = [];
  for (const c of take.cameras) if (boxAt(take, c.id, actor, frame)) out.push(c.id);
  return out;
}

/** Contiguous spans, in seconds, during which each camera sees each actor. */
export function sightings(take) {
  const out = [];
  for (const c of take.cameras)
    for (const a of take.actors) {
      let open = null;
      for (let f = 0; f <= take.frames; f++) {
        const on = f < take.frames && !!boxAt(take, c.id, a.id, f);
        if (on && open === null) open = f;
        if (!on && open !== null) {
          if (f - open >= take.fps / 2)
            out.push({ camera: c.id, actor: a.id, from: open / take.fps, to: f / take.fps });
          open = null;
        }
      }
    }
  return out;
}

const lensCache = new WeakMap();
export function lensOf(camera) {
  if (!lensCache.has(camera)) lensCache.set(camera, lens(camera));
  return lensCache.get(camera);
}

/**
 * What the cameras jointly support about one person at one frame.
 *
 * `state` uses the project's coverage words: multi_independent when two or
 * more cameras see the person, single for one, not_observable for none. The
 * ellipse is one standard deviation from the geometry of the cameras that see
 * them. With no camera, the estimate stays at the last sighting and its radius
 * grows at walking pace, because that is all the system can say.
 */
// (The "closed" state is this page's word for a track that has ended.)
export function estimate(take, actor, frame) {
  const t = take.tracks[actor];
  if (!t) return null;
  const cams = t.x[frame] == null ? [] : seenBy(take, actor, frame);
  if (cams.length) {
    const ground = [t.x[frame], t.z[frame]];
    const infos = cams.map((id) =>
      information(lensOf(take.cameras.find((c) => c.id === id)), ground),
    );
    return {
      state: cams.length > 1 ? "multi_independent" : "single",
      cameras: cams,
      x: ground[0],
      z: ground[1],
      heading: t.heading[frame],
      speed: t.speed[frame],
      action: t.action[frame],
      ellipse: ellipse(infos),
      since: 0,
    };
  }
  let last = frame;
  while (last >= 0 && (t.x[last] == null || !seenBy(take, actor, last).length)) last--;
  if (last < 0) return null;
  const since = (frame - last) / take.fps;
  const radius = Math.min(1.2 + 1.6 * since, 16);
  return {
    // After ten seconds without a sighting the track is closed, not guessed at.
    state: since > CLOSE_AFTER || t.x[frame] == null ? "closed" : "not_observable",
    cameras: [],
    lastCameras: seenBy(take, actor, last),
    x: t.x[last],
    z: t.z[last],
    heading: null,
    speed: null,
    action: null,
    ellipse: { major: radius, minor: radius, angle: 0 },
    since,
  };
}

/** Observed ground positions over the last `seconds`, for drawing a trail. */
export function trail(take, actor, frame, seconds = 8) {
  const t = take.tracks[actor];
  const out = [];
  if (!t) return out;
  for (let f = Math.max(0, frame - seconds * take.fps); f <= frame; f += 2) {
    if (t.x[f] == null) continue;
    out.push(seenBy(take, actor, f).length ? [t.x[f], t.z[f]] : null);
  }
  return out;
}

export const lightsOn = (take, t) => {
  const at = take.effects.find((e) => e.kind === "lights_on" || e.kind === "lights")?.t;
  return at != null && t >= at;
};
