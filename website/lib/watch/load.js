// Server side: reads the published take at build time.
import { fromReports, objectReader, renderIdentity, sha256 } from "./retained.mjs";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { heroTruth } from "./hero.js";
import { distill } from "./native.js";
import { readFusionExcerpt } from "./fusion-excerpt.mjs";
import { readRelayReplay } from "./relay-replay.mjs";
import { adapt, frameAt, sightings, stamp } from "./take.js";
import { buildStory } from "./story.js";

const root = join(process.cwd(), "public", "watch");
/**
 * Compares each measured cross-camera match with where the script put the
 * people at that moment. A match is the tool agreeing that two cameras saw
 * something on the same ground; only this comparison says whether a person was
 * there. The timing of a match can be compared with the scripted floodlights,
 * while its cause remains unknown.
 */
export function checkMatches(native, take) {
  const lights = take.effects.find((e) => e.kind === "lights_on" || e.kind === "lights")?.t ?? null;
  // The two cameras of a match observe at slightly different times and a running
  // person covers ground between them, so each person is measured at their
  // farthest from the matched point over that stretch.
  const nearest = (times, ground) => {
    if (!ground) return null;
    const from = frameAt(take, Math.min(...times));
    const to = frameAt(take, Math.max(...times));
    let best = null;
    let incomplete = false;
    for (const actor of take.actors) {
      const track = take.tracks[actor.id];
      let distance = 0;
      for (let f = from; f <= to; f++) {
        if (!Number.isFinite(track?.x?.[f]) || !Number.isFinite(track?.z?.[f])) {
          incomplete = true;
          distance = null;
          break;
        }
        distance = Math.max(distance, Math.hypot(track.x[f] - ground[0], track.z[f] - ground[1]));
      }
      if (distance != null && (!best || distance < best.distance)) best = { track: actor.track, distance };
    }
    // A complete track inside the gate establishes a match even if another
    // track has gaps. A negative verdict needs positions for every actor.
    return incomplete && (!best || best.distance > native.gate) ? null : best;
  };
  const judge = (item) => {
    const near = nearest(item.times ?? [item.t], item.ground);
    const onPerson = !!near && near.distance <= native.gate;
    return {
      ...item,
      clock: stamp(take, item.t),
      near,
      onPerson,
      afterLights: !!near && !onPerson && lights != null && item.t >= lights && item.t - lights < 1.5,
    };
  };
  for (const pair of native.pairs) {
    pair.separate.list = pair.separate.list.map(judge);
    pair.shared.list = pair.shared.list.map(judge);
    if (pair.coarser) pair.coarser.list = pair.coarser.list.map(judge);
  }
  native.events = native.events.map((event) => (event.ground ? judge(event) : event));
  native.lightsClock = lights == null ? null : stamp(take, lights);
  return native;
}

export function loadTake() {
  const id = "intrusion";
  const sceneBytes = readFileSync(join(root, id, "scene.json"));
  const take = adapt(JSON.parse(sceneBytes.toString("utf8")));
  // Site views rendered after the scene file was written are listed beside the pictures.
  const views = join(root, id, "twin", "twin.json");
  const twinBytes = existsSync(views) ? readFileSync(views) : null;
  if (twinBytes) take.twin = { ...take.twin, ...JSON.parse(twinBytes) };
  const story = buildStory(take);
  // Each row's digest is the SHA-256 of the row exactly as it is displayed.
  story.ledger = story.ledger.map((row) => ({
    ...row,
    digest: sha256(JSON.stringify([row.seq, row.clock, row.kind, row.subject])),
  }));
  const nativePath = join(root, id, "native.json");
  const nativeBytes = existsSync(nativePath) ? readFileSync(nativePath) : null;
  const nativeReport = nativeBytes ? JSON.parse(nativeBytes) : null;
  const dir = join(root, id);
  const read = objectReader(dir, nativeReport?.retained_objects && new Set(nativeReport.retained_objects));
  const fusionReplay = readFusionExcerpt(dir, sceneBytes);
  const relayReplay = readRelayReplay(dir, sceneBytes);
  // The picture behind the headline: the take's own loop and still when they exist.
  const has = (name) => existsSync(join(root, id, name));
  const stills = has("stills") ? readdirSync(join(root, id, "stills")).filter((n) => n.endsWith(".jpg")).sort() : [];
  const still = stills.includes("floods.jpg") ? "floods.jpg" : stills[0];
  const hero = {
    video: has("hero.mp4") ? `/watch/${id}/hero.mp4` : null,
    // A frame from late in the loop, with the lights on, when the loop has been rendered.
    still: has("hero-still.jpg") ? `/watch/${id}/hero-still.jpg` : still ? `/watch/${id}/stills/${still}` : null,
    staged: Boolean(still),
  };
  const { tracks, boxes, ...summary } = take;
  let boxesFile = "native-boxes.json";
  let boxesDigest = null;
  if (nativeReport && Object.hasOwn(nativeReport, "detector_boxes")) {
    boxesFile = nativeReport.detector_boxes;
    const object = typeof boxesFile === "string" && /^native\/objects\/([a-f0-9]{64})\.json$/.exec(boxesFile);
    if (!object) throw Error("Invalid detector box object path");
    boxesDigest = sha256(readFileSync(join(root, id, boxesFile)));
    if (boxesDigest !== object[1]) throw Error("Detector boxes differ from the object named by the native report");
  } else if (has(boxesFile)) {
    boxesDigest = sha256(readFileSync(join(root, id, boxesFile)));
  }
  const span = (list) => list.reduce((n, [from, to]) => n + to - from + 1, 0);
  return {
    id,
    renderDigest: renderIdentity(sceneBytes, nativeBytes, boxesDigest, twinBytes, fusionReplay, relayReplay),
    hero,
    heroTruth: heroTruth(take),
    // How much of the films is one held picture: spans the renderer did not re-render because nobody was in view.
    films: {
      frames: take.frames * take.cameras.length,
      held: take.cameras.reduce((n, cam) => n + span(cam.held), 0),
    },
    // A wide still shown between the console and the walk-through.
    plate: has("plates/floods-1280.jpg") ? `/watch/${id}/plates/floods` : null,
    stills: stills.map((name) => `/watch/${id}/stills/${name}`),
    summary,
    story,
    spans: sightings(take),
    native: nativeReport ? {
      ...checkMatches(distill(fromReports(nativeReport, read)), take),
      fusionReplay,
      relayReplay,
    } : null,
    boxesUrl: boxesDigest ? `/watch/${id}/${boxesFile}` : null,
    boxesDigest: boxesDigest ? "sha256:" + boxesDigest : null,
    sceneUrl: `/watch/${id}/scene.json`,
    sceneDigest: "sha256:" + sha256(sceneBytes),
  };
}
