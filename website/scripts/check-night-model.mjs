// Bind the advertised takes to the shipped fictional estate, characters and FFmpeg output.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CatmullRomCurve3, Vector3 } from "three";
import { motionAt, registeredTakes } from "../lib/night-scene/takes.js";
const root = process.argv[2] || fileURLToPath(new URL("../public/", import.meta.url));
const bytes = (path) => readFile(resolve(root, "." + path));
const json = async (path) => JSON.parse(await bytes(path));
const sha = (data) => createHash("sha256").update(data).digest("hex");
const estate = await json("/estate/estate.json");
assert.equal(estate.name, "Alder House");
assert.equal(estate.fictional, true);
assert.notEqual(estate.status, "provisional");
const glb = await bytes("/estate/estate.glb");
assert.equal(glb.toString("ascii", 0, 4), "glTF");
assert.equal(glb.readUInt32LE(4), 2);
assert.equal(glb.readUInt32LE(8), glb.length);
const scene = JSON.parse(glb.toString("utf8", 20, 20 + glb.readUInt32LE(12)));
assert.ok(
  scene.meshes?.length > 0 && scene.materials?.length > 0,
  "The exterior must have geometry and materials",
);
const hero = await bytes(estate.hero || "/estate/hero.jpg");
assert.equal(
  hero.readUInt16BE(),
  0xffd8,
  "Share-card and HTML cover require a JPEG",
);
const { site, inputs, captures, fps, exposure, width, height } = await json("/night-media/capture.json");
assert.equal(site, "Residential security simulation");
assert.ok(Number.isSafeInteger(fps) && fps > 0);
assert.deepEqual(exposure, { shutterSeconds: 0.5 / fps, samples: 3 });
const mesh = await json("/estate/mesh-receipt.json");
const plates = await json("/night-media/plates/index.json");
const album = await json("/estate/stills.json");
assert.equal(album.source_blend_sha256, mesh.authoringBlendSha256);
const photographs = new Set();
for (const shot of album.stills) {
  assert.match(shot.path, /^\/estate\/(?:hero|stills\/[a-z_]+)\.jpg$/);
  const frame = await bytes(shot.path);
  assert.equal(frame.length, shot.bytes, shot.path);
  assert.equal(sha(frame), shot.sha256, shot.path);
  assert.equal(frame.readUInt16BE(0), 0xffd8);
  assert.ok(!photographs.has(shot.path), shot.path);
  photographs.add(shot.path);
}
for (const path of ["/estate/hero.jpg","/estate/stills/hero_east.jpg","/estate/stills/terrace_view.jpg","/estate/stills/pool.jpg"]) {
  assert.ok(photographs.has(path), "Missing architectural view " + path);
}
assert.equal(mesh.packedGlbSha256, sha(glb));
assert.equal(plates.glbSha256, mesh.packedGlbSha256);
assert.equal(plates.blendSha256, mesh.authoringBlendSha256);
assert.equal(plates.planSha256, sha(await bytes("/estate/estate.json")));
for (const shot of Object.values(plates.views)) {
  assert.equal(sha(await bytes(shot.url)), shot.sha256, shot.url);
}
const materialTextures = new Set();
for (const resource of [...(scene.buffers || []), ...(scene.images || [])]) {
  if (!resource.uri || resource.uri.startsWith("data:")) continue;
  const asset = new URL(
    resource.uri,
    "https://franken-surveillance.com/estate/estate.glb",
  );
  assert.equal(asset.origin, "https://franken-surveillance.com");
  assert.ok(asset.pathname.startsWith("/estate/"));
  if (asset.pathname.endsWith(".webp")) materialTextures.add(asset.pathname);
  assert.ok(
    inputs[decodeURIComponent(asset.pathname)],
    "Missing captured exterior dependency " + asset.pathname,
  );
}
assert.ok(materialTextures.size > 0);
for (const full of materialTextures)
  assert.ok(mesh.compactTextures[full], full);
for (const path of new Set(Object.values(mesh.compactTextures))) {
  assert.match(path, /^\/estate\/textures\/[0-9a-f]{22}\.webp$/);
  assert.equal(
    path.split("/").pop(),
    sha(await bytes(path)).slice(0, 22) + ".webp",
  );
}
for (const path of [
  "/estate/estate.glb",
  "/estate/estate.json",
  "/night-media/actors/visitor.glb",
  "/night-media/actors/courier.glb",
  "/night-media/actors/raccoon.glb",
])
  assert.ok(inputs[path]);
for (const [path, check] of Object.entries(inputs)) {
  const content = await bytes(path);
  assert.equal(content.length, check.bytes, path);
  assert.equal(sha(content), check.sha256, path);
}
assert.deepEqual([...new Set(captures.map(t => t.caseId))].sort(), ["after-hours", "delivery", "wildlife"]);
const takesByCase = registeredTakes(estate);
for (const id of ["after-hours", "delivery", "wildlife"]) {
  const takes = captures.filter((t) => t.caseId === id);
  const incident = estate.incidents.find(c => c.id === id);
  const spec = takesByCase[id];
  const route = new CatmullRomCurve3((spec.path.points || spec.path).map(p =>
    Array.isArray(p) ? new Vector3(...p) : new Vector3(p.x, p.y ?? 0.055, p.z)), false, "centripetal");
  const length = route.getLength();
  assert.deepEqual(takes.map(t => t.camera).sort(), ["overview", ...incident.cameras].sort());
  for (const t of takes) {
    const lens = t.camera === "overview" ? estate.overview : estate.cameras.find(c => c.id === t.camera);
    assert.deepEqual(t.sample.eye, lens.position);
    assert.deepEqual(t.sample.target, lens.look_at);
    assert.equal(t.sample.verticalFovDegrees, lens.vfov);
    assert.equal(t.sample.aspect, width / height);
    assert.equal(t.width, width);
    assert.equal(t.height, height);
    assert.equal(t.seconds, incident.seconds);
    assert.equal(t.film, "/night-media/" + id + "-" + t.camera + ".mp4");
    assert.equal(t.poster, "/night-media/" + id + "-" + t.camera + ".jpg");
    assert.equal(t.fps, fps);
    assert.equal(t.fps * t.seconds, t.frames);
    assert.equal(t.trajectory[0].seconds, 0);
    assert.equal(t.trajectory.at(-1).seconds, (t.frames - 1) / fps);
    let previous = -1;
    for (const row of [...t.trajectory, { ...t.sample, seconds: t.stillSeconds }]) {
      const frame = Math.round(row.seconds * fps);
      assert.ok(frame >= 0 && frame < t.frames && Math.abs(frame / fps - row.seconds) < 1e-9);
      const motion = motionAt(row.seconds, spec.pace, length, spec.braking);
      const point = route.getPointAt(motion.distance / length);
      assert.deepEqual(row.subjectFoot, point.toArray().map(n => Number(n.toFixed(5))));
      assert.equal(row.movementPhase, motion.phase);
    }
    for (const row of t.trajectory) {
      assert.ok(row.seconds > previous, "Out-of-order trajectory in " + t.film);
      previous = row.seconds;
    }
    assert.equal(sha(await bytes(t.film)), t.videoSha256, t.film);
    assert.equal(sha(await bytes(t.poster)), t.posterSha256, t.poster);
  }
}
console.log(
  site +
    " exterior and " +
    captures.length +
    " camera takes match their retained assets.",
);

const briefing = await json("/night-media/briefing.json");
assert.equal(briefing.film, "/night-media/estate-briefing.mp4");
assert.equal(briefing.captions, "/night-media/estate-briefing.vtt");
assert.equal(briefing.fps, fps);
if ("captureSha256" in briefing)
  assert.equal(briefing.captureSha256, sha(await bytes("/night-media/capture.json")));
assert.equal(sha(await bytes(briefing.film)), briefing.filmSha256);
assert.equal(sha(await bytes(briefing.captions)), briefing.captionsSha256);
let end = 0;
const [opening, ...cuts] = briefing.chapters;
assert.equal(opening.source, estate.hero || "/estate/hero.jpg");
assert.equal(opening.seconds, 3);
assert.deepEqual(cuts.map(shot => captures.find(t => t.film === shot.source)?.caseId),
  ["after-hours", "delivery", "wildlife"]);
for (const shot of briefing.chapters) {
  assert.ok(Number.isSafeInteger(shot.seconds) && shot.seconds > 0);
  assert.equal(shot.start, end);
  assert.equal(sha(await bytes(shot.source)), shot.sha256);
  end += shot.seconds;
}
assert.equal(end, briefing.seconds);
console.log("Briefing film, captions and all four source chapters verified.");
