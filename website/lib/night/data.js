import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PerspectiveCamera, Vector3 } from "three";
import { caseFiles, cases } from "./catalog";

const read = (path) =>
  JSON.parse(readFileSync(join(process.cwd(), "public", path), "utf8"));

function projectSceneFootprints(view, lens, take) {
  const camera = new PerspectiveCamera(
    lens.vfov,
    take.width / take.height,
    0.07,
    260,
  );
  camera.position.fromArray(lens.position);
  camera.lookAt(...lens.look_at);
  camera.updateMatrixWorld();
  const poses = new Map(
    take.trajectory.map((p) => [
      Math.round(p.seconds * take.fps),
      p.subjectFoot,
    ]),
  );
  return view.samples.map((sample) => {
    const foot = poses.get(sample.filmFrame);
    if (!foot) return sample;
    const p = new Vector3(...foot).project(camera);
    if (Math.max(Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)) > 1)
      return sample;
    return { ...sample, sceneFoot: [(p.x + 1) / 2, (1 - p.y) / 2] };
  });
}
export function nightData() {
  const evidence = read("night-evidence/index.json");
  const { captures } = read("night-media/capture.json");
  const estate = read("estate/estate.json");
  const { film, captions, seconds } = read("night-media/briefing.json");
  const cameras = Array.isArray(estate.cameras)
    ? estate.cameras
    : Object.entries(estate.cameras).map(([id, c]) => ({ ...c, id }));
  const records = {};
  for (const id of cases) {
    const incident = evidence.cases[id];
    const views = Object.entries(incident.views);
    if (!views.length) throw Error("Missing native camera sources for " + id);
    const selected = caseFiles[id].openingCamera;
    const primary = incident.views[selected] ? selected : views[0][0];
    const reference = captures.find(
      (take) => take.caseId === id && take.camera === primary,
    );
    if (!reference)
      throw Error("Missing camera recording for " + id + "/" + primary);
    records[id] = {
      ...caseFiles[id],
      ...incident,
      primary,
      seconds: reference.seconds,
      fps: reference.fps,
      views: Object.fromEntries(
        views.map(([camera, view]) => {
          const lens = cameras.find((c) => c.id === camera);
          const take = captures.find(
            (t) => t.caseId === id && t.camera === camera,
          );
          if (!lens || !take) throw Error("Unbound source camera " + camera);
          return [
            camera,
            { ...view, samples: projectSceneFootprints(view, lens, take) },
          ];
        }),
      ),
    };
  }
  return {
    records,
    briefing: { film, captions, seconds },
    modelDigest: evidence.modelDigest,
    estate: {
      hero: estate.hero || "/estate/hero.jpg",
      photographs: [
        {
          label: "East lawn and entrance",
          url: "/estate/stills/hero_east.jpg",
        },
        { label: "Rear terrace", url: "/estate/stills/terrace_view.jpg" },
        { label: "Pool grounds", url: "/estate/stills/pool.jpg" },
      ],
      cameras: cameras.map(({ id, position, label }) => ({
        id,
        position,
        label,
      })),
      buildings: estate.buildings,
      walks: [estate.driveway, estate.front_walk].filter(Boolean),
    },
  };
}
