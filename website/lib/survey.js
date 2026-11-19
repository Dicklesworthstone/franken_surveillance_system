import * as T from "three";
import { recording } from "./scenarios.js";

// The linework and measured entries use the optical scene's own coordinates.
export function createSurvey(scene, buildings) {
  const layer = new T.Group();
  const ink = new T.LineBasicMaterial({
    color: "#57969b",
    transparent: true,
    opacity: 0.74,
  });
  const matte = new T.MeshBasicMaterial({
    color: "#152b32",
    polygonOffset: true,
    polygonOffsetFactor: 1,
    polygonOffsetUnits: 1,
  });
  const original = buildings.children.map((m) => m.material);
  for (const mesh of buildings.children)
    layer.add(new T.LineSegments(new T.EdgesGeometry(mesh.geometry, 32), ink));
  const zone = new T.Mesh(
    new T.PlaneGeometry(1, 1),
    new T.MeshBasicMaterial({
      color: "#66bbc9",
      transparent: true,
      opacity: 0.24,
      side: T.DoubleSide,
      depthWrite: false,
    }),
  );
  zone.rotation.x = -Math.PI / 2;
  layer.add(zone);
  const dots = new T.Group(),
    dotShape = new T.SphereGeometry(0.16, 12, 8);
  const colors = {
    porch: new T.MeshBasicMaterial({ color: "#b6ff94", depthTest: false }),
    drive: new T.MeshBasicMaterial({ color: "#ffbd78", depthTest: false }),
  };
  layer.add(dots);
  scene.add(layer);
  let previous = null;
  return {
    show(entries, scenario, time) {
      const active = entries != null;
      layer.visible = active;
      buildings.children.forEach((m, i) => {
        m.material = active ? matte : original[i];
      });
      if (!active) return;
      if (entries !== previous) {
        dots.clear();
        for (const e of entries) {
          const dot = new T.Mesh(dotShape, colors[e.camera]);
          dot.position.set(e.ground[0], 0.2, e.ground[1]);
          dot.userData.time = e.segment / recording.nativeFps;
          dot.renderOrder = 2;
          dots.add(dot);
        }
        previous = entries;
      }
      for (const dot of dots.children) dot.visible = dot.userData.time <= time;
      const [x, x1, z, z1] = scenario.zoneBounds;
      zone.position.set((x + x1) / 2, 0.12, (z + z1) / 2);
      zone.scale.set(x1 - x, z1 - z, 1);
    },
    dispose() {
      buildings.children.forEach((m, i) => {
        m.material = original[i];
      });
      scene.remove(layer);
      for (const obj of layer.children) obj.geometry?.dispose();
      ink.dispose();
      matte.dispose();
      zone.material.dispose();
      dotShape.dispose();
      Object.values(colors).forEach((m) => m.dispose());
    },
  };
}
