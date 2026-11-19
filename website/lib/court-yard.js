import * as T from "three";
import { mergeGeometries } from "three/addons/utils/BufferGeometryUtils.js";

function random(seed) {
  let n = seed;
  return () => {
    n = (1664525 * n + 1013904223) >>> 0;
    return n / 4294967296;
  };
}
function canvasTexture(w, h, paint) {
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  paint(canvas.getContext("2d"), w, h);
  const tex = new T.CanvasTexture(canvas);
  tex.colorSpace = T.SRGBColorSpace;
  return tex;
}
function finish(color, roughness = 0.92) {
  return new T.MeshStandardMaterial({ color, roughness });
}
function grain(color, repeat) {
  const tex = canvasTexture(256, 256, (g, w, h) => {
    g.fillStyle = color;
    g.fillRect(0, 0, w, h);
    const rng = random(29);
    for (let i = 0; i < 22000; i++) {
      g.fillStyle =
        rng() > 0.5 ? "rgba(255,244,220,.15)" : "rgba(40,32,29,.15)";
      g.fillRect(rng() * w, rng() * h, rng() * 1.8 + 0.3, 1.3);
    }
  });
  tex.wrapS = tex.wrapT = T.RepeatWrapping;
  tex.repeat.set(repeat, repeat);
  tex.anisotropy = 4;
  return new T.MeshStandardMaterial({ map: tex, roughness: 0.96 });
}
function mesh(parent, geo, mat, x, y, z) {
  const m = new T.Mesh(geo, mat);
  m.position.set(x, y, z);
  m.castShadow = true;
  m.receiveShadow = true;
  parent.add(m);
  return m;
}
export function basketball() {
  const tex = canvasTexture(768, 384, (g, w, h) => {
    g.fillStyle = "#df752a";
    g.fillRect(0, 0, w, h);
    const rng = random(81);
    for (let i = 0; i < 100000; i++) {
      g.fillStyle = rng() > 0.5 ? "#d06a27" : "#e28035";
      g.fillRect(rng() * w, rng() * h, 1.8, 1.6);
    }
    g.strokeStyle = "#382c25";
    g.lineWidth = 5;
    for (let x = 0; x <= w; x += w / 2) {
      g.beginPath();
      g.moveTo(x, 0);
      g.lineTo(x, h);
      g.stroke();
    }
    for (const band of [0, 1, -1]) {
      g.beginPath();
      for (let x = 0; x <= w; x += 2) {
        const y =
          h * (0.5 + band * (0.215 + 0.135 * Math.cos((4 * Math.PI * x) / w)));
        if (!x) g.moveTo(x, y);
        else g.lineTo(x, y);
      }
      g.stroke();
    }
  });
  return new T.Mesh(
    new T.SphereGeometry(0.119, 48, 32),
    new T.MeshStandardMaterial({ map: tex, roughness: 0.72 }),
  );
}
export function courtyard() {
  const group = new T.Group(),
    clay = grain("#c87752", 5),
    stucco = grain("#dfaa78", 2),
    green = finish("#244b40"),
    cedar = finish("#875d3b"),
    stone = finish("#e8d6b9"),
    steel = finish("#33413c");
  const box = (w, h, d, m, x, y, z) =>
    mesh(group, new T.BoxGeometry(w, h, d), m, x, y, z);
  const slab = mesh(group, new T.PlaneGeometry(20, 12), clay, 0, -0.002, 0);
  slab.rotation.x = -Math.PI / 2;
  box(42, 0.08, 30, grain("#af946f", 12), 0, -0.08, 0);
  const markings = finish("#f6d9b4");
  for (const z of [-2.12, 2.12]) box(12, 0.003, 0.032, markings, 0, 0, z);
  for (const x of [-6, 6]) box(0.032, 0.003, 4.27, markings, x, 0, 0);
  const circle = mesh(
    group,
    new T.RingGeometry(1.68, 1.709, 128),
    markings,
    -0.8,
    0.003,
    0,
  );
  circle.rotation.x = -Math.PI / 2;
  box(0.03, 0.003, 4.24, markings, -0.8, 0.001, 0);
  // An open arcade casts physical shadows onto the court. Each void is an arch.
  const arcade = new T.Shape();
  arcade.moveTo(-8, 0);
  arcade.lineTo(8, 0);
  arcade.lineTo(8, 3.55);
  arcade.lineTo(-8, 3.55);
  arcade.closePath();
  for (const x of [-5.4, -2.7, 0, 2.7, 5.4]) {
    const hole = new T.Path();
    hole.moveTo(x - 1.09, 0.31);
    hole.lineTo(x - 1.09, 1.87);
    hole.absarc(x, 1.87, 1.09, Math.PI, 0, true);
    hole.lineTo(x + 1.09, 0.31);
    hole.closePath();
    arcade.holes.push(hole);
  }
  mesh(
    group,
    new T.ExtrudeGeometry(arcade, {
      depth: 0.33,
      bevelEnabled: true,
      bevelSegments: 2,
      steps: 1,
      bevelSize: 0.022,
      bevelThickness: 0.02,
      curveSegments: 30,
    }),
    stucco,
    0,
    0,
    -3.78,
  );
  box(16.18, 0.15, 0.55, stone, 0, 3.55, -3.62);
  box(20, 0.67, 0.11, green, 0, 0.31, -6.5);
  box(20, 0.065, 0.16, cedar, 0, 0.66, -6.5);
  box(0.24, 2.7, 6.8, green, -8, 1.32, -1.05);
  for (let i = 0; i < 5; i++)
    box(2.9, 0.055, 0.089, cedar, 3.9, 0.49, -2.88 + i * 0.095);
  for (const x of [2.75, 5.05]) box(0.1, 0.48, 0.55, steel, x, 0.24, -2.68);
  function tree(x, z, s, seed) {
    mesh(
      group,
      new T.CylinderGeometry(0.47 * s, 0.31 * s, 0.65 * s, 40),
      finish("#9a6445"),
      x,
      0.325 * s,
      z,
    );
    mesh(
      group,
      new T.CylinderGeometry(0.43 * s, 0.43 * s, 0.015, 40),
      finish("#524132"),
      x,
      0.65 * s,
      z,
    );
    const rng = random(seed),
      leafMat = finish("#657950");
    const leaves = new T.InstancedMesh(
      new T.IcosahedronGeometry(1, 0),
      leafMat,
      750,
    );
    const pose = new T.Object3D(),
      origin = new T.Vector3(x, 0.64 * s, z);
    const trunkMat = finish("#5d5141");
    const shoots = [];
    function twig(a, b, r) {
      const d = b.clone().sub(a),
        m = mesh(
          group,
          new T.CylinderGeometry(r * 0.58, r, d.length(), 8),
          trunkMat,
          0,
          0,
          0,
        );
      m.position.copy(a).lerp(b, 0.5);
      m.quaternion.setFromUnitVectors(new T.Vector3(0, 1, 0), d.normalize());
    }
    const fork = origin
      .clone()
      .add(new T.Vector3(0.08, 1.05, 0).multiplyScalar(s));
    twig(origin, fork, 0.082 * s);
    for (let i = 0; i < 18; i++) {
      const a = rng() * 2 * Math.PI,
        spread = (0.35 + rng() * 0.66) * s;
      const tip = fork
        .clone()
        .add(
          new T.Vector3(
            spread * Math.cos(a),
            (0.56 + rng() * 0.73) * s,
            spread * Math.sin(a),
          ),
        );
      twig(fork, tip, 0.027 * s);
      shoots.push(tip);
    }
    for (let i = 0; i < leaves.count; i++) {
      const tip = shoots[i % shoots.length];
      pose.position
        .copy(tip)
        .add(
          new T.Vector3(
            rng() - 0.5,
            (rng() - 0.5) * 0.85,
            rng() - 0.5,
          ).multiplyScalar(s),
        );
      pose.rotation.set(rng() * Math.PI, rng() * 7, rng() * Math.PI);
      pose.scale.set(0.115 * s, 0.032 * s, 0.058 * s);
      pose.updateMatrix();
      leaves.setMatrixAt(i, pose.matrix);
      leaves.setColorAt(
        i,
        new T.Color().setHSL(
          0.215 + rng() * 0.025,
          0.16 + rng() * 0.1,
          0.5 + rng() * 0.4,
        ),
      );
    }
    leaves.castShadow = true;
    leaves.receiveShadow = true;
    group.add(leaves);
  }
  tree(-4.9, -2.5, 0.93, 7);
  tree(6, -2.2, 1.15, 12);
  // Merge the static architectural pieces by material to keep phone draw calls bounded.
  const batches = new Map();
  for (const obj of [...group.children]) {
    if (!obj.isMesh || obj.isInstancedMesh) continue;
    obj.updateMatrix();
    const geo = obj.geometry.index
      ? obj.geometry.toNonIndexed()
      : obj.geometry.clone();
    geo.applyMatrix4(obj.matrix);
    const bucket = batches.get(obj.material) ?? [];
    bucket.push(geo);
    batches.set(obj.material, bucket);
    group.remove(obj);
    obj.geometry.dispose();
  }
  for (const [mat, bucket] of batches) {
    mesh(group, mergeGeometries(bucket), mat, 0, 0, 0);
    bucket.forEach((g) => g.dispose());
  }
  return group;
}
