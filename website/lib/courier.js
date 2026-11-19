import * as T from "three";
import { RoundedBoxGeometry } from "three/addons/geometries/RoundedBoxGeometry.js";
import { motionPath, parcelSize } from "./motion.js";

const up = new T.Vector3(0, 1, 0);
const material = (color, roughness = 0.75) =>
  new T.MeshStandardMaterial({ color, roughness });
function mesh(parent, geo, mat, x = 0, y = 0, z = 0) {
  const m = new T.Mesh(geo, mat);
  m.position.set(x, y, z);
  m.castShadow = true;
  m.receiveShadow = true;
  parent.add(m);
  return m;
}
function oval(parent, mat, x, y, z, rx, ry, rz) {
  const m = mesh(parent, new T.SphereGeometry(1, 20, 14), mat, x, y, z);
  m.scale.set(rx, ry, rz);
  return m;
}
function block(parent, mat, x, y, z, w, h, d, r) {
  return mesh(parent, new RoundedBoxGeometry(w, h, d, 2, r), mat, x, y, z);
}
// Cross-sections are [height, half-width, half-depth, forward offset].
function loft(rings, n = 28) {
  const vertices = [],
    indices = [];
  for (const [y, rx, rz, cz = 0] of rings)
    for (let k = 0; k < n; k++) {
      const a = (2 * Math.PI * k) / n;
      vertices.push(rx * Math.cos(a), y, cz + rz * Math.sin(a));
    }
  for (let j = 0; j < rings.length - 1; j++)
    for (let k = 0; k < n; k++) {
      const a = j * n + k,
        b = j * n + ((k + 1) % n);
      indices.push(a, a + n, b, b, a + n, b + n);
    }
  for (let k = 1; k < n - 1; k++) {
    const top = (rings.length - 1) * n;
    indices.push(0, k, k + 1, top, top + k + 1, top + k);
  }
  const g = new T.BufferGeometry();
  g.setAttribute("position", new T.Float32BufferAttribute(vertices, 3));
  g.setIndex(indices);
  g.computeVertexNormals();
  return g;
}
function segment(parent, mat, rings) {
  const m = mesh(parent, loft(rings, 20), mat);
  const dir = new T.Vector3();
  return (a, b) => {
    m.position.fromArray(a);
    dir.fromArray(b).sub(m.position);
    m.scale.y = dir.length();
    m.quaternion.setFromUnitVectors(up, dir.normalize());
  };
}
export function courier() {
  const person = new T.Group(),
    torso = new T.Group(),
    parcel = new T.Group();
  person.add(torso);
  person.rotation.y = Math.PI;
  const coat = material("#ba5934"),
    seam = material("#803d2a"),
    collar = material("#63362c"),
    trousers = material("#273b42"),
    cuff = material("#37464a"),
    boots = material("#60412c"),
    sole = material("#262b29"),
    skin = material("#ae7152"),
    hair = material("#312b28"),
    hat = material("#3a5154"),
    lip = material("#8b5743"),
    eye = material("#292a28"),
    metal = material("#d9c198", 0.34);
  mesh(
    torso,
    loft([
      [-0.022, 0.091, 0.064],
      [-0.009, 0.102, 0.072],
      [0.048, 0.106, 0.071],
      [0.12, 0.1, 0.068],
      [0.204, 0.119, 0.078],
      [0.255, 0.132, 0.08],
      [0.288, 0.118, 0.063],
      [0.304, 0.082, 0.053],
      [0.308, 0.049, 0.047],
    ]),
    coat,
  );
  mesh(
    torso,
    loft([
      [-0.024, 0.093, 0.065],
      [-0.02, 0.1, 0.07],
      [-0.008, 0.102, 0.073],
    ]),
    seam,
  );
  mesh(
    torso,
    loft([
      [0.288, 0.061, 0.05],
      [0.311, 0.057, 0.05],
      [0.329, 0.043, 0.037],
    ]),
    collar,
  );
  // Collar flaps frame the neck and the placket follows the jacket bulk.
  for (const s of [-1, 1]) {
    const flap = block(
      torso,
      collar,
      s * 0.032,
      0.279,
      0.064,
      0.046,
      0.045,
      0.009,
      0.003,
    );
    flap.rotation.z = s * 0.67;
    const front = block(
      torso,
      coat,
      s * 0.067,
      0.181,
      0.073,
      0.06,
      0.054,
      0.009,
      0.005,
    );
    front.rotation.y = s * 0.29;
    const welt = block(
      torso,
      seam,
      s * 0.068,
      0.205,
      0.078,
      0.06,
      0.006,
      0.008,
      0.002,
    );
    welt.rotation.y = s * 0.29;
  }
  const zipper = block(
    torso,
    collar,
    0,
    0.139,
    0.079,
    0.004,
    0.262,
    0.004,
    0.001,
  );
  zipper.rotation.x = 0.008;
  block(torso, metal, 0, 0.254, 0.079, 0.006, 0.014, 0.005, 0.002);
  for (const s of [-1, 1]) {
    const pocket = block(
      torso,
      seam,
      s * 0.065,
      0.094,
      0.058,
      0.043,
      0.008,
      0.008,
      0.002,
    );
    pocket.rotation.z = s * 0.55;
    const yoke = block(
      torso,
      collar,
      s * 0.071,
      0.243,
      0.065,
      0.059,
      0.003,
      0.004,
      0.001,
    );
    yoke.rotation.z = -s * 0.08;
  }
  mesh(
    torso,
    loft([
      [0.295, 0.031, 0.032],
      [0.34, 0.035, 0.034],
      [0.355, 0.035, 0.032],
    ]),
    skin,
  );
  const head = new T.Group();
  head.position.set(0, 0.335, 0.006);
  head.scale.setScalar(1.1);
  torso.add(head);
  mesh(
    head,
    loft([
      [0.002, 0.021, 0.032, 0.014],
      [0.012, 0.033, 0.041, 0.012],
      [0.035, 0.043, 0.047, 0.007],
      [0.065, 0.047, 0.053, 0.005],
      [0.086, 0.047, 0.052, 0],
      [0.104, 0.042, 0.047, -0.003],
      [0.119, 0.028, 0.033, -0.006],
      [0.125, 0.01, 0.015, -0.007],
    ]),
    skin,
  );
  for (const s of [-1, 1]) {
    oval(head, skin, s * 0.046, 0.053, -0.001, 0.009, 0.017, 0.011);
    oval(head, lip, s * 0.046, 0.054, -0.001, 0.005, 0.01, 0.007);
    oval(
      head,
      material("#eee0c8"),
      s * 0.02,
      0.061,
      0.052,
      0.009,
      0.003,
      0.0028,
    );
    oval(head, eye, s * 0.02, 0.061, 0.054, 0.003, 0.0028, 0.0024);
    const brow = oval(head, hair, s * 0.02, 0.067, 0.05, 0.012, 0.003, 0.003);
    brow.rotation.z = s * 0.08;
  }
  oval(head, skin, 0, 0.054, 0.053, 0.007, 0.016, 0.01);
  oval(head, skin, 0, 0.043, 0.06, 0.009, 0.006, 0.01);
  oval(head, lip, 0, 0.024, 0.053, 0.012, 0.0019, 0.002);
  mesh(
    head,
    loft([
      [0.082, 0.049, 0.054, -0.002],
      [0.098, 0.051, 0.058, -0.005],
      [0.119, 0.047, 0.054, -0.006],
      [0.137, 0.034, 0.04, -0.008],
      [0.145, 0.01, 0.012, -0.009],
    ]),
    hat,
  );
  mesh(
    head,
    loft([
      [0.074, 0.048, 0.052],
      [0.078, 0.051, 0.055],
      [0.091, 0.052, 0.056],
      [0.094, 0.05, 0.054],
    ]),
    hat,
  );
  for (let i = 0; i < 24; i++) {
    const a = (i * Math.PI) / 12;
    const rib = oval(
      head,
      cuff,
      0.0505 * Math.cos(a),
      0.085,
      0.055 * Math.sin(a),
      0.0011,
      0.008,
      0.0011,
    );
    rib.castShadow = false;
  }
  const pelvis = mesh(
    person,
    loft([
      [-0.038, 0.086, 0.055],
      [0.0, 0.097, 0.064],
      [0.051, 0.093, 0.065],
      [0.067, 0.082, 0.062],
    ]),
    trousers,
  );
  const legs = [],
    arms = [];
  for (const s of [-1, 1]) {
    const thigh = segment(person, trousers, [
      [0, 0.049, 0.056],
      [0.12, 0.056, 0.06],
      [0.42, 0.053, 0.059],
      [0.76, 0.04, 0.045],
      [1, 0.036, 0.038],
    ]);
    const shin = segment(person, trousers, [
      [0, 0.036, 0.038],
      [0.13, 0.039, 0.042],
      [0.37, 0.042, 0.043],
      [0.65, 0.034, 0.037],
      [0.95, 0.029, 0.03],
      [1, 0.03, 0.03],
    ]);
    const knee = oval(person, trousers, 0, 0, 0, 0.036, 0.038, 0.038);
    const shoe = new T.Group();
    person.add(shoe);
    block(shoe, sole, 0, -0.034, 0.018, 0.064, 0.016, 0.147, 0.006);
    block(shoe, boots, 0, -0.019, 0.018, 0.064, 0.033, 0.144, 0.014);
    oval(shoe, boots, 0, -0.003, -0.008, 0.032, 0.034, 0.046);
    for (let i = 0; i < 3; i++)
      block(
        shoe,
        metal,
        0,
        0.005 - i * 0.005,
        0.022 + i * 0.009,
        0.038,
        0.002,
        0.003,
        0.0008,
      );
    legs.push((q) => {
      thigh(q.hip, q.knee);
      shin(q.knee, q.ankle);
      knee.position.fromArray(q.knee);
      shoe.position.fromArray(q.ankle);
    });
    const shoulderCap = oval(person, coat, 0, 0, 0, 0.043, 0.044, 0.047);
    const sleeve = segment(person, coat, [
      [0, 0.039, 0.043],
      [0.11, 0.047, 0.049],
      [0.32, 0.044, 0.046],
      [0.6, 0.038, 0.042],
      [0.72, 0.039, 0.039],
      [0.78, 0.034, 0.039],
      [0.84, 0.037, 0.037],
      [1, 0.029, 0.033],
    ]);
    const forearm = segment(person, coat, [
      [0, 0.03, 0.032],
      [0.12, 0.034, 0.036],
      [0.28, 0.031, 0.036],
      [0.36, 0.035, 0.035],
      [0.43, 0.034, 0.035],
      [0.73, 0.028, 0.031],
      [0.78, 0.027, 0.028],
      [0.86, 0.028, 0.029],
      [0.9, 0.023, 0.025],
      [1, 0.023, 0.024],
    ]);
    const elbow = oval(person, coat, 0, 0, 0, 0.031, 0.032, 0.033);
    const palm = oval(person, skin, 0, 0, 0, 0.019, 0.029, 0.027);
    const thumb = oval(person, skin, 0, 0, 0, 0.009, 0.015, 0.012);
    arms.push((q) => {
      shoulderCap.position.fromArray(q.shoulder);
      sleeve(q.shoulder, q.elbow);
      forearm(q.elbow, q.wrist);
      elbow.position.fromArray(q.elbow);
      palm.position.fromArray(q.wrist);
      thumb.position.copy(palm.position);
      thumb.position.x -= s * 0.009;
      thumb.position.z += 0.017;
    });
  }
  const [w, h, d] = parcelSize,
    cardboard = material("#b5824b"),
    tape = material("#dcc399", 0.45);
  block(parcel, cardboard, 0, 0, 0, w, h, d, 0.008);
  block(parcel, tape, 0, h / 2 + 0.0005, 0, 0.041, 0.002, d, 0.0008);
  for (const s of [-1, 1])
    block(parcel, tape, 0, 0, s * (d / 2 + 0.0004), 0.041, h, 0.002, 0.0005);
  const label = block(
    parcel,
    material("#e9dfc7"),
    -0.085,
    h / 2 + 0.001,
    0,
    0.084,
    0.002,
    0.069,
    0.001,
  );
  label.rotation.y = 0.08;
  for (let i = 0; i < 10; i++)
    block(
      parcel,
      sole,
      -0.117 + i * 0.006,
      h / 2 + 0.0026,
      0.006,
      0.0015 + (i % 3) * 0.00065,
      0.001,
      0.03,
      0.0003,
    );

  return {
    person,
    parcel,
    apply(p, q) {
      person.position.set(motionPath.x, motionPath.floor, q.z);
      person.scale.setScalar(p.height);
      pelvis.position.y = q.hip;
      torso.position.set(0, q.hip, -0.006);
      torso.rotation.x = q.lean;
      head.rotation.x = -0.52 * q.lean;
      legs.forEach((pose, i) => pose(q.legs[i]));
      arms.forEach((pose, i) => pose(q.arms[i]));
      parcel.position.fromArray(q.parcel);
    },
  };
}
