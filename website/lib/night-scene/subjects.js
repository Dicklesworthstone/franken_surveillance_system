import * as T from "three";
import { makePerson, updatePerson } from "./people.js";

const vec = (...xyz) => new T.Vector3(...xyz);
const position = (node) => node.getWorldPosition(vec());
function packageMesh() {
  const group = new T.Group();
  const label = document.createElement("canvas");
  label.width = 320;
  label.height = 192;
  const ink = label.getContext("2d");
  ink.fillStyle = "#e8e3d5";
  ink.fillRect(0, 0, label.width, label.height);
  ink.fillStyle = "#33332f";
  ink.fillRect(13, 14, 294, 5);
  ink.font = "bold 21px sans-serif";
  ink.fillText("PARCEL", 14, 45);
  ink.font = "14px monospace";
  ink.fillText("RESIDENTIAL  /  1 OF 1", 14, 73);
  ink.fillRect(13, 84, 294, 2);
  let x = 16;
  for (const weight of "2213121233111212213112211322121311122111231") {
    const w = Number(weight) * 2;
    ink.fillRect(x, 104, w, 54);
    x += w + 3;
  }
  ink.font = "11px monospace";
  ink.fillText("SIMULATED SHIPMENT", 15, 178);
  const print = new T.CanvasTexture(label);
  print.colorSpace = T.SRGBColorSpace;
  function cardboard(w, h, d, x, y, z, material) {
    const mesh = new T.Mesh(new T.BoxGeometry(w, h, d), material);
    mesh.castShadow = true;
    mesh.receiveShadow = true;
    mesh.position.set(x, y, z);
    group.add(mesh);
  }
  const board = new T.MeshStandardMaterial({
    color: 0xb68855,
    roughness: 0.94,
  });
  const tape = new T.MeshStandardMaterial({ color: 0x987949, roughness: 0.49 });
  cardboard(0.39, 0.225, 0.265, 0, 0, 0, board);
  cardboard(0.04, 0.226, 0.267, 0, 0, 0, tape);
  const paper = new T.MeshStandardMaterial({ map: print, roughness: 0.82 });
  const shipping = new T.Mesh(new T.PlaneGeometry(0.157, 0.094), paper);
  shipping.position.set(0.062, 0.001, 0.133);
  group.add(shipping);
  const packingSlip = shipping.clone();
  packingSlip.rotation.x = -Math.PI / 2;
  packingSlip.position.set(0.077, 0.113, -0.014);
  group.add(packingSlip);
  return group;
}
export function makeActor(asset, role) {
  if (role !== "raccoon")
    return makePerson(asset, role, role === "courier" ? packageMesh() : null);
  const root = new T.Group(),
    carrier = new T.Group(),
    model = asset.scene;
  root.add(carrier);
  carrier.add(model);
  const bones = {},
    skeletons = new Set();
  model.traverse((node) => {
    if (node.isBone)
      bones[node.name.replaceAll("_", "").replaceAll(" ", "")] = node;
    if (node.isSkinnedMesh) skeletons.add(node.skeleton);
    if (!node.isMesh) return;
    node.castShadow = true;
    node.receiveShadow = true;
    node.frustumCulled = false;
    for (const material of [].concat(node.material)) {
      if (material.transparent) {
        material.transparent = false;
        material.alphaTest = 0.44;
        material.depthWrite = true;
      }
      material.metalness = 0;
      material.roughness = 0.85;
    }
  });
  const clip = asset.animations[0];
  if (!clip || clip.duration <= 0)
    throw Error("Missing skeletal gait for " + role);
  const channels = clip.tracks.map((track) => ({
    binding: T.PropertyBinding.create(model, track.name),
    curve: track.createInterpolant(),
  }));
  function sample(time) {
    const phase = ((time % clip.duration) + clip.duration) % clip.duration;
    for (const { binding, curve } of channels)
      binding.setValue(curve.evaluate(phase), 0);
  }
  sample(0);
  root.updateMatrixWorld(true);
  if (bones.head012 && bones.tail0003) {
    const facing = position(bones.head012).sub(position(bones.tail0003));
    model.rotation.y -= Math.atan2(facing.x, facing.z);
    model.updateMatrixWorld(true);
  }
  const bounds = new T.Box3().setFromObject(model, true);
  const size = bounds.getSize(vec()),
    mid = bounds.getCenter(vec());
  model.position.set(-mid.x, -bounds.min.y, -mid.z);
  const referenceHeight = 0.3;
  model.scale.multiplyScalar(referenceHeight / size.y);
  model.position.multiplyScalar(referenceHeight / size.y);
  const contacts = Object.entries(bones)
    .filter(([name]) => /^(?:f|r)(?:middle01|index01|pinky01)[LR]/.test(name))
    .map(([, bone]) => [bone, 0.003]);
  return {
    root,
    carrier,
    model,
    bones,
    sample,
    contacts,
    skeletons,
    clipLength: clip.duration,
    referenceHeight,
  };
}
export function updateActor(
  actor,
  role,
  foot,
  forward,
  distance,
  time,
  height,
  stopAt = Infinity,
  turn = 0,
) {
  if (role !== "raccoon")
    return updatePerson(
      actor,
      foot,
      forward,
      distance,
      time,
      height,
      stopAt,
      turn,
    );
  const { root, carrier, sample, referenceHeight, clipLength } = actor;
  root.position.copy(foot);
  root.rotation.y = Math.atan2(forward.x, forward.z);
  root.scale.setScalar(height / referenceHeight);
  sample((distance / 0.39) * clipLength);
  const phase = (distance / 0.43) * Math.PI * 2;
  carrier.position.y = 0.006 * Math.abs(Math.sin(phase));
  carrier.rotation.set(
    0.022 * Math.sin(phase),
    0.014 * Math.cos(time * 2.5),
    0.029 * Math.sin(phase),
  );
  actor.model.traverse((node) => {
    const i = node.morphTargetDictionary;
    if (i) {
      for (const [name, axis] of [
        ["stride-a", 0],
        ["stride-b", Math.PI],
        ["sniff", null],
      ])
        if (i[name] !== undefined)
          node.morphTargetInfluences[i[name]] =
            axis === null
              ? (Math.sin(time * 3.9) + 1) / 2
              : Math.max(0, Math.sin(phase + axis));
    }
  });
  // Place the lowest sole/digit on the registered grade at this gait phase.
  root.updateMatrixWorld(true);
  if (actor.contacts.length) {
    const bottom = Math.min(
      ...actor.contacts.map(
        ([bone, sole]) => position(bone).y - (sole * height) / referenceHeight,
      ),
    );
    root.position.y += foot.y - bottom;
  }
  root.updateMatrixWorld(true);
  for (const skeleton of actor.skeletons) skeleton.update();
}
