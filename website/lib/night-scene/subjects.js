import * as T from "three";

const vec = (...xyz) => new T.Vector3(...xyz);
const position = (node) => node.getWorldPosition(vec());
function aim(bone, child, goal) {
  const inv = bone.parent.matrixWorld.clone().invert();
  const origin = position(bone).applyMatrix4(inv);
  const from = position(child).applyMatrix4(inv).sub(origin).normalize();
  const to = goal.clone().applyMatrix4(inv).sub(origin).normalize();
  bone.quaternion.premultiply(new T.Quaternion().setFromUnitVectors(from, to));
  bone.updateWorldMatrix(true, true);
}
function hold(actor) {
  const { bones, carrier, parcel } = actor;
  for (const [side, sign] of [
    ["L", 1],
    ["R", -1],
  ]) {
    const upper = bones[side + "UpperArm"],
      lower = bones[side + "Forearm"],
      hand = bones[side + "Hand"];
    const shoulder = position(upper),
      elbow = position(lower);
    const u = shoulder.distanceTo(elbow),
      v = position(hand).distanceTo(elbow);
    const grip = parcel.localToWorld(vec(sign * 0.196, -0.092, 0.024));
    const displacement = grip.clone().sub(shoulder),
      d = Math.min(displacement.length(), u + v - 0.0001);
    const axis = displacement.normalize();
    const along = (u * u - v * v + d * d) / (2 * d);
    const pole = carrier
      .localToWorld(vec(sign * 0.6, 0.43, -0.1))
      .sub(shoulder);
    pole.addScaledVector(axis, -pole.dot(axis)).normalize();
    const joint = shoulder
      .clone()
      .addScaledVector(axis, along)
      .addScaledVector(pole, Math.sqrt(Math.max(0, u * u - along * along)));
    aim(upper, lower, joint);
    aim(lower, hand, grip);
  }
}
function packageMesh() {
  const group = new T.Group();
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
  const paper = new T.MeshStandardMaterial({
    color: 0xded9ca,
    roughness: 0.88,
  });
  cardboard(0.39, 0.225, 0.265, 0, 0, 0, board);
  cardboard(0.04, 0.226, 0.267, 0, 0, 0, tape);
  cardboard(0.109, 0.001, 0.072, 0.103, 0.113, 0.004, paper);
  return group;
}
export function makeActor(asset, role) {
  const root = new T.Group(),
    carrier = new T.Group(),
    model = asset.scene;
  root.add(carrier);
  carrier.add(model);
  const bones = {},
    skeletons = new Set();
  model.traverse((node) => {
    if (node.isBone)
      bones[
        node.name
          .replace(/^Bip01[ _]*/, "")
          .replaceAll("_", "")
          .replaceAll(" ", "")
      ] = node;
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
  const clip =
    asset.animations.find((item) => item.name === "Neutral walk") ||
    asset.animations[0];
  const idle = asset.animations.find((item) => item.name === "Standing");
  if (!clip || clip.duration <= 0)
    throw Error("Missing skeletal gait for " + role);
  const idleTracks = new Map(
    idle?.tracks.map((track) => [track.name, track]) || [],
  );
  const channels = clip.tracks.map((track) => ({
    binding: T.PropertyBinding.create(model, track.name),
    curve: track.createInterpolant(),
    idle: idleTracks.get(track.name)?.createInterpolant(),
    quaternion: track.ValueTypeName === "quaternion",
  }));
  // Sample both motion captures at absolute times so scrubbing restores the same pose.
  function sample(time, standingWeight = 0, idleSeconds = 0) {
    const phase = ((time % clip.duration) + clip.duration) % clip.duration;
    for (const ch of channels) {
      const value = ch.curve.evaluate(phase);
      if (standingWeight && ch.idle) {
        const rest = ch.idle.evaluate(idleSeconds % idle.duration);
        if (ch.quaternion)
          T.Quaternion.slerpFlat(value, 0, value, 0, rest, 0, standingWeight);
        else
          for (let i = 0; i < value.length; i++)
            value[i] += (rest[i] - value[i]) * standingWeight;
      }
      ch.binding.setValue(value, 0);
    }
  }
  sample(0);
  root.updateMatrixWorld(true);
  if (role !== "raccoon") {
    const direction = position(bones.LToe0)
      .sub(position(bones.LFoot))
      .add(position(bones.RToe0).sub(position(bones.RFoot)));
    model.rotation.y -= Math.atan2(direction.x, direction.z);
    model.updateMatrixWorld(true);
  } else if (bones.head012 && bones.tail0003) {
    const facing = position(bones.head012).sub(position(bones.tail0003));
    model.rotation.y -= Math.atan2(facing.x, facing.z);
    model.updateMatrixWorld(true);
  }
  const bounds = new T.Box3().setFromObject(model, true);
  const size = bounds.getSize(vec()),
    mid = bounds.getCenter(vec());
  model.position.set(-mid.x, -bounds.min.y, -mid.z);
  const referenceHeight = role === "raccoon" ? 0.3 : 1.77;
  model.scale.multiplyScalar(referenceHeight / size.y);
  model.position.multiplyScalar(referenceHeight / size.y);
  let parcel;
  if (role === "courier") {
    parcel = packageMesh();
    parcel.position.set(0, 0.99, 0.24);
    carrier.add(parcel);
  }
  const contacts = Object.entries(bones).flatMap(([name, bone]) => {
    if (role === "raccoon")
      return /^(?:f|r)(?:middle01|index01|pinky01)[LR]/.test(name)
        ? [[bone, 0.003]]
        : [];
    if (/^[LR]Toe0$/.test(name)) return [[bone, 0.024]];
    if (/^[LR]Foot$/.test(name)) return [[bone, 0.069]];
    return [];
  });
  return {
    root,
    carrier,
    model,
    bones,
    parcel,
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
  movingFraction = 1,
) {
  const { root, carrier, sample, referenceHeight, clipLength } = actor;
  root.position.copy(foot);
  root.rotation.y = Math.atan2(forward.x, forward.z);
  root.scale.setScalar(height / referenceHeight);
  if (role === "raccoon") {
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
  } else {
    const stride = (1.42 * height) / referenceHeight;
    sample((distance / stride) * clipLength, 1 - movingFraction, time);
    if (movingFraction < 1) {
      root.updateMatrixWorld(true);
      const feetFacing = position(actor.bones.LToe0)
        .sub(position(actor.bones.LFoot))
        .add(position(actor.bones.RToe0).sub(position(actor.bones.RFoot)));
      const correction =
        Math.atan2(forward.x, forward.z) -
        Math.atan2(feetFacing.x, feetFacing.z);
      root.rotation.y +=
        (1 - movingFraction) *
        Math.atan2(Math.sin(correction), Math.cos(correction));
    }
    if (!actor.parcel) {
      root.updateMatrixWorld(true);
      for (const [side, sign] of [
        ["L", 1],
        ["R", -1],
      ]) {
        const upper = actor.bones[side + "UpperArm"],
          lower = actor.bones[side + "Forearm"],
          hand = actor.bones[side + "Hand"];
        const swing =
          movingFraction *
          sign *
          Math.sin((distance / stride) * Math.PI * 2 + 0.65);
        aim(
          upper,
          lower,
          carrier.localToWorld(vec(sign * 0.245, 1.025, 0.025 + 0.1 * swing)),
        );
        aim(
          lower,
          hand,
          carrier.localToWorld(vec(sign * 0.245, 0.79, 0.065 + 0.19 * swing)),
        );
      }
    } else {
      actor.parcel.position.y =
        0.99 + 0.015 * Math.sin((distance / stride) * Math.PI * 4);
      root.updateMatrixWorld(true);
      hold(actor);
    }
  }
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
