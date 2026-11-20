import * as T from "three";

const vec = (...xyz) => new T.Vector3(...xyz);
const world = (bone) => bone.getWorldPosition(vec());
const X = vec(1, 0, 0),
  Y = vec(0, 1, 0),
  Z = vec(0, 0, 1);
const ease = (x) => T.MathUtils.smoothstep(x, 0, 1);

function sampler(model, clips) {
  const channels = new Map();
  for (const clip of clips) {
    for (const track of clip.tracks) {
      if (!channels.has(track.name))
        channels.set(track.name, {
          binding: T.PropertyBinding.create(model, track.name),
          quaternion: track.ValueTypeName === "quaternion",
          curves: new Map(),
        });
      channels.get(track.name).curves.set(clip.name, track.createInterpolant());
    }
  }
  return (name, time, second, secondTime = 0, weight = 0) => {
    for (const { binding, quaternion, curves } of channels.values()) {
      let a = curves.get(name)?.evaluate(time);
      // Three reuses an interpolant's result buffer. Preserve the outgoing
      // sample when settling between two instants in the same captured walk.
      if (weight && name === second && a) a = a.slice();
      const b = weight && curves.get(second)?.evaluate(secondTime);
      if (a && b) {
        if (quaternion) T.Quaternion.slerpFlat(a, 0, a, 0, b, 0, weight);
        else for (let j = 0; j < a.length; j++) a[j] += weight * (b[j] - a[j]);
      }
      if (a || b) binding.setValue(a || b, 0);
    }
  };
}

// A small grid of actual outsole vertices includes toe and rounded heel.
// Their deformed locations support the shoe throughout its roll on the walk.
function soleSamples(mesh) {
  const attr = mesh.geometry.getAttribute("position"),
    points = [];
  let bottom = Infinity;
  for (let i = 0; i < attr.count; i++) {
    const p = vec().fromBufferAttribute(attr, i).applyMatrix4(mesh.matrixWorld);
    bottom = Math.min(bottom, p.y);
    points.push(p);
  }
  const grid = new Map();
  for (let i = 0; i < points.length; i++) {
    const p = points[i];
    if (p.y > bottom + 0.09) continue;
    const key = Math.floor(p.x / 0.047) + "/" + Math.floor(p.z / 0.05);
    if (!grid.has(key) || p.y < points[grid.get(key)].y) grid.set(key, i);
  }
  return [...grid.values()];
}

export function makePerson(asset, role, parcel) {
  const model = asset.scene,
    root = new T.Group(),
    carrier = new T.Group();
  root.add(carrier);
  carrier.add(model);
  const bones = {},
    skeletons = new Set();
  let rig, skin;
  model.traverse((node) => {
    if (node.isBone) bones[node.name] = node;
    if (node.userData.cycle_metres) rig = node.userData;
    if (node.isSkinnedMesh) {
      skin = node;
      skeletons.add(node.skeleton);
    }
    if (node.isMesh) {
      node.castShadow = node.receiveShadow = true;
      node.frustumCulled = false;
    }
  });
  const clips = Object.fromEntries(asset.animations.map((a) => [a.name, a]));
  if (
    !rig?.height_m ||
    !rig.cycle_metres ||
    !skin ||
    !clips.Walk ||
    !bones.pelvis
  )
    throw Error("Incomplete anatomical camera subject " + role);
  root.updateMatrixWorld(true);
  if (parcel) carrier.add(parcel);
  const rest = Object.values(bones).map((bone) => ({
    bone,
    rotation: bone.quaternion.clone(),
    translation: bone.position.clone(),
  }));
  return {
    root,
    carrier,
    model,
    bones,
    skeletons,
    skin,
    parcel,
    clips,
    rest,
    sample: sampler(model, asset.animations),
    referenceHeight: rig.height_m,
    cycleMetres: rig.cycle_metres,
    soles: soleSamples(skin),
    contacts: [
      [bones.ball_l, 0.021],
      [bones.ball_r, 0.021],
    ],
  };
}

function turnBone(actor, bone, axis, angle) {
  const local = axis
    .clone()
    .applyQuaternion(actor.carrier.getWorldQuaternion(new T.Quaternion()))
    .applyQuaternion(
      bone.parent.getWorldQuaternion(new T.Quaternion()).invert(),
    );
  bone.quaternion.premultiply(
    new T.Quaternion().setFromAxisAngle(local, angle),
  );
  bone.updateWorldMatrix(false, true);
}

function aim(bone, child, point) {
  const inverse = bone.parent.matrixWorld.clone().invert();
  const origin = world(bone).applyMatrix4(inverse);
  const from = world(child).applyMatrix4(inverse).sub(origin).normalize();
  const to = point.clone().applyMatrix4(inverse).sub(origin).normalize();
  bone.quaternion.premultiply(new T.Quaternion().setFromUnitVectors(from, to));
  bone.updateWorldMatrix(false, true);
}

function carry(actor, cycle, time) {
  const { bones, carrier, parcel } = actor;
  const lift = ease((time - 2.6) / 0.33) - ease((time - 3.55) / 0.65);
  turnBone(actor, bones.spine_03, X, 0.065 + 0.025 * lift);
  turnBone(actor, bones.neck_01, X, 0.13 * lift - 0.045);
  const chest = carrier.worldToLocal(world(bones.spine_03));
  const hips = carrier.worldToLocal(world(bones.pelvis));
  const phase = cycle * Math.PI * 4;
  parcel.position.set(
    chest.x * 0.76 + 0.014,
    hips.y + 0.17 + 0.034 * lift,
    chest.z + 0.26 + 0.009 * Math.sin(phase - 0.4),
  );
  parcel.rotation.set(
    -0.052 + 0.024 * Math.cos(2 * phase) - 0.042 * lift,
    0.03 * Math.sin(phase - 0.3),
    -0.055 + 0.025 * Math.cos(phase - 0.65),
  );
  parcel.updateWorldMatrix(true, true);
  for (const [side, sign] of [
    ["l", 1],
    ["r", -1],
  ]) {
    const upper = bones["upperarm_" + side],
      lower = bones["lowerarm_" + side],
      hand = bones["hand_" + side];
    const shoulder = world(upper),
      elbow = world(lower);
    const u = shoulder.distanceTo(elbow),
      v = elbow.distanceTo(world(hand));
    const grip = parcel.localToWorld(
      vec(sign * 0.212, -0.058 + sign * 0.009, -0.048 + sign * 0.02),
    );
    const ray = grip.clone().sub(shoulder);
    const d = Math.min(ray.length(), u + v - 0.0001),
      axis = ray.normalize();
    const along = (u * u - v * v + d * d) / (2 * d);
    const pole = carrier
      .localToWorld(vec(sign * 0.43, hips.y - 0.12, -0.105))
      .sub(shoulder);
    pole.addScaledVector(axis, -pole.dot(axis)).normalize();
    const joint = shoulder
      .clone()
      .addScaledVector(axis, along)
      .addScaledVector(pole, Math.sqrt(Math.max(0, u * u - along * along)));
    aim(upper, lower, joint);
    aim(lower, hand, grip);
    // Palm and fingers wrap around the lower outside edge of the load.
    const palm = bones["middle_01_" + side];
    if (palm)
      aim(hand, palm, parcel.localToWorld(vec(sign * 0.183, -0.101, 0.037)));
  }
}

export function updatePerson(
  actor,
  foot,
  forward,
  distance,
  time,
  height,
  stopAt,
  turn,
) {
  const { root, clips, bones, sample, skin } = actor;
  root.position.copy(foot);
  root.rotation.y = Math.atan2(forward.x, forward.z);
  root.scale.setScalar(height / actor.referenceHeight);
  // Optimized glTF clips may omit constant tracks. Scrubbing or changing to a
  // different performance must restore those joints, including the hand IK.
  for (const { bone, rotation, translation } of actor.rest) {
    bone.quaternion.copy(rotation);
    bone.position.copy(translation);
  }
  const cycle = distance / (actor.cycleMetres * root.scale.x);
  const walkTime = (cycle % 1) * clips.Walk.duration;
  const remaining = stopAt - time;
  if (clips.Arrival && remaining < 1.4) {
    // Source frame 36 plants the trailing sole. Continue through the small
    // shoulder/hip weight shift as the calibrated root comes to rest.
    const arrival = T.MathUtils.clamp(
      1.23 - remaining,
      0,
      clips.Arrival.duration,
    );
    if (remaining > 1)
      sample(
        "Walk",
        walkTime,
        "Arrival",
        arrival,
        ease((1.4 - remaining) / 0.4),
      );
    else
      sample(
        "Arrival",
        arrival,
        "Looking",
        Math.max(0, Math.min(-remaining, clips.Looking.duration)),
        ease((-remaining - 0.12) / 0.92),
      );
  } else if (actor.parcel && remaining < 0) {
    // A faster custom courier can reach the end before the film clock expires.
    // At 27.3% of this captured walk both outsoles are down, 18 cm apart.
    const planted = 0.273 * clips.Walk.duration;
    const settled = ease(-remaining / 0.42);
    if (settled === 1) sample("Walk", planted);
    else sample("Walk", walkTime, "Walk", planted, settled);
  } else sample("Walk", walkTime);
  root.updateMatrixWorld(true);
  const glance = actor.parcel
    ? 0.26 * (ease((time - 2.2) / 0.55) - ease((time - 3.5) / 0.7))
    : 0.33 * (ease((time - 1.6) / 0.52) - ease((time - 3.15) / 0.84));
  turnBone(actor, bones.spine_02, Z, -turn * 0.09);
  turnBone(actor, bones.spine_03, Y, turn * 0.23 + glance * 0.26);
  turnBone(actor, bones.neck_01, Y, turn * 0.39 + glance * 0.52);
  turnBone(actor, bones.head, Y, turn * 0.2 + glance * 0.22);
  if (actor.parcel) carry(actor, cycle, time);
  root.updateMatrixWorld(true);
  const point = vec();
  let bottom = Infinity;
  for (const index of actor.soles) {
    skin.getVertexPosition(index, point).applyMatrix4(skin.matrixWorld);
    bottom = Math.min(bottom, point.y);
  }
  if (Number.isFinite(bottom)) root.position.y += foot.y - bottom;
  root.updateMatrixWorld(true);
  for (const skeleton of actor.skeletons) skeleton.update();
}
