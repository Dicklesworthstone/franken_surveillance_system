import * as T from "three";
import { ease } from "./pass.js";

const vec = (...xyz) => new T.Vector3(...xyz);
const pos = (bone) => bone.getWorldPosition(vec());
const orient = (bone, child, point) => {
  // Work in the parent's coordinates so imported negative scales are respected.
  bone.parent.updateWorldMatrix(true, false);
  const inverse = bone.parent.matrixWorld.clone().invert();
  const root = pos(bone).applyMatrix4(inverse);
  const from = pos(child).applyMatrix4(inverse).sub(root).normalize();
  const to = point.clone().applyMatrix4(inverse).sub(root).normalize();
  bone.quaternion.premultiply(new T.Quaternion().setFromUnitVectors(from, to));
  bone.updateWorldMatrix(false, false);
};
function reach(a, b, c, target, pole) {
  const root = pos(a),
    d = target.clone().sub(root),
    length = d.length();
  d.normalize();
  const upper = root.distanceTo(pos(b)),
    lower = pos(b).distanceTo(pos(c));
  const span = T.MathUtils.clamp(
    length,
    Math.abs(upper - lower) + 0.0001,
    upper + lower - 0.0001,
  );
  const mid = (upper * upper - lower * lower + span * span) / (2 * span);
  const perp = pole.clone().addScaledVector(d, -pole.dot(d)).normalize();
  const elbow = root
    .clone()
    .addScaledVector(d, mid)
    .addScaledVector(perp, Math.sqrt(Math.max(0, upper * upper - mid * mid)));
  orient(a, b, elbow);
  orient(b, c, root.clone().addScaledVector(d, span));
}
export function player(gltf, passer) {
  const model = gltf.scene,
    group = new T.Group();
  group.add(model);
  const bones = {};
  model.traverse((n) => {
    if (n.isBone)
      bones[
        n.name
          .replace(/^Bip01[ _]*/, "")
          .replaceAll("_", "")
          .replaceAll(" ", "")
      ] = n;
    if (n.isMesh) {
      n.castShadow = true;
      n.receiveShadow = true;
      n.frustumCulled = false;
      for (const m of [].concat(n.material)) {
        if (m.transparent) {
          m.transparent = false;
          m.alphaTest = 0.4;
          m.depthWrite = true;
        }
        m.roughness = 0.88;
        m.metalness = 0;
      }
    }
  });
  const signs = ["L", "R"],
    dir = passer ? 1 : -1;
  const saved = Object.values(bones).map((b) => [
    b,
    b.position.clone(),
    b.quaternion.clone(),
  ]);
  const bbox = new T.Box3().setFromObject(model, true);
  const restHeight = bbox.max.y - bbox.min.y;
  model.position.y = -bbox.min.y;
  group.rotation.y = dir * Math.PI * 0.48;
  return {
    group,
    pose(p, q, t) {
      for (const [b, base, rot] of saved) {
        b.position.copy(base);
        b.quaternion.copy(rot);
      }
      group.position.x = (-dir * p.spacing) / 2;
      group.scale.setScalar((passer ? p.height : 1.7) / restHeight);
      group.updateMatrixWorld(true);
      const palmsReady = ease(
        (t - q.release + 0.18) / (q.arrival - q.release + 0.18),
      );
      const dip = passer
        ? 0.13 * ease(t / 0.35) * (1 - ease((t - 0.4) / 0.38))
        : Math.min(0.24, Math.max(0.04, (1.2 - q.crossing.y) * 0.28)) *
          palmsReady *
          (1 - ease((t - q.arrival) / 0.55));
      const feet = signs.map((s, i) =>
        pos(bones[s + "Foot"]).add(vec((i === 0 ? 1 : -1) * 0.13 * dir, 0, 0)),
      );
      const pelvis = bones.Pelvis,
        at = pos(pelvis);
      at.y -= dip;
      at.x +=
        dir * (passer ? 0.09 * ease((t - 0.38) / 0.4) : 0.055 * palmsReady);
      pelvis.position.copy(pelvis.parent.worldToLocal(at));
      pelvis.updateWorldMatrix(true, true);
      const tilt = (a, b, radians) => {
        const origin = pos(a),
          offset = pos(b).sub(origin);
        offset.applyAxisAngle(vec(0, 0, 1), -dir * radians);
        orient(a, b, origin.add(offset));
      };
      tilt(
        bones.Spine,
        bones.Spine1,
        passer
          ? 0.07 + 0.07 * ease(t / 0.5)
          : 0.045 + 0.16 * palmsReady * (1 - ease((t - q.arrival) / 0.55)),
      );
      const gaze = 0.09 + 0.14 * Math.max(0, 1.1 - q.ball.y);
      tilt(bones.Neck, bones.Head, gaze);
      for (const [i, s] of signs.entries()) {
        reach(
          bones[s + "Thigh"],
          bones[s + "Calf"],
          bones[s + "Foot"],
          feet[i],
          vec(dir, 0, (i === 0 ? -1 : 1) * 0.12),
        );
      }
      let grip;
      if (passer) {
        const relax = ease((t - q.release - 0.09) / 0.63);
        grip = vec(q.ball.x, q.ball.y, 0);
        if (t >= q.release) {
          const follow = ease((t - q.release) / 0.1);
          grip.set(
            T.MathUtils.lerp(
              q.flight.x0 + 0.05 * follow,
              -p.spacing / 2 + 0.24,
              relax,
            ),
            T.MathUtils.lerp(
              q.flight.y0 + (p.style === "chest" ? 0.14 : -0.12) * follow,
              (0.98 * p.height) / 1.8,
              relax,
            ),
            0,
          );
        }
      } else {
        grip = vec(p.spacing / 2 - 0.27, 0.98, 0).lerp(
          vec(q.flight.catchX, T.MathUtils.clamp(q.crossing.y, 0.65, 1.5), 0),
          palmsReady,
        );
        if (t >= q.arrival && q.caught) grip.set(q.ball.x, q.ball.y, 0);
      }
      for (const [i, s] of signs.entries()) {
        const side = i === 0 ? -dir : dir;
        const hand = grip.clone().add(vec(-dir * 0.041, -0.018, side * 0.119));
        reach(
          bones[s + "UpperArm"],
          bones[s + "Forearm"],
          bones[s + "Hand"],
          hand,
          vec(-dir * 0.21, -0.88, side * 0.72),
        );
        // Fingers point forward and slightly down around the ball.
        if (bones[s + "Finger2"])
          orient(
            bones[s + "Hand"],
            bones[s + "Finger2"],
            hand.clone().add(vec(dir * 0.1, -0.021, -side * 0.037)),
          );
      }
      group.updateMatrixWorld(true);
    },
  };
}
