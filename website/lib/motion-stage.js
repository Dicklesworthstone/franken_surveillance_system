import * as T from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { createSiteStage, disposeSiteStage } from "./property.js";
import { fixedCamera } from "./cameras.js";
import { cameras } from "./scenarios.js";
import { motionPath, motionAt } from "./motion.js";
import { courier } from "./courier.js";

// A body-volume exposure at an earlier instant, drawn in one instanced call.
function exposure(color) {
  const mesh = new T.InstancedMesh(
    new T.SphereGeometry(1, 14, 10),
    new T.MeshBasicMaterial({ color }),
    14,
  );
  mesh.frustumCulled = false;
  const shape = new T.Object3D(),
    axis = new T.Vector3(0, 1, 0),
    dir = new T.Vector3(),
    a = new T.Vector3(),
    b = new T.Vector3();
  function segment(index, start, end, width, depth) {
    a.fromArray(start);
    b.fromArray(end);
    dir.copy(b).sub(a);
    shape.position.copy(a).lerp(b, 0.5);
    shape.scale.set(width, dir.length() / 2 + width * 0.4, depth);
    shape.quaternion.setFromUnitVectors(axis, dir.normalize());
    shape.updateMatrix();
    mesh.setMatrixAt(index, shape.matrix);
  }
  return {
    mesh,
    draw(p, q) {
      mesh.position.set(motionPath.x, motionPath.floor, q.z);
      mesh.scale.setScalar(p.height);
      mesh.rotation.y = Math.PI;
      const chest = [0, q.arms[0].shoulder[1], q.arms[0].shoulder[2]],
        hip = [0, q.hip, 0];
      segment(0, hip, chest, 0.122, 0.079);
      segment(
        1,
        [0, chest[1] + 0.035, chest[2]],
        [0, chest[1] + 0.17, chest[2] + 0.012],
        0.047,
        0.052,
      );
      let i = 2;
      for (const l of q.legs) {
        segment(i++, l.hip, l.knee, 0.05, 0.051);
        segment(i++, l.knee, l.ankle, 0.034, 0.037);
        segment(
          i++,
          l.ankle,
          [l.ankle[0], l.ankle[1] - 0.015, l.ankle[2] + 0.082],
          0.034,
          0.032,
        );
      }
      for (const arm of q.arms) {
        segment(i++, arm.shoulder, arm.elbow, 0.044, 0.045);
        segment(i++, arm.elbow, arm.wrist, 0.033, 0.034);
        segment(
          i++,
          arm.wrist,
          [arm.wrist[0], arm.wrist[1] - 0.022, arm.wrist[2] + 0.012],
          0.017,
          0.023,
        );
      }
      mesh.instanceMatrix.needsUpdate = true;
    },
  };
}

function boneTrail(color, opacity) {
  // Two legs and two arms with two segments each, plus shoulders, hips and spine.
  const points = new Float32Array(12 * 2 * 3);
  const geo = new T.BufferGeometry();
  geo.setAttribute(
    "position",
    new T.BufferAttribute(points, 3).setUsage(T.DynamicDrawUsage),
  );
  const line = new T.LineSegments(
    geo,
    new T.LineBasicMaterial({
      color,
      opacity,
      transparent: true,
      depthTest: false,
    }),
  );
  line.renderOrder = 10;
  line.frustumCulled = false;
  return {
    line,
    draw(p, q) {
      const chains = q.legs
        .map((l) => [l.hip, l.knee, l.ankle])
        .concat(q.arms.map((a) => [a.shoulder, a.elbow, a.wrist]));
      chains.push([
        q.legs[0].hip,
        q.legs[1].hip,
        q.arms[1].shoulder,
        q.arms[0].shoulder,
        q.legs[0].hip,
      ]);
      let i = 0;
      for (const chain of chains)
        for (let k = 1; k < chain.length; k++)
          for (const v of [chain[k - 1], chain[k]]) {
            points[i++] = motionPath.x - p.height * v[0];
            points[i++] = motionPath.floor + p.height * v[1];
            points[i++] = q.z - p.height * v[2];
          }
      geo.attributes.position.needsUpdate = true;
    },
  };
}
export function createMotionStage(canvas, interactive = true) {
  const { renderer, scene, sky, sun, ground, grid, staticObjects } =
    createSiteStage(canvas, interactive);
  const rig = courier();
  scene.add(rig.person, rig.parcel);
  const studio = new T.Group();
  scene.add(studio);
  const floor = new T.Mesh(
    new T.PlaneGeometry(180, 180),
    new T.MeshStandardMaterial({ color: "#a4b7a9", roughness: 0.93 }),
  );
  floor.rotation.x = -Math.PI / 2;
  floor.position.y = motionPath.floor - 0.001;
  floor.receiveShadow = true;
  studio.add(floor);
  const markings = [];
  for (let z = -8; z < 20; z += 0.25) {
    for (const side of [-1, 1]) {
      const x = motionPath.x + side * 0.85;
      const major = Number.isInteger(z);
      markings.push(x, 0, z, x + side * (major ? 0.24 : 0.09), 0, z);
    }
  }
  for (const side of [-1, 1])
    markings.push(
      motionPath.x + side * 0.85,
      0,
      -8,
      motionPath.x + side * 0.85,
      0,
      20,
    );
  const rules = new T.BufferGeometry();
  rules.setAttribute("position", new T.Float32BufferAttribute(markings, 3));
  const line = new T.LineSegments(
    rules,
    new T.LineBasicMaterial({
      color: "#647d73",
      transparent: true,
      opacity: 0.65,
    }),
  );
  line.position.y = motionPath.floor + 0.002;
  studio.add(line);
  const rim = new T.DirectionalLight("#a9dcff", 1.2);
  rim.position.set(4, 3, -6);
  scene.add(rim);
  const portrait = new T.PerspectiveCamera(32, 1, 0.03, 180),
    site = new T.PerspectiveCamera(38, 1, 0.06, 180);
  const fixed = Object.fromEntries(
    cameras.map((c) => [c.id, fixedCamera(c, 16 / 9)]),
  );
  const trails = [
    boneTrail("#ffda89", 1),
    boneTrail("#204e52", 0.74),
    boneTrail("#204e52", 0.4),
  ];
  const echoes = [exposure("#a9bbae"), exposure("#b9c8bc")];
  const offsets = [0, 0.48, 0.96];
  for (const echo of echoes) scene.add(echo.mesh);
  for (const trail of trails) scene.add(trail.line);
  let w = 1,
    h = 1,
    frames = [],
    refresh = () => {},
    lastView;
  const pivot = new T.Vector3(motionPath.x, 1, 6.4);
  const orbit = interactive ? new OrbitControls(site, canvas) : null;
  function reset() {
    site.position.copy(pivot).add(new T.Vector3(-7.2, 4.5, 7.8));
    site.lookAt(pivot);
    if (orbit) {
      orbit.target.copy(pivot);
      orbit.update();
    }
  }
  reset();
  if (orbit) {
    orbit.minDistance = 3;
    orbit.maxDistance = 28;
    orbit.maxPolarAngle = Math.PI * 0.48;
    orbit.enablePan = false;
    orbit.addEventListener("change", () => refresh());
    orbit.enabled = false;
  }
  function shot(camera, left, top, width, height, aspect = width / height) {
    camera.aspect = aspect;
    camera.updateProjectionMatrix();
    camera.updateMatrixWorld();
    renderer.setViewport(left, h - top - height, width, height);
    renderer.setScissor(left, h - top - height, width, height);
    renderer.render(scene, camera);
  }
  return {
    resize(width, height) {
      w = Math.max(2, Math.floor(width));
      h = Math.max(2, Math.floor(height));
      renderer.setSize(w, h, false);
      const wide = w / h > 1.35;
      const cellWidth = wide ? w / 2 : w,
        cellHeight = wide ? h : h / 2;
      const imageWidth = Math.floor(Math.min(cellWidth, (cellHeight * 16) / 9));
      const imageHeight = Math.floor((imageWidth * 9) / 16);
      frames = ["porch", "drive"].map((id, i) => ({
        id,
        width: imageWidth,
        height: imageHeight,
        left: Math.floor(
          (cellWidth - imageWidth) / 2 + (wide ? i * cellWidth : 0),
        ),
        top: Math.floor(
          (cellHeight - imageHeight) / 2 + (wide ? 0 : i * cellHeight),
        ),
      }));
      return frames;
    },
    onOrbit(fn) {
      refresh = fn;
    },
    reset,
    draw(p, t, view = "studio", pose = false) {
      const q = motionAt(p, t),
        inStudio = view === "studio";
      rig.apply(p, q);
      staticObjects.visible = ground.visible = grid.visible = !inStudio;
      studio.visible = inStudio;
      trails.forEach((trail, i) => {
        trail.line.visible =
          pose && inStudio && (i === 0 || (t >= offsets[i] && t < q.arrive));
        if (i > 0) echoes[i - 1].mesh.visible = trail.line.visible;
        if (trail.line.visible) {
          const sample = i === 0 ? q : motionAt(p, t - offsets[i]);
          trail.draw(p, sample);
          if (i > 0) echoes[i - 1].draw(p, sample);
        }
      });
      if (orbit && lastView !== view) {
        orbit.enabled = view === "site";
        canvas.style.touchAction = orbit.enabled ? "none" : "pan-y";
        lastView = view;
      }
      const background = inStudio ? "#c9d5c7" : "#596e75";
      scene.background.set(background);
      scene.fog.color.set(background);
      scene.fog.density = inStudio ? 0.065 : 0.021;
      sky.intensity = inStudio ? 1.9 : 1.65;
      sun.intensity = inStudio ? 3.1 : 3.55;
      sun.color.set(inStudio ? "#ffead0" : "#ffe0ae");
      rim.visible = inStudio;
      renderer.setScissorTest(true);
      if (inStudio) {
        portrait.position.set(
          motionPath.x - 2.65,
          1.13 + motionPath.floor,
          q.z - 3.02,
        );
        portrait.lookAt(motionPath.x, 0.89 + motionPath.floor, q.z - 0.07);
        shot(portrait, 0, 0, w, h);
      } else if (view === "pair") {
        // Letterbox each camera to the recorded 16:9 projection at every viewport size.
        renderer.setScissorTest(false);
        renderer.setClearColor("#122221");
        renderer.clear();
        renderer.setScissorTest(true);
        for (const { id, left, top, width, height } of frames) {
          shot(fixed[id], left, top, width, height, 16 / 9);
        }
      } else {
        shot(view === "site" ? site : fixed[view], 0, 0, w, h);
      }
      renderer.setScissorTest(false);
      return q;
    },
    dispose() {
      refresh = () => {};
      orbit?.dispose();
      disposeSiteStage(scene, renderer);
    },
  };
}
