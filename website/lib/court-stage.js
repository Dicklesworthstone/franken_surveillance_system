import * as T from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { HDRLoader } from "three/addons/loaders/HDRLoader.js";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { createSceneRenderer } from "./property.js";
import { player } from "./pass-actor.js";
import { basketball, courtyard } from "./court-yard.js";
import { cameraRig } from "./stereo.js";
import { stereoRays } from "./stereo-rays.js";
import { freeBall, passAt } from "./pass.js";

export async function createCourtStage(canvas, interactive = true) {
  const renderer = createSceneRenderer(canvas, interactive),
    scene = new T.Scene();
  const resources = new Set();
  let orbit,
    disposed = false;
  function dispose() {
    if (disposed) return;
    disposed = true;
    orbit?.dispose();
    scene.traverse((n) => {
      if (n.geometry) resources.add(n.geometry);
      if (n.skeleton) resources.add(n.skeleton);
      for (const mat of [].concat(n.material ?? [])) {
        resources.add(mat);
        for (const v of Object.values(mat)) if (v?.isTexture) resources.add(v);
      }
      if (n.shadow?.map) resources.add(n.shadow.map);
    });
    for (const obj of resources) {
      obj.dispose();
      if (obj.isTexture) obj.image?.close?.();
    }
    renderer.dispose();
    renderer.forceContextLoss();
  }
  try {
    const loader = new GLTFLoader();
    const loaded = await Promise.allSettled([
      loader.loadAsync("/court/passer.glb"),
      loader.loadAsync("/court/receiver.glb"),
      new HDRLoader().loadAsync("/court/garden.hdr"),
      new T.TextureLoader().loadAsync("/court/garden.webp"),
    ]);
    for (const r of loaded) {
      if (r.status === "fulfilled") {
        if (r.value.scene) scene.add(r.value.scene);
        else resources.add(r.value);
      }
    }
    for (const r of loaded) if (r.status === "rejected") throw r.reason;
    const [first, second, sky, foliage] = loaded.map((r) => r.value);
    sky.mapping = T.EquirectangularReflectionMapping;
    scene.environment = sky;
    scene.background = sky;
    scene.environmentIntensity = 0.52;
    scene.backgroundIntensity = 0.7;
    scene.backgroundBlurriness = 0.055;
    scene.environmentRotation.y = scene.backgroundRotation.y = 2.1;
    scene.add(courtyard());
    foliage.colorSpace = T.SRGBColorSpace;
    const matte = new T.Mesh(
      new T.PlaneGeometry(34, 11.3),
      new T.MeshBasicMaterial({ map: foliage, toneMapped: false }),
    );
    matte.position.set(0, 5.08, -8.15);
    scene.add(matte);
    renderer.toneMappingExposure = 1.11;
    const ambient = new T.HemisphereLight("#fff3dc", "#b9876c", 0.85);
    scene.add(ambient);
    const sun = new T.DirectionalLight("#fff1d7", 3.15);
    sun.position.set(-5.3, 7, 3.1);
    sun.castShadow = true;
    Object.assign(sun.shadow.camera, {
      left: -8,
      right: 8,
      bottom: -6,
      top: 6,
      near: 0.1,
      far: 26,
    });
    sun.shadow.mapSize.set(2048, 2048);
    sun.shadow.normalBias = 0.013;
    sun.shadow.bias = -0.0003;
    scene.add(sun);
    const people = [player(first, true), player(second, false)];
    scene.add(...people.map((p) => p.group));
    const ball = basketball();
    ball.castShadow = true;
    scene.add(ball);
    const path = new T.InstancedMesh(
      new T.SphereGeometry(0.021, 9, 6),
      new T.MeshBasicMaterial({ color: "#fff1ab" }),
      47,
    );
    path.frustumCulled = false;
    scene.add(path);
    const overview = new T.PerspectiveCamera(33, 1, 0.05, 100);
    const dolly = new T.PerspectiveCamera(34, 1, 0.05, 100);
    const cams=Object.fromEntries(Object.entries(cameraRig).map(([id,c])=>{
      const camera=new T.PerspectiveCamera(c.fov,16/9,.08,100);
      camera.position.set(...c.position);camera.lookAt(...c.target);
      return [id,camera];
    }));
    let sightlines;
    let w = 1,
      h = 1,
      refresh = () => {},
      lastView,
      prevParams,
      traceEnd;
    let frame = { left: 0, top: 0, width: 1, height: 1 };
    const aim = new T.Vector3(0, 1.04, 0);
    const reset = () => {
      const scale = Math.max(1, 1.53 / (w / h));
      if (lastView === "stereo") overview.position.set(.3*scale,5.0*scale,9.4*scale);
      else overview.position.set(1.35 * scale, 1.72 * scale, 6.28 * scale);
      overview.lookAt(aim);
      if (orbit) {
        orbit.target.copy(aim);
        orbit.update();
      }
    };
    if (interactive) {
      orbit = new OrbitControls(overview, canvas);
      orbit.enablePan = false;
      orbit.minDistance = 2;
      orbit.maxDistance = 14;
      orbit.maxPolarAngle = Math.PI * 0.49;
      orbit.addEventListener("change", () => refresh());
    }
    reset();
    const matrix = new T.Matrix4();
    return {
      dispose,
      reset,
      onOrbit(fn) {
        refresh = fn;
      },
      resize(width, height) {
        const old = w / h;
        w = width;
        h = height;
        renderer.setSize(w, h, false);
        overview.aspect = w / h;
        overview.updateProjectionMatrix();
        if (Math.abs(old - w / h) > 0.15) reset();
        const cw = Math.floor(Math.min(w, (h * 16) / 9)),
          ch = Math.floor((cw * 9) / 16);
        frame = {
          width: cw,
          height: ch,
          left: Math.floor((w - cw) / 2),
          top: Math.floor((h - ch) / 2),
        };
        return frame;
      },
      draw(p, t, view = "wide", showPath = true, solution = null) {
        if (solution && !sightlines) {sightlines=stereoRays();scene.add(sightlines.group);}
        sightlines?.update(solution);
        const q = passAt(p, t);
        people.forEach((person) => person.pose(p, q, t));
        ball.position.set(q.ball.x, q.ball.y, 0);
        ball.rotation.z =
          -Math.max(
            0,
            Math.min(t - q.release, q.caught ? q.flight.travel : 4),
          ) *
          p.speed *
          3.1;
        path.visible = showPath && view === "wide";
        if (
          path.visible &&
          (p !== prevParams || traceEnd !== q.flight.travel)
        ) {
          for (let i = 0; i < path.count; i++) {
            const f = freeBall(
              p,
              q.flight,
              (q.flight.travel * i) / (path.count - 1),
            );
            matrix.makeTranslation(f.x, f.y, 0);
            path.setMatrixAt(i, matrix);
          }
          path.instanceMatrix.needsUpdate = true;
          prevParams = p;
          traceEnd = q.flight.travel;
        }
        if (lastView !== view) {
          const previous=lastView;lastView=view;
          if(orbit) {
            orbit.enabled=view==="wide" || view==="stereo";
            canvas.style.touchAction=orbit.enabled?"none":"pan-y";
          }
          if(view==="stereo" || previous==="stereo")reset();
        }
        renderer.setScissorTest(false);
        renderer.setViewport(0, 0, w, h);
        if (view === "wide" || view === "stereo") {
          if(view==="stereo" && !interactive){
            const angle=-.19+t*.105;
            overview.position.set(11.5*Math.sin(angle),5.6,11.5*Math.cos(angle));
            overview.lookAt(0,1,.9);
          }
          renderer.render(scene, overview);
          return;
        }
        if (view === "dolly") {
          dolly.position.set(-2.55 + t * 0.43, 1.42 + t * 0.095, 6.05);
          dolly.lookAt(0, 1.04, 0);
          dolly.aspect = w / h;
          dolly.updateProjectionMatrix();
          renderer.render(scene, dolly);
          return;
        }
        const { width: cw, height: ch, left, top } = frame;
        renderer.setClearColor("#182422");
        renderer.clear();
        renderer.setScissorTest(true);
        renderer.setScissor(left, h - top - ch, cw, ch);
        renderer.setViewport(left, h - top - ch, cw, ch);
        renderer.render(scene, cams[view]);
        renderer.setScissorTest(false);
      },
    };
  } catch (e) {
    dispose();
    throw e;
  }
}
