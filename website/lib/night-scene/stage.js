import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { MeshoptDecoder } from "three/addons/libs/meshopt_decoder.module.js";
import { HDRLoader } from "three/addons/loaders/HDRLoader.js";
import { registeredTakes, motionAt } from "./takes.js";
import {
  loadPlates,
  plateExposure,
  contactShadow,
  soleOcclusion,
  createDepthCache,
} from "./plates.js";
import { makeActor, updateActor } from "./subjects.js";

const vector = (xyz) => new THREE.Vector3(...xyz);
const clamp = THREE.MathUtils.clamp;

async function estateLoadingManager(interactive, recording) {
  const manager = new THREE.LoadingManager();
  if (!interactive || recording || window.innerWidth >= 700) return manager;
  const response = await fetch("/estate/mesh-receipt.json");
  if (response.status === 404) return manager;
  if (!response.ok) throw Error("Estate texture receipt unavailable");
  const { compactTextures } = await response.json();
  if (!compactTextures) return manager;
  const texturePath = /^\/estate\/(?:[A-Za-z0-9_-]+\/)+[A-Za-z0-9_-]+\.webp$/;
  const variants = new Map();
  for (const [full, compact] of Object.entries(compactTextures)) {
    if (
      !texturePath.test(full) ||
      typeof compact !== "string" ||
      !texturePath.test(compact)
    ) {
      throw Error("Invalid estate texture variant");
    }
    variants.set(full, compact);
  }
  manager.setURLModifier((request) => {
    const url = new URL(request, window.location.href);
    return url.origin === window.location.origin && !url.search && !url.hash
      ? variants.get(url.pathname) || request
      : request;
  });
  return manager;
}

/** Canvas coordinates and projection samples use metres, +Y up, and a top-left image origin. */
export async function createNightStage(
  canvas,
  { interactive = true, recording = false, photographic = true } = {},
) {
  // Present the completed picture in one operation. A paused lens must retain
  // every skinned submesh even while the browser composites other DOM layers.
  const presenter =
    interactive &&
    !recording &&
    typeof OffscreenCanvas !== "undefined" &&
    typeof OffscreenCanvas.prototype.transferToImageBitmap === "function"
      ? canvas.getContext("bitmaprenderer", { alpha: false })
      : null;
  const surface = presenter ? new OffscreenCanvas(1, 1) : canvas;
  const renderer = new THREE.WebGLRenderer({
    canvas: surface,
    antialias: true,
    alpha: false,
    preserveDrawingBuffer: true,
    powerPreference: "high-performance",
  });
  renderer.setPixelRatio(
    recording ? 1 : Math.min(1.5, window.devicePixelRatio || 1),
  );
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.1;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFShadowMap;
  const scene = new THREE.Scene();
  const assets = [];
  const resources = [];
  let controls;
  function contextLost() {
    if (presenter)
      canvas.dispatchEvent(new Event("webglcontextlost", { cancelable: true }));
  }
  if (presenter) surface.addEventListener("webglcontextlost", contextLost);
  function dispose() {
    if (presenter) surface.removeEventListener("webglcontextlost", contextLost);
    controls?.dispose();
    const geometries = new Set(),
      materials = new Set(),
      textures = new Set();
    for (const root of [scene, ...assets]) {
      root.traverse((node) => {
        if (node.geometry) geometries.add(node.geometry);
        for (const material of [].concat(node.material || [])) {
          materials.add(material);
          for (const value of Object.values(material))
            if (value?.isTexture) textures.add(value);
        }
        node.shadow?.dispose?.();
        node.skeleton?.dispose?.();
      });
    }
    for (const item of [...geometries, ...materials, ...textures, ...resources])
      item.dispose?.();
    renderer.dispose();
  }
  try {
    const manager = await estateLoadingManager(interactive, recording);
    const loader = new GLTFLoader(manager).setMeshoptDecoder(MeshoptDecoder);
    const metaResponse = await fetch("/estate/estate.json");
    if (!metaResponse.ok) throw Error("Estate calibration unavailable");
    const estate = await metaResponse.json();
    const nightCases = registeredTakes(estate);
    const [building, ...bodies] = await Promise.all(
      [
        "/estate/estate.glb",
        ...Object.values(nightCases).map(
          ({ actor }) => "/night-media/actors/" + actor + ".glb",
        ),
      ].map(async (path) => {
        const result = await loader.loadAsync(path);
        assets.push(result.scene);
        return result;
      }),
    );
    scene.add(building.scene);
    const rig = Object.fromEntries(
      estate.cameras.map((camera) => [camera.id, camera]),
    );
    const views = [
      "overview",
      ...Object.keys(rig).filter((id) => id !== "overview"),
    ];
    const configured = Object.fromEntries(
      views.map((id) => {
        const settings =
          id === "overview" ? rig.overview || estate.overview : rig[id];
        const eye = settings.position,
          target = settings.look_at || settings.target;
        const camera = new THREE.PerspectiveCamera(
          settings.vfov || settings.verticalFovDegrees,
          16 / 9,
          0.07,
          260,
        );
        camera.position.copy(vector(eye));
        camera.lookAt(vector(target));
        camera.updateMatrixWorld();
        return [id, { camera, target: vector(target), eye: vector(eye) }];
      }),
    );
    const bounds = new THREE.Box3().setFromObject(building.scene);
    const sceneCentre = bounds.getCenter(new THREE.Vector3());
    scene.background = new THREE.Color(0x273847);
    scene.fog = new THREE.FogExp2(0x344352, 0.006);
    const orbit = configured.overview;
    if (interactive) {
      controls = new OrbitControls(orbit.camera, canvas);
      controls.target.copy(orbit.target);
      controls.minDistance = 3;
      controls.maxDistance = 78;
      controls.maxPolarAngle = Math.PI * 0.487;
      controls.enableDamping = false;
      controls.update();
    }
    const sky = await new HDRLoader()
      .setDataType(THREE.FloatType)
      .loadAsync("/night-media/night-sky.hdr");
    // The source panorama is a long exposure. Restore blue-hour radiance for a short security-camera exposure.
    const skyData = sky.image.data;
    for (let i = 0; i < skyData.length; i += 4) {
      skyData[i] *= 0.24;
      skyData[i + 1] *= 0.49;
      skyData[i + 2] *= 0.87;
    }
    sky.mapping = THREE.EquirectangularReflectionMapping;
    resources.push(sky);
    scene.background = sky;
    scene.backgroundIntensity = 0.13;
    scene.backgroundRotation.y = 0.82;
    scene.environment = sky;
    scene.environmentIntensity = 0.36;
    scene.environmentRotation.y = 0.82;
    const fill = new THREE.HemisphereLight(0xb6d5ff, 0x777970, 0.58);
    scene.add(fill);
    const moon = new THREE.DirectionalLight(0xc1d5ff, 0.92);
    moon.position.set(-32, 42, 22);
    moon.target.position.set(sceneCentre.x, 0, sceneCentre.z);
    moon.castShadow = true;
    moon.shadow.mapSize.set(2048, 2048);
    Object.assign(moon.shadow.camera, {
      near: 0.5,
      far: 125,
      left: -36,
      right: 36,
      top: 36,
      bottom: -36,
    });
    moon.shadow.normalBias = 0.028;
    moon.shadow.bias = -0.00025;
    scene.add(moon, moon.target);
    const staticMaterials = new Set();
    const housings = new Map();
    building.scene.traverse((node) => {
      node.renderOrder = -20;
      if (node.name.startsWith("device_"))
        housings.set(node.name.slice(7).replace(/_placement$/, ""), node);
      if (node.isMesh) {
        node.receiveShadow = true;
        node.castShadow = true;
        for (const material of [].concat(node.material))
          staticMaterials.add(material);
      }
      if (node.isLight && node.intensity > 0) node.castShadow = false;
    });
    const plates = photographic
      ? await loadPlates(configured, resources, recording)
      : new Map();
    const lamps = [];
    for (const fixture of plates.practicals || []) {
      const practical = new THREE.PointLight(
        new THREE.Color(...fixture.colour),
        fixture.power * 0.9,
        11,
        2,
      );
      practical.position.fromArray(fixture.position);
      practical.shadow.mapSize.set(256, 256);
      practical.shadow.camera.near = 0.06;
      practical.shadow.camera.far = practical.distance;
      practical.shadow.bias = -0.001;
      scene.add(practical);
      lamps.push(practical);
    }
    const shadow = contactShadow();
    scene.add(shadow);
    const pads = Array.from({ length: 4 }, () => soleOcclusion());
    scene.add(...pads);
    const depthCache = createDepthCache(renderer, scene, building.scene);
    resources.push(depthCache);
    let activePlate = null;
    const cases = Object.keys(nightCases);
    const actors = Object.fromEntries(
      bodies.map((asset, i) => {
        const actor = makeActor(asset, nightCases[cases[i]].actor);
        scene.add(actor.root);
        return [cases[i], actor];
      }),
    );
    await renderer.compileAsync(scene, orbit.camera);
    const paths = Object.fromEntries(
      cases.map((id) => {
        const route = nightCases[id].path;
        const points = (route.points || route).map((p) =>
          Array.isArray(p) ? vector(p) : vecPoint(p),
        );
        function vecPoint(p) {
          return new THREE.Vector3(p.x, p.y ?? 0.055, p.z);
        }
        return [id, new THREE.CatmullRomCurve3(points, false, "centripetal")];
      }),
    );
    const pixel = new THREE.Vector3();
    const fencePixel = new Uint8Array(4);
    const toArray = (v) => v.toArray().map((n) => Number(n.toFixed(5)));
    let width = 1,
      height = 1,
      changed = () => {},
      previousView,
      previousCase;
    controls?.addEventListener("change", () => changed());
    return {
      cameras: views,
      dispose,
      onChange(listener) {
        changed = listener || (() => {});
      },
      resize(w, h) {
        width = Math.max(1, Math.round(w));
        height = Math.max(1, Math.round(h));
        renderer.setSize(width, height, false);
        if (presenter) {
          canvas.width = surface.width;
          canvas.height = surface.height;
        }
        orbit.camera.aspect = width / height;
        orbit.camera.updateProjectionMatrix();
      },
      reset() {
        orbit.camera.position.copy(orbit.eye);
        if (controls) {
          controls.target.copy(orbit.target);
          controls.update();
        } else orbit.camera.lookAt(orbit.target);
      },
      draw(id, time = 0, view = "overview", params = {}) {
        const take = nightCases[id],
          path = paths[id],
          actor = actors[id],
          optics = configured[view];
        if (!actor || !optics) throw Error("Unknown estate take or camera");
        for (const [key, subject] of Object.entries(actors))
          subject.root.visible = key === id;
        const speed = clamp(params.speed ?? 1, 0.5, 1.7);
        const subjectHeight = clamp(
          params.height ?? take.height,
          take.actor === "raccoon" ? 0.19 : 1.4,
          take.actor === "raccoon" ? 0.5 : 2.2,
        );
        const length = path.getLength();
        const motion = motionAt(time, take.pace * speed, length, take.braking);
        const distance = motion.distance;
        const u = distance / length;
        const foot = path.getPointAt(u),
          forward = path.getTangentAt(u);
        updateActor(
          actor,
          take.actor,
          foot,
          forward,
          distance,
          time,
          subjectHeight,
          motion.speed / (take.pace * speed),
        );
        if (controls) controls.enabled = view === "overview";
        for (const [cameraId, housing] of housings)
          housing.visible = cameraId !== view;
        const orbitAtPlate =
          !controls ||
          (optics.camera.position.distanceTo(optics.eye) < 0.0001 &&
            controls.target.distanceTo(optics.target) < 0.0001);
        const plate =
          view !== "overview" || orbitAtPlate ? plates.get(view) : null;
        // The dominant measured fixture casts the local moving shadow on the walk.
        let nearest,
          greatest = 0;
        for (const lamp of lamps) {
          const distanceSq = lamp.position.distanceToSquared(foot);
          const light = lamp.intensity / Math.max(0.09, distanceSq);
          if (distanceSq < lamp.distance ** 2 && light > greatest) {
            greatest = light;
            nearest = lamp;
          }
        }
        for (const lamp of lamps)
          lamp.castShadow = Boolean(plate) && lamp === nearest;
        // The original geometry supplies foreground depth over its own path-traced photograph.
        if (plate !== activePlate) {
          for (const material of staticMaterials) material.colorWrite = !plate;
          scene.background = plate || sky;
          scene.backgroundIntensity = plate ? 1 : 0.13;
          fill.intensity = plate ? 0.31 : 0.58;
          moon.intensity = plate ? 0.56 : 0.92;
          activePlate = plate;
        }
        renderer.toneMappingExposure = plate
          ? plateExposure(plate, pixel.copy(foot).project(optics.camera))
          : 1.1;
        shadow.visible = Boolean(plate);
        shadow.position.copy(foot);
        shadow.position.y += 0.007;
        const shadowSize = take.actor === "raccoon" ? 1.65 : 3.55;
        shadow.scale.set(shadowSize, shadowSize, 1);
        const quadruped = take.actor === "raccoon";
        const toes = actor.contacts.filter(([bone]) =>
          quadruped ? /middle_01/i.test(bone.name) : /Toe0/.test(bone.name),
        );
        pads.forEach((pad, i) => {
          pad.visible = Boolean(toes[i]);
          if (!toes[i]) return;
          const [bone, sole] = toes[i];
          bone.getWorldPosition(pad.position);
          const lift = Math.max(0, pad.position.y - sole - foot.y);
          pad.material.uniforms.strength.value = 0.42 * Math.exp(-12 * lift);
          pad.position.y = foot.y + 0.013;
          pad.scale.set(quadruped ? 0.115 : 0.25, quadruped ? 0.16 : 0.36, 1);
          pad.rotation.z = -actor.root.rotation.y;
        });
        const nativeAspect = 16 / 9;
        const nativeView = view !== "overview" || Boolean(plate);
        if (view === "overview") {
          optics.camera.aspect = nativeView ? nativeAspect : width / height;
          optics.camera.updateProjectionMatrix();
        }
        const pictureWidth = nativeView
          ? Math.min(width, Math.round(height * nativeAspect))
          : width;
        const pictureHeight = nativeView
          ? Math.min(height, Math.round(width / nativeAspect))
          : height;
        depthCache.select(
          plate ? view : null,
          optics.camera,
          pictureWidth,
          pictureHeight,
        );
        const left = Math.floor((width - pictureWidth) / 2),
          bottom = Math.floor((height - pictureHeight) / 2);
        renderer.setScissorTest(false);
        renderer.setViewport(0, 0, width, height);
        renderer.setClearColor(0x0c1012);
        renderer.clear();
        renderer.setViewport(left, bottom, pictureWidth, pictureHeight);
        renderer.setScissor(left, bottom, pictureWidth, pictureHeight);
        renderer.setScissorTest(true);
        // Resolve a newly selected shadow camera and the actor's skin texture before preserving its first frame.
        const changedLens = previousView !== view || previousCase !== id;
        if (changedLens) renderer.render(scene, optics.camera);
        renderer.render(scene, optics.camera);
        if (interactive && changedLens && !presenter) {
          // A paused canvas can present immediately after changing its shader/texture set.
          // Fence the first fully drawn frame; subsequent animation frames stay asynchronous.
          const gl = renderer.getContext();
          gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, fencePixel);
        }
        if (presenter)
          presenter.transferFromImageBitmap(surface.transferToImageBitmap());
        previousView = view;
        previousCase = id;
        pixel.copy(foot).project(optics.camera);
        return {
          eye: toArray(optics.camera.position),
          target: toArray(
            view === "overview" && controls ? controls.target : optics.target,
          ),
          verticalFovDegrees: optics.camera.fov,
          aspect: optics.camera.aspect,
          subjectFoot: toArray(foot),
          movementPhase: motion.phase,
          speedMps: Number(motion.speed.toFixed(5)),
          distanceM: Number(distance.toFixed(5)),
          stopAtSeconds: Number(motion.stopAt.toFixed(5)),
          subjectPixel: [
            +(left + ((pixel.x + 1) * pictureWidth) / 2).toFixed(3),
            +(
              height -
              bottom -
              pictureHeight +
              ((1 - pixel.y) * pictureHeight) / 2
            ).toFixed(3),
          ],
        };
      },
    };
  } catch (error) {
    dispose();
    throw error;
  }
}
