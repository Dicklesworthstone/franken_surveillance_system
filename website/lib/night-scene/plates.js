import * as THREE from "three";

/** Static radiance and dynamic subjects share one calibrated projection and depth buffer. */
export async function loadPlates(configured, resources, strict) {
  const views = new Map();
  let response;
  try {
    response = await fetch("/night-media/plates/index.json");
  } catch (error) {
    if (strict) throw error;
    return views;
  }
  if (response.status === 404) return views;
  if (!response.ok) {
    if (strict) throw Error("Architectural plate manifest unavailable");
    return views;
  }
  const index = await response.json();
  views.practicals = index.practicals || [];
  const loader = new THREE.TextureLoader();
  for (const [name, plate] of Object.entries(index.views)) {
    const optics = configured[name];
    if (
      !optics ||
      optics.eye.distanceTo(new THREE.Vector3(...plate.eye)) > 0.0001 ||
      optics.target.distanceTo(new THREE.Vector3(...plate.target)) > 0.0001 ||
      Math.abs(optics.camera.fov - plate.verticalFovDegrees) > 0.0001
    ) {
      if (strict)
        throw Error("Plate and camera calibration differ for " + name);
      continue;
    }
    try {
      const texture = await loader.loadAsync(plate.url);
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.generateMipmaps = false;
      texture.minFilter = THREE.LinearFilter;
      const swatch = document.createElement("canvas");
      swatch.width = 40;
      swatch.height = 23;
      const context = swatch.getContext("2d", { willReadFrequently: true });
      context.drawImage(texture.image, 0, 0, 40, 23);
      texture.userData.luminance = context.getImageData(0, 0, 40, 23).data;
      resources.push(texture);
      views.set(name, texture);
    } catch (error) {
      if (strict) throw error;
    }
  }
  return views;
}

/** Estimate the local fill from a broad patch of the same short-exposure image. */
export function plateExposure(texture, ndc) {
  const values = texture.userData.luminance;
  const cx = Math.round((ndc.x + 1) * 19.5),
    cy = Math.round((1 - ndc.y) * 11);
  let sum = 0,
    count = 0;
  for (let dy = -1; dy <= 1; dy++)
    for (let dx = -1; dx <= 1; dx++) {
      const x = THREE.MathUtils.clamp(cx + dx, 0, 39),
        y = THREE.MathUtils.clamp(cy + dy, 0, 22);
      const i = 4 * (x + 40 * y);
      sum +=
        (0.2126 * values[i] + 0.7152 * values[i + 1] + 0.0722 * values[i + 2]) /
        255;
      count++;
    }
  return THREE.MathUtils.clamp(0.37 + (1.45 * sum) / count, 0.39, 0.91);
}

export function contactShadow() {
  const material = new THREE.ShadowMaterial({
    opacity: 0.41,
    transparent: true,
    depthWrite: false,
    polygonOffset: true,
    polygonOffsetFactor: -2,
    polygonOffsetUnits: -1,
  });
  material.defines = { ...material.defines, USE_UV: "" };
  material.onBeforeCompile = (shader) => {
    shader.vertexShader =
      "varying vec2 vContactUv;\n" +
      shader.vertexShader.replace(
        "#include <uv_vertex>",
        "#include <uv_vertex>\nvContactUv=uv;",
      );
    shader.fragmentShader =
      "varying vec2 vContactUv;\n" +
      shader.fragmentShader.replace(
        "#include <tonemapping_fragment>",
        "gl_FragColor.a*=1.0-smoothstep(0.24,0.50,distance(vContactUv,vec2(.5)));\n#include <tonemapping_fragment>",
      );
  };
  const sheet = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), material);
  sheet.rotation.x = -Math.PI / 2;
  sheet.receiveShadow = true;
  sheet.visible = false;
  return sheet;
}

// A planted sole obscures some of the diffuse sky even where several lamps cast competing shadows.
export function soleOcclusion() {
  const material = new THREE.ShaderMaterial({
    uniforms: { strength: { value: 0 } },
    transparent: true,
    depthWrite: false,
    polygonOffset: true,
    polygonOffsetFactor: -3,
    vertexShader:
      "varying vec2 p;void main(){p=uv*2.-1.;gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}",
    fragmentShader:
      "varying vec2 p;uniform float strength;void main(){float a=strength*exp(-3.2*dot(p,p))*(1.-smoothstep(.78,1.,length(p)));gl_FragColor=vec4(0.,0.,0.,a);}",
  });
  const mark = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), material);
  mark.rotation.x = -Math.PI / 2;
  mark.renderOrder = 2;
  return mark;
}

/** Reuse the immutable building depth for each calibrated fixed lens. */
export function createDepthCache(renderer, scene, building) {
  const targetByView = new Map();
  const material = new THREE.ShaderMaterial({
    uniforms: { siteDepth: { value: null } },
    depthWrite: true,
    depthTest: true,
    depthFunc: THREE.AlwaysDepth,
    colorWrite: false,
    vertexShader:
      "varying vec2 coord;void main(){coord=uv;gl_Position=vec4(position.xy,0.,1.);}",
    fragmentShader:
      "uniform sampler2D siteDepth;varying vec2 coord;void main(){gl_FragDepth=texture2D(siteDepth,coord).x;gl_FragColor=vec4(0.);}",
  });
  const surface = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), material);
  surface.frustumCulled = false;
  surface.renderOrder = -100;
  surface.visible = false;
  scene.add(surface);
  building.traverse((node) => node.layers.enable(2));
  let rasterSize = "";
  function clear() {
    for (const item of targetByView.values()) item.dispose();
    targetByView.clear();
  }
  return {
    dispose: clear,
    select(id, camera, w, h) {
      surface.visible = Boolean(id);
      building.visible = !id;
      if (!id) return;
      const size = w + "x" + h;
      if (size !== rasterSize) {
        clear();
        rasterSize = size;
      }
      let target = targetByView.get(id);
      if (!target) {
        target = new THREE.WebGLRenderTarget(w, h, { depthBuffer: true });
        target.depthTexture = new THREE.DepthTexture(
          w,
          h,
          THREE.UnsignedIntType,
        );
        targetByView.set(id, target);
        const depthCamera = camera.clone();
        depthCamera.layers.set(2);
        depthCamera.updateMatrixWorld();
        const background = scene.background,
          previous = renderer.getRenderTarget(),
          shadows = renderer.shadowMap.enabled;
        try {
          building.visible = true;
          scene.background = null;
          renderer.shadowMap.enabled = false;
          renderer.setRenderTarget(target);
          renderer.setScissorTest(false);
          renderer.clear();
          renderer.render(scene, depthCamera);
        } finally {
          renderer.setRenderTarget(previous);
          renderer.shadowMap.enabled = shadows;
          scene.background = background;
          building.visible = false;
        }
      }
      material.uniforms.siteDepth.value = target.depthTexture;
    },
  };
}
