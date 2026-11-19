import { Matrix3, Matrix4, PerspectiveCamera, Vector3 } from "three";

export function fixedCamera(spec, aspect) {
  const camera = new PerspectiveCamera(spec.fov, aspect, 0.1, 100);
  camera.position.set(...spec.position);
  camera.lookAt(...spec.target);
  camera.updateMatrixWorld();
  return camera;
}

// Restrict the actual render camera to the y=0 ground plane and invert its
// projection. FSS accepts image pixel coordinates and row-major coefficients.
export function imageToGround(spec, width, height) {
  const camera = fixedCamera(spec, width / height);
  const clip = new Matrix4().multiplyMatrices(
    camera.projectionMatrix,
    camera.matrixWorldInverse,
  ).elements;
  const columns = [0, 8, 12]; // world x, world z, homogeneous constant
  const pixels = new Matrix3().set(
    ...columns.map((i) => ((clip[i] + clip[i + 3]) * width) / 2),
    ...columns.map((i) => ((clip[i + 3] - clip[i + 1]) * height) / 2),
    ...columns.map((i) => clip[i + 3]),
  );
  if (Math.abs(pixels.determinant()) < 1e-10)
    throw Error("Singular ground projection for " + spec.id);
  const inverse = pixels.invert();
  for (const [x, z] of [
    [0, 0],
    [4, 2],
    [-5, 3],
  ]) {
    const point = new Vector3(x, 0, z).project(camera);
    const ground = new Vector3(
      ((point.x + 1) * width) / 2,
      ((1 - point.y) * height) / 2,
      1,
    ).applyMatrix3(inverse);
    if (Math.hypot(ground.x / ground.z - x, ground.y / ground.z - z) > 1e-8)
      throw Error(
        "Ground projection disagrees with the rendered camera " + spec.id,
      );
  }
  return inverse.transpose().toArray();
}
