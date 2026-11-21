// Plan frame: metres, +x east, +y up, +z south toward the street.

/** Where a lens sits and the tangents of its half angles, treating it as rectilinear. */
export function lens(camera) {
  const tanV = Math.tan((camera.vfov * Math.PI) / 360);
  return { origin: camera.position, tanH: tanV * (camera.width / camera.height), tanV };
}

/**
 * One camera's information about a ground position, as a 2x2 matrix.
 *
 * A box in an image fixes the bearing to a person well and the range poorly.
 * `pixel` is the standard deviation of the foot point in normalised image
 * units. Cross-range uncertainty grows linearly with distance; along-range
 * uncertainty grows with distance squared over lens height, which is why a
 * low, distant camera says little about how far away someone is.
 */
export function information(l, ground, pixel = 0.012) {
  const dx = ground[0] - l.origin[0];
  const dz = ground[1] - l.origin[2];
  const flat = Math.hypot(dx, dz);
  const slant = Math.hypot(flat, l.origin[1]);
  const across = pixel * 2 * l.tanH * slant;
  const along = (pixel * 2 * l.tanV * slant * slant) / Math.max(l.origin[1], 0.3);
  // Directly under the lens there is no bearing, so any axis will do.
  const c = flat ? dx / flat : 1;
  const s = flat ? dz / flat : 0;
  const ia = 1 / (along * along);
  const ic = 1 / (across * across);
  // Rotate diag(ia, ic) from the bearing frame into plan axes.
  return [
    ia * c * c + ic * s * s,
    (ia - ic) * c * s,
    ia * s * s + ic * c * c,
  ];
}

/** Sum of information matrices to a one-sigma ellipse: semi-axes and angle. */
export function ellipse(infos) {
  let a = 0;
  let b = 0;
  let d = 0;
  for (const m of infos) {
    a += m[0];
    b += m[1];
    d += m[2];
  }
  const det = a * d - b * b;
  if (det <= 0) return null;
  const cxx = d / det;
  const cxz = -b / det;
  const czz = a / det;
  const mean = (cxx + czz) / 2;
  const diff = Math.hypot((cxx - czz) / 2, cxz);
  return {
    major: Math.sqrt(mean + diff),
    minor: Math.sqrt(Math.max(mean - diff, 0)),
    angle: (0.5 * Math.atan2(2 * cxz, cxx - czz) * 180) / Math.PI,
  };
}
