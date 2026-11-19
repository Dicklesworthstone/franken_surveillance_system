import * as T from "three";
export function stereoRays() {
  const group = new T.Group(),
    beams = {};
  for (const [id, color] of Object.entries({
    garden: 0x95fcf2,
    patio: 0xffc262,
  })) {
    const material = new T.MeshBasicMaterial({ color, toneMapped: false });
    const tube = new T.Mesh(
      new T.CylinderGeometry(0.018, 0.018, 1, 10),
      material,
    );
    const lens = new T.Mesh(new T.SphereGeometry(0.1, 16, 12), material);
    group.add(tube, lens);
    beams[id] = { tube, lens };
  }
  const v = (a) => new T.Vector3(...a);
  const marker = new T.Mesh(
    new T.SphereGeometry(0.162, 18, 12),
    new T.MeshBasicMaterial({
      color: 0xf6fff4,
      wireframe: true,
      toneMapped: false,
    }),
  );
  group.add(marker);
  return {
    group,
    update(solution) {
      group.visible = Boolean(solution);
      if (!solution) return;
      for (const { tube, lens } of Object.values(beams))
        tube.visible = lens.visible = false;
      for (const [i, ray] of solution.rays.entries()) {
        const { tube, lens } = beams[ray.id],
          origin = v(ray.origin),
          direction = v(ray.direction);
        const target = solution.ends
          ? v(solution.ends[i])
          : origin.clone().addScaledVector(direction, 8);
        const offset = target.sub(origin);
        lens.position.copy(origin);
        lens.visible = tube.visible = true;
        tube.position.copy(origin).addScaledVector(offset, 0.5);
        tube.scale.y = offset.length();
        tube.quaternion.setFromUnitVectors(
          new T.Vector3(0, 1, 0),
          offset.normalize(),
        );
      }
      marker.visible = solution.status === "fit";
      if (marker.visible) marker.position.copy(v(solution.point));
    },
  };
}
