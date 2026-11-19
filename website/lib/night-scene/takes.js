// Camera and route data belong to the estate plan. Only editorial still times live here.
const posterSeconds = {
  "after-hours": { overview: 5.67, porch: 7, entry: 1.33, driveway: 0.66 },
  delivery: { overview: 4.75, porch: 6.33, entry: 2.25 },
  wildlife: { overview: 4, garden: 1.25, porch: 3.3 },
};

export function registeredTakes(estate) {
  const takes = {};
  for (const [id, still] of Object.entries(posterSeconds)) {
    const incident = estate.incidents.find((item) => item.id === id);
    const subject = incident?.actors[0];
    if (
      !subject ||
      ![subject.height_m, subject.speed_m_per_s, incident.seconds].every(
        (value) => Number.isFinite(value) && value > 0,
      )
    ) {
      throw Error("Missing metric subject or duration for " + id);
    }
    if (
      !incident.cameras.every((camera) =>
        estate.cameras.some((item) => item.id === camera),
      )
    ) {
      throw Error("Unregistered fixed lens for " + id);
    }
    takes[id] = {
      actor: subject.id,
      height: subject.height_m,
      pace: subject.speed_m_per_s,
      braking: incident.motion?.braking_seconds || 0,
      seconds: incident.seconds,
      path: subject.path,
      lenses: incident.cameras,
      still,
    };
  }
  return takes;
}

/** Constant cruising speed followed by a bounded, constant-deceleration arrival. */
export function motionAt(time, speed, length, requestedBraking) {
  const t = Math.max(0, time);
  const brake = Math.min(requestedBraking, (2 * length) / speed);
  const coastUntil = length / speed - brake / 2;
  const stopAt = coastUntil + brake;
  if (t >= stopAt)
    return { distance: length, speed: 0, phase: "standing", stopAt };
  if (t <= coastUntil)
    return { distance: t * speed, speed, phase: "walking", stopAt };
  const elapsed = t - coastUntil;
  return {
    distance:
      coastUntil * speed + speed * elapsed * (1 - elapsed / (2 * brake)),
    speed: speed * (1 - elapsed / brake),
    phase: "slowing",
    stopAt,
  };
}
