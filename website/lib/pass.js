// SI units. Court X runs from passer to receiver; Y is measured from the floor.
import { G } from "./motion.js";
export const radius = 0.119,
  release = 0.8,
  clipSeconds = 4,
  frameRate = 24;
export const drag = 0.3;
export const conditions = [
  {
    name: "Bounce pass",
    style: "bounce",
    spacing: 4.2,
    speed: 4.8,
    rebound: 0.82,
    height: 1.8,
  },
  {
    name: "Chest pass",
    style: "chest",
    spacing: 4.2,
    speed: 4.8,
    rebound: 0.82,
    height: 1.8,
  },
  {
    name: "Soft bounce",
    style: "bounce",
    spacing: 4.2,
    speed: 4.8,
    rebound: 0.39,
    height: 1.8,
  },
];
export const parameters = [
  {
    key: "height",
    label: "Passer height",
    unit: "m",
    min: 1.52,
    max: 2.04,
    step: 0.01,
  },
  {
    key: "spacing",
    label: "Player spacing",
    unit: "m",
    min: 3.3,
    max: 5.5,
    step: 0.05,
  },
  {
    key: "speed",
    label: "Horizontal speed",
    unit: "m/s",
    min: 3.2,
    max: 6,
    step: 0.1,
  },
  {
    key: "rebound",
    label: "Floor restitution",
    unit: "",
    min: 0.3,
    max: 0.94,
    step: 0.01,
  },
];
export const samePass = (a, b) =>
  a.style === b.style &&
  parameters.every((c) => Math.abs(a[c.key] - b[c.key]) < 1e-8);
const mix = (a, b, x) => a + (b - a) * x;
export const ease = (n) => {
  const t = Math.max(0, Math.min(1, n));
  return t * t * (3 - 2 * t);
};
export function flight(p) {
  const x0 = -p.spacing / 2 + 0.54,
    catchX = p.spacing / 2 - 0.43,
    y0 = p.height * (p.style === "bounce" ? 0.64 : 0.72);
  const vy = p.style === "bounce" ? -1.5 : 3.15;
  const impactSpeed = Math.sqrt(vy * vy + 2 * G * (y0 - radius));
  const first = (vy + impactSpeed) / G;
  const travel = -Math.log1p((-(catchX - x0) * drag) / p.speed) / drag;
  return { x0, catchX, y0, vy, impactSpeed, first, travel };
}
export function freeBall(p, f, t) {
  let y = f.y0 + f.vy * t - (G * t * t) / 2,
    contacts = 0;
  if (t >= f.first) {
    let remaining = t - f.first,
      up = f.impactSpeed * p.rebound;
    contacts = 1;
    while (up > 0.025 && remaining >= (2 * up) / G) {
      remaining -= (2 * up) / G;
      up *= p.rebound;
      contacts++;
    }
    y =
      radius +
      (up > 0.025
        ? Math.max(0, up * remaining - (G * remaining * remaining) / 2)
        : 0);
  }
  return {
    x: f.x0 - (p.speed * Math.expm1(-drag * t)) / drag,
    y: Math.max(radius, y),
    contacts,
  };
}
export function passAt(p, time) {
  const f = flight(p);
  // Preserve the exact contact selected by a cue across the subtraction of the release time.
  const t =
    time === release + f.travel
      ? f.travel
      : time === release + f.first
        ? f.first
        : Math.max(0, time) - release;
  const crossing = freeBall(p, f, f.travel);
  // Catch envelope is defined by the authored receiver's reach at the catch plane.
  const caught = crossing.y >= 0.57 && crossing.y <= 1.56;
  let ball, phase;
  if (t < 0) {
    const load = ease(time / 0.43),
      extend = ease((time - 0.43) / (release - 0.43));
    ball = {
      x: mix(-p.spacing / 2 + 0.28, f.x0, extend),
      y: mix(p.height * 0.69 - 0.16 * load, f.y0, extend),
      contacts: 0,
    };
    phase = "Preparing";
  } else if (t >= f.travel && caught) {
    const tuck = ease((t - f.travel) / 0.46);
    ball = {
      x: mix(f.catchX, p.spacing / 2 - 0.27, tuck),
      y: mix(crossing.y, 1.13, tuck),
      contacts: crossing.contacts,
    };
    phase = "Caught";
  } else {
    ball = freeBall(p, f, t);
    phase =
      t >= f.travel
        ? "Missed catch"
        : ball.contacts
          ? "After bounce"
          : "In flight";
  }
  return {
    ball,
    phase,
    caught,
    crossing,
    release,
    contact: release + f.first,
    arrival: release + f.travel,
    flight: f,
  };
}
