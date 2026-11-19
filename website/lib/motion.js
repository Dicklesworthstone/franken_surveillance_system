// Metres, seconds, +Z towards the street. The authored courier faces local +Z,
// or decreasing site Z. Anatomical proportions describe this fictional rig.
export const G = 9.80665;
export const motionPath = {
  x: -1.28,
  startZ: 8.05,
  distance: 3.52,
  floor: 0.105,
};
export const parcelSize = [0.36, 0.22, 0.28];
export const controls = [
  { key: "height", label: "Stature", min: 1.48, max: 2, step: 0.01, unit: "m" },
  {
    key: "pace",
    label: "Walking speed",
    min: 0.7,
    max: 1.7,
    step: 0.05,
    unit: "m/s",
  },
  {
    key: "drop",
    label: "Release height",
    min: 0.18,
    max: 0.8,
    step: 0.01,
    unit: "m",
  },
  {
    key: "bounce",
    label: "Restitution",
    min: 0,
    max: 0.65,
    step: 0.05,
    unit: "",
  },
];
export const presets = [
  {
    name: "Doorstep delivery",
    height: 1.74,
    pace: 1.2,
    drop: 0.48,
    bounce: 0.25,
  },
  {
    name: "Gentle set-down",
    height: 1.62,
    pace: 0.9,
    drop: 0.18,
    bounce: 0.05,
  },
  { name: "Springy parcel", height: 1.88, pace: 1.55, drop: 0.72, bounce: 0.6 },
];
export const duration = 9,
  fps = 24;
const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
const smooth = (x) => {
  const t = clamp(x, 0, 1);
  return t * t * (3 - 2 * t);
};
const mix = (a, b, t) => a + (b - a) * t;

export function milestones(p) {
  const arrive = motionPath.distance / p.pace + 0.4;
  const release = arrive + 0.9,
    fall = Math.sqrt((2 * p.drop) / G);
  return {
    arrive,
    release,
    contact: release + fall,
    settle: release + fall + (2 * fall * p.bounce) / (1 - p.bounce),
  };
}

// Exact free fall followed by a convergent series of vertical rebounds on a level plane.
export function parcelAt(p, t) {
  const m = milestones(p);
  if (t < m.release) return { phase: "Carried", clearance: null, speed: 0 };
  if (t >= m.settle) return { phase: "At rest", clearance: 0, speed: 0 };
  if (t < m.contact) {
    const elapsed = t - m.release;
    return {
      phase: "Falling",
      clearance: Math.max(0, p.drop - (G * elapsed * elapsed) / 2),
      speed: -G * elapsed,
    };
  }
  let elapsed = t - m.contact,
    upward = p.bounce * Math.sqrt(2 * G * p.drop);
  // At double precision the remaining sub-micrometre bounces are indistinguishable.
  while (upward > 1e-7) {
    const flight = (2 * upward) / G;
    if (elapsed < flight)
      return {
        phase: "Rebounding",
        clearance: Math.max(0, elapsed * (upward - (G * elapsed) / 2)),
        speed: upward - G * elapsed,
      };
    elapsed -= flight;
    upward *= p.bounce;
  }
  return { phase: "At rest", clearance: 0, speed: 0 };
}

function footAt(side, distance, stride) {
  const u = distance / stride + (side === 1 ? 0.5 : 0);
  const cycle = u - Math.floor(u),
    swing = clamp((cycle - 0.5) * 2, 0, 1);
  return {
    placed: cycle <= 0.5,
    forward: stride * (0.25 - cycle + smooth(swing)),
    lift: 0.065 * Math.sin(Math.PI * swing) ** 2,
  };
}

// Two-link inverse kinematics in normalized body coordinates, with the pole
// selecting the anatomical direction of knee/elbow flexion.
export function joint(a, b, upper, lower, pole) {
  const delta = b.map((x, i) => x - a[i]),
    span = Math.hypot(...delta);
  const axis = delta.map((x) => x / span),
    dot = pole.reduce((sum, v, i) => sum + v * axis[i], 0);
  const perp = pole.map((v, i) => v - dot * axis[i]),
    norm = Math.hypot(...perp);
  const along = clamp(
    (upper * upper - lower * lower + span * span) / (2 * span),
    -upper,
    upper,
  );
  const rise = Math.sqrt(Math.max(0, upper * upper - along * along));
  return a.map((v, i) => v + along * axis[i] + (rise * perp[i]) / norm);
}

export function motionAt(p, time) {
  const t = clamp(time, 0, duration),
    m = milestones(p),
    ramp = 0.4;
  const advance =
    t < ramp
      ? (p.pace * t * t) / (2 * ramp)
      : t < m.arrive - ramp
        ? p.pace * (t - ramp / 2)
        : motionPath.distance -
          (p.pace * Math.max(0, m.arrive - t) ** 2) / (2 * ramp);
  const naturalStride = 0.57 + (p.pace - 0.7) * 0.13;
  const steps = Math.round(
    (2 * motionPath.distance) / (naturalStride * p.height),
  );
  const stride = (2 * motionPath.distance) / (steps * p.height);
  const d = advance / p.height,
    cycle = (2 * Math.PI * d) / stride;
  const down =
    smooth((t - m.arrive) / 0.78) * (1 - smooth((t - m.release - 0.12) / 0.86));
  const effort = clamp((0.62 - p.drop / p.height) * 1.65, 0.15, 1);
  const lean = 0.065 + down * effort * 0.94;
  const hip = 0.496 - 0.009 * Math.cos(2 * cycle) - down * effort * 0.26;
  const shoulderY = hip + 0.294 * Math.cos(lean),
    shoulderZ = 0.294 * Math.sin(lean);
  const carriedBottom = mix(
    0.532 * p.height + 0.008 * p.height * Math.sin(2 * cycle),
    p.drop,
    smooth((t - m.arrive) / 0.78),
  );
  const releaseGrip = smooth((t - m.release) / 0.43);
  const handsY = carriedBottom / p.height + (parcelSize[1] * 0.5) / p.height;
  const legs = [],
    arms = [];
  for (const side of [-1, 1]) {
    const foot = footAt(side, d, stride);
    const ankle = [side * 0.06, 0.042 + foot.lift, foot.forward];
    const upper = [side * 0.058, hip, -0.015];
    legs.push({
      hip: upper,
      knee: joint(upper, ankle, 0.251, 0.245, [0, 0, 1]),
      ankle,
      placed: foot.placed,
    });
    const shoulder = [side * 0.112, shoulderY, shoulderZ];
    const wrist = [
      side * mix((parcelSize[0] * 0.5) / p.height, 0.139, releaseGrip),
      mix(handsY, hip - 0.013, releaseGrip),
      mix(0.224, 0.034, releaseGrip),
    ];
    arms.push({
      shoulder,
      elbow: joint(shoulder, wrist, 0.176, 0.157, [side * 0.65, -0.3, -1]),
      wrist,
    });
  }
  const drop = parcelAt(p, t),
    z = motionPath.startZ - advance;
  const clearance = drop.clearance ?? carriedBottom;
  return {
    t,
    z,
    advance,
    hip,
    lean,
    legs,
    arms,
    down,
    clearance,
    speed: drop.speed,
    phase: drop.phase === "Carried" && t >= m.arrive ? "Lowering" : drop.phase,
    parcel: [
      motionPath.x,
      motionPath.floor + clearance + parcelSize[1] / 2,
      z - 0.224 * p.height,
    ],
    contactSpeed: Math.sqrt(2 * G * p.drop),
    ...m,
  };
}
