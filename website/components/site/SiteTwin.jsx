"use client";
import { estimate, lightsOn, seenBy, trail } from "../../lib/watch/take";

// The part of the lot the take happens on, in plan metres: x east, z south.
const LOT = { x: -31, z: -33, w: 48, h: 80 };
// Where each camera's name sits relative to its pin, in metres, so neighbours do not collide.
const NAME = {
  gate: [0, 2.4, "middle"],
  driveway: [-1.4, 0.5, "end"],
  doorbell: [-1.3, 0.6, "end"],
  porch: [1.3, 0.6, "start"],
  entry: [0, 2.5, "middle"],
};
const HEAD = 1.75;
// The gate opening in the street wall, from the site plan. The backdrops are rendered with it open.
const GATE = { x: -12, z: 38, opening: 4.6 };

const points = (list) => list.map((p) => p[0].toFixed(2) + "," + p[1].toFixed(2)).join(" ");

/** Splits a trail into the stretches where the person was actually seen. */
function runs(list) {
  const out = [];
  let run = [];
  for (const p of list) {
    if (p) run.push(p);
    else if (run.length) {
      out.push(run);
      run = [];
    }
  }
  if (run.length) out.push(run);
  return out.filter((r) => r.length > 1);
}

/**
 * One backdrop and the mapping from plan metres onto it. The picture is 100
 * units wide. Shapes that lie on the ground are drawn in metres inside a group
 * carrying `ground`; pins, heads and labels are placed with `at`, which also
 * lifts a point by its height where the view is tilted.
 */
function projection(view) {
  const [a, b, c, d, e, f] = view.affine;
  const tall = (100 * view.height) / view.width;
  const [hu, hv] = view.per_metre_height ?? [0, 0];
  return {
    tall,
    // Drawing units covered by one metre along x.
    metre: Math.hypot(100 * a, tall * d),
    tilted: Math.abs(hv) > 1e-6,
    ground: `matrix(${100 * a} ${tall * d} ${100 * b} ${tall * e} ${100 * c} ${tall * f})`,
    at: (x, z, height = 0) => [100 * (a * x + b * z + c + hu * height), tall * (d * x + e * z + f + hv * height)],
  };
}

/**
 * The site with what the cameras jointly support drawn on it. Both backdrops
 * are path-traced renders of the same model the films were shot in: `model`
 * looks down from the street side at 55 degrees, `plan` looks straight down.
 */
export default function SiteTwin({ summary, take, frame, selected, onSelect, mode = "plan", backdrop = true }) {
  const view = (mode === "model" && summary.twin.front) || summary.twin.plan;
  const p = projection(view);
  const t = frame / summary.fps;
  const lit = lightsOn(summary, t);
  const shut = summary.effects.some((effect) => effect.kind === "gate_closed" && t >= effect.t);
  const people = take
    ? summary.actors.map((actor) => ({ actor, at: estimate(take, actor.id, frame), path: runs(trail(take, actor.id, frame)) }))
    : [];
  const watching = new Set(take ? summary.actors.flatMap((actor) => seenBy(take, actor.id, frame)) : []);
  // The plan covers the whole lot, so it is cropped to the part in use. The tilted view is rendered already framed.
  const [x0, y0] = p.at(LOT.x, LOT.z);
  const [x1, y1] = p.at(LOT.x + LOT.w, LOT.z + LOT.h);
  const box = p.tilted ? `0 0 100 ${p.tall}` : `${x0} ${y0} ${x1 - x0} ${y1 - y0}`;
  const m = p.metre;
  return (
    <svg
      className={"twin" + (p.tilted ? " twin--model" : "")}
      viewBox={box}
      preserveAspectRatio="xMidYMax slice"
      role="img"
      aria-label={
        p.tilted
          ? "Model of the property seen from the street side, with camera coverage and the tracked people"
          : "Plan of the property with camera coverage and the tracked people"
      }
      style={{ "--m": m }}
    >
      {/* A view's two renders weigh 0.5 to 0.8 MB and an SVG image cannot be lazy, so they are
          only drawn once `backdrop` says the picture is close to the viewport. */}
      {backdrop && (
        <>
          <image href={view.dark} width="100" height={p.tall} preserveAspectRatio="none" className="twin__plate" />
          <image
            href={view.lit}
            width="100"
            height={p.tall}
            preserveAspectRatio="none"
            className={"twin__plate twin__plate--lit" + (lit ? " is-on" : "")}
          />
        </>
      )}
      <g transform={p.ground}>
        {shut && (
          <line
            x1={GATE.x - GATE.opening / 2}
            y1={GATE.z}
            x2={GATE.x + GATE.opening / 2}
            y2={GATE.z}
            className="twin__gate"
          />
        )}
        {summary.cameras.map((cam) => (
          <polygon
            key={cam.id}
            points={points(cam.footprint)}
            className={
              "twin__cover" + (watching.has(cam.id) ? " is-watching" : "") + (cam.id === selected ? " is-selected" : "")
            }
          />
        ))}
        {people.map(
          ({ actor, at, path }) =>
            at && (
              <g key={actor.id} style={{ color: actor.colour }} className={"twin__person twin__person--" + at.state}>
                {path.map((run, i) => (
                  <polyline key={i} points={points(run)} className="twin__trail" />
                ))}
                {at.ellipse && (
                  <ellipse
                    rx={Math.max(at.ellipse.major, 0.35)}
                    ry={Math.max(at.ellipse.minor, 0.35)}
                    transform={`translate(${at.x} ${at.z}) rotate(${at.ellipse.angle})`}
                    className="twin__bound"
                  />
                )}
              </g>
            ),
        )}
      </g>
      {summary.cameras.map((cam) => {
        const [gx, gy] = p.at(cam.position[0], cam.position[2]);
        const [cx, cy] = p.at(cam.position[0], cam.position[2], cam.position[1]);
        const [dx, dy, anchor] = NAME[cam.id] ?? [0, -1.3, "middle"];
        return (
          <g
            key={cam.id}
            className={"twin__camera" + (cam.id === selected ? " is-selected" : "")}
            onClick={onSelect ? () => onSelect(cam.id) : undefined}
          >
            {p.tilted && <line x1={gx} y1={gy} x2={cx} y2={cy} className="twin__mast" />}
            <circle cx={cx} cy={cy} r={0.8 * m} />
            <text x={cx + dx * m} y={cy + dy * m} textAnchor={anchor}>
              {cam.name}
            </text>
          </g>
        );
      })}
      {people.map(({ actor, at }) => {
        if (!at) return null;
        const [gx, gy] = p.at(at.x, at.z);
        const [hx, hy] = p.at(at.x, at.z, p.tilted && at.state !== "closed" ? HEAD : 0);
        return (
          <g key={actor.id} style={{ color: actor.colour }} className={"twin__person twin__person--" + at.state}>
            {p.tilted && <line x1={gx} y1={gy} x2={hx} y2={hy} className="twin__stand" />}
            <circle cx={hx} cy={hy} r={0.62 * m} className="twin__dot" />
            <text x={hx + 1.1 * m} y={hy - 0.9 * m} className="twin__tag">
              {actor.track}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
