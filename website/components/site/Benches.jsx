"use client";
import { Play } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { EVIDENCE, chance as chanceOf } from "../../lib/watch/evidence";
import { ellipse, information } from "../../lib/watch/geometry";
import { lensOf, stamp } from "../../lib/watch/take";
import { Badge, Figure } from "./ui";

/**
 * Moves the console's clock to a moment and brings the console into view. Focus goes with it, so a
 * keyboard user can press Space to play from there rather than staying on a button off screen.
 */
export function SeekLink({ t, clock, children }) {
  return (
    <button
      type="button"
      className="seek"
      onClick={() => {
        window.dispatchEvent(new CustomEvent("fss:seek", { detail: t }));
        const target = document.getElementById("console") ?? document.getElementById("minute");
        target?.scrollIntoView({ block: "start" });
        target?.focus({ preventScroll: true });
      }}
    >
      <span className="data">
        <Play aria-hidden="true" />
        {clock}
      </span>
      <span>{children}</span>
    </button>
  );
}

/** Each camera's own stamp for one instant, and the same instant once aligned. */
export function ClockStrip({ summary, t }) {
  const [aligned, setAligned] = useState(false);
  const offsets = summary.cameras.map((cam) => cam.offset);
  const spread = offsets.length ? Math.max(...offsets) - Math.min(...offsets) : 0;
  const maxAbs = offsets.length ? Math.max(...offsets.map((o) => Math.abs(o))) : 0;
  const span = Math.max(2.5, Math.ceil(maxAbs * 2) / 2);
  return (
    <div className="clocks">
      <div className="clocks__head">
        <div className="switch" role="group" aria-label="Camera clocks">
          <button type="button" aria-pressed={!aligned} onClick={() => setAligned(false)}>
            As stamped
          </button>
          <button type="button" aria-pressed={aligned} onClick={() => setAligned(true)}>
            Aligned
          </button>
        </div>
        <p className="clocks__status" aria-live="polite">
          <b className="num">{(aligned ? 0 : spread).toFixed(1)} s</b> apart
        </p>
      </div>
      <ol className="clocks__rows">
        {summary.cameras.map((cam) => {
          const shown = aligned ? 0 : cam.offset;
          const pos = Math.max(2, Math.min(98, 50 + (shown / span) * 50));
          const stemLeft = Math.min(50, pos);
          const stemWidth = Math.abs(pos - 50);
          return (
            <li key={cam.id}>
              <span className="clocks__name">{cam.name}</span>
              <span className="clocks__axis" aria-hidden="true">
                <b className="clocks__stem" style={{ left: `${stemLeft}%`, width: `${stemWidth}%` }} />
                <i style={{ left: `${pos}%` }} />
              </span>
              <span className="clocks__read">
                <span className="data">{stamp(summary, t, shown, true)}</span>
                <small>
                  {cam.offset === 0
                    ? "on time"
                    : aligned
                      ? `corrected by ${Math.abs(cam.offset).toFixed(1)} s`
                      : `${Math.abs(cam.offset).toFixed(1)} s ${cam.offset > 0 ? "fast" : "slow"}`}
                </small>
              </span>
            </li>
          );
        })}
      </ol>
      <div className="clocks__scale data" aria-hidden="true">
        <span>−{span.toFixed(1)} s</span>
        <span>true time</span>
        <span>+{span.toFixed(1)} s</span>
      </div>
      <p className="clocks__note">
        Staged offsets, written into each film's on-screen clock. Aligning clocks from shared events is planned.
      </p>
    </div>
  );
}

function inside(polygon, x, z) {
  let hit = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, zi] = polygon[i];
    const [xj, zj] = polygon[j];
    if (zi > z !== zj > z && x < ((xj - xi) * (z - zi)) / (zj - zi) + xi) hit = !hit;
  }
  return hit;
}

const BENCH = { x: -30, z: -8, w: 46, h: 54 };
// The coverage shapes are each lens's cone on open ground and pass straight through the
// house, so the person is kept on the grounds in front of it (z = 0 is the front door).
const FRONT = 1;
const compass = (metres, ahead, behind) => `${Math.abs(Math.round(metres))} metres ${metres < 0 ? behind : ahead}`;
const PIN_LABEL = {
  gate: [0, 3.2, "middle"],
  driveway: [-1.8, 0.8, "end"],
  doorbell: [-1.8, -0.4, "end"],
  porch: [1.8, 1.2, "start"],
  entry: [0, 3.2, "middle"],
};
const PRESETS = [
  { id: "overlap", label: "Crossed views", pos: [-5.5, 10], cams: { gate: true, driveway: true, doorbell: true, porch: true, entry: true } },
  { id: "single", label: "One lens only", pos: [-14.5, 22], cams: { gate: false, driveway: true, doorbell: false, porch: false, entry: false } },
  { id: "blind", label: "Uncovered spot", pos: [-26.5, 4], cams: { gate: true, driveway: true, doorbell: true, porch: true, entry: true } },
];

/**
 * Put a person anywhere on the front of the lot and see what the enabled
 * cameras can say about where they are. Computed here from the scene's camera
 * positions and lenses.
 */
export function FusionBench({ summary }) {
  const plan = summary.twin.plan;
  const [a, , c, , e, f] = plan.affine;
  const image = { x: -c / a, y: -f / e, width: 1 / a, height: 1 / e };
  const svg = useRef(null);
  // The plan render is 0.4 MB and an SVG image cannot be lazy, so it is drawn once the bench is close to the viewport.
  const [near, setNear] = useState(false);
  useEffect(() => {
    const watcher = new IntersectionObserver(
      (entries) => entries.some((entry) => entry.isIntersecting) && setNear(true),
      { rootMargin: "700px" },
    );
    watcher.observe(svg.current);
    return () => watcher.disconnect();
  }, []);
  const [at, setAt] = useState([-5.5, 10]);
  const [on, setOn] = useState(() => Object.fromEntries(summary.cameras.map((cam) => [cam.id, true])));
  const drag = useRef(false);
  const tap = useRef(false);
  const move = (event) => {
    const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(svg.current.getScreenCTM().inverse());
    setAt([
      Math.max(BENCH.x + 1, Math.min(BENCH.x + BENCH.w - 1, point.x)),
      Math.max(FRONT, Math.min(BENCH.z + BENCH.h - 1, point.y)),
    ]);
  };
  const seeing = summary.cameras.filter((cam) => on[cam.id] && inside(cam.footprint, at[0], at[1]));
  const bound = useMemo(
    () => (seeing.length ? ellipse(seeing.map((cam) => information(lensOf(cam), at))) : null),
    [seeing.map((cam) => cam.id).join(), at[0], at[1]],
  );
  const names = seeing.map((cam) => cam.name).join(", ");
  let verdict;
  if (!seeing.length)
    verdict = ["not_observable", "No enabled camera covers this ground. The system reports that it cannot see here. It does not report the ground as empty."];
  else if (seeing.length === 1)
    verdict = ["observed", `${names} only. The direction to the person is good, the distance is weak: the bound is ${bound.major.toFixed(1)} m long and ${bound.minor.toFixed(1)} m wide.`];
  else
    verdict = ["corroborated", `${names}. Views from different angles close each other's weak axis: the bound is ${bound.major.toFixed(1)} m by ${bound.minor.toFixed(1)} m.`];
  const nudge = (event) => {
    const step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
    if (!step) return;
    event.preventDefault();
    setAt(([x, z]) => [
      Math.max(BENCH.x + 1, Math.min(BENCH.x + BENCH.w - 1, x + step[0])),
      Math.max(FRONT, Math.min(BENCH.z + BENCH.h - 1, z + step[1])),
    ]);
  };
  const applyPreset = (preset) => {
    setAt(preset.pos);
    setOn(Object.fromEntries(summary.cameras.map((cam) => [cam.id, preset.cams[cam.id] ?? true])));
  };
  return (
    <Figure
      className="fig--flush bench"
      eyebrow="Position bound, one standard deviation"
      title="Put a person anywhere on the front of the lot."
      titleId="bench-title"
      badge={<Badge kind="browser" />}
      note="Computed from this scene's camera positions and lenses. Walls, trees and cars are left out, so the amber fans pass through them."
    >
      <svg
        ref={svg}
        className="bench__plan twin"
        viewBox={`${BENCH.x} ${BENCH.z} ${BENCH.w} ${BENCH.h}`}
        onPointerDown={(event) => {
          // A mouse drags from anywhere. A finger drags only from the person, so that a swipe
          // across the plan still scrolls the page; a tap elsewhere places the person on release.
          const held = event.pointerType !== "touch" || /bench__(grab|handle)/.test(event.target.getAttribute("class") ?? "");
          drag.current = held;
          tap.current = !held;
          if (!held) return;
          event.currentTarget.setPointerCapture(event.pointerId);
          move(event);
        }}
        onPointerMove={(event) => drag.current && move(event)}
        onPointerUp={(event) => {
          if (tap.current) move(event);
          drag.current = tap.current = false;
        }}
        onPointerCancel={() => (drag.current = tap.current = false)}
      >
        {near && <image href={plan.dark} {...image} preserveAspectRatio="none" className="twin__plate" />}
        {summary.cameras.map((cam) => (
          <polygon
            key={cam.id}
            points={cam.footprint.map((p) => p.join(",")).join(" ")}
            className={"twin__cover" + (seeing.includes(cam) ? " is-watching" : "") + (on[cam.id] ? "" : " is-off")}
          />
        ))}
        {seeing.map((cam) => (
          <line key={cam.id} x1={cam.position[0]} y1={cam.position[2]} x2={at[0]} y2={at[1]} className="bench__ray" />
        ))}
        <g style={{ color: "var(--track-a)" }} className={"twin__person" + (bound ? "" : " twin__person--not_observable")}>
          {bound && (
            <ellipse
              rx={Math.max(bound.major, 0.3)}
              ry={Math.max(bound.minor, 0.3)}
              transform={`translate(${at[0]} ${at[1]}) rotate(${bound.angle})`}
              className="twin__bound"
            />
          )}
          {/* A finger-sized target around the dot. A touch that starts here drags the person; elsewhere it scrolls the page. */}
          <circle cx={at[0]} cy={at[1]} r="3.4" className="bench__grab" />
          <circle
            cx={at[0]}
            cy={at[1]}
            r="0.75"
            className="twin__dot bench__handle"
            tabIndex={0}
            role="slider"
            aria-label="Person. Arrow keys move one metre."
            aria-valuemin={BENCH.x + 1}
            aria-valuemax={BENCH.x + BENCH.w - 1}
            aria-valuenow={Math.round(at[0])}
            aria-valuetext={`${compass(at[0], "east", "west")}, ${compass(at[1], "south", "north")} of the front door`}
            onKeyDown={nudge}
          />
        </g>
        {summary.cameras.map((cam) => {
          const [dx, dy, anchor] = PIN_LABEL[cam.id] ?? [0, -1.8, "middle"];
          return (
            <g key={cam.id} className={"bench__pin-group" + (on[cam.id] ? "" : " is-off")}>
              <circle
                cx={cam.position[0]}
                cy={cam.position[2]}
                r="0.8"
                className={"bench__pin" + (on[cam.id] ? "" : " is-off")}
              />
              <text
                x={cam.position[0] + dx}
                y={cam.position[2] + dy}
                textAnchor={anchor}
                className="bench__pin-label"
              >
                {cam.name}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="bench__side">
        <div className="switch bench__presets" role="group" aria-label="Geometry presets">
          {PRESETS.map((preset) => {
            const active =
              Math.hypot(at[0] - preset.pos[0], at[1] - preset.pos[1]) < 0.05 &&
              summary.cameras.every((cam) => Boolean(on[cam.id]) === Boolean(preset.cams[cam.id] ?? true));
            return (
              <button key={preset.id} type="button" aria-pressed={active} onClick={() => applyPreset(preset)}>
                {preset.label}
              </button>
            );
          })}
        </div>
        <fieldset className="bench__cameras">
          <legend className="micro">Cameras</legend>
          {summary.cameras.map((cam) => (
            <label key={cam.id}>
              <input
                type="checkbox"
                checked={on[cam.id]}
                onChange={(event) => setOn({ ...on, [cam.id]: event.target.checked })}
              />
              {cam.name}
            </label>
          ))}
        </fieldset>
        <dl className="bench__metrics" aria-hidden="true">
          <div>
            <dt className="micro">Lenses on them</dt>
            <dd>
              {seeing.length}
              <small> of {summary.cameras.length}</small>
            </dd>
          </div>
          <div>
            <dt className="micro">Position bound</dt>
            <dd>
              {bound ? (
                <>
                  {bound.major.toFixed(1)}
                  <small> × </small>
                  {bound.minor.toFixed(1)}
                  <small> m</small>
                </>
              ) : (
                <small className="bench__none">unbounded</small>
              )}
            </dd>
          </div>
        </dl>
        <p className={"bench__verdict bench__verdict--" + verdict[0]} aria-live="polite">
          <strong className="data">{verdict[0]}</strong>
          {verdict[1]}
        </p>
      </div>
    </Figure>
  );
}

const WEIGHTS = EVIDENCE.filter((item) => !item.late);

/** A conclusion as a sum of weighted evidence that can be taken apart. */
export function BeliefSum() {
  const [off, setOff] = useState({});
  const rows = WEIGHTS.map((w) => ({
    ...w,
    active: !off[w.id] && (w.needs ?? []).every((id) => !off[id]),
    blocked: (w.needs ?? []).some((id) => off[id]),
  }));
  const total = rows.reduce((sum, r) => sum + (r.active ? r.mb : 0), 0);
  const chance = chanceOf(total);
  const scale = 2000;
  return (
    <Figure
      className="belief"
      eyebrow="Weight of evidence, in millibans"
      title="Untick a sighting and the conclusion is worked out again without it."
      titleId="belief-fig"
      badge={<Badge kind="staged">Example weights</Badge>}
      note="These weights are invented for the example. The software adds its own the same way. A thousand millibans multiplies the odds by ten."
    >
      <div className="belief__axis-head data" aria-hidden="true">
        <span>Evidence item</span>
        <span className="belief__axis-marks">
          <span>−2000</span>
          <span>0</span>
          <span>+2000</span>
        </span>
        <span>mB</span>
      </div>
      <ol className="belief__rows">
        {rows.map((r) => (
          <li key={r.id} className={r.active ? "" : "is-off"}>
            <label>
              <input
                type="checkbox"
                checked={r.active}
                disabled={r.fixed || r.blocked}
                onChange={(event) => setOff({ ...off, [r.id]: !event.target.checked })}
              />
              <span>
                {r.label}
                {r.blocked && <small className="belief__hint">Applies only when both cameras are active.</small>}
              </span>
            </label>
            <span className="belief__bar" aria-hidden="true">
              <i
                className={r.mb < 0 ? "is-against" : "is-for"}
                style={{
                  width: `${(Math.abs(r.mb) / scale) * 50}%`,
                  [r.mb < 0 ? "right" : "left"]: "50%",
                }}
              />
            </span>
            <span className="belief__mb data">
              {r.mb > 0 ? "+" : "−"}
              {Math.abs(r.mb)}
            </span>
          </li>
        ))}
      </ol>
      <div className="belief__foot">
        <p className="belief__total" aria-live="polite">
          <strong>{(chance * 100).toFixed(chance > 0.995 || chance < 0.005 ? 1 : 0)}%</strong>
          <span>
            that a stranger is on the property, from a sum of{" "}
            <span className="data">
              {total > 0 ? "+" : total < 0 ? "−" : ""}
              {Math.abs(total)} mB
            </span>
          </span>
        </p>
        <div className="belief__gauge" aria-hidden="true">
          <i style={{ width: `${Math.max(chance * 100, 1)}%` }} />
        </div>
      </div>
    </Figure>
  );
}

const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");

function DiffHash({ value, baseline }) {
  if (!value) return null;
  const shown = value.slice(0, 40);
  const base = baseline.slice(0, 40);
  if (shown === base) return <>{shown}</>;
  return (
    <>
      {[...shown].map((ch, i) => (
        <span key={i} className={ch === base[i] ? "bytes__same" : "bytes__diff"}>
          {ch}
        </span>
      ))}
    </>
  );
}

/** Change one character of a stored object and compare its digest with the one the root names. */
export function ByteCheck({ text }) {
  const [value, setValue] = useState(text);
  const [digests, setDigests] = useState({ root: "", now: "" });
  // Browsers only offer SHA-256 to pages served over HTTPS or from this machine.
  const [able, setAble] = useState(true);
  useEffect(() => {
    if (!globalThis.crypto?.subtle) {
      setAble(false);
      return;
    }
    let live = true;
    const encode = (s) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    Promise.all([encode(text), encode(value)])
      .then(([root, now]) => live && setDigests({ root: hex(root), now: hex(now) }))
      .catch(() => live && setAble(false));
    return () => {
      live = false;
    };
  }, [text, value]);
  const known = digests.root !== "";
  const same = digests.root === digests.now;
  const tamperOneByte = () => {
    const mutated = value.replace(/("at": "\d\d:\d\d:\d\d\.)(\d)(")/, (_, p, d, s) => `${p}${(Number(d) + 1) % 10}${s}`);
    if (mutated !== value) setValue(mutated);
    else setValue(value.replace(/\d/, (d) => String((Number(d) + 1) % 10)));
  };
  if (!able)
    return (
      <Figure className="bytes" title="A stored object and its digest." titleId="bytes-title">
        <p className="soft">
          This browser will not compute SHA-256 for a page loaded over plain HTTP, so the check cannot run here.
        </p>
      </Figure>
    );
  return (
    <Figure
      className={"bytes" + (same ? "" : " is-changed")}
      eyebrow="A stored object"
      title="Change any character and the digest no longer matches the root."
      titleId="bytes-title"
      badge={<Badge kind="browser" />}
    >
      <div className="bytes__head">
        <label className="bytes__label micro" htmlFor="bytes-object">
          The object's bytes
        </label>
        <button type="button" className="bytes__tamper" disabled={!known} onClick={same ? tamperOneByte : () => setValue(text)}>
          {same ? "Flip 1 character" : "Restore original"}
        </button>
      </div>
      <textarea
        id="bytes-object"
        className="data"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        spellCheck="false"
        rows={8}
      />
      <dl>
        <div>
          <dt>The root names</dt>
          <dd className="data">{digests.root.slice(0, 40)}</dd>
        </div>
        <div>
          <dt>These bytes hash to</dt>
          <dd className="data">
            <DiffHash value={digests.now} baseline={digests.root} />
          </dd>
        </div>
      </dl>
      <p className={"bytes__verdict" + (known ? "" : " is-unknown")} aria-live="polite">
        {!known
          ? "Not checked yet. The digest is worked out in this browser."
          : same
            ? "Match. This is the object the root points at."
            : "No match. A reader checking the root would reject this copy."}
      </p>
    </Figure>
  );
}
