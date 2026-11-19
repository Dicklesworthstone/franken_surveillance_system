"use client";
import { useState, useMemo } from "react";
import { RotateCcw, Crosshair } from "lucide-react";
import CourtViewport from "./CourtViewport";
import { conditions, frameRate } from "../lib/pass";
import {
  cameraRig,
  imageSize,
  moments,
  reconstruct,
  referenceFrame,
} from "../lib/stereo";

const labels = { garden: "Garden", patio: "Patio" };
const words = {
  fit: "Two marks agree",
  disagrees: "Marks disagree",
  behind: "Behind a camera",
  weak: "Depth unresolved",
  waiting: "A second view is needed",
};
const noWebGL = () => {};
function MapView({ solution }) {
  const xy = (p) => [170 + 27 * p[0], 28 + 26 * p[2]];
  return (
    <svg
      viewBox="0 0 340 160"
      aria-label="Top-down view of camera rays"
      role="img"
    >
      {solution.rays.map((ray, i) => {
        const [x, y] = xy(ray.origin),
          [x2, y2] = xy(
            solution.ends?.[i] ||
              ray.origin.map((v, j) => v + 8 * ray.direction[j]),
          );
        return (
          <g key={ray.id}>
            <line
              x1={x}
              y1={y}
              x2={x2}
              y2={y2}
              stroke={i ? "#bb7336" : "#4d8781"}
              strokeWidth="3"
            />
            <circle cx={x} cy={y} r="5" fill="currentColor" />
          </g>
        );
      })}
    </svg>
  );
}
function CameraFrame({ id, frame, point, mark }) {
  const limit = (v, i) => Math.min(imageSize[i] - 0.5, Math.max(0.5, v));
  function key(e) {
    const offsets = {
      ArrowUp: [0, -1],
      ArrowDown: [0, 1],
      ArrowLeft: [-1, 0],
      ArrowRight: [1, 0],
    };
    const anchor = point || imageSize.map((v) => v / 2);
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      mark(anchor);
      return;
    }
    if (!offsets[e.key]) return;
    e.preventDefault();
    mark(
      anchor.map((v, i) =>
        limit(v + offsets[e.key][i] * (e.shiftKey ? 10 : 1), i),
      ),
    );
  }
  return (
    <article className={"stereo-frame frame-" + id}>
      <div className="stereo-frame-head">
        <b>{labels[id]} camera</b>
        <span>
          {point
            ? point.map((n) => Math.round(n)).join(", ") + " px"
            : "Unmarked"}
        </span>
      </div>
      <button
        className="stereo-image"
        aria-label={"Mark ball in " + labels[id] + " frame"}
        onKeyDown={key}
        onClick={(e) => {
          if (e.detail === 0) {
            if (!point) mark(imageSize.map((v) => v / 2));
            return;
          }
          const r = e.currentTarget.getBoundingClientRect();
          mark(
            [
              ((e.clientX - r.left) * imageSize[0]) / r.width,
              ((e.clientY - r.top) * imageSize[1]) / r.height,
            ].map(limit),
          );
        }}
      >
        <img
          src={"/stereo/" + id + "-" + frame + ".png"}
          width="896"
          height="504"
          alt={labels[id] + " view of the pass"}
          draggable="false"
        />
        {point && (
          <i
            aria-hidden="true"
            style={{
              left: (point[0] / imageSize[0]) * 100 + "%",
              top: (point[1] / imageSize[1]) * 100 + "%",
            }}
          >
            <Crosshair size={30} />
          </i>
        )}
      </button>
      <button className="unmark" disabled={!point} onClick={() => mark(null)}>
        Clear {labels[id].toLowerCase()} mark
      </button>
    </article>
  );
}
export default function StereoBench({ native }) {
  const [frame, setFrame] = useState(moments[0].frame),
    [custom, setCustom] = useState(null),
    [reset, setReset] = useState(0);
  const reference = useMemo(() => referenceFrame(frame), [frame]);
  const marks = custom ?? reference.marks;
  const solution = useMemo(() => reconstruct(marks), [marks]);
  const time = frame / frameRate,
    report = native[frame];
  const markerCount = solution.rays.length;
  return (
    <article className="stereo-bench">
      <div className="stereo-heading">
        <div>
          <span className="court-kicker">Juniper Court / Stereo bench</span>
          <h2>
            Two rays. <em>One ball.</em>
          </h2>
        </div>
        <p>
          Mark the ball in both cameras. Orbit the court to see where the two
          lines of sight meet.
        </p>
      </div>
      <div
        className="stereo-moments"
        role="group"
        aria-label="Recorded instant"
      >
        {moments.map((m) => (
          <button
            aria-pressed={frame === m.frame}
            key={m.frame}
            onClick={() => {
              setFrame(m.frame);
              setCustom(null);
            }}
          >
            {m.label} <small>{(m.frame / frameRate).toFixed(2)} s</small>
          </button>
        ))}
      </div>
      <div className="stereo-work">
        <div className="stereo-survey">
          <CourtViewport
            p={conditions[0]}
            time={time}
            view="stereo"
            trace={false}
            reset={reset}
            onUnavailable={noWebGL}
            solution={solution}
            fallbackContent={<MapView solution={solution} />}
          />
          <div className="stereo-toolbar">
            <span>
              <i /> Garden sightline
            </span>
            <span>
              <i /> Patio sightline
            </span>
            <button
              onClick={() => setReset((v) => v + 1)}
              aria-label="Reset stereo orbit"
            >
              <RotateCcw size={16} />
            </button>
          </div>
        </div>
        <section className="stereo-result" aria-live="polite">
          <span className="court-kicker">
            {custom ? "Your marks" : "Reference marks"}
          </span>
          <h3 data-stereo-state={solution.status}>{words[solution.status]}</h3>
          <dl>
            <div>
              <dt>Estimated height</dt>
              <dd>
                {solution.status === "fit"
                  ? Math.round(solution.point[1] * 100) + " cm"
                  : "Unresolved"}
              </dd>
            </div>
            <div>
              <dt>Ray separation</dt>
              <dd>
                {solution.miss !== undefined
                  ? (solution.miss * 100).toFixed(1) + " cm"
                  : "—"}
              </dd>
            </div>
            <div>
              <dt>Source frames marked</dt>
              <dd>{markerCount} / 2</dd>
            </div>
          </dl>
          <button onClick={() => setCustom(null)} disabled={!custom}>
            Restore reference marks
          </button>
        </section>
      </div>
      <div className="stereo-frames">
        {Object.keys(cameraRig).map((id) => (
          <CameraFrame
            key={id}
            id={id}
            frame={frame}
            point={marks[id]}
            mark={(point) => setCustom({ ...marks, [id]: point })}
          />
        ))}
      </div>
      <p className="stereo-help">
        Click a frame to place its mark. Arrow keys move one pixel. Hold Shift
        to move ten.
      </p>
      <div className="stereo-proof">
        <div>
          <span className="court-kicker">
            Native reference / fss-scene-fuse
          </span>
          <h3>Where Rust places the ball</h3>
          <p>
            For the two authored center marks, the native solver estimates{" "}
            <strong>{(report.height * 100).toFixed(1)} cm</strong> above the
            scene origin. Both frames share one simulation clock. Moving a mark
            runs a browser geometry exercise.
          </p>
        </div>
        <div>
          <a href={"/stereo/report-" + frame + ".json"}>
            Read the native result ↗
          </a>
          <a href={"/stereo/query-" + frame + ".json"}>
            Inspect the two observations ↗
          </a>
          <a href="/stereo/sightlines.mp4">Watch the sightline film ↗</a>
        </div>
      </div>
      <details className="court-notes">
        <summary>How to interpret a match</summary>
        <p>
          The browser finds the midpoint between the two closest points on the
          forward camera rays. A pair agrees when both reprojections fall within
          four pixels of your marks. A single mark leaves depth unresolved. The
          Rust reports use the projected ball centers and a floor-only twin with
          nominal camera poses. These synthetic correspondences were supplied to
          the solver. They are independent of the person detector in the
          courtyard exhibit.
        </p>
        <div>
          <a href="/stereo/rig.json">Camera rig ↗</a>
          <a href="/stereo/capture.json">Source frames ↗</a>
          <a href="/exhibits/courtyard/">Compare detector frames ↗</a>
        </div>
      </details>
    </article>
  );
}
