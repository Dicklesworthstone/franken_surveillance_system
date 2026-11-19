"use client";
import { useEffect, useRef, useState } from "react";
import { motionAt, parcelSize } from "../lib/motion";

function Elevation({ p, time }) {
  const q = motionAt(p, time);
  const project = (v) => [
    200 + v[2] * p.height * 132,
    279 - v[1] * p.height * 132,
  ];
  const chains = q.legs
    .map((l) => [l.hip, l.knee, l.ankle])
    .concat(q.arms.map((a) => [a.shoulder, a.elbow, a.wrist]));
  const head = project([
    0,
    q.hip + 0.418 * Math.cos(q.lean),
    0.418 * Math.sin(q.lean),
  ]);
  const chest = project(q.arms[1].shoulder),
    hip = project(q.legs[1].hip);
  return (
    <svg
      className="motion-elevation"
      viewBox="0 0 400 315"
      role="img"
      aria-label={
        "Side elevation of the articulated courier. Parcel " +
        q.phase.toLowerCase()
      }
    >
      <path d="M22 280 H378" stroke="#6b8175" />
      <line
        x1={hip[0]}
        y1={hip[1]}
        x2={chest[0]}
        y2={chest[1]}
        stroke="#ad573b"
        strokeWidth="24"
        strokeLinecap="round"
      />
      {chains.map((c, i) => (
        <polyline
          key={i}
          points={c.map((v) => project(v).join(",")).join(" ")}
          stroke={["#48545c", "#26373a", "#a05941", "#db8158"][i]}
          strokeWidth={i < 2 ? 11 : 8}
          strokeLinejoin="round"
          strokeLinecap="round"
          fill="none"
        />
      ))}
      <circle cx={head[0]} cy={head[1]} r={p.height * 8} fill="#966d52" />
      <rect
        x={200 + 0.224 * p.height * 132 - 17}
        y={279 - (q.clearance + parcelSize[1]) * 132}
        width="34"
        height={parcelSize[1] * 132}
        fill="#be9860"
      />
    </svg>
  );
}
export function DetectionBoxes({ sample }) {
  return sample?.detections.map((d, i) => {
    const [left, top, right, bottom] = d.bounds_subpixel.map(
      (edge) => edge / 256,
    );
    return (
      <i
        key={i}
        aria-label={d.label + " detection"}
        style={{
          left: (left / 160) * 100 + "%",
          top: (top / 90) * 100 + "%",
          width: ((right - left) / 160) * 100 + "%",
          height: ((bottom - top) / 90) * 100 + "%",
        }}
      />
    );
  });
}
export default function MotionViewport({
  p,
  time,
  view,
  pose,
  onFallback,
  reference,
}) {
  const canvas = useRef(null),
    stage = useRef(null),
    latest = useRef({ p, time, view, pose });
  const [fallback, setFallback] = useState(false),
    [frames, setFrames] = useState([]),
    [ready, setReady] = useState(false);
  useEffect(() => {
    latest.current = { p, time, view, pose };
    stage.current?.draw(p, time, view, pose);
  }, [p, time, view, pose]);
  useEffect(() => {
    let disposed = false,
      observer;
    const el = canvas.current;
    function lost(e) {
      e?.preventDefault?.();
      if (!disposed) {
        setFallback(true);
        onFallback();
      }
    }
    function redraw() {
      const s = latest.current;
      stage.current?.draw(s.p, s.time, s.view, s.pose);
    }
    el.addEventListener("webglcontextlost", lost);
    import("../lib/motion-stage")
      .then(({ createMotionStage }) => {
        if (disposed) return;
        stage.current = createMotionStage(el);
        function resize() {
          setFrames(stage.current.resize(el.clientWidth, el.clientHeight));
          redraw();
        }
        resize();
        stage.current.onOrbit(redraw);
        observer = new ResizeObserver(resize);
        observer.observe(el);
        setReady(true);
      })
      .catch(lost);
    return () => {
      disposed = true;
      observer?.disconnect();
      el.removeEventListener("webglcontextlost", lost);
      stage.current?.dispose();
      stage.current = null;
    };
  }, [onFallback]);
  return (
    <div
      className={"motion-viewport view-" + view}
      data-ready={fallback ? "elevation" : ready ? "webgl" : "loading"}
    >
      <canvas
        ref={canvas}
        style={{ visibility: fallback ? "hidden" : undefined }}
        aria-label={"3D delivery in " + view + " view"}
        onDoubleClick={() => {
          if (view === "site") stage.current?.reset();
        }}
      />
      {!ready && !fallback && (
        <img
          className="motion-poster"
          src="/motion/studio.jpg"
          alt="Courier carrying the reference parcel"
        />
      )}
      {fallback && <Elevation p={p} time={time} />}
      <div className="frame-corner">
        {fallback
          ? "SIDE ELEVATION"
          : view === "studio"
            ? "TRACKING CAMERA"
            : view === "pair"
              ? "SYNCHRONIZED VIEWS"
              : "JUNIPER HOUSE"}
      </div>
      {view === "site" && !fallback && (
        <span className="stage-hint">
          Drag to orbit · double-click to reset
        </span>
      )}
      {view === "pair" &&
        !fallback &&
        frames.map(({ id, ...rect }) => {
          const camera = reference?.views[id],
            segment = time * (reference?.sampleFps ?? 0);
          const sample = camera?.samples.find((f) => f.segment === segment);
          let reading = "simulation";
          if (camera) {
            if (segment >= camera.frames) reading = "end of recording";
            else if (!Number.isInteger(segment))
              reading = "between native samples";
            else if (!sample) reading = "frame not selected";
            else if (sample.status !== "inferred")
              reading = sample.status.replaceAll("_", " ");
            else
              reading = sample.classes.length
                ? "recorded · " + sample.classes.join(", ")
                : "no class returned";
          }
          return (
            <div className="camera-ident" data-view={id} key={id} style={rect}>
              <DetectionBoxes sample={sample} />
              <span>
                {id === "drive" ? "Driveway" : "Porch"} · {reading}
              </span>
            </div>
          );
        })}
      {fallback && (
        <span className="stage-hint">
          WebGL unavailable · live joint diagram
        </span>
      )}
    </div>
  );
}
