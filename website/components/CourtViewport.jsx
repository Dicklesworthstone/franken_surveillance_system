"use client";
import { useEffect, useRef, useState } from "react";
import { freeBall, passAt } from "../lib/pass";
import { DetectionBoxes } from "./MotionViewport";
export function FlightDiagram({ p, time, large = false }) {
  const q = passAt(p, time),
    width = 408,
    height = large ? 145 : 104;
  const min = -p.spacing / 2 - 0.3,
    scale = width / (p.spacing + 0.6);
  const x = (v) => (v - min) * scale,
    y = (v) => height - 11 - (v * (height - 18)) / 2.05;
  const positions = Array.from({ length: 101 }, (_, i) =>
    freeBall(p, q.flight, (q.flight.travel * i) / 100),
  );
  return (
    <svg
      className="flight-diagram"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Modelled ball flight from release to the receiver"
    >
      {[0, 0.5, 1, 1.5].map((h) => (
        <line
          key={h}
          x1="0"
          x2={width}
          y1={y(h)}
          y2={y(h)}
          stroke="currentColor"
          opacity={h === 0 ? 0.5 : 0.12}
        />
      ))}
      <path
        d={positions
          .map(
            (v, i) =>
              (i ? "L" : "M") + x(v.x).toFixed(2) + " " + y(v.y).toFixed(2),
          )
          .join(" ")}
        fill="none"
        stroke="#be613b"
        strokeWidth="2.5"
      />
      <path
        d={`M${x(q.flight.catchX)} ${y(0.57)}V${y(1.56)}`}
        stroke="#487965"
        strokeWidth="5"
      />
      <circle
        cx={x(q.ball.x)}
        cy={y(q.ball.y)}
        r="5"
        fill="#1d4538"
        stroke="#fff"
        strokeWidth="1"
      />
    </svg>
  );
}
export default function CourtViewport({
  p,
  time,
  view,
  trace,
  reset,
  onUnavailable,
  sample,
  evidence,
  solution,
  fallbackContent,
}) {
  const canvas = useRef(null),
    stage = useRef(null),
    latest = useRef({ p, time, view, trace, solution });
  const [state, setState] = useState("loading");
  const [frame, setFrame] = useState(null);
  useEffect(() => {
    latest.current = { p, time, view, trace, solution };
    stage.current?.draw(p, time, view, trace, solution);
  }, [p, time, view, trace, solution]);
  useEffect(() => {
    stage.current?.reset();
  }, [reset]);
  useEffect(() => {
    let live = true,
      failed = false,
      observer;
    const el = canvas.current;
    function lost(e) {
      e?.preventDefault?.();
      if (!live || failed) return;
      failed = true;
      observer?.disconnect();
      const rig = stage.current;
      stage.current = null;
      rig?.dispose();
      setState("diagram");
      onUnavailable();
    }
    function draw() {
      const s = latest.current;
      stage.current?.draw(s.p, s.time, s.view, s.trace, s.solution);
    }
    el.addEventListener("webglcontextlost", lost);
    import("../lib/court-stage")
      .then(async ({ createCourtStage }) => {
        if (!live) return;
        const rig = await createCourtStage(el);
        if (!live || failed) {
          rig.dispose();
          return;
        }
        stage.current = rig;
        const resize = () => {
          setFrame(
            rig.resize(
              Math.max(2, el.clientWidth),
              Math.max(2, el.clientHeight),
            ),
          );
          draw();
        };
        resize();
        rig.onOrbit(draw);
        observer = new ResizeObserver(resize);
        observer.observe(el);
        setState("webgl");
      })
      .catch(lost);
    return () => {
      live = false;
      observer?.disconnect();
      el.removeEventListener("webglcontextlost", lost);
      stage.current?.dispose();
      stage.current = null;
    };
  }, [onUnavailable]);
  return (
    <div className="court-screen" data-court-state={state}>
      <canvas
        ref={canvas}
        aria-label={"Interactive ball pass, " + view + " view"}
        onDoubleClick={() => stage.current?.reset()}
      />
      {state === "loading" && (
        <img
          className="court-poster"
          src={
            view === "stereo" ? "/stereo/sightlines.jpg" : "/court/cover.jpg"
          }
          alt="The two players on Juniper Court"
        />
      )}
      {state === "diagram" && (
        <div className="court-diagram">
          <span>
            {view === "stereo" ? "Top view" : "Side elevation"} · WebGL
            unavailable
          </span>
          {fallbackContent || <FlightDiagram p={p} time={time} large />}
        </div>
      )}
      {state === "webgl" && view !== "wide" && view !== "stereo" && frame && (
        <div className="court-detection detector-plate" style={frame}>
          <DetectionBoxes sample={sample} />
        </div>
      )}
      {state === "webgl" && (
        <span className="court-view-label">
          {view === "stereo"
            ? "Sightlines · drag to orbit"
            : view === "wide"
              ? "Courtyard · drag to orbit"
              : (view === "garden" ? "Garden camera" : "Patio camera") +
                " · " +
                evidence}
        </span>
      )}
    </div>
  );
}
