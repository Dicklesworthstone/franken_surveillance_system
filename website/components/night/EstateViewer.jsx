"use client";
import { useEffect, useRef, useState } from "react";
import { Orbit, RotateCcw, Pause, Play } from "lucide-react";
import { displayCamera } from "../../lib/night/catalog";
export default function EstateViewer({ id, lenses, seconds, hero }) {
  const canvas = useRef(null),
    stage = useRef(null);
  const [camera, setCamera] = useState("overview"),
    [time, setTime] = useState(0),
    [playing, play] = useState(false),
    [state, status] = useState("loading");
  const referenceHeight = id === "delivery" ? 1.74 : 1.78;
  const [height, setHeight] = useState(referenceHeight),
    [speed, setSpeed] = useState(1),
    [generation, retry] = useState(0);
  const latest = useRef({}),
    duration = Number(seconds) || 8,
    person = id !== "wildlife";
  const draw = () => {
    const q = latest.current;
    stage.current?.draw(q.id, q.time, q.camera, q.parameters);
  };
  const custom = person && (height !== referenceHeight || speed !== 1);
  useEffect(() => {
    latest.current = {
      id,
      time,
      camera,
      parameters: custom ? { height, speed } : undefined,
    };
    draw();
  }, [id, time, camera, height, speed, custom, state]);
  useEffect(() => {
    let disposed = false,
      observer,
      rig;
    const element = canvas.current;
    const lost = (e) => {
      e.preventDefault();
      if (!disposed) {
        play(false);
        status("unavailable");
      }
    };
    element.addEventListener("webglcontextlost", lost);
    status("loading");
    (async () => {
      const { createNightStage } = await import("../../lib/night-scene/stage");
      if (disposed) return;
      rig = await createNightStage(element, { interactive: true });
      if (disposed) {
        rig.dispose();
        return;
      }
      stage.current = rig;
      const size = () => {
        const parent = element.parentElement;
        rig.resize(parent.clientWidth, parent.clientHeight);
        draw();
      };
      observer = new ResizeObserver(size);
      observer.observe(element.parentElement);
      rig.onChange(draw);
      size();
      status("ready");
    })().catch(() => {
      if (!disposed) status("unavailable");
    });
    return () => {
      disposed = true;
      observer?.disconnect();
      element.removeEventListener("webglcontextlost", lost);
      rig?.dispose();
      stage.current = null;
    };
  }, [generation]);
  const startTime = useRef(0);
  useEffect(() => {
    if (!playing) return;
    let raf,
      prev = performance.now(),
      running = startTime.current;
    const tick = (now) => {
      running += Math.min(0.15, (now - prev) / 1000);
      prev = now;
      setTime(Math.min(duration, running));
      if (running >= duration) {
        play(false);
        return;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, duration]);
  return (
    <section className="estate-lab" id="estate-viewer">
      <div className="section-head">
        <div>
          <span className="ticker">Digital twin</span>
          <h2>
            Walk the <em>property.</em>
          </h2>
        </div>
        <p>
          Orbit the same exterior used to render the security films, then look
          through a mounted camera.
        </p>
      </div>
      <div className="twin-shell">
        <div className="twin-surface" data-estate-state={state}>
          <canvas
            ref={canvas}
            aria-label="Interactive 3D exterior of Alder House"
            key={generation}
          />
          {state !== "ready" && (
            <div className="twin-poster">
              <img
                src={hero}
                alt="Rendered exterior of the same fictional estate"
              />
              <span role="status">
                {state === "loading"
                  ? "Loading estate geometry…"
                  : "3D view unavailable"}{" "}
                {state === "unavailable" && (
                  <button onClick={() => retry(generation + 1)}>Retry ↻</button>
                )}
              </span>
            </div>
          )}
          {state === "ready" && (
            <span className="twin-hint">
              <Orbit size={14} />
              {camera === "overview"
                ? "Drag to orbit · pinch to zoom"
                : displayCamera(camera)}
            </span>
          )}
        </div>
        <aside className="twin-instruments">
          <h3>Site reconstruction</h3>
          <label>
            Viewpoint
            <select value={camera} onChange={(e) => setCamera(e.target.value)}>
              {[
                "overview",
                ...lenses.filter((c) => c.id !== "overview").map((c) => c.id),
              ].map((c) => (
                <option key={c} value={c}>
                  {displayCamera(c)}
                </option>
              ))}
            </select>
          </label>
          {person && (
            <>
              <label>
                Person’s stature <output>{height.toFixed(2)} m</output>
                <input
                  type="range"
                  aria-label="Person stature"
                  min="1.5"
                  max="2.0"
                  step=".01"
                  value={height}
                  onChange={(e) => setHeight(+e.target.value)}
                />
              </label>
              <label>
                Walking pace <output>{speed.toFixed(2)}×</output>
                <input
                  type="range"
                  aria-label="Walking pace"
                  min=".65"
                  max="1.5"
                  step=".05"
                  value={speed}
                  onChange={(e) => setSpeed(+e.target.value)}
                />
              </label>
            </>
          )}
          <label>
            Scene time <output>{time.toFixed(2)} s</output>
            <input
              type="range"
              min="0"
              max={duration}
              step=".05"
              value={time}
              onChange={(e) => {
                play(false);
                setTime(+e.target.value);
              }}
            />
          </label>
          <button
            disabled={state !== "ready"}
            onClick={() => {
              startTime.current = time >= duration ? 0 : time;
              play(!playing);
            }}
          >
            {playing ? <Pause size={15} /> : <Play size={15} />}{" "}
            {playing ? "Pause movement" : "Play movement"}
          </button>
          <button
            onClick={() => {
              setHeight(referenceHeight);
              setSpeed(1);
              setTime(0);
              play(false);
              setCamera("overview");
              stage.current?.reset();
            }}
          >
            <RotateCcw size={15} /> Reset scene
          </button>
          <p aria-live="polite">
            {custom
              ? "Custom reconstruction. The native camera reports belong to the recorded take."
              : "Reference take. Camera films and native reports are available below."}
          </p>
        </aside>
      </div>
    </section>
  );
}
