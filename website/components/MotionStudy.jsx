"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownToLine,
  ArrowUpRight,
  Box,
  Camera,
  Orbit,
  Pause,
  PersonStanding,
  Play,
  SlidersHorizontal,
} from "lucide-react";
import {
  controls,
  duration,
  fps,
  milestones,
  motionAt,
  parcelAt,
  presets,
} from "../lib/motion";
import MotionViewport, { DetectionBoxes } from "./MotionViewport";

const views = [
  ["studio", "Studio", PersonStanding],
  ["site", "Property", Orbit],
  ["pair", "Camera pair", Camera],
];
const camName = { porch: "Porch", drive: "Driveway" };
const matches = (a, b) =>
  controls.every(({ key }) => Math.abs(a[key] - b[key]) < 1e-8);
function Curve({ p, time }) {
  const m = milestones(p),
    end = m.settle + 0.12,
    span = end - m.release;
  const x = (t) => 10 + ((t - m.release) * 280) / span,
    y = (h) => 78 - (68 * h) / p.drop;
  const path = useMemo(
    () =>
      Array.from({ length: 241 }, (_, i) => {
        const t = m.release + (span * i) / 240;
        return (
          (i ? "L" : "M") +
          x(t).toFixed(2) +
          " " +
          y(parcelAt(p, t).clearance).toFixed(2)
        );
      }).join(" "),
    [p],
  );
  const dot = Math.max(m.release, Math.min(time, end));
  return (
    <svg
      viewBox="0 0 300 91"
      role="img"
      aria-label="Modelled parcel clearance from release to rest"
    >
      <path
        d="M10 10H290 M10 44H290 M10 78H290"
        fill="none"
        stroke="currentColor"
        opacity=".16"
      />
      <path d={path + " L290 78 H10 Z"} fill="#a8c5ab" opacity=".25" />
      <path d={path} stroke="#43705d" strokeWidth="2.4" fill="none" />
      {time >= m.release && (
        <circle
          cx={x(dot)}
          cy={y(parcelAt(p, dot).clearance)}
          r="4"
          fill="#b44a28"
        />
      )}
    </svg>
  );
}
function Readings({ analysis, reference, reset, look, fallback }) {
  return (
    <section className="motion-evidence" aria-labelledby="measured-heading">
      <div>
        <span className="study-kicker">NATIVE CAMERA REPLAY</span>
        <h2 id="measured-heading">What did the cameras see?</h2>
        <p>
          FSS decoded each reference film at {analysis.sampleFps} frames per
          second and ran its pinned YOLOX-Nano detector on selected frames. Both
          cameras share one synthetic scene and clock.
        </p>
        <a href="/exhibits/camera-fusion/">
          Explore cross-camera association <ArrowUpRight size={15} />
        </a>
      </div>
      {reference ? (
        <div className="native-pair">
          {Object.entries(analysis.views).map(([id, v]) => {
            const sample = v.samples.find((f) => f.segment === v.plateSegment),
              labels = sample?.classes ?? [];
            return (
              <article key={id}>
                <div className="detector-plate">
                  <img
                    src={"/motion/" + id + "-sample.jpg"}
                    alt={camName[id] + " native input frame at one second"}
                    width="160"
                    height="90"
                  />
                  <DetectionBoxes sample={sample} />
                </div>
                <div>
                  <h3>{camName[id]}</h3>
                  <p>
                    {v.frames} decoded frames · {v.candidates} motion{" "}
                    {v.candidates === 1 ? "candidate" : "candidates"}
                  </p>
                  <strong>
                    1.00 s ·{" "}
                    {labels.length
                      ? labels.join(", ")
                      : sample
                        ? "No class labels returned"
                        : "Frame not inferred"}
                  </strong>
                  <span>
                    <a href={"/motion/" + id + ".mp4"}>Film ↗</a>
                    <a href={"/motion/" + id + ".json"}>Native report ↗</a>
                  </span>
                </div>
              </article>
            );
          })}
          <button className="compare-instant" onClick={look}>
            {fallback
              ? "See this pose at one second"
              : "See this instant in the twin"}{" "}
            <ArrowUpRight size={15} />
          </button>
        </div>
      ) : (
        <div className="custom-reading">
          <Camera size={24} />
          <h3>Custom motion</h3>
          <p>
            These settings change the simulation. Native measurements are
            available for the recorded doorstep delivery.
          </p>
          <button onClick={reset}>
            Restore reference delivery <ArrowUpRight size={15} />
          </button>
        </div>
      )}
    </section>
  );
}
export default function MotionStudy({ analysis }) {
  const [p, setP] = useState(presets[0]),
    [time, setTime] = useState(1.25),
    [playing, setPlaying] = useState(false);
  const [view, setView] = useState("studio"),
    [pose, setPose] = useState(true),
    [fallback, setFallback] = useState(false);
  const onFallback = useCallback(() => {
    setFallback(true);
    setView("studio");
  }, []);
  const q = motionAt(p, time),
    m = milestones(p);
  const active = presets.find((entry) => matches(entry, p));
  function seek(t) {
    setPlaying(false);
    setTime(t);
  }
  function preset(next) {
    setP(next);
    seek(1.25);
  }
  useEffect(() => {
    if (!playing) return;
    let id,
      last = performance.now(),
      current = time,
      frame = -1;
    const tick = (now) => {
      current = Math.min(duration, current + Math.max(0, now - last) / 1000);
      last = now;
      const next = Math.floor(current * fps);
      if (next !== frame) {
        setTime(next / fps);
        frame = next;
      }
      if (current >= duration) {
        setPlaying(false);
        return;
      }
      id = requestAnimationFrame(tick);
    };
    const visibility = () => {
      if (document.hidden) setPlaying(false);
    };
    document.addEventListener("visibilitychange", visibility);
    id = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(id);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [playing]);
  return (
    <article className="motion-study">
      <div className="study-heading">
        <div>
          <span className="study-kicker">JUNIPER HOUSE / MOTION LAB</span>
          <h2>
            The parcel <em>drop.</em>
          </h2>
        </div>
        <p>
          Follow a courier from the path to the porch. Change the stride, lower
          the parcel, and watch the same instant through two fixed cameras.
        </p>
      </div>
      <div className="motion-workspace">
        <div className="screen-column">
          <div className="stage-bar">
            <div role="group" aria-label="Motion camera view">
              {views.map(([key, label, Icon]) => (
                <button
                  key={key}
                  aria-pressed={view === key}
                  disabled={fallback}
                  onClick={() => setView(key)}
                >
                  <Icon size={16} />
                  {label}
                </button>
              ))}
            </div>
            <button
              className="pose-toggle"
              disabled={fallback || view !== "studio"}
              aria-pressed={pose && view === "studio"}
              onClick={() => setPose(!pose)}
            >
              <PersonStanding size={16} />
              Joint trails
            </button>
          </div>
          <MotionViewport
            p={p}
            time={time}
            view={view}
            pose={pose}
            reference={active === presets[0] ? analysis : undefined}
            onFallback={onFallback}
          />
          <noscript>
            <a href="/motion/studio.mp4">Watch the recorded delivery</a>
          </noscript>
          <div className="motion-transport">
            <button
              className="transport-play"
              aria-label={playing ? "Pause motion" : "Play motion"}
              onClick={() => {
                if (!playing && time >= duration) setTime(0);
                setPlaying(!playing);
              }}
            >
              {playing ? <Pause size={19} /> : <Play size={19} />}
            </button>
            <input
              type="range"
              aria-label="Study time"
              min="0"
              max={duration}
              step=".001"
              value={time}
              onChange={(e) => seek(+e.target.value)}
            />
            <time>
              {time.toFixed(2)} <small>/ 9 s</small>
            </time>
          </div>
          <div className="cue-strip">
            {[
              ["Approach", 1.25],
              ["Release", m.release],
              ["First contact", m.contact],
              ["Settled", m.settle],
            ].map(([label, t]) => (
              <button
                key={label}
                onClick={() => seek(t)}
                aria-pressed={Math.abs(time - t) < 0.001}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <aside className="motion-inspector">
          <div className="inspector-label">
            <SlidersHorizontal size={16} />
            <h3>Motion parameters</h3>
          </div>
          <label className="preset-label">
            Scenario
            <select
              value={active?.name ?? ""}
              onChange={(e) =>
                preset(presets.find((s) => s.name === e.target.value))
              }
            >
              {!active && <option value="">Custom settings</option>}
              {presets.map((s) => (
                <option key={s.name}>{s.name}</option>
              ))}
            </select>
          </label>
          {controls.map((c) => (
            <label className="rig-control" key={c.key}>
              <span>
                {c.label}
                <output>
                  {p[c.key].toFixed(2)} <small>{c.unit}</small>
                </output>
              </span>
              <input
                type="range"
                aria-label={c.label}
                min={c.min}
                max={c.max}
                step={c.step}
                value={p[c.key]}
                onChange={(e) => {
                  setPlaying(false);
                  setP({ ...p, [c.key]: +e.target.value });
                }}
              />
            </label>
          ))}
          <div className="drop-trace">
            <div>
              <span>Parcel clearance</span>
              <b>{q.clearance.toFixed(2)} m</b>
            </div>
            <Curve p={p} time={time} />
            <div>
              <small>Release</small>
              <small>Rest</small>
            </div>
          </div>
        </aside>
      </div>
      <div className="study-readouts">
        <div>
          <span>Parcel state</span>
          <strong data-motion-phase>{q.phase}</strong>
        </div>
        <div>
          <span>Approach distance</span>
          <strong>
            {q.advance.toFixed(2)} <small>m</small>
          </strong>
        </div>
        <div>
          <span>Impact speed</span>
          <strong>
            {q.contactSpeed.toFixed(2)} <small>m/s</small>
          </strong>
        </div>
        <div>
          <span>First contact</span>
          <strong>
            {m.contact.toFixed(3)} <small>s</small>
          </strong>
        </div>
      </div>
      <Readings
        analysis={analysis}
        reference={active === presets[0]}
        fallback={fallback}
        reset={() => preset(presets[0])}
        look={() => {
          seek(1);
          setView(fallback ? "studio" : "pair");
          document
            .querySelector(".motion-workspace")
            ?.scrollIntoView({ block: "start" });
        }}
      />
      <details className="motion-method">
        <summary>How the study works</summary>
        <p>
          The authored gait uses planted feet and two-link inverse kinematics
          for the arms and legs. Stature and walking speed set the stride and
          approach time. After release, the parcel falls under 9.80665 m/s² of
          gravity. Its vertical speed after each impact equals the incoming
          speed times restitution. The contact model assumes a level, rigid
          surface. Joint trails show the current pose and two earlier walking
          poses.
        </p>
        <div>
          <a href="/motion/studio.mp4">
            <ArrowDownToLine size={15} />
            Studio film
          </a>
          <a href="/motion/capture.json">
            <Box size={15} />
            Render settings and digests
          </a>
          <a href="/motion/analysis.json">Native replay index ↗</a>
        </div>
      </details>
    </article>
  );
}
