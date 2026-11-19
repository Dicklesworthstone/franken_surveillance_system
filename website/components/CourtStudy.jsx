"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Camera, Eye, Orbit, Pause, Play, RotateCcw } from "lucide-react";
import {
  clipSeconds,
  conditions,
  frameRate,
  parameters,
  passAt,
  samePass,
} from "../lib/pass";
import CourtViewport, { FlightDiagram } from "./CourtViewport";
import { DetectionBoxes } from "./MotionViewport";
const viewpoints = [
  ["wide", "Courtyard", Orbit],
  ["garden", "Garden camera", Camera],
  ["patio", "Patio camera", Camera],
];
function FrameReview({ data, original, restore, inspect, mode, setMode }) {
  const [watchSegment, setWatchSegment] = useState(4);
  const segment = mode === "inspection" ? 4 : watchSegment;
  const seconds = segment / 4;
  const segments = Object.keys(data.garden.frameDigests)
    .map(Number)
    .sort((a, b) => a - b);
  return (
    <section className="court-evidence" aria-labelledby="frame-title">
      <div className="review-intro">
        <div>
          <span className="court-kicker">
            Camera evidence / {seconds.toFixed(2)} s
          </span>
          <h2 id="frame-title">
            Read the <em>frame.</em>
          </h2>
        </div>
        <p>
          The scene contains two players and a ball. Compare what the
          motion-triggered watch sampled with a separate detector run requested
          on this exact frame.
        </p>
      </div>
      {!original ? (
        <div className="court-custom">
          <strong>Custom pass</strong>
          <span>
            The camera images now follow your settings. Native reports belong to
            the recorded bounce pass.
          </span>
          <button onClick={restore}>Restore reference pass ↗</button>
        </div>
      ) : (
        <>
          <div
            className="review-tabs"
            role="group"
            aria-label="Native analysis method"
          >
            {[
              ["inspection", "Inspect exact frame"],
              ["watch", "Motion-triggered watch"],
            ].map(([k, v]) => (
              <button
                key={k}
                aria-pressed={k === mode}
                onClick={() => setMode(k)}
              >
                {v}
              </button>
            ))}
            {mode === "watch" && (
              <select
                aria-label="Watch sample time"
                value={segment}
                onChange={(e) => setWatchSegment(+e.target.value)}
              >
                {segments.map((s) => (
                  <option key={s} value={s}>
                    {(s / 4).toFixed(2)} s
                  </option>
                ))}
              </select>
            )}
          </div>
          <div className="review-grid">
            {["garden", "patio"].map((id) => {
              const v = data[id],
                sample =
                  mode === "inspection"
                    ? v.inspection
                    : v.samples.find((f) => f.segment === segment);
              const detections = sample?.detections ?? [],
                counts = {};
              for (const d of detections)
                counts[d.label] = (counts[d.label] ?? 0) + 1;
              const inferred =
                mode === "inspection" || sample?.status === "inferred";
              const result = inferred
                ? detections.length
                  ? Object.entries(counts)
                      .map(([label, count]) => count + " × " + label)
                      .join(" · ")
                  : "No class returned"
                : sample
                  ? sample.status.replaceAll("_", " ")
                  : "Frame not selected";
              return (
                <article key={id}>
                  <a
                    className="review-frame detector-plate"
                    href={"/court/" + id + "-" + segment + ".jpg"}
                  >
                    <img
                      src={"/court/" + id + "-" + segment + ".jpg"}
                      alt={
                        id +
                        " native input at " +
                        seconds.toFixed(2) +
                        " seconds"
                      }
                      width="160"
                      height="90"
                    />
                    <DetectionBoxes sample={sample} />
                  </a>
                  <div className="review-card-body">
                    <span>
                      {id === "garden" ? "Garden camera" : "Patio camera"}
                    </span>
                    <h3>{result}</h3>
                    <p>
                      {inferred
                        ? "Pinned YOLOX-Nano inference"
                        : "No inference on this frame in the watch report"}
                    </p>
                    <div>
                      <button onClick={() => inspect(id, seconds)}>
                        Locate in 3D ↗
                      </button>
                      <a
                        href={
                          "/court/" +
                          id +
                          (mode === "inspection" ? "-inspection" : "") +
                          ".json"
                        }
                      >
                        Rust report ↗
                      </a>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
          <p className="review-foot">
            Both views share a synthetic scene and clock. Model labels describe
            these pixels. The catch is a result of the physical model.{" "}
            <a href="/exhibits/event-ledger/">
              Follow a published doorstep event into the ledger ↗
            </a>
          </p>
        </>
      )}
      <details className="earlier-take">
        <summary>Why did the detector report a bicycle?</summary>
        <div className="earlier-panel">
          <div className="review-frame detector-plate">
            <img
              src="/court/earlier/frame.jpg"
              width="160"
              height="90"
              alt="Earlier garden recording showing the two players beside the bench"
            />
            <DetectionBoxes
              sample={{
                detections: data.earlier.detections.filter(
                  (d) => d.label === "bicycle",
                ),
              }}
            />
          </div>
          <div>
            <span className="court-kicker">Earlier take / Garden / 1.75 s</span>
            <h3>A box to question.</h3>
            <p>
              The garden camera returned two person detections and one bicycle
              proposal. The highlighted crop includes part of a player. The
              scene contains no bicycle. The model’s raw bicycle score was{" "}
              {data.earlier.detections
                .find((d) => d.label === "bicycle")
                .score.toFixed(3)}
              . Its report describes that score as uncalibrated.
            </p>
            <a href="/court/earlier/garden.json">Original watch report ↗</a>{" "}
            <a href="/court/earlier/garden.mp4">Earlier film ↗</a>
          </div>
        </div>
      </details>
    </section>
  );
}
export default function CourtStudy({ data }) {
  const [p, setP] = useState(conditions[0]),
    [time, setTime] = useState(1),
    [playing, setPlaying] = useState(false);
  const [view, setView] = useState("wide"),
    [trace, setTrace] = useState(true),
    [reset, setReset] = useState(0),
    [fallback, setFallback] = useState(false);
  const [method, setMethod] = useState("inspection");
  const surface = useRef(null),
    starting = useRef(1);
  const unavailable = useCallback(() => {
    setFallback(true);
    setView("wide");
  }, []);
  const active = conditions.find((c) => samePass(c, p)),
    q = passAt(p, time);
  const recorded = active === conditions[0] && data[view],
    segment = time * 4;
  const inspected = recorded && method === "inspection" && segment === 4;
  const sample =
    recorded &&
    (inspected
      ? recorded.inspection
      : recorded.samples.find((f) => f.segment === segment));
  function seek(t) {
    setPlaying(false);
    setTime(t);
  }
  function preset(c) {
    setP(c);
    seek(1);
  }
  function toggle() {
    if (playing) {
      setPlaying(false);
      return;
    }
    starting.current = time >= clipSeconds ? 0 : time;
    setTime(starting.current);
    setPlaying(true);
  }
  useEffect(() => {
    if (!playing) return;
    let id,
      start = null;
    const step = (now) => {
      if (start === null) start = now;
      const t = Math.min(clipSeconds, starting.current + (now - start) / 1000);
      setTime(Math.floor(t * frameRate) / frameRate);
      if (t < clipSeconds) id = requestAnimationFrame(step);
      else setPlaying(false);
    };
    const hide = () => {
      if (document.hidden) setPlaying(false);
    };
    id = requestAnimationFrame(step);
    document.addEventListener("visibilitychange", hide);
    return () => {
      cancelAnimationFrame(id);
      document.removeEventListener("visibilitychange", hide);
    };
  }, [playing]);
  return (
    <article className="court-study">
      <div className="court-heading">
        <div>
          <span className="court-kicker">Juniper House / Courtyard</span>
          <h2>
            The bounce <em>pass.</em>
          </h2>
        </div>
        <p>
          Shorten the distance. Soften the bounce. Watch two people reach for
          the same ball, then see what the cameras picked up.
        </p>
      </div>
      <div className="court-lab" ref={surface}>
        <div className="court-monitor">
          <div
            className="court-views"
            role="group"
            aria-label="Court viewpoints"
          >
            {viewpoints.map(([id, label, Icon]) => (
              <button
                key={id}
                disabled={fallback}
                aria-pressed={view === id}
                onClick={() => setView(id)}
              >
                <Icon size={16} />
                {label}
              </button>
            ))}
            <button
              className="court-orbit-reset"
              disabled={fallback || view !== "wide"}
              aria-label="Reset court orbit"
              onClick={() => setReset((n) => n + 1)}
            >
              <RotateCcw size={16} />
            </button>
          </div>
          <CourtViewport
            p={p}
            time={time}
            view={view}
            trace={trace}
            reset={reset}
            onUnavailable={unavailable}
            sample={sample || undefined}
            evidence={
              recorded
                ? inspected
                  ? "Requested frame"
                  : sample?.status === "inferred"
                    ? "Watch inference"
                    : sample
                      ? sample.status.replaceAll("_", " ")
                      : Number.isInteger(segment)
                        ? "Frame not selected"
                        : "Between native samples"
                : "Simulated view"
            }
          />
          <div className="court-transport">
            <button
              onClick={toggle}
              aria-label={playing ? "Pause pass" : "Play pass"}
            >
              {playing ? (
                <Pause size={18} />
              ) : (
                <Play size={18} fill="currentColor" />
              )}
            </button>
            <input
              aria-label="Pass time"
              type="range"
              min="0"
              max={clipSeconds}
              step=".001"
              value={time}
              onChange={(e) => seek(+e.target.value)}
            />
            <time>{time.toFixed(2)} / 4 s</time>
          </div>
          <div className="court-cues">
            {[
              ["Release", q.release],
              ...(q.contact <= q.arrival || !q.caught
                ? [["First bounce", q.contact]]
                : []),
              ["At receiver", q.arrival],
            ].map(([name, t]) => (
              <button
                key={name}
                aria-pressed={Math.abs(time - t) < 0.001}
                onClick={() => seek(t)}
              >
                {name}
              </button>
            ))}
            <button
              disabled={fallback || view !== "wide"}
              aria-pressed={trace && view === "wide"}
              onClick={() => setTrace(!trace)}
            >
              <Eye size={14} />
              Flight path
            </button>
          </div>
        </div>
        <aside className="court-controls">
          <label className="court-preset">
            Pass setup
            <select
              value={active?.name ?? ""}
              onChange={(e) =>
                preset(conditions.find((c) => c.name === e.target.value))
              }
            >
              {!active && <option value="">Custom pass</option>}
              {conditions.map((c) => (
                <option key={c.name}>{c.name}</option>
              ))}
            </select>
          </label>
          {parameters.map((c) => (
            <label className="court-param" key={c.key}>
              <span>
                {c.label}
                <output>
                  {p[c.key].toFixed(c.key === "speed" ? 1 : 2)} {c.unit}
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
          <div className="court-chart">
            <span>Flight profile</span>
            <FlightDiagram p={p} time={time} />
            <small>Green marks the receiver’s reach</small>
          </div>
        </aside>
      </div>
      <dl className="court-metrics">
        <div>
          <dt>Ball state</dt>
          <dd data-pass-phase>{q.phase}</dd>
        </div>
        <div>
          <dt>Height at receiver</dt>
          <dd>
            {(q.crossing.y * 100).toFixed(0)} <small>cm</small>
          </dd>
        </div>
        <div>
          <dt>Time in flight to receiver</dt>
          <dd>
            {q.flight.travel.toFixed(2)} <small>s</small>
          </dd>
        </div>
        <div>
          <dt>Predicted outcome</dt>
          <dd>{q.caught ? "In reach" : "Outside reach"}</dd>
        </div>
      </dl>
      <FrameReview
        data={data}
        mode={method}
        setMode={setMethod}
        original={active === conditions[0]}
        restore={() => preset(conditions[0])}
        inspect={(id, seconds) => {
          seek(seconds);
          setView(fallback ? "wide" : id);
          surface.current?.scrollIntoView({ block: "start" });
        }}
      />
      <details className="court-notes">
        <summary>Physics, footage and source files</summary>
        <p>
          The ball follows vertical free fall under 9.80665 m/s² of gravity,
          with restitution at floor contact and horizontal velocity that decays
          exponentially. The catch plane uses an authored reach range of
          0.57–1.56 m. Two-link inverse kinematics drive the textured players’
          arms and legs. The catch model omits finger contact, spin forces and
          body collisions.
        </p>
        <p>
          The native detector reads the retained 160 × 90 MJPEG imports at four
          frames per second. Each reference film has 96 frames. A separate,
          explicitly requested inspection runs on segment four of each import.
        </p>
        <div>
          {["wide", "garden", "patio"].map((id) => (
            <a key={id} href={"/court/" + id + ".mp4"}>
              {id} film ↗
            </a>
          ))}
          <a href="/exhibits/stereo-bench/">Locate the ball in stereo ↗</a>
          <a href="/court/capture.json">Render settings ↗</a>
          <a href="/court/analysis.json">Native replay index ↗</a>
          <a href="/court/ROCKETBOX-LICENSE.txt">Rocketbox model license ↗</a>
        </div>
      </details>
    </article>
  );
}
