"use client";
import { useEffect, useRef, useState } from "react";
import {
  Play,
  Pause,
  SkipBack,
  ChevronLeft,
  ChevronRight,
  ArrowUpRight,
  Columns2,
} from "lucide-react";
import { useNativeWatch, TrackOverlay, TrackEvents } from "./NativeTracks";
import GroundReview from "./GroundReview";
import CameraFilm from "../CameraFilm";
import { displayCamera } from "../../lib/night/catalog";

const instant = (t) => (Number.isFinite(t) ? t.toFixed(2) + " s" : "—");
function sceneClock(localTime, elapsed) {
  const [hour, minute] = localTime.split(":").map(Number);
  const seconds = hour * 3600 + minute * 60 + Math.floor(elapsed);
  return [
    Math.floor(seconds / 3600) % 24,
    Math.floor(seconds / 60) % 60,
    seconds % 60,
  ]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
}
const stems = (id, c) => "/night-media/" + id + "-" + c;
function waitForMedia(element, event, signal) {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    function done(e) {
      element.removeEventListener(event, done);
      element.removeEventListener("error", done);
      signal.removeEventListener("abort", done);
      if (e.type === event) resolve();
      else reject(Error(e.type));
    }
    element.addEventListener(event, done);
    element.addEventListener("error", done);
    signal.addEventListener("abort", done);
  });
}
function LensPicker({ ids, selected, set, legend }) {
  return (
    <fieldset className="lens-choice">
      <legend>{legend}</legend>
      {ids.map((c) => (
        <button key={c} aria-pressed={selected === c} onClick={() => set(c)}>
          {displayCamera(c)}
        </button>
      ))}
    </fieldset>
  );
}
function Frame({ sample }) {
  return (
    <div className="native-frame">
      <img
        src={sample.image}
        width="160"
        height="90"
        alt="Exact camera JPEG inspected by the native detector"
      />
      {(sample.detections || []).map((d, i) => {
        const [l, t, r, b] = d.bounds_subpixel;
        return (
          <i
            key={i}
            aria-label={d.label + " detector box"}
            style={{
              left: l / 409.6 + "%",
              top: t / 230.4 + "%",
              width: (r - l) / 409.6 + "%",
              height: (b - t) / 230.4 + "%",
            }}
          />
        );
      })}
      {sample.sceneFoot && (
        <span
          className="scene-foot"
          aria-label="Scripted subject ground position"
          style={{
            left: sample.sceneFoot[0] * 100 + "%",
            top: sample.sceneFoot[1] * 100 + "%",
          }}
        >
          +
        </span>
      )}
    </div>
  );
}
export function SampleInspection({ view, camera, inspect }) {
  const samples = view.samples || [];
  const [selected, setSelected] = useState(() =>
    Math.max(0, samples.findIndex((sample) => sample.detections?.length)),
  );
  const sample = samples[Math.min(selected, samples.length - 1)];
  return (
    <div className="inspection-content" id="frame-inspection">
      {sample ? (
        <>
          <div className="native-card">
            <Frame sample={sample} />
            <div>
              <span className="ticker">Original detector input</span>
              <b>
                {displayCamera(camera)} · {instant(sample.time)}
              </b>
            </div>
          </div>
          <div className="observation">
            <span className="ticker">FSS frame inspection</span>
            <h3>
              {sample.detections?.length
                ? "Returned labels"
                : "No class returned"}
            </h3>
            {sample.detections?.length > 0 && (
              <ul className="native-labels">
                {sample.detections.map((d, i) => (
                  <li key={i}>
                    <span>{d.label}</span>
                    <code>{d.score.toFixed(3)}</code>
                  </li>
                ))}
              </ul>
            )}
            <p>
              {sample.detections?.length
                ? "Scores are uncalibrated model outputs for this JPEG."
                : "This result applies to the inspected pixels at this instant."}
            </p>
            {sample.sceneFoot && (
              <p>
                The green cross marks the scripted subject’s feet. Gold boxes
                mark the detector’s observations.
              </p>
            )}
            {samples.length > 1 && (
              <label className="frame-select">
                Inspect frame{" "}
                <select
                  value={Math.min(selected, samples.length - 1)}
                  onChange={(e) => setSelected(+e.target.value)}
                >
                  {samples.map((s, i) => (
                    <option value={i} key={i}>
                      {instant(s.time)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="observation-links">
              {inspect && (
                <button onClick={() => inspect(sample.time)}>
                  Seek recording ↗
                </button>
              )}
              <a href={sample.report}>Native report ↗</a>
              <a href={sample.image}>Source JPEG ↗</a>
            </div>
          </div>
        </>
      ) : (
        <p>
          No native frame inspection was retained for this view.{" "}
          <a href={view.watch}>Open the camera report ↗</a>
        </p>
      )}
    </div>
  );
}
export default function CameraReview({
  estate,
  incident,
  id,
  seconds,
  fps,
  compare = false,
}) {
  const ids = Object.keys(incident.views),
    [camera, setCamera] = useState(incident.primary);
  const [split, setSplit] = useState(compare),
    [second, selectSecond] = useState(() => {
      const match = Object.values(incident.associations.pairs).find(
        (pair) => pair.count > 0 && pair.cameras.includes(incident.primary),
      );
      return (match?.cameras ?? ids).find((c) => c !== incident.primary);
    });
  const [playing, setPlaying] = useState(false),
    [t, setTime] = useState(0),
    [problem, setProblem] = useState({}),
    [playError, setPlayError] = useState("");
  const main = useRef(null),
    other = useRef(null),
    clock = useRef(0);
  const duration = Number(seconds) || 8,
    hz = Number(fps) || 12;
  const view = incident.views[camera],
    otherId = second !== camera ? second : ids.find((c) => c !== camera);
  const [overlays, setOverlays] = useState(true);
  const primaryWatch = useNativeWatch(view),
    secondaryWatch = useNativeWatch(
      split && otherId ? incident.views[otherId] : null,
    );
  const setPosition = (el, time) => {
    if (el && el.readyState >= 1 && Number.isFinite(el.duration))
      el.currentTime = Math.min(
        Math.max(time, 0),
        Math.max(0, el.duration - 0.001),
      );
  };
  function seek(time) {
    setPlaying(false);
    const value = Math.max(0, Math.min(time, duration));
    clock.current = value;
    setTime(value);
    setPosition(main.current, value);
    setPosition(other.current, value);
  }
  function changeCamera(c) {
    setPlaying(false);
    setPlayError("");
    setCamera(c);
    if (c === second) selectSecond(camera);
  }
  useEffect(() => {
    const a = main.current,
      b = other.current;
    if (!playing) {
      a?.pause();
      b?.pause();
      if (b && Math.abs(b.currentTime - clock.current) > 0.04)
        setPosition(b, clock.current);
      return;
    }
    const controller = new AbortController(),
      videos = [a, b].filter(Boolean);
    let raf;
    const start = clock.current;
    async function synchronize() {
      try {
        await Promise.all(
          videos.map(async (el) => {
            if (el.error) throw Error("media");
            if (el.readyState < 1)
              await waitForMedia(el, "loadedmetadata", controller.signal);
            if (Math.abs(el.currentTime - start) > 0.015)
              setPosition(el, start);
            if (el.seeking) await waitForMedia(el, "seeked", controller.signal);
          }),
        );
        if (controller.signal.aborted) return;
        await Promise.all(videos.map((el) => el.play()));
        if (!controller.signal.aborted) raf = requestAnimationFrame(tick);
      } catch {
        if (!controller.signal.aborted) {
          setPlayError("Playback could not start for the selected cameras.");
          setPlaying(false);
        }
      }
    }
    function tick() {
      if (controller.signal.aborted || !a) return;
      const now = a.currentTime;
      clock.current = now;
      setTime(Math.floor(now * hz) / hz);
      if (b && b.readyState >= 2 && Math.abs(now - b.currentTime) > 0.12)
        setPosition(b, now);
      if (!a.ended) raf = requestAnimationFrame(tick);
    }
    synchronize();
    return () => {
      controller.abort();
      cancelAnimationFrame(raf);
      a?.pause();
      b?.pause();
    };
  }, [playing, split, camera, otherId, hz]);
  function video(c, ref, primary) {
    const v = incident.views[c];
    return (
      <figure className="recording" key={c}>
        <div className="film-well">
          {problem[c] ? (
            <div role="status" className="media-failure">
              {problem[c]}{" "}
              <button type="button" onClick={() => {
                setPlayError("");
                setProblem((previous) => ({ ...previous, [c]: null }));
              }}>Retry {displayCamera(c)} recording</button>
              <a href={v.film}>Open source file ↗</a>
            </div>
          ) : (
            <CameraFilm
              videoRef={ref}
              muted
              playsInline
              preload="auto"
              filmUrl={v.film}
              filmDigest={v.filmDigest}
              poster={stems(id, c) + ".jpg"}
              aria-label={displayCamera(c) + " recording"}
              onLoadedMetadata={(e) =>
                setPosition(e.currentTarget, clock.current)
              }
              onError={(event) => {
                const reason = event.nativeEvent.detail || "Camera film unavailable.";
                setProblem((x) => ({ ...x, [c]: reason }));
                setPlaying(false);
              }}
              onEnded={
                primary
                  ? () => {
                      setPlaying(false);
                      setTime(duration);
                      clock.current = duration;
                    }
                  : undefined
              }
            />
          )}
          {overlays && !problem[c] && (
            <TrackOverlay
              videoRef={ref}
              view={v}
              watch={primary ? primaryWatch : secondaryWatch}
            />
          )}
          <span className="film-camera">
            <i />
            {displayCamera(c)}
          </span>
          <span className="film-clock" aria-label="Fictional scene clock">
            {sceneClock(incident.localTime, t)}
          </span>
        </div>
      </figure>
    );
  }
  return (
    <section
      className="review-section"
      id="recordings"
      aria-label="Camera recordings"
    >
      <div className="section-head">
        <div>
          <span className="ticker">Camera room</span>
          <h2>
            Review the <em>recording.</em>
          </h2>
        </div>
        <p>
          Switch viewpoints at the same instant or play two cameras side by
          side.
        </p>
      </div>
      <div className="film-console">
        <div className="console-toolbar">
          <LensPicker
            ids={ids}
            selected={camera}
            set={changeCamera}
            legend="Primary camera"
          />
          {ids.length > 1 && (
            <button
              className="compare-toggle"
              aria-pressed={split}
              onClick={() => {
                setPlaying(false);
                setSplit(!split);
              }}
            >
              <Columns2 size={15} /> Compare cameras
            </button>
          )}
        </div>
        {split && otherId && (
          <div className="compare-picker">
            <LensPicker
              ids={ids.filter((c) => c !== camera)}
              selected={otherId}
              set={(c) => {
                setPlaying(false);
                selectSecond(c);
              }}
              legend="Second camera"
            />
          </div>
        )}
        <div className={"film-grid" + (split && otherId ? " split" : "")}>
          {video(camera, main, true)}
          {split && otherId && video(otherId, other, false)}
        </div>
        <div className="transport">
          <button
            aria-label={playing ? "Pause recording" : "Play recording"}
            onClick={() => {
              setPlayError("");
              if (playing) {
                seek(main.current?.currentTime ?? clock.current);
                return;
              }
              if (clock.current >= duration) seek(0);
              setPlaying(true);
            }}
            disabled={Boolean(problem[camera] || (split && problem[otherId]))}
          >
            {playing ? <Pause /> : <Play />}
          </button>
          <button aria-label="Restart recording" onClick={() => seek(0)}>
            <SkipBack />
          </button>
          <label>
            <span className="sr-only">Recording time</span>
            <input
              type="range"
              min="0"
              max={duration}
              step={1 / hz}
              value={t}
              onChange={(e) => seek(+e.target.value)}
            />
          </label>
          <output>{instant(t)}</output>
          <button
            aria-label="Previous frame"
            onClick={() => seek((Math.round(t * hz) - 1) / hz)}
          >
            <ChevronLeft />
          </button>
          <button
            aria-label="Next frame"
            onClick={() => seek((Math.round(t * hz) + 1) / hz)}
          >
            <ChevronRight />
          </button>
        </div>
      </div>
      <div className="overlay-settings">
        {playError && <p role="status">{playError}</p>}
        <label>
          <input
            type="checkbox"
            checked={overlays}
            onChange={(e) => setOverlays(e.target.checked)}
          />{" "}
          Show measured boxes
        </label>
        <span>
          Track ID <i /> · Detector label <b />
        </span>
      </div>
      <TrackEvents key={"tracks-" + camera} view={view} watch={primaryWatch} seek={seek} />
      {split && otherId && (
        <GroundReview
          estate={estate}
          incident={incident}
          cameras={[camera, otherId]}
          onSeek={(c, time) => {
            changeCamera(c);
            seek(time);
          }}
        />
      )}
      <SampleInspection
        key={"inspection-" + camera}
        view={view}
        camera={camera}
        inspect={seek}
      />
      <div className="source-foot">
        <span>Shared scene and clock · Synthetic camera recordings</span>
        <a href={view.film}>
          Download camera film <ArrowUpRight size={14} />
        </a>
      </div>
    </section>
  );
}
