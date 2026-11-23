"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { adapt, boxAt, estimate, stamp } from "../../lib/watch/take";
import { matchesDigest } from "../../lib/night/digest";
import { createClock, useFrame } from "./clock";
import Feed from "./Feed";
import SiteTwin from "./SiteTwin";
import Timeline from "./Timeline";
import { AgentLog, LedgerLog } from "./Transcript";
import { Badge } from "./ui";

/** The camera with the largest unobstructed view of the first person it can find. */
function bestCamera(take, summary, frame) {
  for (const actor of summary.actors) {
    let best = null;
    for (const cam of summary.cameras) {
      const b = boxAt(take, cam.id, actor.id, frame);
      if (!b) continue;
      const score = (b[2] - b[0]) * (b[3] - b[1]) * b[4];
      if (!best || score > best.score) best = { id: cam.id, score };
    }
    if (best) return best.id;
  }
  return null;
}

const STATE = {
  multi_independent: "Two or more cameras",
  single: "One camera",
  not_observable: "Not observable",
  closed: "Track closed",
};

function Readout({ actor, at, summary, status }) {
  const names = (ids) => ids.map((id) => summary.cameras.find((c) => c.id === id)?.name ?? id).join(", ");
  let state = at ? STATE[at.state] : "Waiting";
  let detail = "Not seen yet.";
  if (status === "loading") [state, detail] = ["Loading", "Positions are loading."];
  else if (status === "failed") [state, detail] = ["Unavailable", "Positions did not load."];
  else if (at?.state === "closed") detail = `No sighting for ${Math.round(at.since)} s. Last seen by ${names(at.lastCameras)}.`;
  else if (at?.state === "not_observable")
    detail = `No camera for ${at.since.toFixed(1)} s. Last seen by ${names(at.lastCameras)}. Could be anywhere within ${at.ellipse.major.toFixed(0)} m of that spot.`;
  else if (at) {
    const bound = at.ellipse ? `Position to within ${Math.max(at.ellipse.major, 0.1).toFixed(1)} m` : "Position bound not available";
    const pace = at.speed == null ? null : at.speed < 0.15 ? "standing still" : `moving at ${at.speed.toFixed(1)} m/s`;
    detail = `${names(at.cameras)}. ${[bound, pace, at.action].filter(Boolean).join(", ")}.`;
  }
  return (
    <div className={"readout readout--" + (at?.state ?? "none")} style={{ "--who": actor.colour }}>
      <p className="readout__head">
        <span className="readout__track">{actor.track}</span>
        <span className="readout__state">{state}</span>
      </p>
      <p className="readout__detail">{detail}</p>
    </div>
  );
}

function useVerifiedJson(url, digest, wanted, project) {
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState(null);
  const request = useMemo(() => ({ url, digest, wanted, attempt }), [url, digest, wanted, attempt]);
  useEffect(() => {
    if (!request.url || !request.wanted) return;
    const controller = new AbortController();
    async function load() {
      if (!/^sha256:[a-f0-9]{64}$/.test(request.digest)) throw Error("Its recorded fingerprint is missing.");
      if (!globalThis.crypto?.subtle) throw Error("This browser cannot verify the file here.");
      const response = await fetch(request.url, { signal: controller.signal, cache: request.attempt ? "reload" : "default" });
      if (!response.ok) throw Error("The file could not be fetched.");
      const bytes = await response.blob();
      if (!(await matchesDigest(bytes, request.digest))) throw Error("The file differs from its recorded fingerprint.");
      return project(JSON.parse(await bytes.text()));
    }
    load().then(
      (value) => { if (!controller.signal.aborted) setResult({ request, value }); },
      (error) => { if (!controller.signal.aborted) setResult({ request, error: error.message }); },
    );
    return () => controller.abort();
  }, [request, project]);
  return {
    ...(result?.request === request ? result : {}),
    retry: () => setAttempt((n) => n + 1),
  };
}

function detectorCameras(file) {
  return Object.fromEntries(Object.entries(file.cameras).map(([id, camera]) => [
    id, { inferred: new Set(camera.inferred), person: camera.person },
  ]));
}

export default function Console({ summary, story, spans, sceneUrl, sceneDigest, boxesUrl, boxesDigest }) {
  const clock = useMemo(() => createClock(summary.duration, summary.fps), [summary.duration, summary.fps]);
  useEffect(() => () => clock.stop(), [clock]);
  useEffect(() => {
    // Sections further down the page can move this clock to the moment they describe.
    const seek = (event) => {
      clock.pause();
      clock.seek(event.detail);
    };
    window.addEventListener("fss:seek", seek);
    return () => window.removeEventListener("fss:seek", seek);
  }, [clock]);
  const frame = useFrame(clock);
  const t = frame / summary.fps;

  // Per-frame positions and boxes are fetched once the page is interactive.
  const positions = useVerifiedJson(sceneUrl, sceneDigest, true, adapt);
  const take = positions.value;

  // Films are only fetched once the console is close to the viewport.
  const root = useRef(null);
  const [near, setNear] = useState(false);
  useEffect(() => {
    const watcher = new IntersectionObserver(
      (entries) => entries.some((entry) => entry.isIntersecting) && setNear(true),
      { rootMargin: "600px" },
    );
    watcher.observe(root.current);
    return () => watcher.disconnect();
  }, []);

  // Detector boxes from the project's binaries, when the take has been analysed.
  const detector = useVerifiedJson(boxesUrl, boxesDigest, near, detectorCameras);

  // Nobody is in view at the start, so the replay opens on the camera that faces the house.
  const [selected, setSelected] = useState((summary.cameras.find((cam) => cam.id === "entry") ?? summary.cameras[0]).id);
  const [presentation, setPresentation] = useState(null);
  const [follow, setFollow] = useState(true);
  const [view, setView] = useState("model");
  const [overlayMode, setOverlayMode] = useState("both");
  const pending = useRef({ id: null, frames: 0 });
  useEffect(() => {
    if (!follow || !take) return;
    const best = bestCamera(take, summary, frame);
    if (!best || best === selected) {
      pending.current = { id: null, frames: 0 };
      return;
    }
    // Cut only when another camera has been the better view for half a second.
    const p = pending.current;
    pending.current = p.id === best ? { id: best, frames: p.frames + 1 } : { id: best, frames: 1 };
    const current = summary.actors.some((a) => boxAt(take, selected, a.id, frame));
    if (!current || pending.current.frames >= summary.fps / 2) setSelected(best);
  }, [frame, follow, take, summary, selected]);

  const camera = summary.cameras.find((c) => c.id === selected);
  const cameraRun = detector.value?.[selected];
  const picture = presentation?.camera === camera ? presentation.frame : null;
  let detectorStatus = "Loading detector results.";
  if (!boxesUrl) detectorStatus = "Detector results were not published.";
  else if (detector.error) detectorStatus = "Detector results unavailable.";
  else if (detector.value && picture == null) {
    detectorStatus = presentation?.camera === camera && !presentation.timingAvailable
      ? "Frame timing is unavailable in this browser."
      : "Waiting for a verified camera frame.";
  } else if (detector.value) {
    const count = cameraRun?.person[picture]?.length ?? 0;
    detectorStatus = cameraRun?.inferred.has(picture)
      ? `The detector returned ${count} person ${count === 1 ? "box" : "boxes"} in this frame.`
      : "No detector run was recorded for this frame.";
  }
  const people = summary.actors.map((actor) => ({ actor, at: take ? estimate(take, actor.id, frame) : null }));
  const pick = (id) => {
    setFollow(false);
    setSelected(id);
  };
  const skew = camera.offset === 0 ? "on time" : `${Math.abs(camera.offset).toFixed(1)} s ${camera.offset > 0 ? "fast" : "slow"}`;

  const onConsoleKeyDown = (event) => {
    if (event.code !== "Space") return;
    const tag = event.target?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "BUTTON" || tag === "A" || tag === "SELECT") return;
    event.preventDefault();
    if (clock.playing()) clock.pause();
    else clock.play();
  };

  return (
    <div className="console" id="console" ref={root} tabIndex={-1} onKeyDown={onConsoleKeyDown}>
      {positions.error && (
        <p className="console__error" role="alert">
          Staged positions unavailable. {positions.error} <button type="button" onClick={positions.retry}>Retry positions</button>
        </p>
      )}
      {detector.error && (
        <p className="console__error" role="alert">
          Detector results unavailable. {detector.error} <button type="button" onClick={detector.retry}>Retry detector results</button>
        </p>
      )}
      <div className="console__bar">
        <div className="console__id">
          <span className="console__rec" aria-hidden="true" />
          <p className="micro">Replay, five films on one clock</p>
        </div>
        <div className="console__controls-bar">
          {boxesUrl && (
            <div className="switch console__overlay-switch" role="group" aria-label="Box overlays">
              {[
                ["both", "Both boxes"],
                ["staged", "Staged"],
                ["measured", "Detector"],
              ].map(([mode, label]) => (
                <button key={mode} type="button" aria-pressed={overlayMode === mode} onClick={() => setOverlayMode(mode)}>
                  {label}
                </button>
              ))}
            </div>
          )}
          <label className="console__follow">
            <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
            Follow the person between cameras
          </label>
        </div>
      </div>

      <div className="console__stage">
        <div className="console__feeds" role="group" aria-label="Cameras">
          {summary.cameras.map((cam, i) => (
            <Feed
              key={cam.id}
              camera={cam}
              take={take}
              summary={summary}
              clock={clock}
              detections={detector.value?.[cam.id]?.person}
              wanted={near}
              large={cam.id === selected}
              showStaged={overlayMode !== "measured"}
              showMeasured={overlayMode !== "staged"}
              setPresentation={cam.id === selected ? setPresentation : undefined}
              style={cam.id === selected ? { gridColumn: "1 / -1", gridRow: 1 } : { gridColumn: i + 1, gridRow: 3 }}
            />
          ))}
          <div className="console__caption">
            <p className="console__caption-info">
              <b className="console__chip" aria-hidden="true">CAM {summary.cameras.indexOf(camera) + 1}</b>
              <strong>{camera.name}.</strong> {camera.product}, {camera.mode === "infrared" ? "infrared night mode" : "colour night mode"}.{" "}
              {picture == null ? <>Its clock is {skew}.</> : <>
                Its clock reads <span className="data">{stamp(summary, picture / summary.fps, camera.offset)}</span>, {skew}.
              </>}
              {" "}<span className="console__detector-status">{detectorStatus}</span>
            </p>
          </div>
          {summary.cameras.map((cam, i) => {
            const seen = take ? summary.actors.filter((a) => boxAt(take, cam.id, a.id, frame)) : [];
            return (
              <button
                key={cam.id}
                type="button"
                className={"slot" + (cam.id === selected ? " is-selected" : "")}
                style={{ gridColumn: i + 1 }}
                aria-pressed={cam.id === selected}
                aria-label={`Show the ${cam.name.toLowerCase()} camera`}
                onClick={() => pick(cam.id)}
              >
                <span className="slot__frame">
                  {cam.id === selected && (
                    <span className="slot__active">
                      <b className="data">MAIN</b>
                      <span>On the main screen</span>
                    </span>
                  )}
                </span>
                <span className="slot__name">
                  {cam.name}
                  {seen.map((a) => (
                    <i key={a.id} style={{ background: a.colour }} />
                  ))}
                </span>
              </button>
            );
          })}
        </div>
        <div className="console__site">
          <SiteTwin summary={summary} take={take} frame={frame} selected={selected} onSelect={pick} mode={view} />
          {summary.twin.front && (
            <div className="switch console__view" role="group" aria-label="View of the site">
              <button type="button" aria-pressed={view === "model"} onClick={() => setView("model")}>
                Model
              </button>
              <button type="button" aria-pressed={view === "plan"} onClick={() => setView("plan")}>
                Plan
              </button>
            </div>
          )}
        </div>
        <div className="console__readouts">
          {people.map((p) => (
            <Readout key={p.actor.id} {...p} summary={summary} status={take ? "ready" : positions.error ? "failed" : "loading"} />
          ))}
        </div>
      </div>

      <Timeline summary={summary} spans={spans} markers={story.markers} belief={story.belief} clock={clock} frame={frame} />

      <div className="console__logs">
        <section aria-labelledby="agent-log">
          <div className="console__log-head">
            <h3 id="agent-log" className="console__heading">
              The agent
            </h3>
            <Badge kind="staged">Staged script</Badge>
          </div>
          <AgentLog rows={story.agent} t={t} clock={clock} />
        </section>
        <section aria-labelledby="ledger-log">
          <div className="console__log-head">
            <h3 id="ledger-log" className="console__heading">
              The ledger
            </h3>
            <Badge kind="staged">Staged script</Badge>
          </div>
          <LedgerLog rows={story.ledger} t={t} clock={clock} />
        </section>
      </div>

      <ul className="console__key" aria-label="How to read the replay">
        <li>
          <Badge kind="staged">Dashed outline</Badge> Staged position of a person.
        </li>
        {boxesUrl && (
          <li>
            <Badge kind="measured">Solid green outline</Badge> The detector's own box for that frame.
          </li>
        )}
        <li>
          <Badge kind="browser">Bounds on the model</Badge> Computed in your browser from camera geometry.
        </li>
        <li>
          <Badge kind="staged">Amber fans</Badge> Each lens on open ground, not cut by walls or trees.
        </li>
      </ul>
    </div>
  );
}
